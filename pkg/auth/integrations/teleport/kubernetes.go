package teleport

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	errUtils "github.com/cloudposse/atmos/errors"
	"github.com/cloudposse/atmos/pkg/auth/cloud/kube"
	teleportCloud "github.com/cloudposse/atmos/pkg/auth/cloud/teleport"
	"github.com/cloudposse/atmos/pkg/auth/integrations"
	"github.com/cloudposse/atmos/pkg/auth/types"
	log "github.com/cloudposse/atmos/pkg/logger"
	"github.com/cloudposse/atmos/pkg/perf"
	"github.com/cloudposse/atmos/pkg/schema"
	"github.com/cloudposse/atmos/pkg/ui"
)

// teleportClientFactory builds a Teleport SDK client from credentials.
// Overridable in tests so Execute can be exercised without a live cluster.
var teleportClientFactory = func(ctx context.Context, creds *types.TeleportCredentials) (teleportCloud.Client, error) {
	return teleportCloud.NewClient(ctx, creds)
}

// kubeconfigModeBase is the numeric base used to parse the kubeconfig file
// mode (an octal string like "0600").
const kubeconfigModeBase = 8

// kubeconfigModeBits is the bit width used to parse the kubeconfig mode.
const kubeconfigModeBits = 32

func init() {
	integrations.Register(integrations.KindTeleportKubernetes, NewKubernetesIntegration)
}

// KubernetesIntegration implements the teleport/kubernetes integration kind.
//
// It mirrors the structure of EKSIntegration (pkg/auth/integrations/aws/eks.go):
// Execute() issues a per-cluster cert via the Teleport SDK and writes a
// kubeconfig entry with an `atmos teleport kube token` exec plugin. Multiple
// teleport/kubernetes integrations may share a kubeconfig file with each
// other and with aws/eks integrations -- the kubeconfig manager (pkg/auth/cloud/kube)
// merges entries safely.
type KubernetesIntegration struct {
	name     string
	identity string
	cluster  *schema.TeleportKubernetesCluster
}

// NewKubernetesIntegration creates a teleport/kubernetes integration from config.
func NewKubernetesIntegration(config *integrations.IntegrationConfig) (integrations.Integration, error) {
	defer perf.Track(nil, "integrations/teleport.NewKubernetesIntegration")()

	if config == nil || config.Config == nil {
		return nil, fmt.Errorf("%w: integration config is nil", errUtils.ErrIntegrationNotFound)
	}

	cluster, err := resolveTeleportCluster(config)
	if err != nil {
		return nil, err
	}
	if err := validateKubeconfigSettings(config.Name, cluster.Kubeconfig); err != nil {
		return nil, err
	}

	return &KubernetesIntegration{
		name:     config.Name,
		identity: resolveIdentity(config.Config.Via),
		cluster:  cluster,
	}, nil
}

// resolveIdentity extracts the upstream identity name from the integration's
// via section. Empty string when via is unset (or via.identity is empty).
func resolveIdentity(via *schema.IntegrationVia) string {
	if via == nil {
		return ""
	}
	return via.Identity
}

// resolveTeleportCluster validates that the integration carries a Teleport
// kubernetes cluster reference and returns it. Returns an error wrapping
// ErrIntegrationFailed when the spec is missing or incomplete.
func resolveTeleportCluster(config *integrations.IntegrationConfig) (*schema.TeleportKubernetesCluster, error) {
	if config.Config.Spec == nil || config.Config.Spec.TeleportKubernetes == nil {
		return nil, fmt.Errorf("%w: integration '%s' has no teleport_kubernetes configured (spec.teleport_kubernetes is required for teleport/kubernetes)", errUtils.ErrIntegrationFailed, config.Name)
	}
	cluster := config.Config.Spec.TeleportKubernetes
	if cluster.Name == "" {
		return nil, fmt.Errorf("%w: integration '%s' has no cluster name configured", errUtils.ErrIntegrationFailed, config.Name)
	}
	return cluster, nil
}

// validateKubeconfigSettings enforces the optional kubeconfig settings:
//   - Mode parses as an octal number.
//   - Update is one of "merge", "replace", or "error".
//
// nil settings are accepted (the integration falls back to defaults at
// Execute time).
func validateKubeconfigSettings(integrationName string, settings *schema.KubeconfigSettings) error {
	if settings == nil {
		return nil
	}
	if settings.Mode != "" {
		if _, err := strconv.ParseUint(settings.Mode, kubeconfigModeBase, kubeconfigModeBits); err != nil {
			return fmt.Errorf("%w: integration '%s' has invalid kubeconfig mode %q", errUtils.ErrIntegrationFailed, integrationName, settings.Mode)
		}
	}
	switch settings.Update {
	case "", "merge", "replace", "error":
		return nil
	default:
		return fmt.Errorf("%w: integration '%s' has invalid kubeconfig update mode %q (must be merge, replace, or error)", errUtils.ErrIntegrationFailed, integrationName, settings.Update)
	}
}

// Kind returns "teleport/kubernetes".
func (k *KubernetesIntegration) Kind() string {
	return integrations.KindTeleportKubernetes
}

// Execute issues a per-cluster Teleport kube cert and writes the kubeconfig
// entry that wires kubectl to use Atmos's exec credential plugin
// (`atmos teleport kube token`). The per-invocation client certificate is
// minted by that exec plugin; Execute uses the SDK call to obtain the cluster's
// CA and proxy address for the kubeconfig server entry.
func (k *KubernetesIntegration) Execute(ctx context.Context, creds types.ICredentials) error {
	defer perf.Track(nil, "integrations/teleport.KubernetesIntegration.Execute")()

	teleportCreds, err := k.assertCredentials(creds)
	if err != nil {
		return err
	}

	client, err := teleportClientFactory(ctx, teleportCreds)
	if err != nil {
		return fmt.Errorf("%w: %w", errUtils.ErrTeleportIntegrationFailed, err)
	}
	defer func() { _ = client.Close() }()

	kubeCert, err := client.GenerateKubeCert(ctx, teleportCloud.GenerateKubeCertRequest{
		KubernetesCluster: k.cluster.Name,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", errUtils.ErrTeleportIntegrationFailed, err)
	}

	proxyAddress := kubeCert.KubeProxyAddress
	if proxyAddress == "" {
		proxyAddress = teleportCreds.ProxyAddress
	}

	path, mode, updateMode := k.resolveKubeconfigSettings()
	mgr, err := kube.NewKubeconfigManager(path, mode)
	if err != nil {
		return fmt.Errorf("%w: %w", errUtils.ErrTeleportIntegrationFailed, err)
	}

	params := &kube.TeleportKubeClusterParams{
		ProxyAddress: proxyAddress,
		ClusterName:  k.cluster.Name,
		Alias:        k.cluster.Alias,
		CACertPEM:    strings.Join(kubeCert.TLSCAsPEM, "\n"),
		IdentityName: k.identity,
	}

	changed, err := mgr.WriteTeleportClusterConfig(params, updateMode)
	if err != nil {
		return fmt.Errorf("%w: %w", errUtils.ErrTeleportIntegrationFailed, err)
	}

	displayName := k.cluster.Alias
	if displayName == "" {
		displayName = k.cluster.Name
	}
	if changed {
		ui.Success(fmt.Sprintf("Teleport kubeconfig: %s → %s", displayName, mgr.GetPath()))
		log.Debug("Teleport kubeconfig written", "cluster", k.cluster.Name, "context", displayName, "path", mgr.GetPath())
	} else {
		log.Debug("Teleport kubeconfig already up to date", "cluster", k.cluster.Name, "context", displayName, "path", mgr.GetPath())
	}

	return nil
}

// assertCredentials validates that the supplied credentials are Teleport
// credentials and returns them typed.
func (k *KubernetesIntegration) assertCredentials(creds types.ICredentials) (*types.TeleportCredentials, error) {
	if creds == nil {
		return nil, fmt.Errorf("%w: nil credentials for teleport/kubernetes integration %q", errUtils.ErrTeleportIntegrationFailed, k.name)
	}
	teleportCreds, ok := creds.(*types.TeleportCredentials)
	if !ok {
		return nil, fmt.Errorf("%w: teleport/kubernetes requires teleport credentials (got %T)", errUtils.ErrTeleportCredentialsType, creds)
	}
	return teleportCreds, nil
}

// Cleanup removes kubeconfig entries for this integration's cluster.
func (k *KubernetesIntegration) Cleanup(_ context.Context) error {
	defer perf.Track(nil, "integrations/teleport.KubernetesIntegration.Cleanup")()

	path, mode, _ := k.resolveKubeconfigSettings()
	mgr, err := kube.NewKubeconfigManager(path, mode)
	if err != nil {
		return fmt.Errorf("%w: %w", errUtils.ErrTeleportIntegrationFailed, err)
	}

	if err := mgr.RemoveTeleportClusterConfig(&kube.TeleportKubeClusterParams{
		ClusterName: k.cluster.Name,
		Alias:       k.cluster.Alias,
	}); err != nil {
		return fmt.Errorf("%w: %w", errUtils.ErrTeleportIntegrationFailed, err)
	}
	return nil
}

// Environment returns environment variables contributed by this integration:
// KUBECONFIG / KUBE_CONFIG_PATH pointing at the managed kubeconfig, matching
// the aws/eks integration so the kubeconfig manager's path merging applies
// uniformly across both kinds.
func (k *KubernetesIntegration) Environment() (map[string]string, error) {
	defer perf.Track(nil, "integrations/teleport.KubernetesIntegration.Environment")()

	path, mode, _ := k.resolveKubeconfigSettings()
	mgr, err := kube.NewKubeconfigManager(path, mode)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUtils.ErrTeleportIntegrationFailed, err)
	}
	p := mgr.GetPath()
	return map[string]string{
		"KUBECONFIG":       p,
		"KUBE_CONFIG_PATH": p,
	}, nil
}

// resolveKubeconfigSettings extracts kubeconfig path, mode, and update mode from
// the cluster config (all optional; empty strings fall back to defaults).
func (k *KubernetesIntegration) resolveKubeconfigSettings() (path, mode, update string) {
	if k.cluster != nil && k.cluster.Kubeconfig != nil {
		return k.cluster.Kubeconfig.Path, k.cluster.Kubeconfig.Mode, k.cluster.Kubeconfig.Update
	}
	return "", "", ""
}

// GetIdentity returns the identity name this integration uses.
func (k *KubernetesIntegration) GetIdentity() string {
	return k.identity
}

// GetCluster returns the configured cluster.
func (k *KubernetesIntegration) GetCluster() *schema.TeleportKubernetesCluster {
	return k.cluster
}
