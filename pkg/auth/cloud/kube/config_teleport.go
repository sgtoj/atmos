package kube

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	errUtils "github.com/cloudposse/atmos/errors"
	"github.com/cloudposse/atmos/pkg/perf"
)

// teleportALPNSNIPrefix is the SNI prefix Teleport's proxy uses to route
// kubernetes traffic over its multiplexed ALPN listener. kubectl must present
// this server name so the proxy knows the connection is for the kube service.
const teleportALPNSNIPrefix = "kube-teleport-proxy-alpn."

// teleportUserPrefix namespaces the kubeconfig auth-info entries Atmos creates
// for Teleport-fronted clusters, keeping them distinct from aws/eks entries
// that may share the same kubeconfig file.
const teleportUserPrefix = "atmos-teleport-"

// teleportClusterPrefix namespaces the kubeconfig cluster/context entries.
const teleportClusterPrefix = "teleport-"

// TeleportKubeClusterParams describes a single Teleport-fronted kubernetes
// cluster entry to materialize in a kubeconfig.
type TeleportKubeClusterParams struct {
	// ProxyAddress is the Teleport proxy host:port kubectl connects to.
	ProxyAddress string

	// ClusterName is the kube cluster name as registered in Teleport.
	ClusterName string

	// Alias is the optional kubeconfig context name. Defaults to
	// "teleport-<cluster>".
	Alias string

	// CACertPEM is the PEM CA bundle used to verify the Teleport proxy's kube
	// endpoint.
	CACertPEM string

	// IdentityName is the optional Atmos identity passed to the exec plugin so
	// `atmos teleport kube token` authenticates as the right identity.
	IdentityName string
}

// contextName returns the kubeconfig context name for the cluster.
func (p *TeleportKubeClusterParams) contextName() string {
	if p.Alias != "" {
		return p.Alias
	}
	return teleportClusterPrefix + p.ClusterName
}

// clusterKey returns the kubeconfig cluster-map key for the cluster.
func (p *TeleportKubeClusterParams) clusterKey() string {
	return teleportClusterPrefix + p.ClusterName
}

// userName returns the kubeconfig auth-info key for the cluster.
func (p *TeleportKubeClusterParams) userName() string {
	return teleportUserPrefix + p.ClusterName
}

// BuildTeleportClusterConfig creates a kubeconfig api.Config for a single
// Teleport-fronted kubernetes cluster. The cluster server points at the
// Teleport proxy (with the ALPN SNI server name set) and the auth info is an
// exec plugin invoking `atmos teleport kube token`.
func BuildTeleportClusterConfig(p *TeleportKubeClusterParams) *clientcmdapi.Config {
	defer perf.Track(nil, "kube.BuildTeleportClusterConfig")()

	contextName := p.contextName()
	clusterKey := p.clusterKey()
	userName := p.userName()

	var execEnv []clientcmdapi.ExecEnvVar
	if p.IdentityName != "" {
		execEnv = append(execEnv, clientcmdapi.ExecEnvVar{Name: "ATMOS_IDENTITY", Value: p.IdentityName})
	}

	execArgs := []string{"teleport", "kube", "token", "--cluster", p.ClusterName}
	if p.IdentityName != "" {
		execArgs = append(execArgs, "--identity="+p.IdentityName)
	}

	config := clientcmdapi.NewConfig()
	config.CurrentContext = contextName

	config.Clusters[clusterKey] = &clientcmdapi.Cluster{
		Server:                   "https://" + p.ProxyAddress,
		TLSServerName:            teleportALPNSNIPrefix + hostOnly(p.ProxyAddress),
		CertificateAuthorityData: []byte(p.CACertPEM),
	}

	config.Contexts[contextName] = &clientcmdapi.Context{
		Cluster:  clusterKey,
		AuthInfo: userName,
	}

	config.AuthInfos[userName] = &clientcmdapi.AuthInfo{
		Exec: &clientcmdapi.ExecConfig{
			APIVersion:      execAPIVersion,
			Command:         atmosCommand,
			Args:            execArgs,
			Env:             execEnv,
			InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
		},
	}

	return config
}

// WriteTeleportClusterConfig writes (merge/replace/error) a Teleport kube
// cluster entry into the managed kubeconfig. Returns changed=true when the
// on-disk file was modified. Reuses the shared merge primitives so Teleport and
// aws/eks entries coexist in one kubeconfig.
func (m *KubeconfigManager) WriteTeleportClusterConfig(p *TeleportKubeClusterParams, updateMode string) (bool, error) {
	defer perf.Track(nil, "kube.KubeconfigManager.WriteTeleportClusterConfig")()

	if updateMode == "" {
		updateMode = defaultUpdateMode
	}

	newConfig := BuildTeleportClusterConfig(p)

	dir := filepath.Dir(m.path)
	if err := os.MkdirAll(dir, defaultDirMode); err != nil {
		return false, fmt.Errorf("%w: failed to create directory %s: %w", errUtils.ErrKubeconfigWrite, dir, err)
	}

	switch updateMode {
	case "replace":
		return m.writeIfChanged(newConfig)
	case "error":
		if err := m.checkTeleportCollision(p); err != nil {
			return false, err
		}
		return m.mergeIfChanged(newConfig)
	case "merge":
		return m.mergeIfChanged(newConfig)
	default:
		return false, fmt.Errorf("%w: invalid update mode %q", errUtils.ErrKubeconfigMerge, updateMode)
	}
}

// checkTeleportCollision returns an error when an entry for this cluster or
// context already exists (used by the "error" update mode).
func (m *KubeconfigManager) checkTeleportCollision(p *TeleportKubeClusterParams) error {
	if _, err := os.Stat(m.path); err != nil {
		return nil // No file yet: no collision possible.
	}
	existing, loadErr := clientcmd.LoadFromFile(m.path)
	if loadErr != nil {
		return nil // Unreadable existing file is handled by the merge path.
	}
	if _, exists := existing.Clusters[p.clusterKey()]; exists {
		return fmt.Errorf("%w: cluster %s already exists in %s", errUtils.ErrKubeconfigMerge, p.clusterKey(), m.path)
	}
	if _, exists := existing.Contexts[p.contextName()]; exists {
		return fmt.Errorf("%w: context %s already exists in %s", errUtils.ErrKubeconfigMerge, p.contextName(), m.path)
	}
	return nil
}

// RemoveTeleportClusterConfig removes the cluster, context, and auth-info
// entries for a Teleport-fronted cluster. Idempotent.
func (m *KubeconfigManager) RemoveTeleportClusterConfig(p *TeleportKubeClusterParams) error {
	defer perf.Track(nil, "kube.KubeconfigManager.RemoveTeleportClusterConfig")()

	return m.RemoveClusterConfig(p.clusterKey(), p.contextName(), p.userName())
}

// hostOnly returns the host portion of a host:port address. When no port is
// present the input is returned unchanged.
func hostOnly(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}
