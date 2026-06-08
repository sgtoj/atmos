package teleport

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/clientcmd"

	errUtils "github.com/cloudposse/atmos/errors"
	teleportCloud "github.com/cloudposse/atmos/pkg/auth/cloud/teleport"
	"github.com/cloudposse/atmos/pkg/auth/integrations"
	"github.com/cloudposse/atmos/pkg/auth/types"
	"github.com/cloudposse/atmos/pkg/schema"
)

// fakeTeleportClient is an in-memory teleportCloud.Client for Execute tests.
type fakeTeleportClient struct {
	kubeCert *teleportCloud.KubeCert
	genErr   error
	closed   bool
}

func (f *fakeTeleportClient) Ping(_ context.Context) (*teleportCloud.PingResponse, error) {
	return &teleportCloud.PingResponse{}, nil
}

func (f *fakeTeleportClient) GenerateKubeCert(_ context.Context, _ teleportCloud.GenerateKubeCertRequest) (*teleportCloud.KubeCert, error) {
	return f.kubeCert, f.genErr
}

func (f *fakeTeleportClient) Close() error {
	f.closed = true
	return nil
}

// withFakeClientFactory overrides teleportClientFactory for the duration of a
// test and restores it on cleanup.
func withFakeClientFactory(t *testing.T, client teleportCloud.Client, factoryErr error) {
	t.Helper()
	orig := teleportClientFactory
	teleportClientFactory = func(_ context.Context, _ *types.TeleportCredentials) (teleportCloud.Client, error) {
		if factoryErr != nil {
			return nil, factoryErr
		}
		return client, nil
	}
	t.Cleanup(func() { teleportClientFactory = orig })
}

// Compile-time sentinel: field-rename guard for the schema types this package
// depends on. A rename of any field below fails the build immediately.
var (
	_ = schema.TeleportKubernetesCluster{Name: "x"}
	_ = schema.IntegrationSpec{TeleportKubernetes: &schema.TeleportKubernetesCluster{}}
)

func TestRegister_TeleportKubernetes_IsRegistered(t *testing.T) {
	// The package's init() must register the kind. This test verifies the
	// init wiring without poking at registry internals.
	assert.True(t, integrations.IsRegistered(integrations.KindTeleportKubernetes),
		"teleport/kubernetes must register via init()")
}

func TestNewKubernetesIntegration_NilConfig(t *testing.T) {
	_, err := NewKubernetesIntegration(nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrIntegrationNotFound))
}

func TestNewKubernetesIntegration_NilInnerConfig(t *testing.T) {
	_, err := NewKubernetesIntegration(&integrations.IntegrationConfig{Name: "x"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrIntegrationNotFound))
}

func TestNewKubernetesIntegration_MissingClusterSpec(t *testing.T) {
	cfg := &integrations.IntegrationConfig{
		Name: "prod-eks",
		Config: &schema.Integration{
			Kind: integrations.KindTeleportKubernetes,
			Via:  &schema.IntegrationVia{Identity: "teleport-user"},
			// Spec is nil.
		},
	}
	_, err := NewKubernetesIntegration(cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrIntegrationFailed))
}

func TestNewKubernetesIntegration_MissingClusterName(t *testing.T) {
	cfg := &integrations.IntegrationConfig{
		Name: "prod-eks",
		Config: &schema.Integration{
			Kind: integrations.KindTeleportKubernetes,
			Via:  &schema.IntegrationVia{Identity: "teleport-user"},
			Spec: &schema.IntegrationSpec{
				TeleportKubernetes: &schema.TeleportKubernetesCluster{},
			},
		},
	}
	_, err := NewKubernetesIntegration(cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrIntegrationFailed))
}

func TestNewKubernetesIntegration_InvalidKubeconfigMode(t *testing.T) {
	cfg := &integrations.IntegrationConfig{
		Name: "prod-eks",
		Config: &schema.Integration{
			Kind: integrations.KindTeleportKubernetes,
			Via:  &schema.IntegrationVia{Identity: "teleport-user"},
			Spec: &schema.IntegrationSpec{
				TeleportKubernetes: &schema.TeleportKubernetesCluster{
					Name: "prod-eks",
					Kubeconfig: &schema.KubeconfigSettings{
						Mode: "not-octal",
					},
				},
			},
		},
	}
	_, err := NewKubernetesIntegration(cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrIntegrationFailed))
}

func TestNewKubernetesIntegration_InvalidKubeconfigUpdate(t *testing.T) {
	cfg := &integrations.IntegrationConfig{
		Name: "prod-eks",
		Config: &schema.Integration{
			Kind: integrations.KindTeleportKubernetes,
			Via:  &schema.IntegrationVia{Identity: "teleport-user"},
			Spec: &schema.IntegrationSpec{
				TeleportKubernetes: &schema.TeleportKubernetesCluster{
					Name: "prod-eks",
					Kubeconfig: &schema.KubeconfigSettings{
						Update: "overwrite", // not a valid mode
					},
				},
			},
		},
	}
	_, err := NewKubernetesIntegration(cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrIntegrationFailed))
}

func TestNewKubernetesIntegration_Valid(t *testing.T) {
	cfg := &integrations.IntegrationConfig{
		Name: "prod-eks",
		Config: &schema.Integration{
			Kind: integrations.KindTeleportKubernetes,
			Via:  &schema.IntegrationVia{Identity: "teleport-user"},
			Spec: &schema.IntegrationSpec{
				TeleportKubernetes: &schema.TeleportKubernetesCluster{
					Name:  "prod-eks",
					Alias: "prod",
					Kubeconfig: &schema.KubeconfigSettings{
						Path:   "/tmp/kubeconfig",
						Mode:   "0600",
						Update: "merge",
					},
				},
			},
		},
	}
	integ, err := NewKubernetesIntegration(cfg)
	require.NoError(t, err)
	require.NotNil(t, integ)
	assert.Equal(t, integrations.KindTeleportKubernetes, integ.Kind())

	// Type-assert to the concrete type so we can verify the accessors.
	k, ok := integ.(*KubernetesIntegration)
	require.True(t, ok)
	assert.Equal(t, "teleport-user", k.GetIdentity())
	assert.Equal(t, "prod-eks", k.GetCluster().Name)
}

func TestKubernetesIntegration_Execute_NilCredentials(t *testing.T) {
	k := &KubernetesIntegration{
		name:    "prod-eks",
		cluster: &schema.TeleportKubernetesCluster{Name: "prod-eks"},
	}
	err := k.Execute(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrTeleportIntegrationFailed))
}

func TestKubernetesIntegration_Execute_WrongCredentialsType(t *testing.T) {
	k := &KubernetesIntegration{
		name:    "prod-eks",
		cluster: &schema.TeleportKubernetesCluster{Name: "prod-eks"},
	}
	// Use any non-TeleportCredentials ICredentials implementation.
	err := k.Execute(context.Background(), &types.GCPCredentials{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrTeleportCredentialsType))
}

// newKubeIntegration builds an integration writing to a temp kubeconfig path so
// tests never touch the developer's real kubeconfig.
func newKubeIntegration(t *testing.T, name, alias string) (*KubernetesIntegration, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	return &KubernetesIntegration{
		name:     name,
		identity: "teleport-user",
		cluster: &schema.TeleportKubernetesCluster{
			Name:       name,
			Alias:      alias,
			Kubeconfig: &schema.KubeconfigSettings{Path: path, Mode: "0600", Update: "merge"},
		},
	}, path
}

func TestKubernetesIntegration_Execute_Success(t *testing.T) {
	k, path := newKubeIntegration(t, "prod-eks", "prod")
	fake := &fakeTeleportClient{kubeCert: &teleportCloud.KubeCert{
		TLSCAsPEM:        []string{"-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----"},
		KubeProxyAddress: "teleport.example.com:443",
	}}
	withFakeClientFactory(t, fake, nil)

	err := k.Execute(context.Background(), &types.TeleportCredentials{ProxyAddress: "teleport.example.com:443", Username: "alice"})
	require.NoError(t, err)
	assert.True(t, fake.closed, "Execute must close the client")

	loaded, err := clientcmd.LoadFromFile(path)
	require.NoError(t, err)
	assert.Contains(t, loaded.Clusters, "teleport-prod-eks")
	assert.Contains(t, loaded.Contexts, "prod")
	assert.Contains(t, loaded.AuthInfos, "atmos-teleport-prod-eks")
}

func TestKubernetesIntegration_Execute_ClientFactoryError(t *testing.T) {
	k, _ := newKubeIntegration(t, "prod-eks", "prod")
	withFakeClientFactory(t, nil, errors.New("dial failed"))

	err := k.Execute(context.Background(), &types.TeleportCredentials{ProxyAddress: "tp:443"})
	require.Error(t, err)
	assert.ErrorIs(t, err, errUtils.ErrTeleportIntegrationFailed)
}

func TestKubernetesIntegration_Execute_GenerateCertError(t *testing.T) {
	k, _ := newKubeIntegration(t, "prod-eks", "prod")
	fake := &fakeTeleportClient{genErr: errors.New("access denied")}
	withFakeClientFactory(t, fake, nil)

	err := k.Execute(context.Background(), &types.TeleportCredentials{ProxyAddress: "tp:443"})
	require.Error(t, err)
	assert.ErrorIs(t, err, errUtils.ErrTeleportIntegrationFailed)
	assert.True(t, fake.closed, "client must be closed even on cert-generation failure")
}

func TestKubernetesIntegration_Cleanup_RemovesEntry(t *testing.T) {
	k, path := newKubeIntegration(t, "prod-eks", "prod")
	fake := &fakeTeleportClient{kubeCert: &teleportCloud.KubeCert{TLSCAsPEM: []string{"ca"}, KubeProxyAddress: "tp:443"}}
	withFakeClientFactory(t, fake, nil)

	require.NoError(t, k.Execute(context.Background(), &types.TeleportCredentials{ProxyAddress: "tp:443"}))
	require.NoError(t, k.Cleanup(context.Background()))

	loaded, err := clientcmd.LoadFromFile(path)
	if err == nil {
		assert.NotContains(t, loaded.Clusters, "teleport-prod-eks")
	}
	// Cleanup is idempotent.
	require.NoError(t, k.Cleanup(context.Background()))
}

func TestKubernetesIntegration_Environment_ExportsKubeconfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	k := &KubernetesIntegration{
		name:    "prod-eks",
		cluster: &schema.TeleportKubernetesCluster{Name: "prod-eks", Kubeconfig: &schema.KubeconfigSettings{Path: path}},
	}
	env, err := k.Environment()
	require.NoError(t, err)
	assert.Equal(t, path, env["KUBECONFIG"])
	assert.Equal(t, path, env["KUBE_CONFIG_PATH"])
}
