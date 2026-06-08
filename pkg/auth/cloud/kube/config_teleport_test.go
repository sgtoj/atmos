package kube

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/clientcmd"
)

func TestBuildTeleportClusterConfig(t *testing.T) {
	t.Run("with alias and identity", func(t *testing.T) {
		cfg := BuildTeleportClusterConfig(&TeleportKubeClusterParams{
			ProxyAddress: "teleport.example.com:443",
			ClusterName:  "prod-eks",
			Alias:        "prod",
			CACertPEM:    "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
			IdentityName: "ci-bot",
		})

		assert.Equal(t, "prod", cfg.CurrentContext)

		cluster := cfg.Clusters["teleport-prod-eks"]
		require.NotNil(t, cluster)
		assert.Equal(t, "https://teleport.example.com:443", cluster.Server)
		assert.Equal(t, "kube-teleport-proxy-alpn.teleport.example.com", cluster.TLSServerName)
		assert.Equal(t, "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----", string(cluster.CertificateAuthorityData))

		ctx := cfg.Contexts["prod"]
		require.NotNil(t, ctx)
		assert.Equal(t, "teleport-prod-eks", ctx.Cluster)
		assert.Equal(t, "atmos-teleport-prod-eks", ctx.AuthInfo)

		user := cfg.AuthInfos["atmos-teleport-prod-eks"]
		require.NotNil(t, user)
		require.NotNil(t, user.Exec)
		assert.Equal(t, atmosCommand, user.Exec.Command)
		assert.Equal(t, []string{"teleport", "kube", "token", "--cluster", "prod-eks", "--identity=ci-bot"}, user.Exec.Args)
		require.Len(t, user.Exec.Env, 1)
		assert.Equal(t, "ATMOS_IDENTITY", user.Exec.Env[0].Name)
		assert.Equal(t, "ci-bot", user.Exec.Env[0].Value)
	})

	t.Run("without alias or identity defaults context and omits identity flag", func(t *testing.T) {
		cfg := BuildTeleportClusterConfig(&TeleportKubeClusterParams{
			ProxyAddress: "tp.internal:3080",
			ClusterName:  "staging",
		})

		assert.Equal(t, "teleport-staging", cfg.CurrentContext)
		require.NotNil(t, cfg.Contexts["teleport-staging"])
		user := cfg.AuthInfos["atmos-teleport-staging"]
		require.NotNil(t, user)
		assert.Equal(t, []string{"teleport", "kube", "token", "--cluster", "staging"}, user.Exec.Args)
		assert.Empty(t, user.Exec.Env)
	})
}

func TestWriteTeleportClusterConfig_RoundTripAndCoexistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	mgr, err := NewKubeconfigManager(path, "0600")
	require.NoError(t, err)

	a := &TeleportKubeClusterParams{ProxyAddress: "tp:443", ClusterName: "prod", CACertPEM: "ca-a"}
	b := &TeleportKubeClusterParams{ProxyAddress: "tp:443", ClusterName: "staging", CACertPEM: "ca-b"}

	changed, err := mgr.WriteTeleportClusterConfig(a, "merge")
	require.NoError(t, err)
	assert.True(t, changed)

	// Re-writing the same cluster (still the current context) is a no-op.
	changed, err = mgr.WriteTeleportClusterConfig(a, "merge")
	require.NoError(t, err)
	assert.False(t, changed)

	// Second cluster merges into the same file without dropping the first.
	changed, err = mgr.WriteTeleportClusterConfig(b, "merge")
	require.NoError(t, err)
	assert.True(t, changed)

	loaded, err := clientcmd.LoadFromFile(path)
	require.NoError(t, err)
	assert.Contains(t, loaded.Clusters, "teleport-prod")
	assert.Contains(t, loaded.Clusters, "teleport-staging")
	assert.Contains(t, loaded.AuthInfos, "atmos-teleport-prod")
	assert.Contains(t, loaded.AuthInfos, "atmos-teleport-staging")
}

func TestWriteTeleportClusterConfig_ErrorModeCollision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	mgr, err := NewKubeconfigManager(path, "0600")
	require.NoError(t, err)

	p := &TeleportKubeClusterParams{ProxyAddress: "tp:443", ClusterName: "prod", CACertPEM: "ca"}
	_, err = mgr.WriteTeleportClusterConfig(p, "merge")
	require.NoError(t, err)

	// Writing the same cluster in "error" mode must fail on collision.
	_, err = mgr.WriteTeleportClusterConfig(p, "error")
	require.Error(t, err)
}

func TestRemoveTeleportClusterConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	mgr, err := NewKubeconfigManager(path, "0600")
	require.NoError(t, err)

	p := &TeleportKubeClusterParams{ProxyAddress: "tp:443", ClusterName: "prod", CACertPEM: "ca"}
	_, err = mgr.WriteTeleportClusterConfig(p, "merge")
	require.NoError(t, err)

	require.NoError(t, mgr.RemoveTeleportClusterConfig(p))

	// Removing again is idempotent.
	require.NoError(t, mgr.RemoveTeleportClusterConfig(p))
}
