package kube

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	errUtils "github.com/cloudposse/atmos/errors"
	teleportCloud "github.com/cloudposse/atmos/pkg/auth/cloud/teleport"
	"github.com/cloudposse/atmos/pkg/auth/types"
	"github.com/cloudposse/atmos/pkg/data"
	iolib "github.com/cloudposse/atmos/pkg/io"
	"github.com/cloudposse/atmos/pkg/schema"
)

// initTestIO initializes the IO context for tests that call data.Write().
func initTestIO(t *testing.T) {
	t.Helper()
	ioCtx, err := iolib.NewContext()
	if err != nil {
		t.Fatalf("failed to create IO context: %v", err)
	}
	data.InitWriter(ioCtx)
	t.Cleanup(func() { data.Reset() })
}

// newTestTokenCmd creates a fresh cobra.Command with token flags for testing,
// avoiding shared state from the global tokenCmd.
func newTestTokenCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "token", RunE: executeTokenCommand}
	cmd.Flags().String("cluster", "", "Teleport Kubernetes cluster name")
	cmd.Flags().StringP("identity", "i", "", "Atmos identity")
	return cmd
}

// restoreTokenFns snapshots and restores the package DI seams.
func restoreTokenFns(t *testing.T) {
	t.Helper()
	origInit, origAuth, origGen := initCliConfigFn, authenticateForTokenFn, generateKubeCertFn
	t.Cleanup(func() {
		initCliConfigFn = origInit
		authenticateForTokenFn = origAuth
		generateKubeCertFn = origGen
	})
	initCliConfigFn = func(_ schema.ConfigAndStacksInfo, _ bool) (schema.AtmosConfiguration, error) {
		return schema.AtmosConfiguration{Auth: schema.AuthConfig{Identities: map[string]schema.Identity{"teleport-user": {Kind: "teleport/user"}}}}, nil
	}
}

func TestTokenCmd_Metadata(t *testing.T) {
	assert.Equal(t, "token", tokenCmd.Use)
	assert.True(t, tokenCmd.SilenceUsage)
	assert.Contains(t, tokenCmd.Long, "exec credential plugin")
	assert.Contains(t, tokenCmd.Long, "--cluster")

	require.NotNil(t, tokenCmd.Flags().Lookup("cluster"))
	identityFlag := tokenCmd.Flags().Lookup("identity")
	require.NotNil(t, identityFlag)
	assert.Equal(t, "i", identityFlag.Shorthand)

	require.NotNil(t, tokenCmd.Parent())
	assert.Equal(t, "kube", tokenCmd.Parent().Name())
}

func TestResolveDefaultIdentity(t *testing.T) {
	assert.Empty(t, resolveDefaultIdentity(nil))
	assert.Empty(t, resolveDefaultIdentity(&schema.AuthConfig{}))
	assert.Equal(t, "only", resolveDefaultIdentity(&schema.AuthConfig{
		Identities: map[string]schema.Identity{"only": {Kind: "teleport/user"}},
	}))
	assert.Empty(t, resolveDefaultIdentity(&schema.AuthConfig{
		Identities: map[string]schema.Identity{"a": {}, "b": {}},
	}))
}

func TestExecuteTokenCommand_MissingCluster(t *testing.T) {
	restoreTokenFns(t)
	cmd := newTestTokenCmd()
	err := executeTokenCommand(cmd, []string{})
	require.Error(t, err)
	assert.ErrorIs(t, err, errUtils.ErrTeleportKubeCertGeneration)
}

func TestExecuteTokenCommand_AuthFailure(t *testing.T) {
	restoreTokenFns(t)
	authenticateForTokenFn = func(_ context.Context, _ *schema.AuthConfig, _, _ string) (types.ICredentials, error) {
		return nil, errUtils.ErrIdentityAuthFailed
	}
	cmd := newTestTokenCmd()
	require.NoError(t, cmd.Flags().Set("cluster", "prod-eks"))
	err := executeTokenCommand(cmd, []string{})
	require.Error(t, err)
	assert.ErrorIs(t, err, errUtils.ErrTeleportKubeCertGeneration)
}

func TestExecuteTokenCommand_WrongCredentialType(t *testing.T) {
	restoreTokenFns(t)
	authenticateForTokenFn = func(_ context.Context, _ *schema.AuthConfig, _, _ string) (types.ICredentials, error) {
		return &types.GCPCredentials{}, nil
	}
	cmd := newTestTokenCmd()
	require.NoError(t, cmd.Flags().Set("cluster", "prod-eks"))
	err := executeTokenCommand(cmd, []string{})
	require.Error(t, err)
	assert.ErrorIs(t, err, errUtils.ErrTeleportKubeCertGeneration)
}

func TestExecuteTokenCommand_CertGenFailure(t *testing.T) {
	restoreTokenFns(t)
	authenticateForTokenFn = func(_ context.Context, _ *schema.AuthConfig, _, _ string) (types.ICredentials, error) {
		return &types.TeleportCredentials{ProxyAddress: "tp:443"}, nil
	}
	generateKubeCertFn = func(_ context.Context, _ *types.TeleportCredentials, _ string) (*teleportCloud.KubeCert, error) {
		return nil, errUtils.ErrTeleportKubeCertGeneration
	}
	cmd := newTestTokenCmd()
	require.NoError(t, cmd.Flags().Set("cluster", "prod-eks"))
	err := executeTokenCommand(cmd, []string{})
	require.Error(t, err)
	assert.ErrorIs(t, err, errUtils.ErrTeleportKubeCertGeneration)
}

func TestExecuteTokenCommand_Success(t *testing.T) {
	initTestIO(t)
	restoreTokenFns(t)

	var gotCluster string
	authenticateForTokenFn = func(_ context.Context, _ *schema.AuthConfig, _, _ string) (types.ICredentials, error) {
		return &types.TeleportCredentials{ProxyAddress: "tp:443", Username: "alice"}, nil
	}
	expiry := time.Now().Add(time.Hour).UTC()
	generateKubeCertFn = func(_ context.Context, _ *types.TeleportCredentials, cluster string) (*teleportCloud.KubeCert, error) {
		gotCluster = cluster
		return &teleportCloud.KubeCert{
			TLSCertPEM: "CERT-PEM",
			TLSKeyPEM:  "KEY-PEM",
			Expires:    expiry,
		}, nil
	}

	cmd := newTestTokenCmd()
	require.NoError(t, cmd.Flags().Set("cluster", "prod-eks"))

	// Capture stdout produced by data.Write.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := executeTokenCommand(cmd, []string{})
	_ = w.Close()
	os.Stdout = oldStdout
	out, _ := io.ReadAll(r)

	require.NoError(t, err)
	assert.Equal(t, "prod-eks", gotCluster)

	var cred execCredential
	require.NoError(t, json.Unmarshal(out, &cred))
	assert.Equal(t, "ExecCredential", cred.Kind)
	assert.Equal(t, execCredentialAPIVersion, cred.APIVersion)
	assert.Equal(t, "CERT-PEM", cred.Status.ClientCertificateData)
	assert.Equal(t, "KEY-PEM", cred.Status.ClientKeyData)
	assert.Equal(t, expiry.Format(time.RFC3339), cred.Status.ExpirationTimestamp)
}
