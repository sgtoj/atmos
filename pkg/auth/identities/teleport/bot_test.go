package teleport

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	errUtils "github.com/cloudposse/atmos/errors"
	teleportCloud "github.com/cloudposse/atmos/pkg/auth/cloud/teleport"
	"github.com/cloudposse/atmos/pkg/auth/types"
)

func validBotPrincipal() *types.TeleportBotIdentityPrincipal {
	return &types.TeleportBotIdentityPrincipal{
		TeleportProxyProvider: "company-teleport",
		BotName:               "github-actions",
		JoinMethod:            "github",
		JoinToken:             "gha-deploy-token",
	}
}

// realBotCreds returns TeleportCredentials with real TLS + SSH material so they
// survive the identity-file write/read round-trip the lifecycle performs.
func realBotCreds(t *testing.T) *types.TeleportCredentials {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "bot"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	return &types.TeleportCredentials{
		ClusterName: "example",
		Username:    "bot-github-actions",
		TLSCertPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		TLSKeyPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		SSHCertPEM:  genSSHCert(t),
	}
}

func genSSHCert(t *testing.T) string {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caSigner, err := ssh.NewSignerFromSigner(caPriv)
	require.NoError(t, err)
	userPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(userPub)
	require.NoError(t, err)
	cert := &ssh.Certificate{Key: sshPub, CertType: ssh.UserCert, KeyId: "bot", ValidBefore: ssh.CertTimeInfinity}
	require.NoError(t, cert.SignCert(rand.Reader, caSigner))
	return string(ssh.MarshalAuthorizedKey(cert))
}

// withFakeJoin overrides botJoinFn for the test and captures the request.
func withFakeJoin(t *testing.T, creds *types.TeleportCredentials, joinErr error, captured **teleportCloud.JoinRequest) {
	t.Helper()
	orig := botJoinFn
	botJoinFn = func(_ context.Context, req *teleportCloud.JoinRequest) (*types.TeleportCredentials, error) {
		if captured != nil {
			*captured = req
		}
		return creds, joinErr
	}
	t.Cleanup(func() { botJoinFn = orig })
}

func TestNewBotIdentity_NilPrincipal(t *testing.T) {
	_, err := NewBotIdentity(nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrInvalidIdentityConfig))
}

func TestNewBotIdentity_Valid(t *testing.T) {
	i, err := NewBotIdentity(validBotPrincipal())
	require.NoError(t, err)
	require.NotNil(t, i)
	assert.Equal(t, BotIdentityKind, i.Kind())
}

func TestBotIdentity_Validate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*types.TeleportBotIdentityPrincipal)
		errIs  error
	}{
		{"missing proxy provider", func(p *types.TeleportBotIdentityPrincipal) { p.TeleportProxyProvider = "" }, errUtils.ErrInvalidIdentityConfig},
		{"missing bot name", func(p *types.TeleportBotIdentityPrincipal) { p.BotName = "" }, errUtils.ErrInvalidIdentityConfig},
		{"missing join method", func(p *types.TeleportBotIdentityPrincipal) { p.JoinMethod = "" }, errUtils.ErrInvalidIdentityConfig},
		{"missing join token", func(p *types.TeleportBotIdentityPrincipal) { p.JoinToken = "" }, errUtils.ErrInvalidIdentityConfig},
		{"unsupported join method", func(p *types.TeleportBotIdentityPrincipal) { p.JoinMethod = "azure" }, errUtils.ErrTeleportUnsupportedJoinMethod},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validBotPrincipal()
			tt.mutate(p)
			i, err := NewBotIdentity(p)
			require.NoError(t, err)
			err = i.Validate()
			require.Error(t, err)
			assert.ErrorIs(t, err, tt.errIs)
		})
	}
}

func TestBotIdentity_Authenticate_RequiresResolvedProxyAddress(t *testing.T) {
	i, err := NewBotIdentity(validBotPrincipal())
	require.NoError(t, err)
	// No SetTeleportProxyAddress call → join cannot proceed.
	_, err = i.Authenticate(context.Background(), &types.AWSCredentials{})
	require.Error(t, err)
	assert.ErrorIs(t, err, errUtils.ErrTeleportProxyResolution)
}

func TestBotIdentity_Authenticate_Success(t *testing.T) {
	p := validBotPrincipal()
	p.JoinMethod = "iam"
	p.AWS = &types.TeleportBotAWSJoin{Region: "us-west-2"}
	i, err := NewBotIdentity(p)
	require.NoError(t, err)
	i.SetTeleportProxyAddress("teleport.example.com:443")

	var captured *teleportCloud.JoinRequest
	withFakeJoin(t, &types.TeleportCredentials{Username: "bot-github-actions"}, nil, &captured)

	creds, err := i.Authenticate(context.Background(), &types.AWSCredentials{AccessKeyID: "AKIA"})
	require.NoError(t, err)

	tc, ok := creds.(*types.TeleportCredentials)
	require.True(t, ok)
	assert.True(t, tc.IsBot, "Authenticate must mark bot credentials")
	assert.Equal(t, "teleport.example.com:443", tc.ProxyAddress)
	assert.NotEmpty(t, tc.IdentityFilePath)

	// Request construction.
	require.NotNil(t, captured)
	assert.Equal(t, "teleport.example.com:443", captured.ProxyAddress)
	assert.Equal(t, "github-actions", captured.BotName)
	assert.Equal(t, "iam", captured.JoinMethod)
	assert.Equal(t, "us-west-2", captured.AWSRegion)
	assert.NotNil(t, captured.AWSCredentials)
}

func TestBotIdentity_Authenticate_JoinError(t *testing.T) {
	i, err := NewBotIdentity(validBotPrincipal())
	require.NoError(t, err)
	i.SetTeleportProxyAddress("tp:443")
	withFakeJoin(t, nil, errors.New("token rejected"), nil)

	_, err = i.Authenticate(context.Background(), &types.AWSCredentials{})
	require.Error(t, err)
	assert.ErrorIs(t, err, errUtils.ErrTeleportJoinFailed)
}

func TestBotIdentity_IdentityFilePath(t *testing.T) {
	t.Run("output_dir override", func(t *testing.T) {
		p := validBotPrincipal()
		p.OutputDir = filepath.Join(t.TempDir(), "bot")
		i, err := NewBotIdentity(p)
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(p.OutputDir, "identity"), i.identityFilePath())
	})

	t.Run("realm-scoped default", func(t *testing.T) {
		t.Setenv("ATMOS_XDG_DATA_HOME", t.TempDir())
		i, err := NewBotIdentity(validBotPrincipal())
		require.NoError(t, err)
		i.SetRealm("test-realm")
		path := filepath.ToSlash(i.identityFilePath())
		assert.Contains(t, path, "teleport/bot/test-realm/github-actions/identity")
	})
}

func TestBotIdentity_FileLifecycle(t *testing.T) {
	p := validBotPrincipal()
	p.OutputDir = filepath.Join(t.TempDir(), "bot")
	i, err := NewBotIdentity(p)
	require.NoError(t, err)

	// Initially no identity file.
	exists, err := i.CredentialsExist()
	require.NoError(t, err)
	assert.False(t, exists)

	// PostAuthenticate materializes the file.
	creds := realBotCreds(t)
	require.NoError(t, i.PostAuthenticate(context.Background(), &types.PostAuthenticateParams{Credentials: creds}))

	exists, err = i.CredentialsExist()
	require.NoError(t, err)
	assert.True(t, exists)

	// LoadCredentials reads it back.
	loaded, err := i.LoadCredentials(context.Background())
	require.NoError(t, err)
	loadedTC, ok := loaded.(*types.TeleportCredentials)
	require.True(t, ok)
	assert.True(t, loadedTC.IsBot)
	assert.Equal(t, strings.TrimSpace(creds.SSHCertPEM), strings.TrimSpace(loadedTC.SSHCertPEM))

	// Logout removes the file (and is idempotent).
	require.NoError(t, i.Logout(context.Background()))
	exists, err = i.CredentialsExist()
	require.NoError(t, err)
	assert.False(t, exists)
	require.NoError(t, i.Logout(context.Background()))
}

func TestBotIdentity_PostAuthenticate_WrongCredentialType(t *testing.T) {
	p := validBotPrincipal()
	p.OutputDir = filepath.Join(t.TempDir(), "bot")
	i, err := NewBotIdentity(p)
	require.NoError(t, err)

	err = i.PostAuthenticate(context.Background(), &types.PostAuthenticateParams{Credentials: &types.GCPCredentials{}})
	require.Error(t, err)
	assert.ErrorIs(t, err, errUtils.ErrTeleportCredentialsType)
}

func TestBotIdentity_LoadCredentials_MissingFile(t *testing.T) {
	p := validBotPrincipal()
	p.OutputDir = filepath.Join(t.TempDir(), "bot")
	i, err := NewBotIdentity(p)
	require.NoError(t, err)

	_, err = i.LoadCredentials(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, errUtils.ErrTeleportBotIdentityRead)
}

func TestBotIdentity_Environment_PointsAtIdentityFile(t *testing.T) {
	p := validBotPrincipal()
	p.OutputDir = filepath.Join(t.TempDir(), "bot")
	i, err := NewBotIdentity(p)
	require.NoError(t, err)

	env, err := i.Environment()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(p.OutputDir, "identity"), env["TELEPORT_IDENTITY_FILE"])
}

func TestBotIdentity_Environment_DefaultPathWhenOutputDirUnset(t *testing.T) {
	t.Setenv("ATMOS_XDG_DATA_HOME", t.TempDir())
	i, err := NewBotIdentity(validBotPrincipal())
	require.NoError(t, err)

	env, err := i.Environment()
	require.NoError(t, err)
	// With a bot name set, the realm-scoped default path is always exported.
	path, hasIdent := env["TELEPORT_IDENTITY_FILE"]
	assert.True(t, hasIdent)
	assert.Contains(t, filepath.ToSlash(path), "teleport/bot/github-actions/identity")
}

func TestBotIdentity_PrepareEnvironment_Aliasing(t *testing.T) {
	i, err := NewBotIdentity(validBotPrincipal())
	require.NoError(t, err)
	in := map[string]string{"FOO": "bar"}
	out, err := i.PrepareEnvironment(context.Background(), in)
	require.NoError(t, err)
	out["FOO"] = "mutated"
	assert.Equal(t, "bar", in["FOO"], "mutating output leaked into input map")
}
