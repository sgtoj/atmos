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
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	errUtils "github.com/cloudposse/atmos/errors"
	"github.com/cloudposse/atmos/pkg/auth/types"
)

// genSSHCert creates a real OpenSSH user certificate in authorized-keys format
// (the format Teleport identity files use for the SSH cert). A valid identity
// file must contain one, so the round-trip test needs a real cert here.
func genSSHCert(t *testing.T, principal string) string {
	t.Helper()

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caSigner, err := ssh.NewSignerFromSigner(caPriv)
	require.NoError(t, err)

	userPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshUserPub, err := ssh.NewPublicKey(userPub)
	require.NoError(t, err)

	cert := &ssh.Certificate{
		Key:             sshUserPub,
		CertType:        ssh.UserCert,
		KeyId:           principal,
		ValidPrincipals: []string{principal},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	require.NoError(t, cert.SignCert(rand.Reader, caSigner))
	return string(ssh.MarshalAuthorizedKey(cert))
}

// genCertPEM creates a real self-signed certificate and its private key,
// returned as PEM strings. Using real PEM (rather than fixture strings) ensures
// the material survives the Teleport identity-file encode/decode round-trip,
// which parses PEM blocks with crypto/x509.
func genCertPEM(t *testing.T, commonName string) (certPEM, keyPEM string, certDER []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM, der
}

// derOf decodes a PEM string and returns the DER bytes of its first block.
// Comparing DER bytes makes round-trip assertions immune to PEM whitespace
// normalization performed by the identity-file encoder/decoder.
func derOf(t *testing.T, pemStr string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block, "expected a PEM block in %q", pemStr)
	return block.Bytes
}

func TestWriteLoadIdentityFile_RoundTrip(t *testing.T) {
	ctx := context.Background()

	certPEM, keyPEM, certDER := genCertPEM(t, "bot-runner")
	ca1PEM, _, ca1DER := genCertPEM(t, "ca-root")
	ca2PEM, _, ca2DER := genCertPEM(t, "ca-leaf")

	sshCert := genSSHCert(t, "bot-runner")

	in := &types.TeleportCredentials{
		ClusterName: "example",
		Username:    "bot-runner",
		TLSCertPEM:  certPEM,
		TLSKeyPEM:   keyPEM,
		SSHCertPEM:  sshCert,
		TLSCAsPEM:   []string{ca1PEM, ca2PEM},
		IsBot:       true,
	}

	// Write into a nested path to also verify parent-directory creation.
	path := filepath.Join(t.TempDir(), "teleport", "bot", "realmA", "runner", "identity")
	require.NoError(t, WriteIdentityFile(ctx, in, path))

	out, err := LoadIdentityFile(ctx, path)
	require.NoError(t, err)

	// Compare DER, not PEM text, to be whitespace-normalization-proof.
	assert.Equal(t, certDER, derOf(t, out.TLSCertPEM))
	assert.Equal(t, derOf(t, keyPEM), derOf(t, out.TLSKeyPEM))

	require.Len(t, out.TLSCAsPEM, 2)
	assert.Equal(t, ca1DER, derOf(t, out.TLSCAsPEM[0]))
	assert.Equal(t, ca2DER, derOf(t, out.TLSCAsPEM[1]))

	// SSH cert (authorized-keys format) round-trips; the SSH key mirrors the
	// single shared private key.
	assert.Equal(t, strings.TrimSpace(sshCert), strings.TrimSpace(out.SSHCertPEM))
	assert.Equal(t, derOf(t, keyPEM), derOf(t, out.SSHKeyPEM))

	assert.True(t, out.IsBot)
	assert.Equal(t, path, out.IdentityFilePath)
}

func TestWriteIdentityFile_Errors(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM, _ := genCertPEM(t, "bot")
	validPath := filepath.Join(t.TempDir(), "identity")

	tests := []struct {
		name  string
		creds *types.TeleportCredentials
		path  string
	}{
		{
			name:  "nil credentials",
			creds: nil,
			path:  validPath,
		},
		{
			name:  "empty path",
			creds: &types.TeleportCredentials{TLSCertPEM: certPEM, TLSKeyPEM: keyPEM},
			path:  "",
		},
		{
			name:  "no private key",
			creds: &types.TeleportCredentials{TLSCertPEM: certPEM},
			path:  validPath,
		},
		{
			name:  "no TLS certificate",
			creds: &types.TeleportCredentials{TLSKeyPEM: keyPEM},
			path:  validPath,
		},
		{
			name:  "no SSH certificate",
			creds: &types.TeleportCredentials{TLSCertPEM: certPEM, TLSKeyPEM: keyPEM},
			path:  validPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := WriteIdentityFile(ctx, tt.creds, tt.path)
			require.Error(t, err)
			assert.ErrorIs(t, err, errUtils.ErrTeleportBotIdentityWrite)
		})
	}
}

func TestLoadIdentityFile_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("empty path", func(t *testing.T) {
		_, err := LoadIdentityFile(ctx, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, errUtils.ErrTeleportBotIdentityRead)
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := LoadIdentityFile(ctx, filepath.Join(t.TempDir(), "does-not-exist"))
		require.Error(t, err)
		assert.ErrorIs(t, err, errUtils.ErrTeleportBotIdentityRead)
	})
}
