package credentials

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudposse/atmos/pkg/auth/types"
)

// Compile-time guard: a rename of the TeleportCredentials fields exercised by
// the round-trip below must break the build rather than silently skip coverage.
var _ = types.TeleportCredentials{IsBot: true, KubeClusters: nil}

// newTeleportCreds returns a fully-populated TeleportCredentials with
// multi-element slices so round-trip tests can assert element contents (not
// just length), per the slice-result testing mandate.
func newTeleportCreds() *types.TeleportCredentials {
	return &types.TeleportCredentials{
		ProxyAddress:     "teleport.example.com:443",
		ClusterName:      "example-cluster",
		Username:         "bot-aws-runner",
		Roles:            []string{"terraform-ci", "kube-viewer"},
		TLSCertPEM:       "-----BEGIN CERTIFICATE-----\ntls\n-----END CERTIFICATE-----",
		TLSKeyPEM:        "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
		TLSCAsPEM:        []string{"-----BEGIN CERTIFICATE-----\nca-root\n-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\nca-leaf\n-----END CERTIFICATE-----"},
		SSHCertPEM:       "ssh-cert",
		SSHKeyPEM:        "ssh-key",
		KubeClusters:     []string{"prod-eks", "staging-eks", "dev-eks"},
		ValidUntil:       time.Now().UTC().Add(1 * time.Hour),
		IdentityFilePath: "/data/teleport/bot/realmA/aws-runner/identity",
		IsBot:            true,
	}
}

// assertTeleportRoundTrip stores and retrieves Teleport credentials and asserts
// every field survives serialization, including the first and last element of
// each slice.
func assertTeleportRoundTrip(t *testing.T, s types.CredentialStore, alias, realm string) {
	t.Helper()

	in := newTeleportCreds()
	require.NoError(t, s.Store(alias, in, realm))

	got, err := s.Retrieve(alias, realm)
	require.NoError(t, err)

	out, ok := got.(*types.TeleportCredentials)
	require.True(t, ok, "retrieved credentials must be *types.TeleportCredentials, got %T", got)

	assert.Equal(t, in.ProxyAddress, out.ProxyAddress)
	assert.Equal(t, in.ClusterName, out.ClusterName)
	assert.Equal(t, in.Username, out.Username)
	assert.Equal(t, in.TLSCertPEM, out.TLSCertPEM)
	assert.Equal(t, in.TLSKeyPEM, out.TLSKeyPEM)
	assert.Equal(t, in.SSHCertPEM, out.SSHCertPEM)
	assert.Equal(t, in.SSHKeyPEM, out.SSHKeyPEM)
	assert.Equal(t, in.IdentityFilePath, out.IdentityFilePath)
	assert.Equal(t, in.IsBot, out.IsBot)
	assert.WithinDuration(t, in.ValidUntil, out.ValidUntil, time.Second)

	// Assert slice contents (first and last), not just length.
	require.Len(t, out.Roles, len(in.Roles))
	assert.Equal(t, in.Roles[0], out.Roles[0])
	assert.Equal(t, in.Roles[len(in.Roles)-1], out.Roles[len(out.Roles)-1])

	require.Len(t, out.TLSCAsPEM, len(in.TLSCAsPEM))
	assert.Equal(t, in.TLSCAsPEM[0], out.TLSCAsPEM[0])
	assert.Equal(t, in.TLSCAsPEM[len(in.TLSCAsPEM)-1], out.TLSCAsPEM[len(out.TLSCAsPEM)-1])

	require.Len(t, out.KubeClusters, len(in.KubeClusters))
	assert.Equal(t, in.KubeClusters[0], out.KubeClusters[0])
	assert.Equal(t, in.KubeClusters[len(in.KubeClusters)-1], out.KubeClusters[len(out.KubeClusters)-1])
}

func TestStoreRetrieve_Teleport_MemoryStore(t *testing.T) {
	assertTeleportRoundTrip(t, newMemoryKeyringStore(), "teleport-user", "realmA")
}

func TestStoreRetrieve_Teleport_FileStore(t *testing.T) {
	t.Setenv("ATMOS_KEYRING_TYPE", "file")
	t.Setenv("ATMOS_KEYRING_PASSWORD", "test-password")
	t.Setenv("ATMOS_XDG_DATA_HOME", t.TempDir())

	assertTeleportRoundTrip(t, NewCredentialStore(), "teleport-file", "realmA")
}

func TestStoreRetrieve_Teleport_SystemStore(t *testing.T) {
	// The system keyring uses the in-memory mock backend (keyring.MockInit in package init).
	t.Setenv("ATMOS_KEYRING_TYPE", "system")

	assertTeleportRoundTrip(t, NewCredentialStore(), "teleport-system", "realmA")
}

// TestStoreRetrieve_Teleport_RealmScoping verifies credentials stored under one
// realm are not visible under another realm (keyring keys are realm-scoped).
func TestStoreRetrieve_Teleport_RealmScoping(t *testing.T) {
	store := newMemoryKeyringStore()

	require.NoError(t, store.Store("ci-bot", newTeleportCreds(), "realmA"))

	// Same alias, different realm → not found.
	_, err := store.Retrieve("ci-bot", "realmB")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCredentialsNotFound)

	// Correct realm → found.
	got, err := store.Retrieve("ci-bot", "realmA")
	require.NoError(t, err)
	assert.IsType(t, &types.TeleportCredentials{}, got)
}

// TestTeleport_IsExpired_ViaStore verifies the store delegates expiry to the
// credential's own IsExpired implementation for both a fresh and an expired
// Teleport certificate.
func TestTeleport_IsExpired_ViaStore(t *testing.T) {
	store := newMemoryKeyringStore()

	fresh := newTeleportCreds()
	fresh.ValidUntil = time.Now().UTC().Add(30 * time.Minute)
	expired := newTeleportCreds()
	expired.ValidUntil = time.Now().UTC().Add(-5 * time.Minute)

	require.NoError(t, store.Store("fresh", fresh, "realmA"))
	require.NoError(t, store.Store("expired", expired, "realmA"))

	isExpired, err := store.IsExpired("fresh", "realmA")
	require.NoError(t, err)
	assert.False(t, isExpired)

	isExpired, err = store.IsExpired("expired", "realmA")
	require.NoError(t, err)
	assert.True(t, isExpired)
}
