package teleport

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	errUtils "github.com/cloudposse/atmos/errors"
	"github.com/cloudposse/atmos/pkg/auth/types"
)

func TestNew_NilSpec(t *testing.T) {
	_, err := New(nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrInvalidProviderConfig))
}

func TestNew_Valid(t *testing.T) {
	p, err := New(&types.TeleportProxyProviderSpec{ProxyAddress: "teleport.example.com:443"})
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, ProviderKind, p.Kind())
}

func TestProvider_Validate_MissingProxyAddress(t *testing.T) {
	p, err := New(&types.TeleportProxyProviderSpec{})
	require.NoError(t, err)
	err = p.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrInvalidProviderConfig))
}

func TestProvider_Validate_MutuallyExclusiveCAFields(t *testing.T) {
	p, err := New(&types.TeleportProxyProviderSpec{
		ProxyAddress: "teleport.example.com:443",
		CACertPath:   "/etc/ssl/ca.pem",
		CACertPEM:    "PEM",
	})
	require.NoError(t, err)
	err = p.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrInvalidProviderConfig))
}

func TestProvider_Name_FallsBackToKind(t *testing.T) {
	p, err := New(&types.TeleportProxyProviderSpec{ProxyAddress: "x:443"})
	require.NoError(t, err)
	assert.Equal(t, ProviderKind, p.Name(), "without SetName, Name() returns the kind")
}

func TestProvider_Name_UsesSetValue(t *testing.T) {
	p, err := New(&types.TeleportProxyProviderSpec{ProxyAddress: "x:443"})
	require.NoError(t, err)
	p.SetName("company-teleport")
	assert.Equal(t, "company-teleport", p.Name())
}

func TestProvider_Environment(t *testing.T) {
	p, err := New(&types.TeleportProxyProviderSpec{ProxyAddress: "teleport.example.com:443"})
	require.NoError(t, err)
	env, err := p.Environment()
	require.NoError(t, err)
	assert.Equal(t, "teleport.example.com:443", env["TELEPORT_PROXY"])
	// Credentials live in the Atmos keychain, not ~/.tsh, so no TELEPORT_HOME.
	_, hasHome := env["TELEPORT_HOME"]
	assert.False(t, hasHome, "TELEPORT_HOME must not be set (no ~/.tsh dependency)")
}

func TestProvider_Paths_AlwaysEmpty(t *testing.T) {
	// Teleport user credentials are stored in the Atmos keychain, not on a
	// profile path, so the provider surfaces no credential files.
	p, err := New(&types.TeleportProxyProviderSpec{ProxyAddress: "x:443"})
	require.NoError(t, err)
	paths, err := p.Paths()
	require.NoError(t, err)
	assert.Empty(t, paths)
}

func TestProvider_PrepareEnvironment_Aliasing(t *testing.T) {
	// Mutating the returned env must not affect the input map.
	p, err := New(&types.TeleportProxyProviderSpec{ProxyAddress: "x:443"})
	require.NoError(t, err)
	in := map[string]string{"FOO": "bar"}
	out, err := p.PrepareEnvironment(context.Background(), in)
	require.NoError(t, err)
	out["FOO"] = "mutated"
	assert.Equal(t, "bar", in["FOO"], "mutating output leaked into input map")
}

func TestProvider_Authenticate_Phase1NotImplemented(t *testing.T) {
	p, err := New(&types.TeleportProxyProviderSpec{ProxyAddress: "x:443"})
	require.NoError(t, err)
	creds, err := p.Authenticate(context.Background())
	assert.Nil(t, creds)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrNotImplemented),
		"Phase 1 stub should return ErrNotImplemented; got: %v", err)
}

func TestProvider_Logout_NoOp(t *testing.T) {
	p, err := New(&types.TeleportProxyProviderSpec{ProxyAddress: "x:443"})
	require.NoError(t, err)
	assert.NoError(t, p.Logout(context.Background()))
}

func TestProvider_GetFilesDisplayPath_Empty(t *testing.T) {
	// Credentials live in the Atmos keychain, so there is no file path to show.
	p, err := New(&types.TeleportProxyProviderSpec{ProxyAddress: "x:443"})
	require.NoError(t, err)
	assert.Empty(t, p.GetFilesDisplayPath())
}
