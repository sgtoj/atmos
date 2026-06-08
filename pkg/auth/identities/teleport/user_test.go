package teleport

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	errUtils "github.com/cloudposse/atmos/errors"
	"github.com/cloudposse/atmos/pkg/auth/types"
	"github.com/cloudposse/atmos/pkg/schema"
)

func TestNewUserIdentity_NilPrincipalIsAccepted(t *testing.T) {
	// A nil principal is valid for teleport/user (means "use the SSO login's
	// credentials as-is").
	i, err := NewUserIdentity(nil)
	require.NoError(t, err)
	require.NotNil(t, i)
	assert.Equal(t, UserIdentityKind, i.Kind())
}

func TestUserIdentity_Name(t *testing.T) {
	i, err := NewUserIdentity(nil)
	require.NoError(t, err)
	assert.Equal(t, UserIdentityKind, i.Name(), "without SetName, Name() returns the kind")

	i.SetName("teleport-user")
	assert.Equal(t, "teleport-user", i.Name())
}

func TestUserIdentity_GetProviderName(t *testing.T) {
	i, err := NewUserIdentity(nil)
	require.NoError(t, err)

	// No config set: returns empty.
	name, err := i.GetProviderName()
	require.NoError(t, err)
	assert.Empty(t, name)

	// With config Via.Provider set: returns it.
	i.SetConfig(&schema.Identity{
		Via: &schema.IdentityVia{Provider: "company-teleport"},
	})
	name, err = i.GetProviderName()
	require.NoError(t, err)
	assert.Equal(t, "company-teleport", name)
}

func TestUserIdentity_Validate_AlwaysOK(t *testing.T) {
	i, err := NewUserIdentity(nil)
	require.NoError(t, err)
	// teleport/user has no mandatory principal fields.
	assert.NoError(t, i.Validate())
}

func TestUserIdentity_Authenticate_NilBaseCreds(t *testing.T) {
	i, err := NewUserIdentity(nil)
	require.NoError(t, err)
	_, err = i.Authenticate(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrAuthenticationFailed))
}

func TestUserIdentity_Authenticate_WrongCredentialsType(t *testing.T) {
	i, err := NewUserIdentity(nil)
	require.NoError(t, err)
	_, err = i.Authenticate(context.Background(), &types.GCPCredentials{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrTeleportCredentialsType))
}

func TestUserIdentity_Authenticate_Phase1NotImplemented(t *testing.T) {
	i, err := NewUserIdentity(nil)
	require.NoError(t, err)
	_, err = i.Authenticate(context.Background(), &types.TeleportCredentials{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrNotImplemented),
		"Phase 1 stub should return ErrNotImplemented; got: %v", err)
}

func TestUserIdentity_PrepareEnvironment_Aliasing(t *testing.T) {
	i, err := NewUserIdentity(nil)
	require.NoError(t, err)
	in := map[string]string{"FOO": "bar"}
	out, err := i.PrepareEnvironment(context.Background(), in)
	require.NoError(t, err)
	out["FOO"] = "mutated"
	assert.Equal(t, "bar", in["FOO"], "mutating output leaked into input map")
}

func TestUserIdentity_CredentialsExist_Phase1False(t *testing.T) {
	i, err := NewUserIdentity(nil)
	require.NoError(t, err)
	ok, err := i.CredentialsExist()
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestUserIdentity_LoadCredentials_Phase1NotImplemented(t *testing.T) {
	i, err := NewUserIdentity(nil)
	require.NoError(t, err)
	_, err = i.LoadCredentials(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrNotImplemented))
}
