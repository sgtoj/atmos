package factory

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	errUtils "github.com/cloudposse/atmos/errors"
	"github.com/cloudposse/atmos/pkg/auth/types"
)

func TestRegisterTeleportProviders(t *testing.T) {
	f := NewFactory()
	assert.True(t, f.HasProvider(types.ProviderKindTeleportProxy),
		"teleport/proxy provider must be registered by RegisterTeleportProviders")
}

func TestRegisterTeleportIdentities(t *testing.T) {
	f := NewFactory()
	assert.True(t, f.HasIdentity(types.IdentityKindTeleportUser),
		"teleport/user identity must be registered by RegisterTeleportIdentities")
	assert.True(t, f.HasIdentity(types.IdentityKindTeleportBot),
		"teleport/bot identity must be registered by RegisterTeleportIdentities")
}

func TestCreateTeleportProxyProvider_Valid(t *testing.T) {
	f := NewFactory()

	spec := map[string]any{
		"proxy_address":  "teleport.example.com:443",
		"auth_connector": "okta",
	}
	provider, err := f.CreateProvider(types.ProviderKindTeleportProxy, "company-teleport", spec)
	require.NoError(t, err)
	require.NotNil(t, provider)
	assert.Equal(t, types.ProviderKindTeleportProxy, provider.Kind())
	assert.Equal(t, "company-teleport", provider.Name())
}

func TestCreateTeleportProxyProvider_MissingProxyAddress(t *testing.T) {
	f := NewFactory()

	// proxy_address is required; this should fail at spec-parse time.
	_, err := f.CreateProvider(types.ProviderKindTeleportProxy, "bad", map[string]any{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrInvalidProviderConfig))
}

func TestCreateTeleportUserIdentity_Empty(t *testing.T) {
	f := NewFactory()

	// teleport/user accepts an empty principal -- use ~/.tsh as-is.
	identity, err := f.CreateIdentity(types.IdentityKindTeleportUser, "tp-user", nil)
	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, types.IdentityKindTeleportUser, identity.Kind())
}

func TestCreateTeleportUserIdentity_WithRoles(t *testing.T) {
	f := NewFactory()

	principal := map[string]any{
		"roles": []any{"editor", "kube-prod"},
		"ttl":   "1h",
	}
	identity, err := f.CreateIdentity(types.IdentityKindTeleportUser, "tp-user", principal)
	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, types.IdentityKindTeleportUser, identity.Kind())
	assert.Equal(t, "tp-user", identity.(interface{ Name() string }).Name())
}

func TestCreateTeleportBotIdentity_GitHubJoin(t *testing.T) {
	f := NewFactory()

	principal := map[string]any{
		"teleport_proxy_provider": "company-teleport",
		"bot_name":                "github-actions",
		"join_method":             "github",
		"join_token":              "gha-deploy-token",
	}
	identity, err := f.CreateIdentity(types.IdentityKindTeleportBot, "ci-bot", principal)
	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, types.IdentityKindTeleportBot, identity.Kind())
}

func TestCreateTeleportBotIdentity_IAMJoin(t *testing.T) {
	f := NewFactory()

	principal := map[string]any{
		"teleport_proxy_provider": "company-teleport",
		"bot_name":                "aws-runner",
		"join_method":             "iam",
		"join_token":              "aws-runner-token",
		"aws": map[string]any{
			"region": "us-west-2",
		},
	}
	identity, err := f.CreateIdentity(types.IdentityKindTeleportBot, "ci-bot", principal)
	require.NoError(t, err)
	require.NotNil(t, identity)
}

func TestCreateTeleportBotIdentity_MissingRequiredFields(t *testing.T) {
	f := NewFactory()

	// Missing required fields should fail at parse time.
	_, err := f.CreateIdentity(types.IdentityKindTeleportBot, "bad", map[string]any{
		"join_method": "github",
		"join_token":  "tok",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrInvalidIdentityConfig))
}

func TestCreateTeleportBotIdentity_UnsupportedJoinMethod(t *testing.T) {
	f := NewFactory()

	_, err := f.CreateIdentity(types.IdentityKindTeleportBot, "bad", map[string]any{
		"teleport_proxy_provider": "p",
		"bot_name":                "b",
		"join_method":             "kubernetes", // not in v1
		"join_token":              "t",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrInvalidIdentityConfig))
}
