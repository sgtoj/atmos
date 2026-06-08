package types

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	errUtils "github.com/cloudposse/atmos/errors"
)

// Compile-time sentinel: the tests in this file reference the principal/spec
// struct fields by name. A rename of any of these would silently invalidate the
// asserts below — these lines fail the build immediately if a field is renamed.
var (
	_ = TeleportProxyProviderSpec{ProxyAddress: "x"}
	_ = TeleportUserIdentityPrincipal{Roles: []string{}}
	_ = TeleportBotIdentityPrincipal{TeleportProxyProvider: "x", BotName: "y", JoinMethod: "github", JoinToken: "z"}
)

func TestParseTeleportProxyProviderSpec_Valid(t *testing.T) {
	spec := map[string]any{
		"proxy_address":  "teleport.example.com:443",
		"auth_connector": "okta",
	}

	out, err := ParseTeleportProxyProviderSpec(spec)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, "teleport.example.com:443", out.ProxyAddress)
	assert.Equal(t, "okta", out.AuthConnector)
	assert.False(t, out.Insecure)
}

func TestParseTeleportProxyProviderSpec_NilSpec(t *testing.T) {
	out, err := ParseTeleportProxyProviderSpec(nil)
	assert.Nil(t, out)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrInvalidAuthConfig))
}

func TestParseTeleportProxyProviderSpec_EmptySpec(t *testing.T) {
	// Empty spec lacks the required proxy_address.
	out, err := ParseTeleportProxyProviderSpec(map[string]any{})
	assert.Nil(t, out)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrInvalidAuthConfig))
}

func TestParseTeleportProxyProviderSpec_MutuallyExclusiveCAFields(t *testing.T) {
	spec := map[string]any{
		"proxy_address": "teleport.example.com:443",
		"ca_cert_path":  "/etc/ssl/ca.pem",
		"ca_cert_pem":   "-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----",
	}
	out, err := ParseTeleportProxyProviderSpec(spec)
	assert.Nil(t, out)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrInvalidAuthConfig))
}

func TestParseTeleportProxyProviderSpec_InsecureFlag(t *testing.T) {
	spec := map[string]any{
		"proxy_address": "teleport.example.com:443",
		"insecure":      true,
	}
	out, err := ParseTeleportProxyProviderSpec(spec)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.True(t, out.Insecure)
}

func TestParseTeleportProxyProviderSpec_AliasingIsolation(t *testing.T) {
	// Mutating the decoded spec must not affect the source map (result -> src).
	src := map[string]any{"proxy_address": "teleport.example.com:443"}
	out, err := ParseTeleportProxyProviderSpec(src)
	require.NoError(t, err)
	out.ProxyAddress = "mutated.example.com:443"
	assert.Equal(t, "teleport.example.com:443", src["proxy_address"], "mutating decoded spec leaked into source map")
}

func TestParseTeleportUserIdentityPrincipal_EmptyPrincipal(t *testing.T) {
	// An empty principal is valid for teleport/user — it means "use the SSO
	// login's credentials as-is".
	out, err := ParseTeleportUserIdentityPrincipal(nil)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Empty(t, out.Roles)
}

func TestParseTeleportUserIdentityPrincipal_FullPrincipal(t *testing.T) {
	principal := map[string]any{
		"roles":               []any{"editor", "kube-prod"},
		"kubernetes_clusters": []any{"prod-eks", "dev-eks"},
		"ttl":                 "1h",
		"teleport_cluster":    "leaf-cluster",
	}
	out, err := ParseTeleportUserIdentityPrincipal(principal)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, []string{"editor", "kube-prod"}, out.Roles)
	assert.Equal(t, []string{"prod-eks", "dev-eks"}, out.KubernetesClusters)
	assert.Equal(t, "1h", out.TTL)
	assert.Equal(t, "leaf-cluster", out.TeleportCluster)
}

func TestParseTeleportBotIdentityPrincipal_ValidGitHub(t *testing.T) {
	principal := map[string]any{
		"teleport_proxy_provider": "company-teleport",
		"bot_name":                "github-actions",
		"join_method":             "github",
		"join_token":              "gha-deploy-token",
		"roles":                   []any{"terraform-ci"},
		"ttl":                     "1h",
		"github": map[string]any{
			"audience": "teleport.cluster.local",
		},
	}
	out, err := ParseTeleportBotIdentityPrincipal(principal)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, "company-teleport", out.TeleportProxyProvider)
	assert.Equal(t, "github-actions", out.BotName)
	assert.Equal(t, "github", out.JoinMethod)
	assert.Equal(t, "gha-deploy-token", out.JoinToken)
	assert.Equal(t, []string{"terraform-ci"}, out.Roles)
	assert.Equal(t, "1h", out.TTL)
	require.NotNil(t, out.GitHub)
	assert.Equal(t, "teleport.cluster.local", out.GitHub.Audience)
}

func TestParseTeleportBotIdentityPrincipal_ValidIAM(t *testing.T) {
	principal := map[string]any{
		"teleport_proxy_provider": "company-teleport",
		"bot_name":                "aws-runner",
		"join_method":             "iam",
		"join_token":              "aws-runner-token",
		"aws": map[string]any{
			"region":       "us-west-2",
			"sts_endpoint": "https://sts.us-west-2.amazonaws.com",
		},
	}
	out, err := ParseTeleportBotIdentityPrincipal(principal)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, "iam", out.JoinMethod)
	require.NotNil(t, out.AWS)
	assert.Equal(t, "us-west-2", out.AWS.Region)
	assert.Equal(t, "https://sts.us-west-2.amazonaws.com", out.AWS.STSEndpoint)
}

func TestParseTeleportBotIdentityPrincipal_NilPrincipal(t *testing.T) {
	out, err := ParseTeleportBotIdentityPrincipal(nil)
	assert.Nil(t, out)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrInvalidAuthConfig))
}

func TestParseTeleportBotIdentityPrincipal_MissingRequiredFields(t *testing.T) {
	// Each missing required field should fail loudly.
	cases := []struct {
		name string
		omit string
	}{
		{name: "missing teleport_proxy_provider", omit: "teleport_proxy_provider"},
		{name: "missing bot_name", omit: "bot_name"},
		{name: "missing join_method", omit: "join_method"},
		{name: "missing join_token", omit: "join_token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			principal := map[string]any{
				"teleport_proxy_provider": "p",
				"bot_name":                "b",
				"join_method":             "github",
				"join_token":              "t",
			}
			delete(principal, tc.omit)
			out, err := ParseTeleportBotIdentityPrincipal(principal)
			assert.Nil(t, out)
			require.Error(t, err)
			assert.True(t, errors.Is(err, errUtils.ErrInvalidAuthConfig),
				"expected ErrInvalidAuthConfig for %q, got %v", tc.omit, err)
		})
	}
}

func TestParseTeleportBotIdentityPrincipal_UnsupportedJoinMethod(t *testing.T) {
	principal := map[string]any{
		"teleport_proxy_provider": "p",
		"bot_name":                "b",
		"join_method":             "azure", // not supported in v1
		"join_token":              "t",
	}
	out, err := ParseTeleportBotIdentityPrincipal(principal)
	assert.Nil(t, out)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrInvalidAuthConfig))
}

func TestTeleportCredentials_IsExpired(t *testing.T) {
	t.Run("zero ValidUntil means unknown, treated as not expired", func(t *testing.T) {
		c := &TeleportCredentials{}
		assert.False(t, c.IsExpired())
	})
	t.Run("nil receiver is expired", func(t *testing.T) {
		var c *TeleportCredentials
		assert.True(t, c.IsExpired())
	})
}

func TestTeleportCredentials_BuildWhoamiInfo(t *testing.T) {
	c := &TeleportCredentials{
		ClusterName: "company.teleport.local",
		Username:    "alice",
	}
	info := &WhoamiInfo{}
	c.BuildWhoamiInfo(info)
	assert.Equal(t, "company.teleport.local", info.Account)
	assert.Equal(t, "alice", info.Principal)
}

func TestTeleportCredentials_BuildWhoamiInfo_NilSafe(t *testing.T) {
	var c *TeleportCredentials
	// Must not panic.
	c.BuildWhoamiInfo(nil)
	c.BuildWhoamiInfo(&WhoamiInfo{})
}
