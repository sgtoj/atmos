package types

import (
	"fmt"

	"github.com/go-viper/mapstructure/v2"

	errUtils "github.com/cloudposse/atmos/errors"
	"github.com/cloudposse/atmos/pkg/perf"
)

// TeleportProxyProviderSpec defines the spec for the teleport/proxy provider.
//
// The teleport/proxy provider does not perform authentication itself: it
// describes a Teleport cluster (proxy address, optional CA cert, optional auth
// connector hint) that downstream identities use.
//
// For the workstation user identity (teleport/user), the provider drives
// Atmos's in-process Teleport SSO web-login against this cluster and the
// resulting credentials are stored in the Atmos keychain. Atmos does not read
// ~/.tsh or invoke the tsh binary.
type TeleportProxyProviderSpec struct {
	// ProxyAddress is the Teleport proxy host:port (required).
	// Example: "teleport.company.com:443".
	ProxyAddress string `mapstructure:"proxy_address" json:"proxy_address" yaml:"proxy_address"`

	// AuthConnector is the optional Teleport auth connector name (SSO connector
	// id: "okta", "github", "azure-ad", etc.). When set, Atmos uses it to select
	// the IdP for the in-process SSO web-login.
	AuthConnector string `mapstructure:"auth_connector,omitempty" json:"auth_connector,omitempty" yaml:"auth_connector,omitempty"`

	// Insecure skips TLS verification when talking to the proxy. Intended for
	// development against self-hosted Teleport with self-signed certs.
	// Production deployments should set CACertPath or CACertPEM instead.
	Insecure bool `mapstructure:"insecure,omitempty" json:"insecure,omitempty" yaml:"insecure,omitempty"`

	// CACertPath is an optional path to a PEM file containing the proxy's CA
	// certificate. Mutually exclusive with CACertPEM.
	CACertPath string `mapstructure:"ca_cert_path,omitempty" json:"ca_cert_path,omitempty" yaml:"ca_cert_path,omitempty"`

	// CACertPEM is an optional inline PEM-encoded CA certificate. Mutually
	// exclusive with CACertPath.
	CACertPEM string `mapstructure:"ca_cert_pem,omitempty" json:"ca_cert_pem,omitempty" yaml:"ca_cert_pem,omitempty"`
}

// TeleportUserIdentityPrincipal defines the principal for the teleport/user identity.
//
// The teleport/user identity surfaces the cert/key issued by Atmos's in-process
// SSO web-login (cached in the Atmos keychain). The fields here are optional
// refinements -- requesting a subset of roles or a specific kubernetes cluster
// routing, both of which require Atmos to call GenerateUserCerts via the SDK
// after the base login.
type TeleportUserIdentityPrincipal struct {
	// Roles is an optional subset of Teleport roles to request. When empty,
	// the identity uses all roles granted by the SSO login.
	Roles []string `mapstructure:"roles,omitempty" json:"roles,omitempty" yaml:"roles,omitempty"`

	// KubernetesClusters is an optional list of Teleport k8s cluster names to
	// pre-route to. Used by the integration layer when issuing kube certs.
	KubernetesClusters []string `mapstructure:"kubernetes_clusters,omitempty" json:"kubernetes_clusters,omitempty" yaml:"kubernetes_clusters,omitempty"`

	// TTL is the requested certificate lifetime (e.g., "1h", "30m").
	// When empty, the SSO login's default TTL is used.
	TTL string `mapstructure:"ttl,omitempty" json:"ttl,omitempty" yaml:"ttl,omitempty"`

	// RequireMFA, when true, requires a fresh MFA cert for this identity.
	// Documented for forward compatibility; may not be honored until the SSO
	// web-login is validated against a live cluster.
	RequireMFA bool `mapstructure:"require_mfa,omitempty" json:"require_mfa,omitempty" yaml:"require_mfa,omitempty"`

	// TeleportCluster is the optional Teleport cluster name when using trusted
	// clusters (leaf-cluster routing). Empty means the root cluster.
	TeleportCluster string `mapstructure:"teleport_cluster,omitempty" json:"teleport_cluster,omitempty" yaml:"teleport_cluster,omitempty"`
}

// TeleportBotIdentityPrincipal defines the principal for the teleport/bot identity.
//
// The teleport/bot identity is a machine identity equivalent to tbot. It joins
// the Teleport cluster using credentials sourced from a different upstream
// (GitHub OIDC for CI workloads, AWS STS sigv4 for AWS-resident workloads) and
// persists the resulting Teleport certs to an identity file on disk.
type TeleportBotIdentityPrincipal struct {
	// TeleportProxyProvider is the name of the upstream teleport/proxy
	// provider that identifies which Teleport cluster to join (required).
	// Note: This is NOT the same as the auth chain's "via.provider" --
	// "via.provider" points at the source of join credentials (e.g. github/oidc
	// or an aws/* identity), whereas this names the target Teleport cluster.
	TeleportProxyProvider string `mapstructure:"teleport_proxy_provider" json:"teleport_proxy_provider" yaml:"teleport_proxy_provider"`

	// BotName is the Teleport bot name (required). Must exist in the Teleport
	// cluster's configuration as a registered bot.
	BotName string `mapstructure:"bot_name" json:"bot_name" yaml:"bot_name"`

	// JoinMethod selects how the bot joins. Supported values in v1: "github"
	// (GitHub Actions OIDC) and "iam" (AWS STS GetCallerIdentity sigv4).
	// Future: "kubernetes", "azure", "gcp", "tpm", "bound-keypair", "token".
	JoinMethod string `mapstructure:"join_method" json:"join_method" yaml:"join_method"`

	// JoinToken is the Teleport join token name (required). Must exist in the
	// Teleport cluster's configuration and match the JoinMethod.
	JoinToken string `mapstructure:"join_token" json:"join_token" yaml:"join_token"`

	// Roles is the optional subset of roles the bot should be granted. Empty
	// means "all roles configured on the bot in Teleport".
	Roles []string `mapstructure:"roles,omitempty" json:"roles,omitempty" yaml:"roles,omitempty"`

	// OutputDir overrides the default identity-file output directory. Default
	// is $ATMOS_DATA_HOME/teleport/bot/<realm>/<bot_name>/.
	OutputDir string `mapstructure:"output_dir,omitempty" json:"output_dir,omitempty" yaml:"output_dir,omitempty"`

	// TTL is the requested certificate lifetime (e.g., "1h"). Default "1h".
	TTL string `mapstructure:"ttl,omitempty" json:"ttl,omitempty" yaml:"ttl,omitempty"`

	// RenewalInterval is the optional renewal cadence (e.g., "20m"). Not
	// honored in v1; reserved for future background-renewal support.
	RenewalInterval string `mapstructure:"renewal_interval,omitempty" json:"renewal_interval,omitempty" yaml:"renewal_interval,omitempty"`

	// AWS contains options specific to JoinMethod="iam".
	AWS *TeleportBotAWSJoin `mapstructure:"aws,omitempty" json:"aws,omitempty" yaml:"aws,omitempty"`

	// GitHub contains options specific to JoinMethod="github".
	GitHub *TeleportBotGitHubJoin `mapstructure:"github,omitempty" json:"github,omitempty" yaml:"github,omitempty"`
}

// TeleportBotAWSJoin holds options for the AWS IAM join method.
type TeleportBotAWSJoin struct {
	// Region is the AWS region used to construct the STS GetCallerIdentity
	// signing endpoint. Defaults to "us-east-1".
	Region string `mapstructure:"region,omitempty" json:"region,omitempty" yaml:"region,omitempty"`

	// STSEndpoint is an optional override for the STS endpoint (e.g., for
	// VPC endpoints or LocalStack). Empty uses the default regional endpoint.
	STSEndpoint string `mapstructure:"sts_endpoint,omitempty" json:"sts_endpoint,omitempty" yaml:"sts_endpoint,omitempty"`
}

// TeleportBotGitHubJoin holds options for the GitHub OIDC join method.
type TeleportBotGitHubJoin struct {
	// Audience overrides the GitHub Actions ID token audience. Empty uses
	// the Teleport-recommended default ("teleport.cluster.local").
	Audience string `mapstructure:"audience,omitempty" json:"audience,omitempty" yaml:"audience,omitempty"`
}

// ParseTeleportProxyProviderSpec parses a map into TeleportProxyProviderSpec.
func ParseTeleportProxyProviderSpec(spec map[string]any) (*TeleportProxyProviderSpec, error) {
	defer perf.Track(nil, "types.ParseTeleportProxyProviderSpec")()

	if spec == nil {
		return nil, fmt.Errorf("%w: spec is nil", errUtils.ErrInvalidAuthConfig)
	}

	var out TeleportProxyProviderSpec
	if err := mapstructure.Decode(spec, &out); err != nil {
		return nil, fmt.Errorf("%w: failed to decode teleport/proxy provider spec: %w", errUtils.ErrInvalidAuthConfig, err)
	}

	// proxy_address is required: it's the only field that's never inferable.
	if out.ProxyAddress == "" {
		return nil, fmt.Errorf("%w: proxy_address is required for teleport/proxy provider", errUtils.ErrInvalidAuthConfig)
	}

	// CACertPath and CACertPEM are mutually exclusive.
	if out.CACertPath != "" && out.CACertPEM != "" {
		return nil, fmt.Errorf("%w: teleport/proxy: ca_cert_path and ca_cert_pem are mutually exclusive", errUtils.ErrInvalidAuthConfig)
	}

	return &out, nil
}

// ParseTeleportUserIdentityPrincipal parses a map into TeleportUserIdentityPrincipal.
//
// All fields are optional: a teleport/user identity with no principal is valid
// and represents "use the SSO login's credentials as-is".
func ParseTeleportUserIdentityPrincipal(principal map[string]any) (*TeleportUserIdentityPrincipal, error) {
	defer perf.Track(nil, "types.ParseTeleportUserIdentityPrincipal")()

	var out TeleportUserIdentityPrincipal
	if principal == nil {
		return &out, nil
	}

	if err := mapstructure.Decode(principal, &out); err != nil {
		return nil, fmt.Errorf("%w: failed to decode teleport/user principal: %w", errUtils.ErrInvalidAuthConfig, err)
	}
	return &out, nil
}

// ParseTeleportBotIdentityPrincipal parses a map into TeleportBotIdentityPrincipal.
func ParseTeleportBotIdentityPrincipal(principal map[string]any) (*TeleportBotIdentityPrincipal, error) {
	defer perf.Track(nil, "types.ParseTeleportBotIdentityPrincipal")()

	if principal == nil {
		return nil, fmt.Errorf("%w: principal is nil", errUtils.ErrInvalidAuthConfig)
	}

	var out TeleportBotIdentityPrincipal
	if err := mapstructure.Decode(principal, &out); err != nil {
		return nil, fmt.Errorf("%w: failed to decode teleport/bot principal: %w", errUtils.ErrInvalidAuthConfig, err)
	}

	// Required fields: enforce here so identity construction fails loudly.
	if out.TeleportProxyProvider == "" {
		return nil, fmt.Errorf("%w: teleport_proxy_provider is required for teleport/bot identity", errUtils.ErrInvalidAuthConfig)
	}
	if out.BotName == "" {
		return nil, fmt.Errorf("%w: bot_name is required for teleport/bot identity", errUtils.ErrInvalidAuthConfig)
	}
	if out.JoinMethod == "" {
		return nil, fmt.Errorf("%w: join_method is required for teleport/bot identity", errUtils.ErrInvalidAuthConfig)
	}
	if out.JoinToken == "" {
		return nil, fmt.Errorf("%w: join_token is required for teleport/bot identity", errUtils.ErrInvalidAuthConfig)
	}

	// Validate JoinMethod against v1's supported set.
	switch out.JoinMethod {
	case "github", "iam":
		// Supported.
	default:
		return nil, fmt.Errorf("%w: unsupported join_method %q for teleport/bot (v1 supports: github, iam)",
			errUtils.ErrInvalidAuthConfig, out.JoinMethod)
	}

	return &out, nil
}
