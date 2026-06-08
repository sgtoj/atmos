package teleport

import (
	"context"
	"fmt"

	errUtils "github.com/cloudposse/atmos/errors"
	"github.com/cloudposse/atmos/pkg/auth/types"
	"github.com/cloudposse/atmos/pkg/perf"
)

// ProviderKind is the kind identifier for this provider.
const ProviderKind = types.ProviderKindTeleportProxy // "teleport/proxy"

// Provider implements the teleport/proxy authentication provider.
//
// The provider holds the cluster's connection metadata (proxy address, CA,
// auth connector). For the teleport/user identity it is the credentials source:
// its Authenticate() drives Atmos's in-process Teleport SSO web-login and
// returns the issued credentials, which the auth manager caches in the Atmos
// keychain (Atmos does not read ~/.tsh and never shells out to the tsh binary).
// For the teleport/bot identity, the provider serves only as a reference point
// (named by the bot's principal); the bot performs its own join handshake
// against a different upstream.
type Provider struct {
	name  string
	realm string
	spec  *types.TeleportProxyProviderSpec
}

// New creates a new teleport/proxy provider from the given spec.
func New(spec *types.TeleportProxyProviderSpec) (*Provider, error) {
	defer perf.Track(nil, "providers/teleport.New")()

	if spec == nil {
		return nil, fmt.Errorf("%w: teleport/proxy provider spec cannot be nil", errUtils.ErrInvalidProviderConfig)
	}
	return &Provider{spec: spec}, nil
}

// SetName sets the provider name (used by the factory when registering).
func (p *Provider) SetName(name string) {
	p.name = name
}

// SetRealm sets the credential realm. Teleport credentials are stored in the
// Atmos keychain keyed by realm, so the realm scopes the cached SSO session.
func (p *Provider) SetRealm(realm string) {
	p.realm = realm
}

// Kind returns the provider kind.
func (p *Provider) Kind() string {
	return ProviderKind
}

// Name returns the provider name as defined in configuration.
func (p *Provider) Name() string {
	if p.name != "" {
		return p.name
	}
	return ProviderKind
}

// PreAuthenticate is a no-op for the teleport/proxy provider.
func (p *Provider) PreAuthenticate(_ types.AuthManager) error {
	return nil
}

// Authenticate drives the in-process Teleport SSO web-login against the proxy
// and returns the issued credentials (cached by the auth manager in the Atmos
// keychain).
//
// The interactive SSO web-login flow requires validation against a live
// Teleport cluster; until it lands this returns ErrNotImplemented. The provider
// is registered and recognized by the factory so configs that reference it are
// accepted.
func (p *Provider) Authenticate(_ context.Context) (types.ICredentials, error) {
	defer perf.Track(nil, "providers/teleport.Authenticate")()

	if err := p.Validate(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w: teleport/proxy SSO web-login not yet implemented (pending live-cluster validation)", errUtils.ErrNotImplemented)
}

// Validate validates the provider configuration.
func (p *Provider) Validate() error {
	if p.spec == nil {
		return fmt.Errorf("%w: teleport/proxy provider spec cannot be nil", errUtils.ErrInvalidProviderConfig)
	}
	if p.spec.ProxyAddress == "" {
		return fmt.Errorf("%w: proxy_address is required", errUtils.ErrInvalidProviderConfig)
	}
	if p.spec.CACertPath != "" && p.spec.CACertPEM != "" {
		return fmt.Errorf("%w: ca_cert_path and ca_cert_pem are mutually exclusive", errUtils.ErrInvalidProviderConfig)
	}
	return nil
}

// Environment returns environment variables exported by this provider.
//
// TELEPORT_PROXY surfaces here so subprocess invocations (atmos auth shell /
// exec) see consistent cluster context.
func (p *Provider) Environment() (map[string]string, error) {
	defer perf.Track(nil, "providers/teleport.Environment")()

	env := map[string]string{}
	if p.spec != nil && p.spec.ProxyAddress != "" {
		env["TELEPORT_PROXY"] = p.spec.ProxyAddress
	}
	return env, nil
}

// Paths returns credential files/directories used by this provider. Teleport
// user credentials live in the Atmos keychain, not on a profile path, so there
// are none to surface.
func (p *Provider) Paths() ([]types.Path, error) {
	return []types.Path{}, nil
}

// PrepareEnvironment prepares environment variables for external processes.
func (p *Provider) PrepareEnvironment(_ context.Context, environ map[string]string) (map[string]string, error) {
	defer perf.Track(nil, "providers/teleport.PrepareEnvironment")()

	out := make(map[string]string, len(environ))
	for k, v := range environ {
		out[k] = v
	}
	env, err := p.Environment()
	if err != nil {
		return nil, err
	}
	for k, v := range env {
		out[k] = v
	}
	return out, nil
}

// Logout is a no-op for the provider: teleport/user credentials live in the
// Atmos keychain and are cleared by the auth manager's logout; bot identity
// files are removed by the teleport/bot identity's Logout.
func (p *Provider) Logout(_ context.Context) error {
	return nil
}

// GetFilesDisplayPath returns the display path for credential files. Teleport
// credentials are stored in the Atmos keychain, so there is no file path.
func (p *Provider) GetFilesDisplayPath() string {
	return ""
}
