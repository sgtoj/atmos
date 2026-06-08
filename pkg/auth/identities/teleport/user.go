package teleport

import (
	"context"
	"fmt"

	errUtils "github.com/cloudposse/atmos/errors"
	"github.com/cloudposse/atmos/pkg/auth/types"
	"github.com/cloudposse/atmos/pkg/perf"
	"github.com/cloudposse/atmos/pkg/schema"
)

// UserIdentityKind is the kind identifier for the teleport/user identity.
const UserIdentityKind = types.IdentityKindTeleportUser // "teleport/user"

// UserIdentity implements the teleport/user identity.
//
// The identity authenticates by passing through the credentials provided by the
// upstream teleport/proxy provider (which obtains them via Atmos's in-process
// SSO web-login, cached in the Atmos keychain). When the principal requests
// specific roles or kubernetes clusters, the identity calls GenerateUserCerts
// via the Teleport SDK to re-issue refined credentials.
type UserIdentity struct {
	name      string
	realm     string
	principal *types.TeleportUserIdentityPrincipal
	config    *schema.Identity
	provider  types.Provider
}

// NewUserIdentity creates a new teleport/user identity from a principal.
func NewUserIdentity(principal *types.TeleportUserIdentityPrincipal) (*UserIdentity, error) {
	defer perf.Track(nil, "identities/teleport.NewUserIdentity")()

	if principal == nil {
		// teleport/user accepts an empty principal (use the SSO login as-is).
		principal = &types.TeleportUserIdentityPrincipal{}
	}
	return &UserIdentity{principal: principal}, nil
}

// SetName sets the identity name.
func (i *UserIdentity) SetName(name string) { i.name = name }

// SetRealm sets the credential realm.
func (i *UserIdentity) SetRealm(realm string) { i.realm = realm }

// SetConfig sets the identity configuration (for Via.Provider resolution).
func (i *UserIdentity) SetConfig(config *schema.Identity) { i.config = config }

// SetProvider sets the upstream provider for this identity.
func (i *UserIdentity) SetProvider(provider types.Provider) { i.provider = provider }

// Kind returns the identity kind.
func (i *UserIdentity) Kind() string { return UserIdentityKind }

// Name returns the identity name.
func (i *UserIdentity) Name() string {
	if i.name != "" {
		return i.name
	}
	return UserIdentityKind
}

// GetProviderName returns the upstream provider name from config.
func (i *UserIdentity) GetProviderName() (string, error) {
	if i.config != nil && i.config.Via != nil && i.config.Via.Provider != "" {
		return i.config.Via.Provider, nil
	}
	if i.provider != nil {
		return i.provider.Name(), nil
	}
	return "", nil
}

// Validate validates the identity configuration.
func (i *UserIdentity) Validate() error {
	// teleport/user has no mandatory principal fields; the SSO web-login is
	// performed by the upstream provider at Authenticate time.
	return nil
}

// Authenticate refines the upstream Teleport credentials (issued by the
// provider's SSO web-login) according to the principal (selected roles, kube
// clusters). When the principal is empty, the upstream credentials are returned
// unchanged.
//
// Role/kube-cluster refinement via GenerateUserCerts requires validation
// against a live Teleport cluster; until it lands this returns
// ErrNotImplemented.
func (i *UserIdentity) Authenticate(_ context.Context, baseCreds types.ICredentials) (types.ICredentials, error) {
	defer perf.Track(nil, "identities/teleport.UserIdentity.Authenticate")()

	if baseCreds == nil {
		return nil, fmt.Errorf("%w: no upstream credentials for teleport/user identity %q", errUtils.ErrAuthenticationFailed, i.Name())
	}
	if _, ok := baseCreds.(*types.TeleportCredentials); !ok {
		return nil, fmt.Errorf("%w: teleport/user requires teleport credentials from upstream provider", errUtils.ErrTeleportCredentialsType)
	}
	return nil, fmt.Errorf("%w: teleport/user Authenticate not yet implemented (pending live-cluster validation)", errUtils.ErrNotImplemented)
}

// Environment returns identity-specific environment variables.
func (i *UserIdentity) Environment() (map[string]string, error) {
	return map[string]string{}, nil
}

// Paths returns credential file paths for this identity.
func (i *UserIdentity) Paths() ([]types.Path, error) {
	return []types.Path{}, nil
}

// PrepareEnvironment prepares environment variables for external processes.
func (i *UserIdentity) PrepareEnvironment(_ context.Context, environ map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(environ))
	for k, v := range environ {
		out[k] = v
	}
	return out, nil
}

// PostAuthenticate is a no-op for teleport/user: the auth manager persists the
// returned credentials in the Atmos keychain; the identity keeps no separate
// on-disk copy.
func (i *UserIdentity) PostAuthenticate(_ context.Context, _ *types.PostAuthenticateParams) error {
	return nil
}

// Logout is a no-op for teleport/user: the cached SSO credentials live in the
// Atmos keychain and are cleared by the auth manager's logout.
func (i *UserIdentity) Logout(_ context.Context) error {
	return nil
}

// CredentialsExist reports whether the identity manages its own on-disk
// credentials. teleport/user does not (the keychain is canonical), so this is
// always false.
func (i *UserIdentity) CredentialsExist() (bool, error) {
	return false, nil
}

// LoadCredentials loads credentials from identity-managed storage. teleport/user
// has none (credentials come from the provider's SSO web-login and are cached in
// the keychain by the auth manager), so this returns ErrNotImplemented.
func (i *UserIdentity) LoadCredentials(_ context.Context) (types.ICredentials, error) {
	return nil, fmt.Errorf("%w: teleport/user has no identity-managed credential store (keychain is canonical)", errUtils.ErrNotImplemented)
}
