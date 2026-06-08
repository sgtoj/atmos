package factory

import (
	"errors"
	"fmt"

	errUtils "github.com/cloudposse/atmos/errors"
	teleportIdentities "github.com/cloudposse/atmos/pkg/auth/identities/teleport"
	teleportProviders "github.com/cloudposse/atmos/pkg/auth/providers/teleport"
	"github.com/cloudposse/atmos/pkg/auth/types"
	"github.com/cloudposse/atmos/pkg/perf"
)

// RegisterTeleportProviders registers all Teleport provider constructors.
func RegisterTeleportProviders(f *Factory) {
	defer perf.Track(nil, "factory.RegisterTeleportProviders")()

	f.RegisterProvider(types.ProviderKindTeleportProxy, func(name string, spec map[string]any) (types.Provider, error) {
		defer perf.Track(nil, "factory.CreateTeleportProxyProvider")()

		parsed, err := types.ParseTeleportProxyProviderSpec(spec)
		if err != nil {
			return nil, fmt.Errorf("parse teleport/proxy spec: %w", errors.Join(errUtils.ErrInvalidProviderConfig, err))
		}
		provider, err := teleportProviders.New(parsed)
		if err != nil {
			return nil, err
		}
		provider.SetName(name)
		return provider, nil
	})
}

// teleportIdentityNamer is the minimal contract the Teleport identity
// constructors satisfy so this package can apply the configured identity name
// after construction. Both teleport/user and teleport/bot expose SetName.
type teleportIdentityNamer interface {
	types.Identity
	SetName(name string)
}

// newTeleportIdentity is the shared shape for Teleport identity constructors:
// parse the principal map, hand it to the vendor's constructor, then attach
// the user-supplied name. Extracting this collapses the registration calls
// below to one line each, avoiding boilerplate-duplication and keeping per-kind
// behavior co-located with the kind constant.
//
// The %w wrapping at each error site preserves both ErrInvalidIdentityConfig
// (for errors.Is checks) and the underlying parse error chain.
func newTeleportIdentity[P any, I teleportIdentityNamer](
	kind, name string,
	principal map[string]any,
	parse func(map[string]any) (P, error),
	build func(P) (I, error),
) (types.Identity, error) {
	parsed, err := parse(principal)
	if err != nil {
		return nil, fmt.Errorf("%w: parse %s principal: %w", errUtils.ErrInvalidIdentityConfig, kind, err)
	}
	identity, err := build(parsed)
	if err != nil {
		return nil, err
	}
	identity.SetName(name)
	return identity, nil
}

// RegisterTeleportIdentities registers all Teleport identity constructors.
func RegisterTeleportIdentities(f *Factory) {
	defer perf.Track(nil, "factory.RegisterTeleportIdentities")()

	f.RegisterIdentity(types.IdentityKindTeleportUser, func(name string, principal map[string]any) (types.Identity, error) {
		defer perf.Track(nil, "factory.CreateTeleportUserIdentity")()
		return newTeleportIdentity(
			types.IdentityKindTeleportUser, name, principal,
			types.ParseTeleportUserIdentityPrincipal,
			teleportIdentities.NewUserIdentity,
		)
	})

	f.RegisterIdentity(types.IdentityKindTeleportBot, func(name string, principal map[string]any) (types.Identity, error) {
		defer perf.Track(nil, "factory.CreateTeleportBotIdentity")()
		return newTeleportIdentity(
			types.IdentityKindTeleportBot, name, principal,
			types.ParseTeleportBotIdentityPrincipal,
			teleportIdentities.NewBotIdentity,
		)
	})
}
