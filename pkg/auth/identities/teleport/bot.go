package teleport

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	errUtils "github.com/cloudposse/atmos/errors"
	teleportCloud "github.com/cloudposse/atmos/pkg/auth/cloud/teleport"
	"github.com/cloudposse/atmos/pkg/auth/types"
	"github.com/cloudposse/atmos/pkg/perf"
	"github.com/cloudposse/atmos/pkg/schema"
	"github.com/cloudposse/atmos/pkg/xdg"
)

// BotIdentityKind is the kind identifier for the teleport/bot identity.
const BotIdentityKind = types.IdentityKindTeleportBot // "teleport/bot"

// identityFileName is the filename used for a persisted bot identity file.
const identityFileName = "identity"

// botJoinFn performs the Teleport bot join handshake. It is a package var so
// tests can substitute a fake joiner and exercise the identity lifecycle
// (keychain persistence + identity-file materialization) without a live
// Teleport cluster.
var botJoinFn = teleportCloud.Join

// BotIdentity implements the teleport/bot identity: a tbot-equivalent machine
// identity that joins Teleport via GitHub OIDC or AWS IAM.
//
// Unlike teleport/user, the bot identity does NOT chain off the teleport/proxy
// provider for its base credentials. Instead, its `via` chain points at the
// source of join credentials (a github/oidc provider, or an aws/* identity),
// and the principal's TeleportProxyProvider field names the target Teleport
// cluster (by referencing a teleport/proxy provider).
type BotIdentity struct {
	name      string
	realm     string
	principal *types.TeleportBotIdentityPrincipal
	config    *schema.Identity
	provider  types.Provider

	// proxyAddress is the target Teleport cluster's proxy host:port, resolved
	// from principal.TeleportProxyProvider. It must be injected via
	// SetTeleportProxyAddress before Authenticate can perform the join.
	//
	// Wiring this from the named teleport/proxy provider's spec at chain-build
	// time (in the auth manager) is the remaining integration step; the join
	// itself is validated against a live Teleport cluster.
	proxyAddress string
}

// SetTeleportProxyAddress injects the target cluster's proxy host:port (resolved
// from principal.TeleportProxyProvider).
func (i *BotIdentity) SetTeleportProxyAddress(addr string) { i.proxyAddress = addr }

// NewBotIdentity creates a new teleport/bot identity from a principal.
func NewBotIdentity(principal *types.TeleportBotIdentityPrincipal) (*BotIdentity, error) {
	defer perf.Track(nil, "identities/teleport.NewBotIdentity")()

	if principal == nil {
		return nil, fmt.Errorf("%w: teleport/bot principal cannot be nil", errUtils.ErrInvalidIdentityConfig)
	}
	return &BotIdentity{principal: principal}, nil
}

// SetName sets the identity name.
func (i *BotIdentity) SetName(name string) { i.name = name }

// SetRealm sets the credential realm.
func (i *BotIdentity) SetRealm(realm string) { i.realm = realm }

// SetConfig sets the identity configuration.
func (i *BotIdentity) SetConfig(config *schema.Identity) { i.config = config }

// SetProvider sets the upstream provider (source of join credentials).
func (i *BotIdentity) SetProvider(provider types.Provider) { i.provider = provider }

// Kind returns the identity kind.
func (i *BotIdentity) Kind() string { return BotIdentityKind }

// Name returns the identity name.
func (i *BotIdentity) Name() string {
	if i.name != "" {
		return i.name
	}
	return BotIdentityKind
}

// GetProviderName returns the upstream provider name from config (the source
// of join credentials, NOT the teleport_proxy_provider field).
func (i *BotIdentity) GetProviderName() (string, error) {
	if i.config != nil && i.config.Via != nil && i.config.Via.Provider != "" {
		return i.config.Via.Provider, nil
	}
	if i.provider != nil {
		return i.provider.Name(), nil
	}
	return "", nil
}

// Validate validates the identity configuration.
func (i *BotIdentity) Validate() error {
	if i.principal == nil {
		return fmt.Errorf("%w: principal is nil", errUtils.ErrInvalidIdentityConfig)
	}
	if i.principal.TeleportProxyProvider == "" {
		return fmt.Errorf("%w: teleport_proxy_provider is required", errUtils.ErrInvalidIdentityConfig)
	}
	if i.principal.BotName == "" {
		return fmt.Errorf("%w: bot_name is required", errUtils.ErrInvalidIdentityConfig)
	}
	if i.principal.JoinMethod == "" {
		return fmt.Errorf("%w: join_method is required", errUtils.ErrInvalidIdentityConfig)
	}
	if i.principal.JoinToken == "" {
		return fmt.Errorf("%w: join_token is required", errUtils.ErrInvalidIdentityConfig)
	}
	switch i.principal.JoinMethod {
	case "github", "iam":
		// Supported.
	default:
		return fmt.Errorf("%w: %q (supported: github, iam)", errUtils.ErrTeleportUnsupportedJoinMethod, i.principal.JoinMethod)
	}
	return nil
}

// Authenticate performs the Teleport bot join handshake using the upstream
// base credentials (GitHub OIDC token or AWS credentials) and returns the
// issued Teleport credentials. The auth manager persists the returned
// credentials in the keychain; PostAuthenticate additionally materializes a
// derived identity file for subprocess interop.
//
// The join handshake itself (botJoinFn) is validated against a live Teleport
// cluster; this method's request construction and credential decoration are
// unit-tested via the botJoinFn seam.
func (i *BotIdentity) Authenticate(ctx context.Context, baseCreds types.ICredentials) (types.ICredentials, error) {
	defer perf.Track(nil, "identities/teleport.BotIdentity.Authenticate")()

	if err := i.Validate(); err != nil {
		return nil, err
	}
	if i.proxyAddress == "" {
		return nil, fmt.Errorf("%w: teleport proxy address for provider %q is not resolved", errUtils.ErrTeleportProxyResolution, i.principal.TeleportProxyProvider)
	}

	creds, err := botJoinFn(ctx, i.buildJoinRequest(baseCreds))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUtils.ErrTeleportJoinFailed, err)
	}

	// Decorate with context the join handshake may not have populated.
	creds.IsBot = true
	if creds.ProxyAddress == "" {
		creds.ProxyAddress = i.proxyAddress
	}
	if path := i.identityFilePath(); path != "" {
		creds.IdentityFilePath = path
	}
	return creds, nil
}

// buildJoinRequest assembles the join request from the principal and the
// upstream base credentials (AWS credentials for the iam method; the OIDC
// token source for the github method is resolved inside the join handshake).
func (i *BotIdentity) buildJoinRequest(baseCreds types.ICredentials) *teleportCloud.JoinRequest {
	req := &teleportCloud.JoinRequest{
		ProxyAddress:   i.proxyAddress,
		BotName:        i.principal.BotName,
		JoinToken:      i.principal.JoinToken,
		JoinMethod:     i.principal.JoinMethod,
		TTL:            i.principal.TTL,
		Roles:          i.principal.Roles,
		AWSCredentials: baseCreds,
	}
	if i.principal.AWS != nil {
		req.AWSRegion = i.principal.AWS.Region
		req.AWSSTSEndpoint = i.principal.AWS.STSEndpoint
	}
	if i.principal.GitHub != nil {
		req.GitHubAudience = i.principal.GitHub.Audience
	}
	return req
}

// Environment returns identity-specific environment variables.
//
// The bot identity exposes TELEPORT_IDENTITY_FILE pointing at the on-disk
// identity file so that subprocesses (kubectl, tsh -i, etc.) can use it
// directly. The value resolves to the bot's output_dir + "/identity".
func (i *BotIdentity) Environment() (map[string]string, error) {
	env := map[string]string{}
	if path := i.identityFilePath(); path != "" {
		env["TELEPORT_IDENTITY_FILE"] = path
	}
	return env, nil
}

// Paths returns credential file paths for this identity.
func (i *BotIdentity) Paths() ([]types.Path, error) {
	path := i.identityFilePath()
	if path == "" {
		return []types.Path{}, nil
	}
	return []types.Path{
		{
			Location: path,
			Type:     types.PathTypeFile,
			Required: false,
			Purpose:  "Teleport bot identity file",
		},
	}, nil
}

// PrepareEnvironment prepares environment variables for external processes.
func (i *BotIdentity) PrepareEnvironment(_ context.Context, environ map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(environ))
	for k, v := range environ {
		out[k] = v
	}
	env, err := i.Environment()
	if err != nil {
		return nil, err
	}
	for k, v := range env {
		out[k] = v
	}
	return out, nil
}

// PostAuthenticate materializes the bot's TeleportCredentials as a derived
// identity file on disk (for tsh -i / kubectl exec-plugin interop). The keychain
// remains the canonical store (written by the auth manager); this file is
// rewritten on each authentication and removed on Logout.
func (i *BotIdentity) PostAuthenticate(_ context.Context, params *types.PostAuthenticateParams) error {
	defer perf.Track(nil, "identities/teleport.BotIdentity.PostAuthenticate")()

	if params == nil || params.Credentials == nil {
		return nil
	}
	teleportCreds, ok := params.Credentials.(*types.TeleportCredentials)
	if !ok {
		return fmt.Errorf("%w: teleport/bot PostAuthenticate received %T", errUtils.ErrTeleportCredentialsType, params.Credentials)
	}
	path := i.identityFilePath()
	if path == "" {
		return nil
	}
	return teleportCloud.WriteIdentityFile(context.Background(), teleportCreds, path)
}

// Logout removes the derived bot identity file. Idempotent: a missing file is
// not an error (the keychain entry is removed separately by the auth manager).
func (i *BotIdentity) Logout(_ context.Context) error {
	defer perf.Track(nil, "identities/teleport.BotIdentity.Logout")()

	path := i.identityFilePath()
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %w", errUtils.ErrTeleportBotIdentityWrite, err)
	}
	return nil
}

// CredentialsExist returns true when a bot identity file is present on disk.
func (i *BotIdentity) CredentialsExist() (bool, error) {
	defer perf.Track(nil, "identities/teleport.BotIdentity.CredentialsExist")()

	path := i.identityFilePath()
	if path == "" {
		return false, nil
	}
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("%w: %w", errUtils.ErrTeleportBotIdentityRead, err)
}

// LoadCredentials loads bot credentials from the derived identity file.
func (i *BotIdentity) LoadCredentials(ctx context.Context) (types.ICredentials, error) {
	defer perf.Track(nil, "identities/teleport.BotIdentity.LoadCredentials")()

	path := i.identityFilePath()
	if path == "" {
		return nil, fmt.Errorf("%w: no identity file path for teleport/bot %q", errUtils.ErrTeleportBotIdentityRead, i.Name())
	}
	creds, err := teleportCloud.LoadIdentityFile(ctx, path)
	if err != nil {
		return nil, err
	}
	if creds.ProxyAddress == "" {
		creds.ProxyAddress = i.proxyAddress
	}
	return creds, nil
}

// identityFilePath returns the on-disk path of the bot's identity file.
//
// Default: $ATMOS_DATA_HOME/atmos/teleport/bot/<realm>/<bot_name>/identity
// (realm-scoped). Overridable via principal.output_dir, in which case the file
// is "<output_dir>/identity".
func (i *BotIdentity) identityFilePath() string {
	if i.principal != nil && i.principal.OutputDir != "" {
		return filepath.Join(i.principal.OutputDir, identityFileName)
	}
	if i.principal == nil || i.principal.BotName == "" {
		return ""
	}
	subpath := filepath.Join("teleport", "bot")
	if i.realm != "" {
		subpath = filepath.Join(subpath, i.realm)
	}
	subpath = filepath.Join(subpath, i.principal.BotName, identityFileName)
	return xdg.LookupXDGDataDir(subpath)
}
