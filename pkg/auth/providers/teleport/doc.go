// Package teleport implements the teleport/proxy authentication provider.
//
// The teleport/proxy provider does not authenticate by itself. It describes a
// Teleport cluster (proxy address, optional CA cert, optional auth connector
// hint) that downstream identities (teleport/user, teleport/bot) reference.
//
// When the downstream identity is teleport/user, the provider's Authenticate()
// drives Atmos's in-process Teleport SSO web-login (against the proxy's
// /webapi endpoints) and returns the issued credentials, which the auth
// manager caches in the Atmos keychain. Atmos does not read ~/.tsh and never
// shells out to the tsh binary. When the downstream identity is teleport/bot,
// the provider's Authenticate() is a no-op: bot credentials come from a join
// handshake performed by the identity itself, using credentials sourced from a
// separate upstream provider (github/oidc, an aws/* identity, etc.).
package teleport
