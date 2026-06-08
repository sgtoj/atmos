// Package teleport wraps the Teleport API SDK
// (github.com/gravitational/teleport/api) for Atmos.
//
// This package isolates the SDK behind a Client interface so that callers in
// pkg/auth/providers/teleport, pkg/auth/identities/teleport, and
// pkg/auth/integrations/teleport can be unit-tested without a live Teleport
// cluster. The interface is mockgen-generated.
//
// Responsibilities by file:
//
//   - client.go   -- Client interface + SDK-backed implementation
//     (Ping, GenerateKubeCert for per-kube-cluster certs).
//   - identity.go -- Read/write tbot-format identity files.
//   - join.go     -- tbot-equivalent GitHub OIDC / AWS IAM join handshake.
//
// Atmos credentials are stored in the Atmos keychain, not ~/.tsh. The bot join
// handshake and the interactive SSO web-login require validation against a live
// Teleport cluster.
package teleport
