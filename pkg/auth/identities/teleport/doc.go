// Package teleport implements the teleport/user and teleport/bot identity
// kinds.
//
// teleport/user obtains credentials via Atmos's in-process Teleport SSO
// web-login (cached in the Atmos keychain; no ~/.tsh or tsh binary). It
// optionally refines them (requesting a sub-set of roles or pre-routing to
// specific Kubernetes clusters) by calling GenerateUserCerts through the
// Teleport SDK using the base credentials.
//
// teleport/bot performs a tbot-equivalent join handshake to obtain machine
// credentials. Supported join methods in v1 are GitHub OIDC (chains off a
// github/oidc provider) and AWS IAM (chains off any aws/* identity).
//
// Both identities produce types.TeleportCredentials. The kubernetes
// integration in pkg/auth/integrations/teleport consumes these credentials to
// issue per-cluster kube certs.
package teleport
