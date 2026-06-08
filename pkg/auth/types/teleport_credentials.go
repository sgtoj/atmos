package types

import (
	"context"
	"fmt"
	"time"

	errUtils "github.com/cloudposse/atmos/errors"
)

// TeleportCredentials defines Teleport-specific credential fields.
//
// These credentials carry the certificate material returned by either a
// teleport/user identity (sourced from Atmos's in-process SSO web-login) or a
// teleport/bot identity (sourced from a join handshake). Downstream consumers
// (the teleport integration layer, the kube token command) use
// TLSCertPEM/TLSKeyPEM/TLSCAsPEM to dial the Teleport proxy and call
// GenerateUserCerts for per-resource access (e.g., per-kubernetes-cluster
// certs).
//
// TeleportCredentials are persisted in the Atmos keychain via the "teleport"
// credential envelope (see pkg/auth/credentials), the canonical store for both
// user and bot identities. For bot identities a derived tbot identity file is
// additionally materialized on disk for subprocess interop (see
// $ATMOS_DATA_HOME/.../teleport/bot/<realm>/<bot_name>/identity); it is a cache
// artifact, not the source of truth.
type TeleportCredentials struct {
	// ProxyAddress is the proxy host:port the credentials authenticate against.
	ProxyAddress string `json:"proxy_address,omitempty"`

	// ClusterName is the Teleport cluster name embedded in the cert.
	ClusterName string `json:"cluster_name,omitempty"`

	// Username is the principal name. For bot identities this is the bot's
	// username (typically "bot-<bot_name>" as Teleport models it).
	Username string `json:"username,omitempty"`

	// Roles are the Teleport roles encoded in the cert.
	Roles []string `json:"roles,omitempty"`

	// TLSCertPEM and TLSKeyPEM are the PEM-encoded client cert and key used
	// to dial the Teleport proxy.
	TLSCertPEM string `json:"tls_cert_pem,omitempty"`
	TLSKeyPEM  string `json:"tls_key_pem,omitempty"`

	// TLSCAsPEM are PEM-encoded CA certificates for verifying the proxy.
	TLSCAsPEM []string `json:"tls_cas_pem,omitempty"`

	// SSHCertPEM and SSHKeyPEM are optional SSH credentials (future teleport/ssh
	// integration). Populated when available, ignored by teleport/kubernetes.
	SSHCertPEM string `json:"ssh_cert_pem,omitempty"`
	SSHKeyPEM  string `json:"ssh_key_pem,omitempty"`

	// KubeClusters is the set of kubernetes cluster names the cert is
	// authorized to access. Used by the integration to fail fast when a
	// requested cluster is not in this set.
	KubeClusters []string `json:"kube_clusters,omitempty"`

	// ValidUntil is the expiry of the credentials.
	ValidUntil time.Time `json:"valid_until,omitempty"`

	// IdentityFilePath is the on-disk path to the source identity file (set
	// for bot identities). Useful for downstream tools that re-read the file
	// directly (e.g., diagnostics, "atmos auth whoami --verbose").
	IdentityFilePath string `json:"identity_file_path,omitempty"`

	// IsBot indicates whether these credentials were produced by a teleport/bot
	// identity (true) or a teleport/user identity (false). Used by the
	// integration layer and whoami to differentiate ergonomics.
	IsBot bool `json:"is_bot,omitempty"`
}

// IsExpired returns true if the credentials are expired.
// Returns false if ValidUntil is the zero value (treated as "unknown / no expiry").
// This implements the ICredentials interface.
func (c *TeleportCredentials) IsExpired() bool {
	if c == nil {
		return true
	}
	if c.ValidUntil.IsZero() {
		return false
	}
	return !time.Now().Before(c.ValidUntil)
}

// GetExpiration implements ICredentials.
// Returns nil, nil when the credentials carry no expiration information.
func (c *TeleportCredentials) GetExpiration() (*time.Time, error) {
	if c == nil || c.ValidUntil.IsZero() {
		return nil, nil
	}
	localTime := c.ValidUntil.Local()
	return &localTime, nil
}

// BuildWhoamiInfo implements ICredentials.
//
// Surfaces Teleport-specific context for `atmos auth whoami`:
//   - Account → Teleport cluster name (closest analog to an AWS account or GCP project)
//   - Principal → username (bot-prefixed for bots)
//   - Expiration → cert expiry
func (c *TeleportCredentials) BuildWhoamiInfo(info *WhoamiInfo) {
	if info == nil || c == nil {
		return
	}
	if c.ClusterName != "" {
		info.Account = c.ClusterName
	}
	if c.Username != "" {
		info.Principal = c.Username
	}
	if t, _ := c.GetExpiration(); t != nil {
		info.Expiration = t
	}
}

// Validate implements ICredentials.
//
// Phase 1 returns ErrNotImplemented. Phase 2 will dial the Teleport proxy and
// call Ping() to verify the cert is accepted by the cluster.
func (c *TeleportCredentials) Validate(_ context.Context) (*ValidationInfo, error) {
	return nil, fmt.Errorf("%w: teleport credential validation not yet implemented", errUtils.ErrNotImplemented)
}
