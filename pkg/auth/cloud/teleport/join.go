package teleport

import (
	"context"
	"fmt"

	errUtils "github.com/cloudposse/atmos/errors"
	"github.com/cloudposse/atmos/pkg/auth/types"
	"github.com/cloudposse/atmos/pkg/perf"
)

// JoinRequest carries the inputs required to register a teleport/bot identity
// via the join service. The JoinMethod field selects the specific handshake.
type JoinRequest struct {
	// ProxyAddress is the Teleport proxy host:port (required).
	ProxyAddress string

	// CACertPEM is an optional PEM-encoded CA cert for TLS verification when
	// the proxy is fronted by a private CA.
	CACertPEM string

	// Insecure disables TLS verification (development only).
	Insecure bool

	// BotName is the Teleport bot name (required).
	BotName string

	// JoinToken is the Teleport join token name (required).
	JoinToken string

	// JoinMethod is "github" or "iam" in v1.
	JoinMethod string

	// TTL is the requested certificate lifetime.
	TTL string

	// Roles is the optional role subset to request.
	Roles []string

	// GitHubAudience is the optional ID-token audience override for the
	// "github" join method.
	GitHubAudience string

	// AWSRegion is the STS region for the "iam" join method (default us-east-1).
	AWSRegion string

	// AWSSTSEndpoint optionally overrides the STS endpoint for the "iam"
	// join method.
	AWSSTSEndpoint string

	// AWSCredentials is the upstream AWS credentials (e.g., AWSCredentials)
	// to use when signing the STS GetCallerIdentity challenge. Required for
	// the "iam" join method.
	//
	// We accept types.ICredentials here to avoid a hard dep on AWS-specific
	// types; the iam join implementation will type-assert to *types.AWSCredentials.
	AWSCredentials types.ICredentials
}

// Join performs a tbot-equivalent join handshake against the Teleport cluster
// and returns the issued TeleportCredentials. The returned credentials are
// suitable for both immediate use and persistence as an identity file via
// WriteIdentityFile.
//
// The req argument is passed by pointer because JoinRequest is a relatively
// large struct (including AWS credentials and join-method-specific options);
// avoiding the copy keeps hot paths cheap.
//
// Phase 1: stub. Phase 4 will implement github + iam join methods using
// github.com/gravitational/teleport/api/client.JoinServiceClient.
func Join(_ context.Context, req *JoinRequest) (*types.TeleportCredentials, error) {
	defer perf.Track(nil, "teleport.Join")()

	if req == nil {
		return nil, fmt.Errorf("%w: join request is nil", errUtils.ErrTeleportInvalidConfig)
	}

	switch req.JoinMethod {
	case "github", "iam":
		// Supported; full implementation lands in phase 4.
	case "":
		return nil, fmt.Errorf("%w: join_method is required", errUtils.ErrTeleportInvalidConfig)
	default:
		return nil, fmt.Errorf("%w: %q", errUtils.ErrTeleportUnsupportedJoinMethod, req.JoinMethod)
	}

	return nil, fmt.Errorf("%w: teleport.Join not yet implemented (phase 4)", errUtils.ErrNotImplemented)
}
