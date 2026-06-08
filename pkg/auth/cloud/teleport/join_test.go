package teleport

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	errUtils "github.com/cloudposse/atmos/errors"
)

func TestJoin_NilRequest(t *testing.T) {
	_, err := Join(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrTeleportInvalidConfig))
}

func TestJoin_MissingJoinMethod(t *testing.T) {
	_, err := Join(context.Background(), &JoinRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrTeleportInvalidConfig))
}

func TestJoin_UnsupportedJoinMethod(t *testing.T) {
	_, err := Join(context.Background(), &JoinRequest{JoinMethod: "azure"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUtils.ErrTeleportUnsupportedJoinMethod))
}

func TestJoin_SupportedMethodsReturnNotImplemented(t *testing.T) {
	// Phase 1: supported method gates pass but the implementation is a stub.
	for _, method := range []string{"github", "iam"} {
		method := method
		t.Run(method, func(t *testing.T) {
			_, err := Join(context.Background(), &JoinRequest{JoinMethod: method})
			require.Error(t, err)
			assert.True(t, errors.Is(err, errUtils.ErrNotImplemented),
				"phase 1 stub should return ErrNotImplemented; got: %v", err)
		})
	}
}
