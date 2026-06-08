package teleport

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTeleportCommandProvider(t *testing.T) {
	p := &TeleportCommandProvider{}

	cmd := p.GetCommand()
	require.NotNil(t, cmd)
	assert.Equal(t, "teleport", cmd.Use)
	assert.Equal(t, "teleport", p.GetName())
	assert.Equal(t, "Cloud Integration", p.GetGroup())
	assert.Nil(t, p.GetAliases())
	assert.Nil(t, p.GetFlagsBuilder())
	assert.Nil(t, p.GetPositionalArgsBuilder())
	assert.Nil(t, p.GetCompatibilityFlags())
	assert.False(t, p.IsExperimental())

	// The kube subcommand must be attached.
	kubeCmd, _, err := cmd.Find([]string{"kube"})
	require.NoError(t, err)
	assert.Equal(t, "kube", kubeCmd.Name())

	// The kube token subcommand must be reachable.
	tokenCmd, _, err := cmd.Find([]string{"kube", "token"})
	require.NoError(t, err)
	assert.Equal(t, "token", tokenCmd.Name())
}
