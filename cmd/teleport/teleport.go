package teleport

import (
	"github.com/spf13/cobra"

	"github.com/cloudposse/atmos/cmd/internal"
	"github.com/cloudposse/atmos/cmd/teleport/kube"
	"github.com/cloudposse/atmos/pkg/flags"
	"github.com/cloudposse/atmos/pkg/flags/compat"
)

// teleportCmd groups Teleport-related commands.
var teleportCmd = &cobra.Command{
	Use:                "teleport",
	Short:              "Run Teleport commands for accessing infrastructure through Teleport",
	Long:               `Commands for working with Teleport-mediated access, such as generating Kubernetes credentials for kubectl via the Teleport proxy.`,
	FParseErrWhitelist: struct{ UnknownFlags bool }{UnknownFlags: false},
	Args:               cobra.NoArgs,
}

func init() {
	// Add the kube subcommand group.
	teleportCmd.AddCommand(kube.KubeCmd)

	// Register this command with the registry.
	internal.Register(&TeleportCommandProvider{})
}

// TeleportCommandProvider implements the CommandProvider interface.
type TeleportCommandProvider struct{}

// GetCommand returns the teleport command.
func (p *TeleportCommandProvider) GetCommand() *cobra.Command {
	return teleportCmd
}

// GetName returns the command name.
func (p *TeleportCommandProvider) GetName() string {
	return "teleport"
}

// GetGroup returns the command group for help organization.
func (p *TeleportCommandProvider) GetGroup() string {
	return "Cloud Integration"
}

// GetAliases returns command aliases.
func (p *TeleportCommandProvider) GetAliases() []internal.CommandAlias {
	return nil
}

// GetFlagsBuilder returns the flags builder for this command.
func (p *TeleportCommandProvider) GetFlagsBuilder() flags.Builder {
	return nil
}

// GetPositionalArgsBuilder returns the positional args builder for this command.
func (p *TeleportCommandProvider) GetPositionalArgsBuilder() *flags.PositionalArgsBuilder {
	return nil
}

// GetCompatibilityFlags returns compatibility flags for this command.
func (p *TeleportCommandProvider) GetCompatibilityFlags() map[string]compat.CompatibilityFlag {
	return nil
}

// IsExperimental returns whether this command is experimental.
func (p *TeleportCommandProvider) IsExperimental() bool {
	return false
}
