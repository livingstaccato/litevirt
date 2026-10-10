package main

import (
	"github.com/spf13/cobra"

	"github.com/litevirt/litevirt/internal/systemdunit"
)

// newNICTableOwnerCmd is the hidden command the systemd unit's ExecStartPre
// asks before starting the daemon: exit 0 says "this binary renders the
// per-NIC firewall table, keep it". A binary rolled back to a release without
// the command fails it, and the unit deletes the stale table
// (systemdunit.NICTableCleanup).
func newNICTableOwnerCmd() *cobra.Command {
	return &cobra.Command{
		Use:    systemdunit.NICTableOwnerCommand,
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE:   func(*cobra.Command, []string) error { return nil },
	}
}
