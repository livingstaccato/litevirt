package main

import (
	"context"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

// newHostInstallMigrationTLSCmd provisions migration-TLS credentials on an
// existing cluster. A cluster founded or grown by this build already has them:
// `lv host init` and `lv host add` issue them.
func newHostInstallMigrationTLSCmd() *cobra.Command {
	var sshUser string
	var reissue bool
	cmd := &cobra.Command{
		Use:   "install-migration-tls",
		Short: "Issue every host the credentials that encrypt storage migrations",
		Long: `Issue and install migration-TLS credentials on every host, minting the migration CA first if this machine has none.

A migration that copies disks (lv migrate --with-storage) cannot be tunnelled
through libvirt's TLS connection; QEMU opens its own migration stream and disk
copy to the target. Those are encrypted only when BOTH hosts hold migration
credentials. They come from a separate migration CA, never the cluster CA,
because QEMU reads them inside a process a guest could escape into.

Clusters created or grown by 'lv host init' / 'lv host add' have them from the
start. Run this on an existing cluster, from the machine that holds the cluster
CA. Each host's daemon installs its credentials for QEMU before its next storage
migration; no restart is needed. Hosts that already have credentials are left
alone unless --reissue.

  lv host install-migration-tls
  lv host install-migration-tls --reissue --ssh-user admin`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				hosts, closeAll, err := cli.SSHMigrationTLSHosts(ctx, c, sshUser)
				if err != nil {
					return err
				}
				defer closeAll()
				return cli.InstallMigrationTLS(ctx, cli.PKIDir(), hosts, reissue, cmd.OutOrStdout())
			})
		},
	}
	cmd.Flags().StringVar(&sshUser, "ssh-user", "root", "user to SSH to each host as")
	cmd.Flags().BoolVar(&reissue, "reissue", false, "replace credentials on hosts that already have them")
	return cmd
}
