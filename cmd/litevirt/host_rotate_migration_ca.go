package main

import (
	"context"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

// newHostRotateMigrationCACmd replaces the migration CA on every host, from
// the machine that holds it. See docs/design/migration-ca-rotation.md.
func newHostRotateMigrationCACmd() *cobra.Command {
	var sshUser string
	var opts cli.RotateMigrationCAOptions
	cmd := &cobra.Command{
		Use:   "rotate-migration-ca",
		Short: "Replace the CA that storage-migration credentials are issued from",
		Long: `Replace the migration CA on every host, from the machine that holds it.

By default it runs three phases, checking every host's daemon between them:
  1. trust-both  every host trusts the old CA and the new one
  2. reissue     every host gets a certificate from the new CA
  3. drop-old    every host trusts the new CA alone; this machine retires the old one
Storage migrations keep working throughout. No restart is needed.

Before it starts, it asks every host's daemon for its migration credentials and
refuses, changing nothing, unless each holds a complete, valid set its daemon
can install, trusting this machine's migration CA.

If it stops (a host is unreachable), progress is saved; run it again to continue.

  --no-overlap  For a compromised CA key. One pass straight to the new CA alone:
                migrations between updated and not-yet-updated hosts are refused
                until every host is done. Never sent in plaintext unless that
                host set migration.allow_unencrypted_storage.
  --force       Leave unreachable hosts behind. They keep the old CA's
                credentials, so migrations with them are refused, until you run
                'lv host install-migration-tls --reissue' once they are back.

Check the result with 'lv doctor migration-tls'.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				hosts, closeAll, err := cli.SSHMigrationTLSHostsLenient(ctx, c, sshUser)
				if err != nil {
					return err
				}
				defer closeAll()
				status := func(ctx context.Context) ([]*pb.MigrationTLSHostStatus, error) {
					resp, err := c.MigrationTLSStatus(ctx, &pb.MigrationTLSStatusRequest{})
					return resp.GetHosts(), err
				}
				return cli.RotateMigrationCA(ctx, cli.PKIDir(), hosts, status, opts, cmd.OutOrStdout())
			})
		},
	}
	cmd.Flags().StringVar(&sshUser, "ssh-user", "root", "user to SSH to each host as")
	cmd.Flags().BoolVar(&opts.NoOverlap, "no-overlap", false, "cut over in one pass, without a window where both CAs are trusted (use when the CA key is compromised)")
	cmd.Flags().BoolVar(&opts.Force, "force", false, "leave unreachable hosts behind instead of stopping")
	return cmd
}
