package main

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

// newHostInstallFenceSSHCmd gives an existing cluster's hosts the managed
// fence SSH sshd drop-in. A host `lv host init` or `lv host add` provisioned
// has it already.
func newHostInstallFenceSSHCmd() *cobra.Command {
	var sshUser string
	var only []string
	var remove bool
	var wait time.Duration
	cmd := &cobra.Command{
		Use:   "install-fence-ssh",
		Short: "Give every host's sshd the managed fence SSH drop-in",
		Long: `Have every host's sshd read /etc/litevirt/ssh/authorized_keys for root, so peers can
fence it over the managed fence key (docs/migration-failover.md "Managed fence SSH").

Each host's daemon publishes its own fence key and sshd host keys once the cluster
runs release_2026_12_v1, and renders every peer's key into that file: accepted only
from the peer's certificate address and only to run a forced command that powers
this host off when the request names it. This command writes the sshd drop-in
(/etc/ssh/sshd_config.d/60-litevirt-fence.conf) that 'lv host init' and
'lv host add' write for a new host: it keeps the list sshd had for root, is
evaluated for a fence from every other host's address, is validated with sshd -t
and rolled back on a refusal, and never overrides PermitRootLogin no.

It then waits until every host reports that it accepts the managed key. Fences in
the default mode (enforcement.fence_ssh: auto) then take the managed path toward
each host that does. Check the probe matrix with 'lv doctor fence', then set
enforcement.fence_ssh: managed on each host. Hand-made fence keys and root's ssh
config are left alone; a managed fence never reads them.

  lv host install-fence-ssh
  lv host install-fence-ssh --host node-3 --ssh-user admin
  lv host install-fence-ssh --remove`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				hosts, all, closeAll, err := cli.SSHFenceSSHHosts(ctx, c, sshUser, only)
				if err != nil {
					return err
				}
				defer closeAll()
				return cli.InstallFenceSSH(ctx, c, hosts, all, cli.FenceSSHOptions{
					Out: cmd.OutOrStdout(), Remove: remove, Wait: wait})
			})
		},
	}
	cmd.Flags().StringVar(&sshUser, "ssh-user", "root", "user to SSH to each host as")
	cmd.Flags().StringSliceVar(&only, "host", nil, "provision only these hosts (repeatable); each is still evaluated for a fence from every host")
	cmd.Flags().BoolVar(&remove, "remove", false, "remove the drop-in instead (the daemon then reports the host as not accepting)")
	cmd.Flags().DurationVar(&wait, "wait", 3*time.Minute, "how long to wait for every host to report that it accepts the managed key")
	return cmd
}
