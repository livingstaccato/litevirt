package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/ssh"
)

func newHostCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "host",
		Short: "Manage cluster hosts",
	}

	cmd.AddCommand(
		newHostInitCmd(),
		newHostAddCmd(),
		newHostLsCmd(),
		newHostInspectCmd(),
		newHostDrainCmd(),
		newHostShutdownWorkloadsCmd(),
		newHostUndrainCmd(),
		newHostFailbackCmd(),
		newHostRmCmd(),
		newHostLabelCmd(),
		newHostFenceCmd(),
		newHostFenceConfirmCmd(),
		newHostConfigCmd(),
		newHostRescanCmd(),
		newHostDevicesCmd(),
		newHostSupersededDisksCmd(),
		newHostKeptDisksCmd(),
		newHostLUNHoldsCmd(),
		newHostLUNHoldCmd(),
		newHostUpgradeCmd(),
		newHostPreflightUpgradeCmd(),
		newHostStatsCmd(),
		newHostCephCmd(),
		newHostRotateAuditKeyCmd(),
		newHostInstallGossipKeyCmd(),
		newHostInstallFenceSSHCmd(),
		newHostInstallMigrationTLSCmd(),
		newHostRotateMigrationCACmd(),
		newHostRotateGossipKeyCmd(),
		newHostRetireAuditKeyCmd(),
		newHostPublishCRLCmd(),
		newHostRenewCertCmd(),
		newHostUICertCmd(),
		newHostRevokeCertCmd(),
		newHostNetworkCmd(),
		newHostIsolateCmd(),
		newHostReseedCmd(),
	)

	return cmd
}

func newHostInitCmd() *cobra.Command {
	var name string
	var local bool
	var address string
	var force bool
	var noFenceSSH bool
	cmd := &cobra.Command{
		Use:   "init [user@host]",
		Short: "Bootstrap first cluster host",
		Long: `Bootstrap the first host in a litevirt cluster.

For remote hosts:   lv host init root@10.0.50.10 --name host-a
For localhost:      lv host init --local --name node-1 --address 10.77.0.11

With --local, --address is what peers will dial. It goes into the host certificate,
so leaving it wrong means every peer handshake fails with "certificate is valid for
127.0.0.1, not <addr>". It defaults to the default-route source IP, which is the
wrong interface on a multi-homed host — pass the same value you will put in
advertise_address.

init refuses a target that is already a cluster member, because it rewrites the
whole config.yaml and would reset join_peers to []. Use "lv host add" to add a
node to an existing cluster; --force re-initialises a member anyway. A founder's
own join_peers is empty, so init also asks the cluster this CLI is configured for,
and refuses an address that cluster lists beside other hosts.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli.SetFenceSSHDropIn(!noFenceSSH)
			if local {
				return cli.HostInitLocal(cmd.Context(), name, address, force)
			}
			if len(args) == 0 {
				return fmt.Errorf("SSH target required (or use --local for standalone setup)")
			}
			// A founder's own join_peers is empty, so the target-side check
			// cannot tell it from a half-finished first node; the cluster can.
			// One look at the ssh config serves the check and the init.
			if err := pki.ValidateHostName(name); err != nil {
				return err
			}
			rt, err := ssh.Resolve(args[0])
			if err != nil {
				return err
			}
			if err := cli.RefuseInitOfAClusterMemberResolved(cmd.Context(), args[0], rt, force); err != nil {
				return err
			}
			return cli.HostInitResolved(cmd.Context(), args[0], rt, name, force)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Host name (required)")
	cmd.Flags().BoolVar(&local, "local", false, "Initialize on localhost (no SSH)")
	cmd.Flags().StringVar(&address, "address", "",
		"with --local, the IP peers will dial this host on; it goes in the host "+
			"certificate. Defaults to the default-route source IP, which is wrong on a "+
			"multi-homed host — use the same value you will set as advertise_address")
	cmd.Flags().BoolVar(&force, "force", false,
		"re-initialize a host that is already a cluster member, overwriting its "+
			"config.yaml and resetting join_peers to []")
	cmd.Flags().BoolVar(&noFenceSSH, "no-fence-ssh", false, noFenceSSHUsage)
	cmd.MarkFlagRequired("name")
	return cmd
}

// noFenceSSHUsage is --no-fence-ssh on `lv host init` and `lv host add`.
const noFenceSSHUsage = "do not add the managed fence SSH drop-in to sshd (" +
	"/etc/ssh/sshd_config.d/60-litevirt-fence.conf), for a site whose sshd configuration is managed " +
	"elsewhere; add /etc/litevirt/ssh/authorized_keys to root's AuthorizedKeysFile there instead"

func newHostAddCmd() *cobra.Command {
	var name string
	var noFenceSSH bool
	cmd := &cobra.Command{
		Use:   "add <user@host>",
		Short: "Add host to existing cluster",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Query existing cluster hosts to get gossip peer addresses. This was
			// best-effort and silent, which meant an unreachable daemon produced an
			// empty peer list and a node provisioned with nowhere to join. HostAdd
			// refuses an empty list now, so the only job here is to say WHY it is
			// empty rather than leaving the operator to guess.
			var peerAddrs []string
			c, closer, err := cli.Connect(cmd.Context())
			if err != nil {
				return fmt.Errorf("cannot reach a cluster daemon to read the existing hosts, "+
					"whose addresses become %s's gossip peers: %w", name, err)
			}
			resp, lerr := c.ListHosts(cmd.Context(), nil)
			if lerr != nil {
				closer()
				return fmt.Errorf("cannot list the existing cluster hosts, whose addresses "+
					"become %s's gossip peers: %w", name, lerr)
			}
			for _, h := range resp.Hosts {
				if h.Address == "" {
					continue
				}
				// hosts.address is replicated and peer-writable, and this value
				// lands in the new node's join_peers AND in the remote setup
				// command line. A row that is not a bare IPv4 literal cannot be
				// a real gossip peer, so skipping it loses nothing and keeps a
				// poisoned row from reaching either consumer.
				if !corrosion.ValidHostAddress(h.Address) {
					fmt.Fprintf(os.Stderr, "warning: skipping peer %q: address %q is not a bare IPv4 literal\n",
						h.Name, h.Address)
					continue
				}
				// JoinHostPort, not Sprintf("%s:%d"): h.Address is a bare host
				// from the hosts table and lands in the new node's join_peers.
				peerAddrs = append(peerAddrs, net.JoinHostPort(h.Address, "7946"))
			}
			defer closer()
			cli.SetFenceSSHDropIn(!noFenceSSH)
			return cli.HostAdd(cmd.Context(), c, args[0], name, peerAddrs)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Host name (required)")
	cmd.Flags().BoolVar(&noFenceSSH, "no-fence-ssh", false, noFenceSSHUsage)
	cmd.MarkFlagRequired("name")
	return cmd
}

func newHostLsCmd() *cobra.Command {
	var namesOnly bool
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List cluster hosts",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListHosts(ctx, nil)
				if err != nil {
					return fmt.Errorf("list hosts: %w", err)
				}

				// --names prints one bare host name per line (no header), for
				// shell loops like `for h in $(lv host ls --names); do …`.
				if namesOnly {
					for _, h := range resp.Hosts {
						fmt.Println(h.Name)
					}
					return nil
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "NAME\tADDRESS\tSTATE\tCPU\tMEMORY\tVMs\tVERSION\tUPDATES\n")
				for _, h := range resp.Hosts {
					ver := h.Version
					if ver == "" {
						ver = "-"
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%d/%d\t%d/%d MiB\t%d\t%s\t%s\n",
						h.Name, h.Address, h.State,
						h.CpuUsed, h.CpuTotal,
						h.MemUsedMib, h.MemTotalMib,
						h.VmCount, ver, cli.HostUpdatesSummary(h.Labels),
					)
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().BoolVar(&namesOnly, "names", false, "print only host names, one per line (for scripting)")
	return cmd
}

func newHostInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <host>",
		Short: "Show host details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				return cli.PrintHostInspect(ctx, c, args[0])
			})
		},
	}
}

func newHostDrainCmd() *cobra.Command {
	var parallel int
	cmd := &cobra.Command{
		Use:   "drain <host>",
		Short: "Migrate all VMs off a host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.DrainHost(ctx, &pb.DrainHostRequest{
					Name:     args[0],
					Parallel: int32(parallel),
				})
				if err != nil {
					return fmt.Errorf("drain: %w", err)
				}

				for {
					p, err := stream.Recv()
					if err == io.EOF {
						break
					}
					if err != nil {
						// The drain ended without moving everything: the
						// server's "drain incomplete" names how many VMs
						// remain, and the lines above say why each one did.
						return fmt.Errorf("drain: %w", err)
					}
					if p.Error != "" {
						fmt.Fprintln(os.Stderr, drainProgressLine(p))
					} else {
						fmt.Println(drainProgressLine(p))
					}
				}

				fmt.Printf("Host %s drained.\n", args[0])
				return nil
			})
		},
	}
	cmd.Flags().IntVar(&parallel, "parallel", 2, "Number of parallel migrations")
	return cmd
}

// drainProgressLine is one VM's line of `lv host drain` output. The strategy
// is shown only for a VM the drain moved or tried to move: a frame for one it
// did not (MIGRATE_NONE) names no strategy, since none was used.
func drainProgressLine(p *pb.DrainProgress) string {
	strategy := ""
	if p.Strategy != pb.MigrateStrategy_MIGRATE_NONE {
		strategy = " [" + p.Strategy.String() + "]"
	}
	if p.Error != "" {
		return fmt.Sprintf("  %s → %s%s ERROR: %s", p.VmName, p.TargetHost, strategy, p.Error)
	}
	return fmt.Sprintf("  %s → %s%s %s", p.VmName, p.TargetHost, strategy, p.Status)
}

func newHostShutdownWorkloadsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shutdown-workloads <host>",
		Short: "Gracefully stop a host's VMs in reverse startup order (honors stop-delay)",
		Long: `Stop every running VM on a host in REVERSE startup order (highest
startup_order first), pausing each VM's stop_delay_sec before the next.

This is an explicit operator action for ordered host shutdown — it is NOT run on
a normal daemon restart/upgrade (those keep VMs running). Each VM's ACPI
stop_timeout_sec is honored.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.ShutdownHostWorkloads(ctx, &pb.ShutdownHostWorkloadsRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("shutdown-workloads: %w", err)
				}
				for {
					p, err := stream.Recv()
					if err != nil {
						break
					}
					if p.Error != "" {
						fmt.Fprintf(os.Stderr, "  %s [%s] ERROR: %s\n", p.VmName, p.Status, p.Error)
					} else {
						fmt.Printf("  %s [%s]\n", p.VmName, p.Status)
					}
				}
				fmt.Printf("Host %s workloads shut down.\n", args[0])
				return nil
			})
		},
	}
	return cmd
}

func newHostUndrainCmd() *cobra.Command {
	var failback bool
	cmd := &cobra.Command{
		Use:   "undrain <host>",
		Short: "Return host to active scheduling",
		Long: `Return a draining, maintenance, fenced or offline host to active scheduling.

It records the host active whatever it is recorded as now, except a host
recorded upgrading (a restart): that one only if its daemon answers a Ping,
and otherwise the undrain is refused, since the host turns active by itself
once its daemon serves. For a fenced or
offline host that ends the fence: the failover leader no longer resumes a
recovery from it, and the host may run workloads again. Confirm it should
first. A host whose own boot kept its fence (condition boot_kept_fence) needs
this to return.

By itself this moves nothing back. VMs a drain moved away return when they opted
in (placement.failback in compose) or the cluster policy is on (lv cluster
failback on): the daemon then live-migrates them back in the background, one at
a time, and the reply says that it started and on which daemon. That run ends
if the daemon restarts; lv host failback <host> finishes what is left.

--failback waits for that run and prints each VM's result. It is the same run,
not a second one, so it moves only the VMs that opted in; to move the rest,
use lv host failback <host> --all.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				h, err := c.UndrainHost(ctx, &pb.UndrainHostRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("undrain: %w", err)
				}
				fmt.Printf("Host %s is now %s.\n", h.Name, h.State)
				if h.FailbackNote != "" {
					fmt.Println(h.FailbackNote)
				}
				if failback && h.FailbackStarted {
					return streamFailback(ctx, c, &pb.FailbackHostRequest{Name: args[0], Follow: true}, args[0])
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&failback, "failback", false, "Wait for the failback this undrain started and print each VM's result")
	return cmd
}

func newHostFailbackCmd() *cobra.Command {
	var all, dryRun, follow bool
	cmd := &cobra.Command{
		Use:   "failback <host>",
		Short: "Move VMs a drain moved away back to the host, by live migration",
		Long: `Move the VMs a drain of <host> moved away back to it, by live migration, one at
a time with a pause between moves.

Only a VM the drain moved, and that nothing has moved since, returns: one an
operator migrated by hand, that failed over, or that a later drain moved again
stays where it is, and the output says so. The VM's owner re-checks that, under
the VM's lock, before each move. Each move is an ordinary live migration, after
checking the host as a placement target (capacity, labels, devices,
anti-affinity). A VM on host-local storage, or stopped, is reported and left;
move it with lv migrate.

Without --all only VMs that opted in return: placement.failback in compose, or
the cluster policy (lv cluster failback on). --all moves every VM the drain
moved. --dry-run shows what would move and why each other VM stays. --follow
attaches to the run an undrain started on this daemon instead of starting one.

The host must be active (lv host undrain first). Failback also needs every host
to run a release that tracks where drains put VMs: it is the drain_failback
feature of the release token. Until that token has latched, drains record
nothing and failback refuses ("the cluster upgrade must finish first ...
failback waits for the upgrade"); lv cluster upgrade-status shows the token.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				return streamFailback(ctx, c, &pb.FailbackHostRequest{Name: args[0], All: all, DryRun: dryRun, Follow: follow}, args[0])
			})
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "Move back every VM the drain moved, not only those that opted in")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Report what would move; move nothing")
	cmd.Flags().BoolVar(&follow, "follow", false, "Attach to the failback an undrain started on this daemon")
	return cmd
}

// streamFailback streams one failback and prints each VM's result. It returns
// an error when any VM failed, so a script sees it.
func streamFailback(ctx context.Context, c pb.LiteVirtClient, req *pb.FailbackHostRequest, host string) error {
	stream, err := c.FailbackHost(ctx, req)
	if err != nil {
		return fmt.Errorf("failback: %w", err)
	}
	failed, n := 0, 0
	for {
		p, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failback: %w", err)
		}
		n++
		fmt.Println(failbackLine(p, host))
		if p.Status == "failed" {
			failed++
		}
	}
	if n == 0 {
		fmt.Printf("No VM was moved away from %s by a drain that is waiting to return.\n", host)
	}
	if failed > 0 {
		return fmt.Errorf("failback: %d VM(s) did not move back", failed)
	}
	return nil
}

// failbackLine is one VM's line of failback output.
func failbackLine(p *pb.FailbackProgress, host string) string {
	line := fmt.Sprintf("  %s %s → %s [%s]", p.VmName, p.FromHost, host, p.Status)
	if p.Reason != "" {
		line += ": " + p.Reason
	}
	return line
}

// newHostPublishCRLCmd is the direct recovery path when a CRL was minted locally
// but the cluster was unreachable before host removal. HostRemove now preserves
// the host row until this publication succeeds, so the command is also safe to
// retry from the beginning afterwards.
func newHostPublishCRLCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "publish-crl",
		Short: "Publish this machine's certificate revocation list to the cluster",
		Long: `Hand the local crl.pem to the cluster, which replicates it to every node.

` + "`lv host rm`" + ` does this automatically before it removes the host. Run this
by hand when a CRL was minted locally but that publication step failed, then retry
the removal.

Safe to repeat: a CRL the cluster already holds is stored under its own contents,
so republishing it changes nothing. The daemon verifies it against the cluster CA
before storing it, and enforces its serials together with every other verified CRL
the cluster has published.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				return cli.PublishClusterCRL(ctx, c)
			})
		},
	}
}

func newHostRmCmd() *cobra.Command {
	var force, dead, dryRun bool
	var serial, address string
	cmd := &cobra.Command{
		Use:   "rm <host>",
		Short: "Remove host from cluster",
		Long: `Removes a host: revokes its certificate, publishes the CRL, and deletes its row.

--serial removes one admission, selected by its certificate (any spelling of
the number) rather than by the row the name has now. When the row of <host>
holds that certificate it is the removal above, refused if the row changes
first. Otherwise no row is touched (the admission's row is gone, or <host> is
now another admission), and --address is required: the daemon runs a
removal's checks and a pull and confirms no live row holds the serial; the
machine at --address must hold a trace of it for <host>, no add may hold the
machine, and a machine serving it may be a completed add (only its staged
files and an earlier run's claim go, nothing is revoked). Under the machine's add lock it is claimed
for that serial alone, which keeps that admission's adds out; then the serial
is revoked, the CRL published, its adds' staged files and records removed,
and the claim removed. The machine's install record is never written, and
only that serial's own add's claim is taken off it; another admission's
record and the installed identity stay. A step that fails names this
same command, which finishes it. 'lv host add' names this command when it
refuses a machine it cannot prove is its own to install on.

--dead removes a host that is fenced proof-grade and gone for good, so the
recoveries decided for it can move on (recovery claims, docs/design/recovery-claims.md
§3.12). It refuses unless the host has an IPMI or Redfish power-off or an operator
'lv host fence-confirm' recorded; removes it from the voter set first if it is a
member; revokes and publishes as 'lv host rm' does; and reports how many
stranded recoveries will retry. Its workloads need no --force: they are the
stranded ones. It also refuses while a Secure Boot / vTPM VM recorded on the
host has a live firmware move to it that is not settled: settle it with
'lv doctor firmware-move <vm>', or add --force to remove the host anyway (the
source's copy stays for the doctor). --dry-run runs every check and prints the
plan without changing anything.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if dryRun && !dead {
				return fmt.Errorf("--dry-run applies to --dead")
			}
			if dead && serial != "" {
				return fmt.Errorf("--serial does not apply to --dead")
			}
			if address != "" && serial == "" {
				return fmt.Errorf("--address applies to --serial")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if dead {
					return cli.HostRemoveDeadForce(ctx, c, args[0], dryRun, force)
				}
				if serial != "" {
					return cli.HostRemoveAdmission(ctx, c, args[0], serial, address, force)
				}
				return cli.HostRemove(ctx, c, args[0], force)
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Force removal even if VMs exist; with --dead, even while a firmware VM's live move to it is not settled")
	cmd.Flags().BoolVar(&dead, "dead", false, "Remove a host that is fenced proof-grade and gone for good, unblocking recoveries decided for it")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "With --dead: run every check and print the plan, changing nothing")
	cmd.Flags().StringVar(&serial, "serial", "", "Remove only the admission of this certificate serial (hex)")
	cmd.Flags().StringVar(&address, "address", "", "With --serial: the machine the admission's add was run against (IPv4)")
	return cmd
}

func newHostLabelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "label",
		Short: "Manage host labels",
	}
	cmd.AddCommand(
		newHostLabelSetCmd(),
		newHostLabelRmCmd(),
		newHostLabelLsCmd(),
	)
	return cmd
}

func newHostLabelSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <host> <key=value>...",
		Short: "Set labels on a host",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				labels := make(map[string]string)
				for _, kv := range args[1:] {
					parts := splitKeyValue(kv)
					if parts == nil {
						return fmt.Errorf("invalid label %q (expected key=value)", kv)
					}
					labels[parts[0]] = parts[1]
				}

				h, err := c.SetHostLabels(ctx, &pb.SetHostLabelsRequest{
					Name:   args[0],
					Labels: labels,
				})
				if err != nil {
					return fmt.Errorf("set labels: %w", err)
				}
				fmt.Printf("Host %s labels updated.\n", h.Name)
				printLabels(h.Labels)
				return nil
			})
		},
	}
}

func newHostLabelRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <host> <key>...",
		Short: "Remove labels from a host",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				h, err := c.SetHostLabels(ctx, &pb.SetHostLabelsRequest{
					Name:   args[0],
					Remove: args[1:],
				})
				if err != nil {
					return fmt.Errorf("remove labels: %w", err)
				}
				fmt.Printf("Host %s labels updated.\n", h.Name)
				printLabels(h.Labels)
				return nil
			})
		},
	}
}

func newHostLabelLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls <host>",
		Short: "List labels on a host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				h, err := c.InspectHost(ctx, &pb.InspectHostRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("inspect host: %w", err)
				}
				printLabels(h.Labels)
				return nil
			})
		},
	}
}

func splitKeyValue(s string) []string {
	for i, c := range s {
		if c == '=' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return nil
}

func printLabels(labels map[string]string) {
	if len(labels) == 0 {
		fmt.Println("(no labels)")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "KEY\tVALUE")
	for k, v := range labels {
		fmt.Fprintf(w, "%s\t%s\n", k, v)
	}
	w.Flush()
}

func newHostFenceCmd() *cobra.Command {
	var confirmed bool
	cmd := &cobra.Command{
		Use:   "fence <host>",
		Short: "Manually fence a host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				result, err := c.FenceHost(ctx, &pb.FenceHostRequest{
					Name:      args[0],
					Confirmed: confirmed,
				})
				if err != nil {
					return fmt.Errorf("fence: %w", err)
				}
				// assurance is derived here rather than sent: result says
				// "fenced" for an IPMI power-off observed off and for an SSH
				// poweroff nobody checked, and the operator running this is the
				// person who most needs to know which one they just got.
				fmt.Printf("Host %s: method=%s result=%s assurance=%s detail=%s\n",
					result.HostName, result.Method, result.Result,
					corrosion.FenceAssurance(result.Method, result.Result), result.Detail)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&confirmed, "confirmed", false, "Confirm fencing")
	return cmd
}

// newHostFenceConfirmCmd records that the operator has manually powered off
// a host whose FenceStrategy is "manual". Without this confirmation, the
// failover coordinator's split-brain guard refuses to reschedule the host's
// VMs.
func newHostFenceConfirmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fence-confirm <host>",
		Short: "Confirm a manual fence so VMs may be rescheduled",
		Long: `Record that an operator has powered the host off externally.

Use this after FenceStrategy=manual hosts that the coordinator has flagged as
needing manual intervention. Without this confirmation the coordinator will
NOT reschedule the host's VMs, to prevent split-brain on shared storage.

The host MUST be physically off (or otherwise demonstrably not running its
workloads) before running this command. It is refused while the host still
answers: another host's health verdict about it is healthy or unready and under
30 seconds old, or the node serving the request reaches it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				result, err := c.FenceHost(ctx, &pb.FenceHostRequest{
					Name:              args[0],
					Confirmed:         true,
					ConfirmManualOnly: true,
				})
				if err != nil {
					return fmt.Errorf("fence-confirm: %w", err)
				}
				fmt.Printf("Host %s: method=%s result=%s detail=%s\n",
					result.HostName, result.Method, result.Result, result.Detail)
				return nil
			})
		},
	}
}

func newHostConfigCmd() *cobra.Command {
	var fenceStrategy, ipmiAddr, ipmiUser, ipmiPass, ipmiPassFile, watchdogDev, role, region string
	var cpuOvercommit, memOvercommit float64
	var cpuReserve, memReserveMiB int
	var clearIPMI bool
	var rfEndpoint, rfUser, rfPass, rfPassFile, rfSystemID, rfAuth, rfCAFile string
	var clearRedfish, clearRedfishCA bool
	var trustSSHPoweroff bool

	cmd := &cobra.Command{
		Use:   "config <host>",
		Short: "Configure host settings (fencing, IPMI, Redfish, watchdog, role, region)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// The CA bundle is read here, on the operator's machine, and sent
			// as PEM: the daemon that takes the request may be any host.
			var rfCA string
			if rfCAFile != "" {
				b, err := os.ReadFile(rfCAFile)
				if err != nil {
					return fmt.Errorf("read --redfish-ca-file: %w", err)
				}
				rfCA = string(b)
			}
			// The password from a file, or stdin for "-", keeps it out of
			// argv (ps, shell history). One trailing newline is dropped.
			if ipmiPassFile != "" {
				warnSecretFileMode(cmd.ErrOrStderr(), "--ipmi-pass-file", ipmiPassFile)
				p, err := readSecretFile(cmd.InOrStdin(), ipmiPassFile)
				if err != nil {
					return fmt.Errorf("--ipmi-pass-file: %w", err)
				}
				ipmiPass = p
			} else if cmd.Flags().Changed("ipmi-pass") {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: --ipmi-pass is visible to every user in the process "+
					"list (ps) and is kept in shell history; use --ipmi-pass-file <path>, or --ipmi-pass-file - "+
					"to read it from stdin")
			}
			if rfPassFile != "" {
				warnSecretFileMode(cmd.ErrOrStderr(), "--redfish-pass-file", rfPassFile)
				p, err := readSecretFile(cmd.InOrStdin(), rfPassFile)
				if err != nil {
					return fmt.Errorf("--redfish-pass-file: %w", err)
				}
				rfPass = p
			}
			// --redfish-system-id="" given explicitly unsets the system id; an
			// omitted flag leaves it alone.
			clearSystemID := cmd.Flags().Changed("redfish-system-id") && rfSystemID == ""
			// --trust-ssh-poweroff is the host's corrosion.LabelTrustSSHPoweroff
			// label (SetHostLabels: admin, audited, replicated to every
			// coordinator); every other flag is ConfigureHost's.
			trustChanged := cmd.Flags().Changed("trust-ssh-poweroff")
			others := 0
			cmd.Flags().Visit(func(f *pflag.Flag) {
				if f.Name != "trust-ssh-poweroff" {
					others++
				}
			})
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if trustChanged {
					if err := setTrustSSHPoweroff(ctx, c, args[0], trustSSHPoweroff); err != nil {
						return err
					}
					if others == 0 {
						return nil
					}
				}
				out := &pb.ConfigureHostRequest{
					Name:          args[0],
					FenceStrategy: fenceStrategy,
					IpmiAddress:   ipmiAddr,
					IpmiUser:      ipmiUser,
					IpmiPass:      ipmiPass,
					WatchdogDev:   watchdogDev,
					Role:          role,
					Region:        region,
					ClearIpmi:     clearIPMI,

					RedfishEndpoint: rfEndpoint,
					RedfishUser:     rfUser,
					RedfishPass:     rfPass,
					RedfishSystemId: rfSystemID,
					RedfishAuth:     rfAuth,
					RedfishCaPem:    rfCA,
					ClearRedfish:    clearRedfish,

					ClearRedfishSystemId: clearSystemID,
					ClearRedfishCa:       clearRedfishCA,
				}
				// Send capacity overrides only when the operator actually passed the
				// flag: an omitted numeric flag is 0, which for a reserve is a REAL
				// value ("hand guests everything"), so silence has to mean silence.
				if cmd.Flags().Changed("cpu-overcommit") {
					out.CpuOvercommit = &cpuOvercommit
				}
				if cmd.Flags().Changed("mem-overcommit") {
					out.MemOvercommit = &memOvercommit
				}
				if cmd.Flags().Changed("cpu-reserve") {
					v := int32(cpuReserve)
					out.CpuReserve = &v
				}
				if cmd.Flags().Changed("mem-reserve") {
					v := int32(memReserveMiB)
					out.MemReserveMib = &v
				}
				h, err := c.ConfigureHost(ctx, out)
				if err != nil {
					return fmt.Errorf("configure host: %w", err)
				}
				if clearIPMI {
					if err := checkIPMICleared(h); err != nil {
						return err
					}
				}
				if err := checkRedfishApplied(h, out); err != nil {
					return err
				}
				fmt.Printf("Host %s configured.\n", h.Name)
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&fenceStrategy, "fence-strategy", "",
		"Fencing strategy: ssh | ipmi | redfish | watchdog | manual | best-effort. 'manual' never powers the host off — it records the intent and waits for `lv host fence-confirm`.")
	cmd.Flags().StringVar(&ipmiAddr, "ipmi-address", "", "IPMI BMC address")
	cmd.Flags().StringVar(&ipmiUser, "ipmi-user", "", "IPMI username")
	cmd.Flags().StringVar(&ipmiPass, "ipmi-pass", "",
		"IPMI password (visible in ps and shell history; prefer --ipmi-pass-file)")
	cmd.Flags().StringVar(&ipmiPassFile, "ipmi-pass-file", "",
		"Read the IPMI password from this file, or from stdin for '-' (preferred over --ipmi-pass)")
	cmd.MarkFlagsMutuallyExclusive("ipmi-pass", "ipmi-pass-file")
	cmd.Flags().StringVar(&watchdogDev, "watchdog-dev", "", "Watchdog device path")
	cmd.Flags().StringVar(&role, "role", "",
		"Role: 'worker' (run VMs + vote) or 'witness' (vote-only tiebreaker for even-N clusters). Host must have no VMs to be promoted to witness.")
	cmd.Flags().StringVar(&region, "region", "",
		"Region label (failure domain — DC, rack, AZ). Default 'default'. Used by `lv region status` and cross-region migration.")
	cmd.Flags().Float64Var(&cpuOvercommit, "cpu-overcommit", 0,
		"vCPU oversubscription ratio for this host (0 = inherit the cluster default). vCPU is time-sliced, so >1 is normal.")
	cmd.Flags().Float64Var(&memOvercommit, "mem-overcommit", 0,
		"Memory oversubscription ratio for this host (0 = inherit). Raise above 1 only with ballooning/KSM/swap to back it.")
	cmd.Flags().IntVar(&cpuReserve, "cpu-reserve", 0,
		"vCPUs held back for the host itself (negative = inherit the cluster default).")
	cmd.Flags().IntVar(&memReserveMiB, "mem-reserve", 0,
		"MiB held back for the host itself (negative = inherit). 0 means hand guests every last MiB — the host gets no headroom.")
	cmd.Flags().BoolVar(&clearIPMI, "clear-ipmi", false,
		"Remove the host's IPMI address, user and password (an empty --ipmi-* flag leaves them alone). A host that fences by ipmi needs another --fence-strategy with it.")
	for _, f := range []string{"ipmi-address", "ipmi-user", "ipmi-pass", "ipmi-pass-file"} {
		cmd.MarkFlagsMutuallyExclusive("clear-ipmi", f)
	}
	cmd.Flags().StringVar(&rfEndpoint, "redfish-endpoint", "", "Redfish BMC base URL, https://host[:port] (http is refused)")
	cmd.Flags().StringVar(&rfUser, "redfish-user", "", "Redfish username")
	cmd.Flags().StringVar(&rfPass, "redfish-pass", "",
		"Redfish password (visible in ps and shell history; prefer --redfish-pass-file). Stored on the sensitive lane, never on the hosts row")
	cmd.Flags().StringVar(&rfPassFile, "redfish-pass-file", "",
		"Read the Redfish password from this file, or from stdin for '-' (preferred over --redfish-pass)")
	cmd.Flags().StringVar(&rfSystemID, "redfish-system-id", "",
		"Redfish ComputerSystem Id to power off; needed only when the BMC lists more than one. --redfish-system-id=\"\" unsets it")
	cmd.Flags().StringVar(&rfAuth, "redfish-auth", "", "Redfish auth: session (default) or basic")
	cmd.Flags().StringVar(&rfCAFile, "redfish-ca-file", "",
		"PEM file of the CA the BMC's certificate must chain to (default: the system roots; TLS is always verified)")
	cmd.Flags().BoolVar(&clearRedfishCA, "clear-redfish-ca", false,
		"Unset the Redfish CA bundle, so the BMC certificate is verified against the system roots")
	cmd.MarkFlagsMutuallyExclusive("clear-redfish-ca", "redfish-ca-file")
	cmd.MarkFlagsMutuallyExclusive("redfish-pass", "redfish-pass-file")
	cmd.Flags().BoolVar(&clearRedfish, "clear-redfish", false,
		"Remove the host's Redfish settings (an empty --redfish-* flag leaves them alone). A host that fences by redfish needs another --fence-strategy with it.")
	for _, f := range []string{"redfish-endpoint", "redfish-user", "redfish-pass", "redfish-pass-file",
		"redfish-system-id", "redfish-auth", "redfish-ca-file", "clear-redfish-ca"} {
		cmd.MarkFlagsMutuallyExclusive("clear-redfish", f)
	}
	cmd.Flags().BoolVar(&trustSSHPoweroff, "trust-ssh-poweroff", false,
		"Recover this host's workloads on an SSH power-off its remote shell confirmed over the pinned host key (default off). "+
			"A confirmed request is not an observed power-off: a host that ignores it, or whose power-off hangs, keeps "+
			"running its workloads beside their replacements. Never applies to a dial failure, a host-key mismatch or an "+
			"unconfirmed result. --trust-ssh-poweroff=false turns it off")

	return cmd
}

// setTrustSSHPoweroff sets or clears host's trust in a confirmed SSH
// power-off (corrosion.LabelTrustSSHPoweroff), through SetHostLabels, which
// is admin-only and audited.
func setTrustSSHPoweroff(ctx context.Context, c pb.LiteVirtClient, host string, on bool) error {
	req := &pb.SetHostLabelsRequest{Name: host}
	if on {
		req.Labels = map[string]string{corrosion.LabelTrustSSHPoweroff: "true"}
	} else {
		req.Remove = []string{corrosion.LabelTrustSSHPoweroff}
	}
	if _, err := c.SetHostLabels(ctx, req); err != nil {
		return fmt.Errorf("set --trust-ssh-poweroff: %w", err)
	}
	if on {
		fmt.Printf("Host %s: a confirmed SSH power-off now recovers its workloads without proof the host is off. "+
			"If it ignores or does not finish one, they run twice.\n", host)
	} else {
		fmt.Printf("Host %s: a confirmed SSH power-off no longer recovers its workloads by itself.\n", host)
	}
	return nil
}

// checkIPMICleared confirms a --clear-ipmi took effect. A server that predates
// clear_ipmi ignores the field: alone it refuses ("no fields to update"), but
// beside another setting it applies that one and returns the host with its
// IPMI settings intact.
func checkIPMICleared(h *pb.Host) error {
	if h.GetIpmiAddress() != "" {
		return fmt.Errorf("host %s still has IPMI address %s: the server did not clear it (it may predate "+
			"--clear-ipmi; retry once every host is upgraded)", h.GetName(), h.GetIpmiAddress())
	}
	return nil
}

// warnSecretFileMode warns, on w, when the password file path (not "-",
// stdin) can be read by its group or by other users. It does not refuse:
// the file is the operator's, and the password is still kept out of argv.
func warnSecretFileMode(w io.Writer, flag, path string) {
	if path == "-" {
		return
	}
	fi, err := os.Stat(path)
	if err != nil {
		return // the read reports it
	}
	if m := fi.Mode().Perm(); m&0o044 != 0 {
		fmt.Fprintf(w, "warning: %s %s is mode %04o, readable by its group or other users; "+
			"chmod 600 it to keep the password private\n", flag, path, m)
	}
}

// readSecretFile reads a secret from path, or from in for "-", dropping one
// trailing newline. An empty secret is an error, never "leave alone".
func readSecretFile(in io.Reader, path string) (string, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(io.LimitReader(in, 64<<10))
	} else {
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return "", err
	}
	s := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if s == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return s, nil
}

// checkRedfishApplied confirms the server took a request's Redfish settings.
// A server that predates them ignores the fields: beside another setting it
// applies that one and returns the host with no Redfish endpoint (or, for a
// --clear-redfish, with the old one).
func checkRedfishApplied(h *pb.Host, req *pb.ConfigureHostRequest) error {
	switch {
	case req.GetClearRedfish() && h.GetRedfishEndpoint() != "":
		return fmt.Errorf("host %s still has Redfish endpoint %s: the server did not clear it (it may predate "+
			"--clear-redfish; retry once every host is upgraded)", h.GetName(), h.GetRedfishEndpoint())
	case req.GetClearRedfishSystemId() && h.GetRedfishSystemId() != "":
		return fmt.Errorf("host %s still has Redfish system id %s: the server did not unset it (it may predate "+
			"unsetting it; retry once every host is upgraded)", h.GetName(), h.GetRedfishSystemId())
	case req.GetClearRedfishCa() && h.GetRedfishCaConfigured():
		return fmt.Errorf("host %s still has a Redfish CA bundle: the server did not unset it (it may predate "+
			"--clear-redfish-ca; retry once every host is upgraded)", h.GetName())
	case req.GetRedfishEndpoint() != "" && h.GetRedfishEndpoint() == "":
		return fmt.Errorf("host %s has no Redfish endpoint: the server did not store it (it may predate "+
			"--redfish-endpoint; retry once every host is upgraded)", h.GetName())
	}
	return nil
}

func newHostRescanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rescan [host]",
		Short: "Rescan PCI devices on a host",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				name := ""
				if len(args) > 0 {
					name = args[0]
				}

				resp, err := c.RescanHost(ctx, &pb.RescanHostRequest{Name: name})
				if err != nil {
					return fmt.Errorf("rescan: %w", err)
				}

				fmt.Printf("PCI rescan complete: %d added, %d removed, %d total\n",
					resp.Added, resp.Removed, resp.Total)
				return nil
			})
		},
	}
}

func newHostUpgradeCmd() *cobra.Command {
	var binaryPath string
	var yes bool
	var force bool
	var noPreStage bool
	var skipPreStage []string
	cmd := &cobra.Command{
		Use:   "upgrade [host-name...]",
		Short: "Roll out a new litevirtd binary to cluster hosts",
		Long: `Performs a rolling upgrade of litevirtd across cluster hosts.

For each target host: copy binary → swap → restart → verify.
VMs, HAProxy, and keepalived all survive daemon restarts.

A pre-flight check inspects the host for in-flight migrations, leader-lease
holdings, replication backlog, and clock skew. The upgrade aborts on
"block" findings unless --force is passed (warnings are logged either way).

  lv host upgrade                           # all outdated hosts, with preflight
  lv host upgrade host-b host-c             # specific hosts
  lv host upgrade --binary ./bin/litevirtd  # use a local binary
  lv host upgrade --force                   # skip preflight blocks
  lv host upgrade host-b --skip-prestage host-d  # host-d is down: leave its schema behind
  lv host preflight-upgrade <host>          # check without upgrading`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				return cli.HostUpgrade(ctx, c, cli.UpgradeOpts{
					BinaryPath:   binaryPath,
					HostNames:    args,
					Yes:          yes,
					Force:        force,
					NoPreStage:   noPreStage,
					SkipPreStage: skipPreStage,
				})
			})
		},
	}
	cmd.Flags().StringVar(&binaryPath, "binary", "/usr/local/bin/litevirt", "Path to litevirtd binary to distribute")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt")
	cmd.Flags().BoolVar(&force, "force", false, "Skip preflight blocks (warnings still printed)")
	cmd.Flags().BoolVar(&noPreStage, "no-prestage", false, "Skip the cluster-wide schema pre-stage pass (not recommended for multi-version upgrades)")
	cmd.Flags().StringSliceVar(&skipPreStage, "skip-prestage", nil, "Members outside the upgrade that are down: pre-stage each only if it answers, and otherwise leave it on its schema with a warning")
	return cmd
}

// newHostPreflightUpgradeCmd reports preflight findings without triggering
// the actual upgrade. Operators can run this before scheduling maintenance.
func newHostPreflightUpgradeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "preflight-upgrade <host>",
		Short: "Report preflight findings for an upgrade without performing it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.PreflightUpgrade(ctx,
					&pb.PreflightUpgradeRequest{TargetHost: args[0]})
				if err != nil {
					return fmt.Errorf("preflight: %w", err)
				}
				if len(resp.Findings) == 0 {
					fmt.Printf("Host %s: no findings, upgrade is safe.\n", resp.Host)
					return nil
				}
				fmt.Printf("Host %s preflight findings:\n", resp.Host)
				for _, f := range resp.Findings {
					fmt.Printf("  [%s] %s: %s\n", f.Severity, f.Code, f.Message)
				}
				if !resp.Ok {
					return fmt.Errorf("upgrade blocked by %d finding(s)", countBlockingCLI(resp.Findings))
				}
				return nil
			})
		},
	}
}

func countBlockingCLI(findings []*pb.PreflightFinding) int {
	n := 0
	for _, f := range findings {
		if f.Severity == "block" {
			n++
		}
	}
	return n
}

// newHostRotateAuditKeyCmd replaces the key a host signs audit rows with. It
// is SSH + a restart, not an RPC: only the host holds its new private key, so
// only the host can sign the chain head that seals what the old key wrote.
func newHostRotateAuditKeyCmd() *cobra.Command {
	var sshTarget string
	cmd := &cobra.Command{
		Use:   "rotate-audit-key <host>",
		Short: "Replace a host's audit signing key",
		Long: `Mint a new audit signing certificate for a host and install it.

Run this when the host's signing key may have been exposed — notably on any node
provisioned before the fix that pushed /etc/litevirt/pki/host.key mode 0644.
Tightening the mode does not undo a copy someone already took.

Must run from the node that holds the cluster CA private key (the one that ran
'lv host init'): there is no CSR flow, so nowhere else can sign a certificate.

The host's TLS identity (host.crt / host.key) is NOT touched — peer mTLS and
qemu+tls:// live migration are unaffected. The target's daemon is restarted,
because the signing keyring is loaded once at boot.

  lv host rotate-audit-key host-b
  lv host rotate-audit-key host-b --ssh root@10.0.50.11`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.HostRotateAuditKey(cmd.Context(), args[0], sshTarget)
		},
	}
	cmd.Flags().StringVar(&sshTarget, "ssh", "",
		"SSH target for the host (default root@<host>) — needed when the litevirt host name is not the address you reach it on")
	return cmd
}

// newHostRetireAuditKeyCmd ends a host's audit signing contract when the host
// cannot end it itself.
//
// The daemon signs its own retirement whenever enforcement.audit_signature is
// turned off, so an ordinary rollback needs no command at all. This is for a
// host that has lost its key, is gone, or is being decommissioned.
func newHostRetireAuditKeyCmd() *cobra.Command {
	var atSeq int64
	var force bool
	var keyID string
	cmd := &cobra.Command{
		Use:   "retire-audit-key <host>",
		Short: "Retire a host's audit signing key on its behalf",
		Long: `End a host's audit signing contract when the host cannot end it itself.

Publishing a signing certificate declares that a host's audit rows are signed
from that point on. A host that stops signing while that declaration stands has
every unsigned row reported as tampering on every node — which is correct when
someone took its key away, and wrong when the machine is simply gone.

You do not need this for a normal rollback: turning enforcement.audit_signature
off makes the daemon sign its own retirement on the next start. Use it when the
host cannot sign one — key lost or unreadable, machine destroyed, decommission.

Run it where the cluster CA private key is (the machine that ran 'lv host init'):
signing on another host's behalf means minting a certificate carrying that host's
name, which is exactly what holding the CA authorises. The signing happens
locally — the CA key is never sent to a node, and the daemon only verifies.

Rows the retired key signed stay verifiable forever — retirement is a validity
window, never a deletion.

The boundary is derived from replicated state, and the command refuses to run from
a node whose copy of the host's log a signed chain head says is behind: pinning a
boundary below rows the key legitimately signed cannot be undone. Use --at-seq only
when that refusal cannot be satisfied, because a head signed by the key you are
retiring can claim any sequence at all and cannot be withdrawn — a leaked key can
block this command indefinitely.

An --at-seq at or above what this node can already see is accepted; a lower one is
refused unless you add --force, because lowering the boundary is the direction that
cannot be walked back and a typo looks exactly like a decision.

A host with more than one live key — what a rotation that never completed leaves
behind — needs --key-id, because each key has its own boundary. The refusal lists
the live key ids; retire them one at a time until none remain.

  lv host retire-audit-key host-b
  lv host retire-audit-key host-b --key-id 96a1bc89...     # one of several live keys
  lv host retire-audit-key host-b --at-seq 4210
  lv host retire-audit-key host-b --at-seq 100 --force   # key known to have leaked at row 100`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Changed(), not a zero check: 0 is a meaningful boundary — "this key
			// signed nothing valid" — and must not be indistinguishable from the flag
			// being absent.
			var at *int64
			if cmd.Flags().Changed("at-seq") {
				at = &atSeq
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				return cli.HostRetireAuditKey(ctx, c, args[0], keyID, at, force)
			})
		},
	}
	cmd.Flags().Int64Var(&atSeq, "at-seq", 0,
		"retire at this sequence instead of the one the cluster derives (bypasses the "+
			"lagging-replica refusal; a value below what the host really signed is permanent)")
	cmd.Flags().BoolVar(&force, "force", false,
		"with --at-seq, permit a boundary BELOW the one the cluster derives — the "+
			"unrecoverable direction, since rows above it become permanent findings")
	cmd.Flags().StringVar(&keyID, "key-id", "",
		"which live signing key to retire; required when the host has more than one, "+
			"since each carries its own boundary")
	return cmd
}

func newHostDevicesCmd() *cobra.Command {
	var typeFilter string
	cmd := &cobra.Command{
		Use:   "devices <host>",
		Short: "List PCI devices on a host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListHostDevices(ctx, &pb.ListHostDevicesRequest{
					Name:       args[0],
					TypeFilter: typeFilter,
				})
				if err != nil {
					return fmt.Errorf("list devices: %w", err)
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(w, "ADDRESS\tTYPE\tVENDOR\tDEVICE\tDRIVER\tIOMMU\tVM")
				for _, d := range resp.Devices {
					vm := d.VmName
					if vm == "" {
						vm = "-"
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
						d.Address, d.Type, d.VendorId, d.DeviceId,
						d.Driver, d.IommuGroup, vm)
				}
				w.Flush()
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&typeFilter, "type", "", "Filter by device type (gpu, network, nvme, infiniband)")
	return cmd
}
