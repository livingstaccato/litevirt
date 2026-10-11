package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newCloneCmd() *cobra.Command {
	var (
		mode     string
		project  string
		ip       string
		start    bool
		snapshot string
		host     string
		pool     string
	)
	cmd := &cobra.Command{
		Use:   "clone <source> <new-name>",
		Short: "Clone a template or stopped VM into a new VM",
		Long: `Clone a template (or a stopped VM) into a new VM.

The clone gets a fresh identity — new MAC addresses and a regenerated cloud-init
instance-id/hostname, so it boots clean (new SSH host keys, new machine-id).

Mode (default: storage-aware auto):
  auto    linked when the source's disks are on shared storage, or are a
          clone of disks that are (instant, space-efficient); full when on
          local storage (independent, avoids pinning the clone to the
          source's host). The mode used, and why, is printed.
  linked  qcow2 overlay backed by the source's disk — instant, thin
  full    independent copy (qcow2 convert) — no dependency on the source

Where the clone lives (default: the source's host, in its default disk directory):
  --host   another host. The clone is made as a full copy where the source's
           disks are, then moved to that host the way lv migrate --cold moves a
           stopped VM: its disks stream over the cluster's mTLS connection, its
           domain is defined there, and the staged copy is removed. A linked
           clone cannot be made on another host. Needs vm.migrate and vm.delete
           on the new VM (vm.start with --start) as well as the clone
           permissions, all checked as you before the copy starts, and room
           for the staged copy on the source host.
  --pool   a file-based storage pool (local, dir, nfs, btrfs) on the host the
           clone ends up on. A clone in a pool is a full copy. Needs the project
           to be allowed to use the pool (and, on another host, the move-volume
           permission, vm.move).
If the move fails, the staged copy is removed and nothing is left behind (a crash of
the daemon mid-clone can leave the staged VM: lv rm removes it). If it
succeeded and a later step (the pool, the start) fails, the VM is complete on its
host and the error names the command that finishes the job.

Examples:
  lv clone ubuntu-template web-01
  lv clone ubuntu-template web-02 --mode full --start
  lv clone db-template db-staging --ip 10.0.0.50
  lv clone ubuntu-template web-03 --host kvm2 --pool ssd --start`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				var hdr metadata.MD
				vm, err := c.CloneVM(ctx, &pb.CloneVMRequest{
					Source:          args[0],
					Target:          args[1],
					Mode:            mode,
					Project:         project,
					Ip:              ip,
					Start:           start,
					Snapshot:        snapshot,
					DestinationHost: host,
					TargetPool:      pool,
				}, grpc.Header(&hdr))
				if err != nil {
					return fmt.Errorf("clone VM: %w", err)
				}
				where := ""
				if vm.HostName != "" {
					where = " on " + vm.HostName
				}
				fmt.Printf("Cloned %s → %s%s (state: %s)\n", args[0], vm.Name, where, vm.State)
				if m := hdr.Get("x-litevirt-clone-mode"); len(m) > 0 {
					fmt.Printf("  mode %s\n", m[0])
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&mode, "mode", "", "Clone mode: auto (default) | linked | full")
	cmd.Flags().StringVar(&project, "project", "", "Tenancy project for the clone (default: source's)")
	cmd.Flags().StringVar(&ip, "ip", "", "Static IP for the clone's first NIC (default: DHCP)")
	cmd.Flags().BoolVar(&start, "start", false, "Start the clone after creation")
	cmd.Flags().StringVar(&snapshot, "snapshot", "", "Clone from this snapshot of the source")
	cmd.Flags().StringVar(&host, "host", "", "Host the clone ends up on (default: the source's host)")
	cmd.Flags().StringVar(&pool, "pool", "", "Storage pool, on that host, for the clone's disks (default: its default disk directory)")
	return cmd
}

func newTemplateCmd() *cobra.Command {
	var revert bool
	cmd := &cobra.Command{
		Use:   "template <vm>",
		Short: "Convert a stopped VM into a clone template (or --revert back to a VM)",
		Long: `Convert a stopped VM into a template: a VM that can no longer start and
whose disks become immutable clone sources. Use --revert to turn a template
back into a normal, startable VM (refused while linked clones still depend on
it).

Examples:
  lv template ubuntu-base            # ubuntu-base becomes a template
  lv template ubuntu-base --revert   # back to a normal VM`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.ConvertToTemplate(ctx, &pb.ConvertToTemplateRequest{Name: args[0], Revert: revert})
				if err != nil {
					return fmt.Errorf("convert template: %w", err)
				}
				if revert {
					fmt.Printf("%s reverted to a normal VM\n", vm.Name)
				} else {
					fmt.Printf("%s is now a template (clone it with: lv clone %s <new-name>)\n", vm.Name, vm.Name)
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&revert, "revert", false, "Turn a template back into a normal VM")
	return cmd
}
