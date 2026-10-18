package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// olderDaemonError explains an Unimplemented reply: the daemon that answered
// predates the RPC.
func olderDaemonError(what string, err error) error {
	if status.Code(err) == codes.Unimplemented {
		return fmt.Errorf("%s: the daemon (or the host it forwarded to) runs an older build without this command; upgrade it: %w", what, err)
	}
	return fmt.Errorf("%s: %w", what, err)
}

func newReplicationCheckpointsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "checkpoints",
		Short: "List incremental-replication checkpoint rows, or remove one no schedule uses",
		Long: `lv replication checkpoints ls lists the live checkpoint rows that anchor each
VM's incremental replication chain into a target pool (--vm narrows it to one
VM). IN USE: a live replication schedule uses the row. VM DELETED: the VM has
no live row.

lv replication checkpoints rm <vm> --target-pool <pool> removes one row
(admin, audited); the next run of a schedule added later for that VM and pool
is a full copy. It is refused while a live replication schedule uses the row.`,
	}
	cmd.AddCommand(newReplicationCheckpointsLsCmd(), newReplicationCheckpointsRmCmd())
	return cmd
}

func newReplicationCheckpointsLsCmd() *cobra.Command {
	var vm string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List incremental-replication checkpoint rows",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListReplicationCheckpoints(ctx, &pb.ListReplicationCheckpointsRequest{VmName: vm})
				if err != nil {
					return olderDaemonError("list replication checkpoints", err)
				}
				printReplicationCheckpoints(os.Stdout, resp.GetCheckpoints())
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&vm, "vm", "", "only this VM's rows")
	return cmd
}

func newReplicationCheckpointsRmCmd() *cobra.Command {
	var targetPool string
	cmd := &cobra.Command{
		Use:   "rm <vm>",
		Short: "Remove a replication checkpoint row no live schedule uses (admin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.DeleteReplicationCheckpoint(ctx, &pb.DeleteReplicationCheckpointRequest{VmName: args[0], TargetPool: targetPool})
				if err != nil {
					return olderDaemonError("remove replication checkpoint", err)
				}
				fmt.Printf("replication checkpoint %s of %s into %s removed\n", resp.GetCheckpoint(), args[0], targetPool)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&targetPool, "target-pool", "", "the row's target pool")
	_ = cmd.MarkFlagRequired("target-pool")
	return cmd
}

func printReplicationCheckpoints(out io.Writer, rows []*pb.ReplicationCheckpointRow) {
	if len(rows) == 0 {
		fmt.Fprintln(out, "(no replication checkpoints)")
		return
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "VM\tPOOL\tCHECKPOINT\tIN USE\tVM DELETED\tUPDATED")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%v\t%v\t%s\n", r.GetVmName(), r.GetTargetPool(), r.GetCheckpoint(), r.GetInUse(), r.GetVmDeleted(), r.GetUpdatedAt())
	}
	_ = w.Flush()
}

func newPITOverlaysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pit-overlays",
		Short: "List set-aside point-in-time overlays, or remove one (admin)",
		Long: `A point-in-time overlay that cannot belong to its disk any more (the disk was
restored or written afresh) is never deleted: it is kept beside the disk, with
its binding, as .<disk file>.lv-pit.orphan-<time>.

lv pit-overlays ls lists them, answered on each VM's host. IN USE says why one
cannot be removed now: it is the set-aside evidence of the disk's current
point-in-time window, a VM disk references it, the VM's domain names it, the
disk is held on its overlay (lv resolve-pit-overlay first), or its storage
does not answer.

lv pit-overlays rm <vm> <disk> <name> removes one and its binding, on the VM's
host (admin, audited); it may hold the guest's writes of the window it was
taken in. It is refused while the overlay is in use.`,
	}
	cmd.AddCommand(newPITOverlaysLsCmd(), newPITOverlaysRmCmd())
	return cmd
}

func newPITOverlaysLsCmd() *cobra.Command {
	var host, vm string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List the set-aside point-in-time overlays of a host's VMs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListSetAsideOverlays(ctx, &pb.ListSetAsideOverlaysRequest{Host: host, VmName: vm})
				if err != nil {
					return olderDaemonError("list set-aside overlays", err)
				}
				printSetAsideOverlays(os.Stdout, resp)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "the host to list (default: the host answering)")
	cmd.Flags().StringVar(&vm, "vm", "", "only this VM's, listed on its host")
	return cmd
}

func newPITOverlaysRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <vm> <disk> <name>",
		Short: "Remove a set-aside point-in-time overlay not in use (admin)",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.RemoveSetAsideOverlay(ctx, &pb.RemoveSetAsideOverlayRequest{VmName: args[0], DiskName: args[1], Name: args[2]})
				if err != nil {
					return olderDaemonError("remove set-aside overlay", err)
				}
				fmt.Printf("removed %s on %s (%d bytes)\n", resp.GetPath(), resp.GetHost(), resp.GetSizeBytes())
				return nil
			})
		},
	}
}

func printSetAsideOverlays(out io.Writer, resp *pb.ListSetAsideOverlaysResponse) {
	if len(resp.GetOverlays()) == 0 {
		fmt.Fprintf(out, "(no set-aside point-in-time overlays on %s)\n", resp.GetHost())
		return
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "VM\tDISK\tNAME\tSET ASIDE\tSIZE\tIN USE")
	for _, o := range resp.GetOverlays() {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n", o.GetVmName(), o.GetDiskName(), o.GetName(),
			defaultStr(o.GetSetAsideAt(), "-"), o.GetSizeBytes(), defaultStr(o.GetInUse(), "no"))
	}
	_ = w.Flush()
}
