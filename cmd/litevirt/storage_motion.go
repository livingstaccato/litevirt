package main

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newMoveVolumeCmd() *cobra.Command {
	var deleteSource bool
	cmd := &cobra.Command{
		Use:   "move-volume <vm> <disk> <target-pool>",
		Short: "Move a VM disk to a different storage pool on the same host",
		Long: `Move-volume copies the disk into the target pool, hot-swaps the libvirt
source, then optionally deletes the original. Today only file-based pools
(local, nfs, dir, btrfs) are supported and the VM must be stopped — live
cutover (running-VM move) is in flight.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.MoveVolume(ctx, &pb.MoveVolumeRequest{
					VmName: args[0], DiskName: args[1], TargetPool: args[2],
					DeleteSource: deleteSource,
				})
				if err != nil {
					return err
				}
				for {
					prog, err := stream.Recv()
					if err == io.EOF {
						return nil
					}
					if err != nil {
						return err
					}
					fmt.Printf("[%s] %5.1f%% — %s\n", prog.Phase, prog.CopyPct, prog.Status)
					if prog.Phase == pb.MoveVolumeProgress_DONE {
						return nil
					}
				}
			})
		},
	}
	cmd.Flags().BoolVar(&deleteSource, "delete-source", false,
		"Remove the original disk after successful cutover")
	return cmd
}

func newReplicateVolumeCmd() *cobra.Command {
	var targetPath string
	cmd := &cobra.Command{
		Use:   "replicate-volume <vm> <disk> <target-pool>",
		Short: "Copy a VM disk to another pool without disturbing the VM",
		Long: `Replicate-volume produces a point-in-time copy in target-pool. The VM
keeps using its source disk; the copy is suitable for off-site DR or
clone-to-new-VM workflows. The copy is always a new file the daemon names
in the pool; --target-path (admin only) names it instead, and an existing
file is refused, never replaced. A zfs or ceph disk copied into a pool of
the same driver uses native send/receive into a new dataset or image, and a
btrfs disk in its own subvolume copied into a btrfs pool into a new
subvolume.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.ReplicateVolume(ctx, &pb.ReplicateVolumeRequest{
					VmName: args[0], DiskName: args[1], TargetPool: args[2],
					TargetPath: targetPath,
				})
				if err != nil {
					return err
				}
				for {
					prog, err := stream.Recv()
					if err == io.EOF {
						return nil
					}
					if err != nil {
						return err
					}
					fmt.Printf("[%s] %5.1f%% — %s\n", prog.Phase, prog.CopyPct, prog.Status)
					if prog.Phase == pb.ReplicateVolumeProgress_DONE {
						if prog.TargetPath != "" {
							fmt.Printf("Target: %s\n", prog.TargetPath)
						}
						return nil
					}
				}
			})
		},
	}
	cmd.Flags().StringVar(&targetPath, "target-path", "",
		"Name the destination file (admin only; never an existing file). Default: a new <vm>-<disk>-copy-<time>-<id>.qcow2 in the pool")
	return cmd
}
