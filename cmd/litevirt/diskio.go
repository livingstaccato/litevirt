package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
)

func newDiskIOCmd() *cobra.Command {
	var disk string
	var clear bool
	rates := map[string]*string{}
	counts := map[string]*int64{}
	cmd := &cobra.Command{
		Use:   "disk-io <vm> [--disk <name>] [limits | --clear]",
		Short: "Throttle a VM disk's I/O (live on a running VM)",
		Long: "Set the I/O limits of one disk (libvirt <iotune>): bytes and operations per second, " +
			"with an optional burst ceiling above the sustained rate. A running VM is throttled " +
			"live and its persistent definition updated; the limits are kept in the VM's spec, so " +
			"a restart, a failover start and a migration carry them.\n\n" +
			"Each call sets the disk's COMPLETE set of limits: a limit you do not name is " +
			"unlimited afterwards. --clear removes every limit. A --total-* limit cannot be " +
			"combined with --read-* / --write-* of the same kind. Byte rates take a K, M or G " +
			"suffix (50M).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lim := &pb.DiskIOLimits{}
			rate := func(key string) (int64, error) {
				if *rates[key] == "" {
					return 0, nil
				}
				return compose.ParseByteRate(*rates[key])
			}
			var err error
			for _, f := range []struct {
				key string
				dst *int64
			}{
				{"total-bps", &lim.TotalBytesSec}, {"read-bps", &lim.ReadBytesSec}, {"write-bps", &lim.WriteBytesSec},
				{"total-bps-max", &lim.TotalBytesSecMax}, {"read-bps-max", &lim.ReadBytesSecMax}, {"write-bps-max", &lim.WriteBytesSecMax},
			} {
				if *f.dst, err = rate(f.key); err != nil {
					return fmt.Errorf("--%s: %w", f.key, err)
				}
			}
			lim.TotalIopsSec, lim.ReadIopsSec, lim.WriteIopsSec = *counts["total-iops"], *counts["read-iops"], *counts["write-iops"]
			lim.TotalIopsSecMax, lim.ReadIopsSecMax, lim.WriteIopsSecMax = *counts["total-iops-max"], *counts["read-iops-max"], *counts["write-iops-max"]
			lim.BurstSeconds = *counts["burst-seconds"]
			if clear && !compose.IOTuneFromSpec(lim).IsZero() {
				return fmt.Errorf("--clear cannot be combined with limits")
			}
			if !clear && compose.IOTuneFromSpec(lim).IsZero() {
				return fmt.Errorf("name at least one limit, or --clear to remove them all")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: args[0], DiskName: disk, Limits: lim})
				if err != nil {
					return fmt.Errorf("set disk I/O limits: %w", err)
				}
				if clear {
					fmt.Printf("Disk %q on VM %s: I/O limits cleared\n", disk, vm.Name)
				} else {
					fmt.Printf("Disk %q on VM %s: I/O limits set\n", disk, vm.Name)
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&disk, "disk", "root", "Disk name")
	cmd.Flags().BoolVar(&clear, "clear", false, "Remove every I/O limit from the disk")
	for _, k := range []string{"total-bps", "read-bps", "write-bps", "total-bps-max", "read-bps-max", "write-bps-max"} {
		rates[k] = new(string)
		cmd.Flags().StringVar(rates[k], k, "", "Bytes per second (e.g. 50M); 0 or unset = unlimited")
	}
	for _, k := range []string{"total-iops", "read-iops", "write-iops", "total-iops-max", "read-iops-max", "write-iops-max", "burst-seconds"} {
		counts[k] = new(int64)
		cmd.Flags().Int64Var(counts[k], k, 0, "Operations per second (burst-seconds: burst length); 0 = unlimited")
	}
	return cmd
}
