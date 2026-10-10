package main

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

func newHostSupersededDisksCmd() *cobra.Command {
	var purge bool
	var olderThan time.Duration
	var remove []string
	var restore string
	cmd := &cobra.Command{
		Use:   "superseded-disks <host>",
		Short: "List, remove or restore the disk copies a failover set aside on a host",
		Long: `A VM with a host-local disk that is restarted on another host after a host
failure gets a new disk built from its image; its real disk stays on the failed
host. When that host is back it renames the disk to
<disk path>.superseded-<time>. A restart onto a host that still has a copy of
the disk from an earlier stay renames that copy the same way instead of
booting it.

This lists those copies on a host, with the VM each came from. Each one can be
the only copy of the VM's data from before a failover, so while its VM exists
a copy is retained: the host never removes it on its own, and neither does
--purge. While the VM is in error, pending or starting a copy is also held: a
failed restart may need it, so not even --remove takes it. Once the VM is gone
the host removes its copies when they are older than
superseded_disk_retention_days (default 7; 0 keeps every copy).

--purge removes every copy that is neither retained nor held, whatever its
age. Narrow it with --older-than.

--remove <copy> removes exactly the named copy, retained or not. Repeat it to
name more.

--restore <copy> puts the copy back as its VM's disk. The VM must be stopped on
this host: to run a VM on the real disk a failover left on a host, undrain the
host (it comes back fenced: ` + "`lv host undrain <host>`" + `), stop the VM, move it
there with ` + "`lv migrate <vm> <host> --cold`" + `, restore the copy and start it. The disk the copy replaces is not deleted: it is set aside and
retained in turn.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if olderThan < 0 {
				return fmt.Errorf("--older-than must not be negative")
			}
			if olderThan != 0 && !purge {
				return fmt.Errorf("--older-than applies only with --purge")
			}
			acts := 0
			for _, on := range []bool{purge, len(remove) > 0, restore != ""} {
				if on {
					acts++
				}
			}
			if acts > 1 {
				return fmt.Errorf("--purge, --remove and --restore are separate requests")
			}
			req := &pb.SupersededDisksRequest{Host: args[0], Purge: purge, OlderThanSec: int64(olderThan / time.Second)}
			if len(remove) > 0 || restore != "" {
				// Sent with purge and an age no copy has, so an older host that
				// does not know the named fields requires admin and removes
				// nothing (grpcapi.SupersededNamedOnlySec).
				req.Purge, req.OlderThanSec = true, grpcapi.SupersededNamedOnlySec
				req.RemovePaths, req.RestorePath = remove, restore
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.SupersededDisks(ctx, req)
				if err != nil {
					return fmt.Errorf("superseded disks: %w", err)
				}
				if restore != "" {
					if resp.Restored == "" {
						return fmt.Errorf("%s did not restore %s; it may run an older release without --restore", resp.Host, restore)
					}
					fmt.Fprintf(cmd.OutOrStdout(), "Restored %s as %s on %s.\n", resp.Restored, resp.RestoredTo, resp.Host)
					if resp.SetAside != "" {
						fmt.Fprintf(cmd.OutOrStdout(), "The disk it replaced is kept as %s.\n", resp.SetAside)
					}
					return nil
				}
				printSupersededDisks(cmd.OutOrStdout(), resp, purge || len(remove) > 0, time.Now())
				if len(remove) > 0 {
					gone := map[string]bool{}
					for _, d := range resp.Disks {
						if d.Removed {
							gone[d.Path] = true
						}
					}
					for _, p := range remove {
						if !gone[p] {
							return fmt.Errorf("%s did not remove %s; it may run an older release without --remove", resp.Host, p)
						}
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&purge, "purge", false, "Remove every copy that is neither retained nor held")
	cmd.Flags().DurationVar(&olderThan, "older-than", 0, "With --purge, remove only copies set aside at least this long ago (e.g. 72h)")
	cmd.Flags().StringArrayVar(&remove, "remove", nil, "Remove exactly this copy (its full path), even one retained for an existing VM; repeatable")
	cmd.Flags().StringVar(&restore, "restore", "", "Put this copy (its full path) back as its VM's disk; the VM must be stopped on this host")
	return cmd
}

func printSupersededDisks(out io.Writer, resp *pb.SupersededDisksResponse, purge bool, now time.Time) {
	if len(resp.Disks) == 0 {
		fmt.Fprintf(out, "No superseded disk copies on %s.\n", resp.Host)
		return
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PATH\tVM\tSET ASIDE\tSIZE\tSTATUS")
	var removed, removedBytes int64
	for _, d := range resp.Disks {
		vm := d.VmName
		if vm == "" {
			vm = "-"
		}
		age := d.SetAsideAt
		if at, err := time.Parse(time.RFC3339, d.SetAsideAt); err == nil {
			age = fmt.Sprintf("%s (%s ago)", d.SetAsideAt, now.Sub(at).Round(time.Minute))
		}
		st := "kept"
		switch {
		case d.Removed:
			st = "removed"
			removed++
			removedBytes += d.SizeBytes
		case d.Held != "":
			st = "held: " + d.Held
		case d.Retained != "":
			st = "retained: " + d.Retained
		case resp.RetentionDays > 0:
			if at, err := time.Parse(time.RFC3339, d.SetAsideAt); err == nil {
				st = "removed after " + at.Add(time.Duration(resp.RetentionDays)*24*time.Hour).Format(time.RFC3339)
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", d.Path, vm, age, d.SizeBytes, st)
	}
	w.Flush()
	if purge {
		fmt.Fprintf(out, "Removed %d copies (%d bytes) on %s.\n", removed, removedBytes, resp.Host)
	}
}
