package main

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newHostSupersededDisksCmd() *cobra.Command {
	var purge bool
	var olderThan time.Duration
	cmd := &cobra.Command{
		Use:   "superseded-disks <host>",
		Short: "List, or purge, the old disk copies a failover set aside on a host",
		Long: `A VM with a host-local disk that is restarted on another host after a host
failure gets a new disk built from its image. If that host still had a copy of
the disk from an earlier stay, the restart renames it to
<disk path>.superseded-<time> instead of booting it.

This lists those copies on a host, with the VM each came from and whether it
is held. A copy is held while its VM is in error, pending or starting, because
a failed restart may need it. The host removes a copy on its own once it is
older than superseded_disk_retention_days (default 7; 0 keeps every copy) and
not held.

--purge removes every copy that is not held now, whatever its age. Narrow it
with --older-than.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if olderThan < 0 {
				return fmt.Errorf("--older-than must not be negative")
			}
			if olderThan != 0 && !purge {
				return fmt.Errorf("--older-than applies only with --purge")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.SupersededDisks(ctx, &pb.SupersededDisksRequest{
					Host: args[0], Purge: purge, OlderThanSec: int64(olderThan / time.Second),
				})
				if err != nil {
					return fmt.Errorf("superseded disks: %w", err)
				}
				printSupersededDisks(cmd.OutOrStdout(), resp, purge, time.Now())
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&purge, "purge", false, "Remove every copy that is not held")
	cmd.Flags().DurationVar(&olderThan, "older-than", 0, "With --purge, remove only copies set aside at least this long ago (e.g. 72h)")
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
