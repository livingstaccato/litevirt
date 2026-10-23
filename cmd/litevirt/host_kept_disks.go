package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

// errNoTTYReleaseConfirm is a release with neither --yes nor a terminal to
// confirm on.
var errNoTTYReleaseConfirm = errors.New("stdin is not a terminal, so the confirmation cannot be answered; review the files above and re-run with --yes to remove them")

func newHostKeptDisksCmd() *cobra.Command {
	var release string
	var dryRun, yes bool
	cmd := &cobra.Command{
		Use:   "kept-disks <host>",
		Short: "List, or release, the disk chains VM deletes kept on a host",
		Long: `A VM delete keeps a disk it cannot prove unused (` + "`lv rm --keep-disks`" + `, a disk
recorded delete_with_vm=false, a delete of a VM with no domain while a host did
not answer, a removal that failed). The host notes it in
<data_dir>/kept-disks/<vm>.json, with the files its chain backs on, or records
it in <data_dir>/kept-disks.json, which disk_leftover names. Nothing on the
host removes such a file, and every path that removes disk files refuses it.

This lists each kept chain on a host: the deleted VM, the files a release
removes (an overlay before the file it backs on; "under" marks a file a kept
layer above it backs on), the files below it that are not the VM's own (an
image, left in place), the total size, when it was kept and why, the note and
record naming it, and why it may not be released now.

--release <vm|path> removes, on that host, every kept chain of the deleted VM
of that name, or the one chain a file (its full path) is in, with their note
and record entries; disk_leftover then clears for them. It removes whole
chains only. It is refused, and removes nothing, while anything references a
file it would remove: a VM's disk row, another VM's disk or another kept chain
backing on it, a snapshot record (of the deleted VM on that host, or naming it
as a memory image), a recorded replica, a set-aside copy layered on it, or a
domain on that host using it or named as the deleted VM. It is refused too
while a note, the record or a chain cannot be read. It names exactly what it
removes and asks to confirm; --yes skips the question. --dry-run shows what it
would remove, and why it is refused, removing nothing. A release needs admin,
and writes an audit entry (host.kept_disks.release) naming each file and its
size. A host on an older build does not know the command, and removes
nothing.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if release == "" && (dryRun || yes) {
				return fmt.Errorf("--dry-run and --yes go with --release")
			}
			out := cmd.OutOrStdout()
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				call := func(req *pb.KeptDisksRequest) (*pb.KeptDisksResponse, error) {
					resp, err := c.KeptDisks(ctx, req)
					if status.Code(err) == codes.Unimplemented {
						return nil, fmt.Errorf("kept disks: %s runs a build without lv host kept-disks; nothing was removed: %w", args[0], err)
					}
					if err != nil {
						return nil, fmt.Errorf("kept disks: %w", err)
					}
					return resp, nil
				}
				if release == "" {
					resp, err := call(&pb.KeptDisksRequest{Host: args[0]})
					if err != nil {
						return err
					}
					printKeptDisks(out, resp)
					return nil
				}
				plan, err := call(&pb.KeptDisksRequest{Host: args[0], Release: release, DryRun: true})
				if err != nil {
					return err
				}
				var paths, held []string
				for _, ch := range plan.Chains {
					for _, f := range ch.Files {
						paths = append(paths, f.Path)
					}
					if ch.Held != "" {
						held = append(held, ch.Held)
					}
				}
				printKeptRelease(out, plan, true)
				if len(held) > 0 {
					return fmt.Errorf("release %s on %s is refused: %s; nothing was removed", release, plan.Host, strings.Join(held, "; "))
				}
				if dryRun {
					return nil
				}
				if !yes {
					if !stdinIsTerminal() {
						return errNoTTYReleaseConfirm
					}
					ok, err := cli.Confirm(ctx, os.Stdin, out, fmt.Sprintf("Remove these %d file(s) on %s, and their note and record entries?", len(paths), plan.Host))
					if err != nil {
						return err
					}
					if !ok {
						fmt.Fprintln(out, "Aborted; nothing was removed.")
						return nil
					}
				}
				resp, err := call(&pb.KeptDisksRequest{Host: args[0], Release: release, ExpectPaths: paths})
				if err != nil {
					return err
				}
				printKeptRelease(out, resp, false)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&release, "release", "", "Remove every kept chain of this deleted VM, or the one chain this file (full path) is in, with its note and record entries")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "With --release, show what it would remove and why it is refused; remove nothing")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "With --release, remove without asking to confirm")
	return cmd
}

func keptChainSize(ch *pb.KeptDiskChain) int64 {
	var n int64
	for _, f := range ch.Files {
		n += f.SizeBytes
	}
	return n
}

func keptFileLine(f *pb.KeptDiskFile) string {
	s := fmt.Sprintf("%s (%d bytes)", f.Path, f.SizeBytes)
	switch {
	case f.Gone:
		s = f.Path + " (gone: only its entry is forgotten)"
	case f.Under:
		s += " under"
	}
	return s
}

func printKeptDisks(out io.Writer, resp *pb.KeptDisksResponse) {
	if len(resp.Chains) == 0 {
		fmt.Fprintf(out, "No disks deletes kept on %s.\n", resp.Host)
		return
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "VM\tFILES\tSIZE\tKEPT\tREASON\tSTATUS")
	for _, ch := range resp.Chains {
		var files []string
		for _, f := range ch.Files {
			files = append(files, keptFileLine(f))
		}
		st := "releasable (--release " + ch.VmName + ")"
		if ch.Held != "" {
			st = "held: " + ch.Held
		}
		kept := ch.KeptAt
		if kept == "" {
			kept = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\n", ch.VmName, strings.Join(files, ", "), keptChainSize(ch), kept, ch.Reason, st)
		if len(ch.StandsOn) > 0 {
			fmt.Fprintf(w, "\t  stands on (left in place): %s\t\t\t\t\n", strings.Join(ch.StandsOn, ", "))
		}
		if ch.MissingBase != "" {
			fmt.Fprintf(w, "\t  missing backing file: %s\t\t\t\t\n", ch.MissingBase)
		}
		if len(ch.Records) > 0 {
			fmt.Fprintf(w, "\t  named by: %s\t\t\t\t\n", strings.Join(ch.Records, ", "))
		}
	}
	w.Flush()
}

func printKeptRelease(out io.Writer, resp *pb.KeptDisksResponse, plan bool) {
	verb := "Removed"
	if plan {
		verb = "A release removes"
	}
	var total int64
	for _, ch := range resp.Chains {
		fmt.Fprintf(out, "%s, on %s, the disks the delete of VM %s kept:\n", verb, resp.Host, ch.VmName)
		for _, f := range ch.Files {
			fmt.Fprintf(out, "  %s\n", keptFileLine(f))
		}
		for _, r := range ch.Records {
			fmt.Fprintf(out, "  and its entries in %s\n", r)
		}
		if len(ch.StandsOn) > 0 {
			fmt.Fprintf(out, "  leaving what it stands on: %s\n", strings.Join(ch.StandsOn, ", "))
		}
		if plan && ch.Held != "" {
			fmt.Fprintf(out, "  refused: %s\n", ch.Held)
		}
		total += keptChainSize(ch)
	}
	fmt.Fprintf(out, "%d bytes in all.\n", total)
}
