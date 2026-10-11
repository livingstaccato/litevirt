package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// overwriteNewerWarning is printed, before anything is sent, when a forced
// commit would write an overlay that is already in the disk over it again.
const overwriteNewerWarning = `WARNING: this overlay is already in the disk (verdict %s). Committing it again
writes the window's old blocks over everything the guest has written to the
disk since: a silent rollback of part of the disk. Discarding it
(--discard --confirm) loses nothing.
  --commit would: %s
`

// forceCommitWarning is printed before a --force-commit is sent.
const forceCommitWarning = `WARNING: --force-commit writes the overlay's blocks into the disk although
litevirt could not show the disk is the file the overlay was taken of, unchanged
or half-written by its commit. If the disk was restored, re-created, or written
by the VM since, the commit overwrites newer data with older blocks and can
corrupt the guest's filesystem. Use it only after checking the verdict and both
files yourself.
`

func newResolvePITOverlayCmd() *cobra.Command {
	var commit, discard, confirm, forceCommit, acceptTorn, overwriteNewer bool
	cmd := &cobra.Command{
		Use:   "resolve-pit-overlay <vm> <disk>",
		Short: "Show the verdict on, then commit or discard, a point-in-time copy overlay that holds a VM (admin)",
		Long: `A replication or replicate-volume copy of a running VM may leave a
point-in-time snapshot overlay (.<disk file>.lv-pit) beside the disk, holding
the guest's newest writes. When litevirt cannot verify that overlay against the
disk it holds the VM (lv inspect shows pitOverlayHeld; lv health shows a
pit_overlay.held condition) rather than start it on the bare disk. This command
is the admin's decision.

Without --confirm nothing is done: it prints the verdict and what each action
would do. The verdicts:

  matches       the disk is the file the overlay was taken of, unchanged:
                --commit keeps the window's writes
  half-written  a commit into the disk was cut short: only --commit makes the
                disk whole; --discard leaves it inconsistent
  pivoted       the overlay is already in the disk: --discard is the cleanup;
                --commit would overwrite the guest's newer writes
  unknown       the disk cannot be verified (replaced, restored, written
                since, no binding, or the VM ran on it without the overlay)

  --commit            write the overlay's blocks into the disk, then remove it.
                      Refused unless the verdict is matches or half-written.
  --force-commit      with --commit: commit whatever the verdict (experts only;
                      the overlay's backing file must still be this disk)
  --discard           delete the overlay and its writes
  --overwrite-newer-writes
                      with --force-commit: commit an overlay that is already
                      in the disk (verdict pivoted). That writes its old
                      blocks over the guest's newer writes; refused without
                      it, and asked for interactively if missing
  --accept-torn-disk  with --discard: discard although a commit had begun
                      writing the disk, which leaves it inconsistent; restoring
                      the disk from a backup or a replica is the alternative

The VM must not be running. Admin only. Audited.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if commit && discard {
				return fmt.Errorf("give one of --commit or --discard, not both")
			}
			if confirm && !commit && !discard {
				return fmt.Errorf("--confirm carries out --commit or --discard; give one")
			}
			if forceCommit && !commit {
				return fmt.Errorf("--force-commit goes with --commit")
			}
			if acceptTorn && !discard {
				return fmt.Errorf("--accept-torn-disk goes with --discard")
			}
			if overwriteNewer && !forceCommit {
				return fmt.Errorf("--overwrite-newer-writes goes with --force-commit")
			}
			action := ""
			switch {
			case commit:
				action = "commit"
			case discard:
				action = "discard"
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if forceCommit && confirm {
					// Ask the verdict first, and warn before anything is sent.
					dry, err := c.ResolvePITOverlay(ctx, &pb.ResolvePITOverlayRequest{VmName: args[0], DiskName: args[1]})
					if err != nil {
						return fmt.Errorf("resolve point-in-time overlay: %w", err)
					}
					fmt.Fprint(os.Stderr, forceCommitWarning)
					if dry.GetNeedsOverwriteNewerWrites() && !overwriteNewer {
						fmt.Fprintf(os.Stderr, overwriteNewerWarning, dry.GetVerdict(), dry.GetIfCommit())
						if !confirmOverwriteNewer(os.Stdin, os.Stderr) {
							return fmt.Errorf("refused: the overlay is already in the disk; pass --overwrite-newer-writes (or answer yes) to overwrite the newer writes")
						}
						overwriteNewer = true
					}
				}
				resp, err := c.ResolvePITOverlay(ctx, &pb.ResolvePITOverlayRequest{
					VmName: args[0], DiskName: args[1], Action: action, Confirm: confirm,
					ForceCommit: forceCommit, AcceptTornDisk: acceptTorn, OverwriteNewerWrites: overwriteNewer,
				})
				if err != nil {
					return fmt.Errorf("resolve point-in-time overlay: %w", err)
				}
				printPITResolve(os.Stdout, resp)
				if !resp.GetDone() && action != "" {
					return fmt.Errorf("nothing done: repeat with --confirm")
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&commit, "commit", false, "commit the overlay's writes into the disk (only on a safe verdict)")
	cmd.Flags().BoolVar(&discard, "discard", false, "delete the overlay and its writes")
	cmd.Flags().BoolVar(&confirm, "confirm", false, "carry the action out (without it, only report the verdict)")
	cmd.Flags().BoolVar(&forceCommit, "force-commit", false, "with --commit: commit whatever the verdict (experts only)")
	cmd.Flags().BoolVar(&acceptTorn, "accept-torn-disk", false, "with --discard: discard although a commit had begun writing the disk")
	cmd.Flags().BoolVar(&overwriteNewer, "overwrite-newer-writes", false, "with --force-commit: commit an overlay already in the disk, over the guest's newer writes")
	return cmd
}

// confirmOverwriteNewer asks, on a terminal only, for a typed "yes".
func confirmOverwriteNewer(in io.Reader, out io.Writer) bool {
	if !stdinIsTerminal() {
		return false
	}
	fmt.Fprint(out, "Type yes to overwrite the newer writes: ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	return strings.TrimSpace(line) == "yes"
}

func printPITResolve(w io.Writer, resp *pb.ResolvePITOverlayResponse) {
	fmt.Fprintf(w, "Overlay:  %s\nDisk:     %s\nBinding:  %s\n", resp.GetOverlay(), resp.GetDisk(), resp.GetBinding())
	if resp.GetVerdict() != "" {
		fmt.Fprintf(w, "Now:      %s\nOverlay now: %s\nBacking:  %s\nVerdict:  %s", resp.GetCurrent(), resp.GetOverlayCurrent(), resp.GetBackingFile(), resp.GetVerdict())
		if r := resp.GetVerdictReason(); r != "" {
			fmt.Fprintf(w, " (%s)", r)
		}
		fmt.Fprintf(w, "\n--commit:  %s\n--discard: %s\nAdvice:   %s\n", resp.GetIfCommit(), resp.GetIfDiscard(), resp.GetRecommendation())
	}
	fmt.Fprintln(w, resp.GetStatus())
}
