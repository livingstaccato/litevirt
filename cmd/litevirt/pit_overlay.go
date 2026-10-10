package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newResolvePITOverlayCmd() *cobra.Command {
	var commit, discard, confirm bool
	cmd := &cobra.Command{
		Use:   "resolve-pit-overlay <vm> <disk>",
		Short: "Commit or discard a point-in-time copy overlay that holds a VM (admin)",
		Long: `A replication or replicate-volume copy of a running VM may leave a
point-in-time snapshot overlay (.<disk file>.lv-pit) beside the disk, holding
the guest's newest writes. When litevirt cannot verify that overlay against the
disk — the disk was replaced or written since, or the overlay's binding is
missing — it holds the VM (lv inspect shows pitOverlayHeld) rather than start
it on the bare disk. This command is the admin's decision:

  --commit   write the overlay's blocks into the disk (they overwrite what the
             disk holds there), then remove the overlay
  --discard  delete the overlay and its writes for good

The VM must not be running. Without --confirm nothing is done: the command
prints the two files and the overlay's binding. Audited.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if commit == discard {
				return fmt.Errorf("give exactly one of --commit or --discard")
			}
			action := "commit"
			if discard {
				action = "discard"
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ResolvePITOverlay(ctx, &pb.ResolvePITOverlayRequest{
					VmName: args[0], DiskName: args[1], Action: action, Confirm: confirm,
				})
				if err != nil {
					return fmt.Errorf("resolve point-in-time overlay: %w", err)
				}
				fmt.Printf("Overlay: %s\nDisk:    %s\nBinding: %s\n%s\n", resp.GetOverlay(), resp.GetDisk(), resp.GetBinding(), resp.GetStatus())
				if !resp.GetDone() {
					return fmt.Errorf("nothing done: repeat with --confirm")
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&commit, "commit", false, "commit the overlay's writes into the disk")
	cmd.Flags().BoolVar(&discard, "discard", false, "delete the overlay and its writes")
	cmd.Flags().BoolVar(&confirm, "confirm", false, "carry the action out (without it, only report)")
	return cmd
}
