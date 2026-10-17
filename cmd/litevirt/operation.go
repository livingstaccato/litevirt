package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// newOperationCmd is the F1 admin recovery surface for an in-flight operation
// wedged on a VM's mutation barrier (active_operation_id). `show` inspects it;
// `abort` force-clears the barrier so the VM is mutable again.
func newOperationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "operation",
		Short: "Inspect and recover in-flight VM operations",
	}
	cmd.AddCommand(newOperationShowCmd(), newOperationAbortCmd(), newOperationReleaseReservationCmd())
	return cmd
}

func newOperationShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <vm>",
		Short: "Show the operation holding a VM's mutation barrier",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.GetVMOperation(ctx, &pb.GetVMOperationRequest{VmName: args[0]})
				if err != nil {
					return fmt.Errorf("get operation: %w", err)
				}
				if !resp.HasActive {
					fmt.Printf("%s: no in-flight operation\n", args[0])
					return nil
				}
				fmt.Printf("VM:              %s\n", args[0])
				fmt.Printf("Operation:       %s (%s)\n", resp.OperationId, resp.OperationKind)
				fmt.Printf("State:           %s\n", resp.CurrentState)
				if resp.Faulted {
					fmt.Printf("  ⚠ SAFETY FAULT: conflicting terminal states recorded\n")
				}
				if resp.HeaderMissing {
					fmt.Printf("  ⚠ barrier points at a missing operation header\n")
				}
				fmt.Printf("Owner epoch:     %d\nSpec generation: %d\n", resp.VmOwnerEpoch, resp.SpecGeneration)
				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(w, "STEP\tEPOCH\tRECORDED")
				for _, st := range resp.Steps {
					fmt.Fprintf(w, "%s\t%d\t%s\n", st.StepName, st.OwnerEpoch, st.CreatedAt)
				}
				return w.Flush()
			})
		},
	}
}

// errAbortScopedUnsupported refuses --operation against a daemon whose Ping
// lacks abort_scoped.
var errAbortScopedUnsupported = fmt.Errorf("the daemon serving this call predates --operation; nothing was aborted")

func newOperationAbortCmd() *cobra.Command {
	var force bool
	var operation string
	cmd := &cobra.Command{
		Use:   "abort <vm>",
		Short: "Force-clear a wedged operation's mutation barrier (admin recovery)",
		Long: `Force-clear the operation holding a VM's mutation barrier so the VM can be
mutated again. This is a deliberate recovery action for a wedged operation — it
clears the barrier only via the exact owner/generation compare-and-swap (a stale
or superseded operation can't clear a newer one). Requires --force.

With --operation <id>, the abort is refused unless <id> is the VM's active
operation, so an operation that finished, or was followed by another, between
lv operation show and the abort is never the one cleared. A daemon too old to
honour --operation is refused before anything is sent.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				return fmt.Errorf("--force is required to abort an operation")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				// An older daemon drops operation_id and aborts whatever is
				// active, so the scoped abort is sent only to one that says
				// it honours the field. There is no unscoped fallback.
				if operation != "" {
					ping, perr := c.Ping(ctx, &pb.PingRequest{})
					if perr != nil {
						return fmt.Errorf("cannot confirm the daemon honours --operation (ping: %w); nothing was aborted", perr)
					}
					if !ping.GetAbortScoped() {
						return errAbortScopedUnsupported
					}
				}
				resp, err := c.AbortVMOperation(ctx, &pb.AbortVMOperationRequest{VmName: args[0], Force: true, OperationId: operation})
				if err != nil {
					return fmt.Errorf("abort operation: %w", err)
				}
				if !resp.Aborted {
					fmt.Printf("not aborted: %s\n", resp.Detail)
					return nil
				}
				fmt.Printf("aborted operation %s on %s\n", resp.PreviousOperationId, args[0])
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Confirm the destructive abort")
	cmd.Flags().StringVar(&operation, "operation", "", "Abort only if this operation id is the VM's active operation")
	return cmd
}

// errReleaseReservationNeedsForce is the client-side refusal without --force.
var errReleaseReservationNeedsForce = fmt.Errorf("--force is required: check the reservation first with lv host inspect <host>")

func newOperationReleaseReservationCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "release-reservation <operation-id>",
		Short: "Release a host capacity reservation whose operation is no longer running (admin)",
		Long: `Release the host capacity reservation an operation holds when that operation
is no longer running, so admission stops counting it against its host.
lv host inspect <host> lists a host's reservations with their operation ids and
states; this is for a "stale" or "release-blocked" one, or a "releasable" one
before the sweep reaches it.

The release is decided on the reservation's target host, under the workload's
lock there. It is refused while the operation still runs or holds its VM's or
container's mutation barrier, while it may still be admitting, and for an
admission lease or a vm_replace or drain_cold_move journal.

Requires the host.reservation.release permission (Admin) and --force. Every
request, released or refused, is audited as operation.reservation.release.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				return errReleaseReservationNeedsForce
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ReleaseHostReservation(ctx, &pb.ReleaseHostReservationRequest{OperationId: args[0], Force: true})
				if err != nil {
					return fmt.Errorf("release reservation: %w", err)
				}
				if !resp.Released {
					fmt.Printf("%s: %s\n", args[0], resp.Detail)
					return nil
				}
				fmt.Printf("released %d vCPU/%d MiB on %s held by operation %s\n",
					resp.Vcpu, resp.MemoryMib, resp.Host, args[0])
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Confirm the release")
	return cmd
}
