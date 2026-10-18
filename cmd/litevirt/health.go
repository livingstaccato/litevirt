package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// silentExitError carries an exit code without a printable message. The root
// command recognizes it and exits with the code, printing NOTHING — a health
// report that ends "overall: CRITICAL" must not be followed by a generic
// "Error: exit status 2" line that buries the report it annotates.
type silentExitError struct{ code int }

func (e silentExitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// exitCodeOf returns (code, true) when err carries a silent typed exit.
func exitCodeOf(err error) (int, bool) {
	var se silentExitError
	if errors.As(err, &se) {
		return se.code, true
	}
	return 0, false
}

// healthExitCode maps the overall state to the scriptable contract:
// 0 healthy · 1 degraded or unknown · 2 critical.
func healthExitCode(overall string) int {
	switch overall {
	case "HEALTHY":
		return 0
	case "CRITICAL":
		return 2
	default: // DEGRADED, UNKNOWN, or anything unrecognized
		return 1
	}
}

func newHealthCmd() *cobra.Command {
	var includeResolved bool
	cmd := &cobra.Command{
		Use:   "health",
		Short: "Show cluster health: conditions, coverage, connectivity",
		Long: `Show the cluster's health: the overall state, every active condition with its
lifecycle and involved hosts, evaluator coverage, and peer connectivity.

Exit code: 0 healthy · 1 degraded or unknown · 2 critical.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.GetClusterHealth(ctx, &pb.GetClusterHealthRequest{IncludeResolved: includeResolved})
				if err != nil {
					return fmt.Errorf("get cluster health: %w", err)
				}
				printClusterHealth(resp)
				if code := healthExitCode(resp.GetOverall()); code != 0 {
					return silentExitError{code: code}
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&includeResolved, "resolved", false, "include recently-resolved conditions (30-day history)")
	cmd.AddCommand(newHealthResolveCmd())
	return cmd
}

// lv health resolve — mark one open dual-run or move-volume condition
// resolved by hand.
func newHealthResolveCmd() *cobra.Command {
	var evaluator, reason string
	var accept []string
	cmd := &cobra.Command{
		Use:   "resolve <code> <kind/subject>",
		Short: "Resolve an open dual-run or move-volume health condition by hand (admin, audited)",
		Long: `Mark one open condition resolved, named as 'lv health' prints it:
its CODE and its SUBJECT (kind/id), for example

  lv health resolve runtime_owner_mismatch vm/web-1 --reason "VM deleted"

Only the dual-run detector's conditions (vm_dual_run, ct_dual_run,
vip_dual_run, runtime_owner_mismatch, owner_epoch_mismatch,
owner_epoch_suppressed, coverage_gap, lww_unresolved) can be resolved this
way. They are the ones that gate admission, and the detector re-derives them
every pass: one that still holds is raised again, and blocks admission again,
on its next pass. It is refused until the detector has looked and not seen
the condition: a scan later than its last sighting that completely probed
every host it names. Resolving proves nothing; use it for a condition the
detector can no longer clear by itself.

An unresolved volume move (vm.move_unresolved) can be resolved this way too,
with --reason: run against the host holding the move's record, which removes
it, or from any host once that host is proven powered off (fenced or removed
over an IPMI power-off or an operator's lv host fence-confirm). It is refused
otherwise: that host settles the move itself. 'lv health' lists each move's
two files, whether the guest was pivoted, and its error: read them first.

--accept <path> names the file to keep of one disk's move, once per disk.
The disk record is pointed at it first, only on the VM's owner, where that
file is its own or on a mounted shared pool it and the holding host define
alike; on a holding host that does not own the VM, --accept may only name the
file the disk record names. A move the disk record does not settle (a live
move with no pivot recorded) is refused without one: nothing in the cluster
knows which file the guest wrote last, unless the holding host owns the VM
and its persistent config and disk record name the source. On the VM's owner,
with its domain defined, its persistent config must name the file each disk
record is left on, and no disk record is changed while it is active. After a
pivot only the copy is accepted, except on the VM's owner when the VM changed
hands after the move began and its config names the file the disk record
names: --accept of that file keeps the owner's writes since, and the copy is
kept on disk (docs/diagnostics.md, "A forked history").

Requires the cluster.health.resolve verb (Admin). The resolution is written
to the audit log with your principal and --reason, and published as an
ha.condition.resolved event.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			kind, id, ok := strings.Cut(args[1], "/")
			if !ok || kind == "" || id == "" {
				return fmt.Errorf("subject %q: want kind/id as `lv health` prints it, e.g. vm/web-1", args[1])
			}
			if len(accept) > 0 && args[0] != moveUnresolvedCode {
				return fmt.Errorf("--accept applies only to %s, not %s", moveUnresolvedCode, args[0])
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				for _, a := range accept {
					ctx = metadata.AppendToOutgoingContext(ctx, moveAcceptMDKey, a)
				}
				resp, err := c.ResolveHealthCondition(ctx, &pb.ResolveHealthConditionRequest{
					Code: args[0], SubjectKind: kind, SubjectId: id,
					Evaluator: evaluator, Reason: reason,
				})
				if err != nil {
					return fmt.Errorf("resolve %s on %s: %w", args[0], args[1], err)
				}
				h := resp.GetCondition()
				if h.GetCode() == moveUnresolvedCode {
					fmt.Printf("%s on %s/%s: %s.\n", h.GetCode(), h.GetSubjectKind(), h.GetSubjectId(), h.GetLifecycle())
					printMoveEvidence(h.GetEvidence())
					return nil
				}
				fmt.Printf("%s on %s/%s (%s): %s. If it still holds, the detector raises it again on its next pass.\n",
					h.GetCode(), h.GetSubjectKind(), h.GetSubjectId(), h.GetEvaluator(), h.GetLifecycle())
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&evaluator, "evaluator", "", "the evaluator, when two hold an open condition under the same code and subject")
	cmd.Flags().StringVar(&reason, "reason", "", "why, recorded in the audit log")
	cmd.Flags().StringArrayVar(&accept, "accept", nil, "vm.move_unresolved only: the file to keep of one disk's move; once per disk")
	return cmd
}

func printClusterHealth(h *pb.ClusterHealth) {
	fmt.Printf("overall: %s\n", h.GetOverall())
	for _, r := range h.GetReasons() {
		fmt.Printf("  - %s\n", r)
	}

	if conds := h.GetConditions(); len(conds) > 0 {
		fmt.Println("\nconditions:")
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  SEVERITY\tLIFECYCLE\tCODE\tSUBJECT\tHOSTS\tSINCE")
		for _, c := range conds {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s/%s\t%s\t%s\n",
				c.GetSeverity(), c.GetLifecycle(), c.GetCode(),
				c.GetSubjectKind(), c.GetSubjectId(),
				strings.Join(c.GetHosts(), ","), c.GetFirstSeen())
		}
		w.Flush()
		for _, c := range conds {
			if c.GetCode() == moveUnresolvedCode {
				fmt.Printf("\n%s on %s/%s:\n", c.GetCode(), c.GetSubjectKind(), c.GetSubjectId())
				printMoveEvidence(c.GetEvidence())
			}
		}
	}

	if evs := h.GetEvaluators(); len(evs) > 0 {
		fmt.Println("\nevaluators:")
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  EVALUATOR\tCOVERAGE\tLAST SCAN\tDETAIL")
		for _, e := range evs {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", e.GetEvaluator(), e.GetCoverage(), e.GetLastScan(), e.GetDetail())
		}
		w.Flush()
	}

	if edges := h.GetConnectivity(); len(edges) > 0 {
		fmt.Println("\nconnectivity:")
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  OBSERVER\tTARGET\tSTATUS\tFAILURES")
		for _, e := range edges {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%d\n", e.GetObserver(), e.GetTarget(), e.GetStatus(), e.GetConsecutiveFailures())
		}
		w.Flush()
	}

	if caps := h.GetCapacity(); len(caps) > 0 {
		fmt.Println("\ncapacity:")
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  HOST\tEFFECTIVE\tDB\tEXTRA\tCOMPLETE\tDETAIL")
		for _, c := range caps {
			fmt.Fprintf(w, "  %s\t%dc/%dMiB\t%s\t%dc/%dMiB\t%v\t%s\n",
				c.GetHostName(),
				c.GetEffectiveCpu(), c.GetEffectiveMemMib(),
				capacityDBCell(c),
				c.GetExtraCpu(), c.GetExtraMemMib(),
				c.GetComplete(), c.GetDetail())
		}
		w.Flush()
	}
}

// capacityDBCell renders the capacity table's DB column: what running VMs
// hold, then the memory running containers hold ("1c/768MiB +512MiB ct").
// Containers carry no cpu term — a container's cpu is a cap, not a
// reservation, and capacity never charges it.
func capacityDBCell(c *pb.HostCapacityAssessment) string {
	ct := c.GetDbCtMemMib()
	cell := fmt.Sprintf("%dc/%dMiB", c.GetDbCpu(), c.GetDbMemMib()-ct)
	if ct > 0 {
		cell += fmt.Sprintf(" +%dMiB ct", ct)
	}
	return cell
}

// moveAcceptMDKey and moveUnresolvedCode match grpcapi.MoveAcceptMDKey and
// health.MoveUnresolvedCode.
const (
	moveAcceptMDKey    = "x-litevirt-move-accept"
	moveUnresolvedCode = "vm.move_unresolved"
)

// printMoveEvidence prints the moves a vm.move_unresolved condition recorded,
// each with what is known of it and the error its move hit, so the operator
// sees what --accept chooses between before resolving.
func printMoveEvidence(evidence string) {
	var ev struct {
		Host  string `json:"host"`
		Moves []struct {
			Disk    string `json:"disk"`
			Src     string `json:"src"`
			Dst     string `json:"dst"`
			Live    bool   `json:"live"`
			Pivoted bool   `json:"pivoted"`
			CatchUp bool   `json:"catch_up"`
			Error   string `json:"error"`
		} `json:"moves"`
	}
	if json.Unmarshal([]byte(evidence), &ev) != nil {
		fmt.Println("  (evidence unreadable)")
		return
	}
	for _, m := range ev.Moves {
		fmt.Printf("  %s on %s: %s -> %s (live=%v pivoted=%v catch_up=%v)\n", m.Disk, ev.Host, m.Src, m.Dst, m.Live, m.Pivoted, m.CatchUp)
		switch {
		case m.Pivoted || m.CatchUp:
			fmt.Printf("    holds every write: %s\n", m.Dst)
		case m.Live:
			fmt.Println("    no pivot recorded: either file may hold the guest's last writes")
		default:
			fmt.Println("    offline move: both files hold the same data")
		}
		if m.Error != "" {
			fmt.Printf("    error: %s\n", m.Error)
		}
	}
}
