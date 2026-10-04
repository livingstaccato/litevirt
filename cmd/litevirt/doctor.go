package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// newDoctorCmd groups read-only cluster-health diagnostics.
func newDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Cluster diagnostics and repairs",
		Long: `Cluster-health diagnostics and targeted repairs.

Most subcommands are read-only (e.g. 'divergence'). A few mutate cluster state
to remediate a diagnosed problem (e.g. 'repair-owner') — those are admin-gated
and audited; check each subcommand's help before running it.`,
	}
	cmd.AddCommand(newDoctorDivergenceCmd(), newDoctorRepairOwnerCmd(), newDoctorMachineTypesCmd(),
		newDoctorVMUUIDsCmd(), newDoctorFenceCmd(), newDoctorCPUModeCmd(), newDoctorMigrationTLSCmd())
	return cmd
}

func newDoctorRepairOwnerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "repair-owner <vm> <host>",
		Short: "Re-assert a VM's owner on the host that runs it (converge an equal-timestamp ownership split)",
		Long: `Re-stamp a VM's ownership with a fresh timestamp on <host>, which must be the
host that actually runs the VM. The daemon forwards the request to <host> and
applies the write ONLY if that host confirms the VM is running locally — so it
can never point ownership at a host that doesn't run the VM. It rewrites only the
VM's DB row (host_name, state=running, cleared state_detail, fresh timestamp); it
never touches the running domain, so it cannot move or destroy a workload.

Use it to converge a stale bystander host_name left by an equal-timestamp
last-writer-wins split that a stationary VM can't self-heal — find such rows with
'lv doctor divergence'. Requires the vm.repair-owner permission on the VM's path
(admin by default); audited.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.RepairVMOwner(ctx, &pb.RepairVMOwnerRequest{Name: args[0], Host: args[1]})
				if err != nil {
					return fmt.Errorf("repair owner: %w", err)
				}
				fmt.Printf("vm %s owner re-asserted on %s (was %s); a fresh timestamp will converge stale peers\n",
					args[0], resp.GetHost(), resp.GetPreviousHost())
				return nil
			})
		},
	}
}

func newDoctorDivergenceCmd() *cobra.Command {
	var jsonOut, includeSensitive bool
	var tables []string
	cmd := &cobra.Command{
		Use:   "divergence",
		Short: "Report replicated rows that diverge across cluster nodes",
		Long: `Scan every active node and report rows of replicated state that disagree
across nodes, plus cluster-wide semantic-invariant violations (e.g. the same
container name live on two hosts). Read-only — it never writes or merges state.

Divergences are reported only when they persist across two samples (an in-flight
replication delta is filtered out). --include-sensitive also scans secret-bearing
tables over the peer-mTLS lane, reporting only keyed HMAC labels (never plaintext).

A contested row that every host holding it has acknowledged ('lv cluster
acknowledge-lease-term'), in a table where nothing else differs, is listed under
"Acknowledged ties" as acknowledged_tie and is not counted as a divergence: the
rule 'lv cluster converge' uses for ACKNOWLEDGED. A tie acknowledged on only some
hosts stays a divergence, and its line names the hosts still to acknowledge it.

Run this BEFORE any remediation that changes merge behavior — convergence
destroys the per-node evidence.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				rep, err := c.DiagnoseDivergence(ctx, &pb.DiagnoseDivergenceRequest{
					IncludeSensitive: includeSensitive,
					Tables:           tables,
				})
				if err != nil {
					return fmt.Errorf("diagnose divergence: %w", err)
				}
				if jsonOut {
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					return enc.Encode(rep)
				}
				renderDivergenceReport(rep)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the full report as JSON")
	cmd.Flags().BoolVar(&includeSensitive, "include-sensitive", false, "also scan secret-bearing tables (HMAC labels only)")
	cmd.Flags().StringSliceVar(&tables, "table", nil, "restrict to these tables (repeatable)")
	return cmd
}

func renderDivergenceReport(rep *pb.DivergenceReport) {
	fmt.Printf("scanned %d node(s): %s\n", len(rep.GetNodesScanned()), strings.Join(rep.GetNodesScanned(), ", "))
	if u := rep.GetNodesUnreachable(); len(u) > 0 {
		fmt.Printf("UNREACHABLE (not scanned): %s\n", strings.Join(u, ", "))
	}
	if su := rep.GetSensitiveUnreachable(); len(su) > 0 {
		fmt.Printf("SENSITIVE LANE PARTIAL (secret tables NOT scanned on): %s\n", strings.Join(su, ", "))
	}
	fmt.Printf("samples: %d   stable: %t\n", rep.GetSamples(), rep.GetStable())
	if !rep.GetStable() {
		fmt.Println("WARNING: cluster was not quiescent across the scan — a stuck_different may be replication backlog; re-run when settled.")
	}

	// An acknowledged tie (every host holding it has acknowledged it, and
	// nothing else in its table differs: what `lv cluster converge` lists as
	// ACKNOWLEDGED) is listed, since both claims are kept, but it is not a
	// divergence and does not keep the scan from reading clean.
	var diverging, acknowledged []*pb.DivergenceRow
	for _, r := range rep.GetRows() {
		if r.GetClass() == ackTieClass {
			acknowledged = append(acknowledged, r)
		} else {
			diverging = append(diverging, r)
		}
	}

	if len(diverging) == 0 && len(rep.GetViolations()) == 0 {
		fmt.Println("\nno divergence detected.")
	}

	if len(diverging) > 0 {
		fmt.Printf("\nDiverging rows (%d):\n", len(diverging))
		printDivergenceRows(diverging)
	}
	if len(acknowledged) > 0 {
		fmt.Printf("\nAcknowledged ties (%d) — both claims kept; not counted as divergence:\n", len(acknowledged))
		printDivergenceRows(acknowledged)
	}

	if vs := rep.GetViolations(); len(vs) > 0 {
		fmt.Printf("\nSemantic-invariant violations (%d):\n", len(vs))
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "KIND\tKEY\tHOSTS\tDETAIL")
		for _, v := range vs {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", v.GetKind(), v.GetKey(), strings.Join(v.GetHosts(), ","), v.GetDetail())
		}
		_ = w.Flush()
	}
}

// ackTieClass is corrosion.ClassAcknowledgedTie, spelled here so the CLI
// matches the class the server assigns.
const ackTieClass = string(corrosion.ClassAcknowledgedTie)

func printDivergenceRows(rows []*pb.DivergenceRow) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TABLE\tPK\tCLASS\tPER-NODE (host=updated_at/hash)")
	for _, r := range rows {
		parts := make([]string, 0, len(r.GetPerNode()))
		for _, m := range r.GetPerNode() {
			h := shortHash(m.GetRowHash())
			marker := ""
			if m.GetDeleted() {
				marker = " (deleted)"
			}
			parts = append(parts, fmt.Sprintf("%s=%s/%s%s", m.GetHost(), m.GetUpdatedAt(), h, marker))
		}
		// A row in a table where some host acknowledged a tie, that is not
		// itself acknowledged_tie: say who is still to acknowledge, or that
		// everyone has and something else in the table differs.
		switch off := r.GetTieUnacknowledgedOn(); {
		case len(off) > 0:
			parts = append(parts, fmt.Sprintf("(tie not acknowledged on %s)", strings.Join(off, ",")))
		case len(r.GetTieAcknowledgedOn()) > 0 && r.GetClass() != ackTieClass:
			parts = append(parts, "(tie acknowledged on every host, but the table differs elsewhere)")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.GetTable(), r.GetPk(), r.GetClass(), strings.Join(parts, "  "))
	}
	_ = w.Flush()
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
