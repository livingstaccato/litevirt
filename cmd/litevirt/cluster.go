package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newClusterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Cluster management",
	}
	cmd.AddCommand(
		newClusterDigestCmd(),
		newClusterConvergeCmd(),
		newClusterAckLeaseTermCmd(),
		newClusterFailoverScopeCmd(),
		newClusterVoterCmd(),
		newClusterClaimCmd(),
	)
	return cmd
}

// lv cluster failover-scope [cluster|region] — show or change the cluster-wide
// failover_scope policy (docs/design/region-scoped-failover.md).
func newClusterFailoverScopeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "failover-scope [cluster|region]",
		Short: "Show or set whether failover quorum is cluster-wide or per region",
		Long: `With no argument, show the failover scope and every region's voting strength.

  cluster  (the default) one quorum over every voter: a host is fenced when a
           majority of the whole cluster reports it down, and its workloads may
           be recovered onto any active host, in any region.
  region   a host is fenced, and its workloads recovered, only by a majority of
           its OWN region's voters, and recovery stays in that region. A site
           partition then leaves the far site's workloads alone instead of
           letting the majority site fence them over the WAN.

A region with fewer than three voters cannot fence one of its own hosts, so
under region scope its hosts have no automatic failover. It is never widened to
the cluster-wide count; the table marks it, and the
litevirt_failover_regions_without_quorum gauge counts it. A witness counts as a
voter of its own region.

The policy is replicated and cluster-wide. Changing it needs the admin role,
refuses until every host runs a release that honours it (failover_scope_v1),
and refuses while any voter is unreachable from the host you are connected to,
because a change made from one side of a partition reaches only that side.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				var st *pb.FailoverScopeStatus
				var err error
				if len(args) == 1 {
					st, err = c.SetFailoverScope(ctx, &pb.SetFailoverScopeRequest{Scope: args[0]})
					if err != nil {
						return fmt.Errorf("set failover scope: %w", err)
					}
				} else {
					st, err = c.GetFailoverScope(ctx, &emptypb.Empty{})
					if err != nil {
						return fmt.Errorf("get failover scope: %w", err)
					}
				}
				printFailoverScope(os.Stdout, st)
				return nil
			})
		},
	}
}

func printFailoverScope(out io.Writer, st *pb.FailoverScopeStatus) {
	fmt.Fprintf(out, "Failover scope: %s\n", st.GetScope())
	if st.GetSetBy() != "" {
		fmt.Fprintf(out, "Set by:         %s at %s\n", st.GetSetBy(), st.GetUpdatedAt())
	}
	if !st.GetSettable() {
		fmt.Fprintln(out, "Changeable:     no — failover_scope_v1 has not latched on every host yet")
	}
	fmt.Fprintln(out)
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "REGION\tHOSTS\tWORKERS\tVOTERS\tWITNESSES\tQUORUM\tOWN FENCING\n")
	small := 0
	for _, r := range st.GetRegions() {
		own := "yes"
		if !r.GetCanFenceOwn() {
			own = "cannot fence its own hosts"
			if r.GetWorkers() > 0 {
				small++
			}
		}
		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%d\t%s\n", r.GetName(), r.GetHosts(), r.GetWorkers(),
			r.GetVoters(), r.GetVotingWitnesses(), r.GetQuorum(), own)
	}
	w.Flush()
	if st.GetScope() == "region" && small > 0 {
		fmt.Fprintf(out, "\n%d region(s) above hold workloads but have fewer than three voters. Their hosts are NOT\n"+
			"automatically fenced or recovered under region scope. Add voters (a witness counts), or\n"+
			"run 'lv cluster failover-scope cluster'.\n", small)
	}
}

// lv cluster acknowledge-lease-term — clear a contested lease term from the CONNECTED
// host's unresolved-tie register.
//
// Node-local on purpose, and the reason this command has no --host flag: the register
// lives in one daemon's memory, the RPC refuses peer certificates, and a node must not
// be able to silence its own split-brain evidence. So the operator points LV_HOST at
// each host the condition names and runs this there — the same per-host shape the
// handler and the ha.lww.unresolved condition already describe.
func newClusterAckLeaseTermCmd() *cobra.Command {
	var key string
	var term int64
	cmd := &cobra.Command{
		Use:     "acknowledge-lease-term",
		Aliases: []string{"ack-lease-term"},
		Short:   "Acknowledge a contested leader-lease term on the connected host",
		Long: `Two nodes each minted the same leader-lease term, and anti-entropy refused to
merge the disagreement — a deliberate safety fault, reported as the ha.lww.unresolved
health condition and as a SAFETY-FAULT row for leader_lease_terms in 'lv cluster digest'.

Lease-term rows are immutable, so there is no remediating write to wait for: the
condition stays dirty forever until a human says they have seen it. This records that
statement.

It clears EVIDENCE TRACKING, not the conflict. Both claims stay in the ledger, no
winner is picked, and the acknowledgement is written to the audit log with your
principal, the key and the term.

Node-local: acknowledge on EVERY host the condition names, pointing LV_HOST at each in
turn. Requires the cluster.lww.acknowledge verb (held by Operator and Admin).

More than two claims needs more than one run per host. An acknowledgement answers ONE
observed pair, and a host compares itself with one peer at a time, so a row contested by
N nodes presents N-1 distinct disagreements from any one seat. Each run answers whichever
is currently tracked; re-run until 'lv health' stops naming the host. Answers accumulate
rather than replacing each other, so runs cannot undo one another.

  --key    which lease: failover, rebalancer, dual_run_detector
  --term   the contested term, as reported by the health condition

Investigate BEFORE acknowledging: two live leaders for one lease means the fencing
token did its job and something upstream let both nodes believe they held the lease.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if key == "" || term <= 0 {
				return fmt.Errorf("--key and --term are both required (term starts at 1)")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.AcknowledgeLeaseTermTie(ctx, &pb.AcknowledgeLeaseTermTieRequest{
					Key: key, Term: term,
				})
				if err != nil {
					return fmt.Errorf("acknowledge %s term %d: %w", key, term, err)
				}
				// acknowledged=false is not an error — an already-acknowledged term, a
				// term that never contested, or a daemon that restarted since. Say which
				// state the operator is in rather than printing a bare boolean, because
				// "nothing to do here" and "done" lead to different next steps on the
				// remaining hosts.
				if resp.GetAcknowledged() {
					fmt.Printf("Acknowledged %s term %d on this host. Both claims remain in the ledger.\n", key, term)
				} else {
					fmt.Printf("No tracked tie for %s term %d on this host — already acknowledged, or this host never contested it.\n", key, term)
				}
				fmt.Println("Run this on every host `lv health` names; verify with `lv cluster digest`.")
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "lease key: failover, rebalancer or dual_run_detector")
	cmd.Flags().Int64Var(&term, "term", 0, "the contested lease term")
	return cmd
}

// lv cluster digest — per-table state digest for EVERY host, aggregated server-side (the
// connected host fans GetStateDigest/GetSensitiveStateDigest out to its peers), so it works
// from a single connection.
func newClusterDigestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "digest",
		Short: "Show per-table state digest for every host",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				dig, err := c.GetClusterStateDigest(ctx, &emptypb.Empty{})
				if err != nil {
					return fmt.Errorf("cluster digest: %w", err)
				}
				ver := digestVersions(dig)
				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "HOST\tTABLE\tROWS\tVER\tHASH\tTIES\n")
				for _, h := range dig.GetHosts() {
					for _, t := range h.GetTables() {
						if t.GetCount() == 0 && t.GetUnresolvedTies() == 0 {
							continue
						}
						ties := ""
						if t.GetUnresolvedTies() > 0 {
							ties = fmt.Sprintf("%d", t.GetUnresolvedTies())
							if a := t.GetAcknowledgedTies(); a > 0 {
								ties = fmt.Sprintf("%d (%d acknowledged)", t.GetUnresolvedTies(), a)
							}
						}
						fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\n",
							h.GetHostName(), t.GetName(), t.GetCount(), ver.label(t.GetName()), ver.hash(t.GetName(), t), ties)
					}
				}
				w.Flush()
				printCoverageGaps(dig)
				return nil
			})
		},
	}
}

// lv cluster converge — kick an immediate anti-entropy pass and verify cross-host convergence.
func newClusterConvergeCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:     "converge",
		Aliases: []string{"sync"},
		Short:   "Kick an immediate anti-entropy pass and report cross-host convergence",
		Long: `Cluster state converges automatically via anti-entropy (roughly once a minute) plus
WAL replication. This command ACCELERATES that (kick a pass now instead of waiting) and
VERIFIES it (report per-table digest convergence across hosts). It does not merge or repair
state by itself.

  --all   relay the kick to every active peer as well (default: only the connected host)

Divergence caused by a deliberate safety fault — unresolved equal-timestamp LWW ties, which
anti-entropy will NOT auto-merge — is labelled as such; resolve those with
'lv doctor repair-owner', not by re-running this. For a row-level scan use 'lv doctor divergence'.

A table held apart only by ties that every host has acknowledged ('lv cluster
acknowledge-lease-term'), with nothing else different, is listed as ACKNOWLEDGED and
counts as converged. One unacknowledged tie on any host keeps it a SAFETY-FAULT.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.CalledAs() == "sync" {
				fmt.Fprintln(os.Stderr, "note: `lv cluster sync` is deprecated — use `lv cluster converge`")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				tr, err := c.TriggerAntiEntropy(ctx, &pb.TriggerAntiEntropyRequest{All: all})
				if err != nil {
					return fmt.Errorf("trigger anti-entropy: %w", err)
				}
				printTriggerSummary(tr)
				dig, err := c.GetClusterStateDigest(ctx, &emptypb.Empty{})
				if err != nil {
					return fmt.Errorf("cluster digest: %w", err)
				}
				printConvergence(dig)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "relay the anti-entropy kick to every active peer")
	return cmd
}

func printTriggerSummary(tr *pb.TriggerAntiEntropyResponse) {
	line := func(label string, hosts []string) {
		if len(hosts) > 0 {
			fmt.Printf("  %-12s %s\n", label+":", strings.Join(hosts, ", "))
		}
	}
	fmt.Println("Anti-entropy pass:")
	line("triggered", tr.GetTriggered())
	line("debounced", tr.GetDebounced()) // ran too recently — a pass is already fresh
	line("unreachable", tr.GetUnreachable())
	line("older-binary", tr.GetUnsupported())
}

// digestVersion resolves, per table, which digest the operator commands compare and
// display: the order-invariant digest_v2 hash ONLY when EVERY host reporting that table
// supplied hash_v2 (⇒ all have digest_v2 enabled), else the positional v1 hash. This
// mirrors the pairwise field-presence negotiation the anti-entropy path uses, so a mixed
// cluster (some hosts pre-v2 / flag-off) is compared on v1 in both directions — never a
// spurious v1-vs-v2 mismatch, and never a false converge.
type digestVersion struct {
	v2 map[string]bool // table -> compare/display v2
}

func digestVersions(dig *pb.ClusterStateDigestResponse) digestVersion {
	seen := map[string]bool{}  // table -> reported by at least one host
	allV2 := map[string]bool{} // table -> every reporting host supplied hash_v2 (so far)
	for _, h := range dig.GetHosts() {
		for _, t := range h.GetTables() {
			name := t.GetName()
			if !seen[name] {
				seen[name] = true
				allV2[name] = true
			}
			if t.GetHashV2() == "" {
				allV2[name] = false
			}
		}
	}
	return digestVersion{v2: allV2}
}

func (d digestVersion) label(table string) string {
	if d.v2[table] {
		return "v2"
	}
	return "v1"
}

// hash returns the version-appropriate hash for one host's table digest.
func (d digestVersion) hash(table string, t *pb.TableDigest) string {
	if d.v2[table] {
		return t.GetHashV2()
	}
	return t.GetHash()
}

// convergenceRepairTables lists tables whose equal-timestamp safety-fault divergence
// `lv doctor repair-owner` can restamp — today only VM ownership (the `vms` table;
// RepairVMOwner updates it after proving the VM runs on the claimed host). Any other
// table needs `lv doctor divergence` + its own table-specific remediation — emitting a
// blanket repair-owner suggestion from a table digest alone would be wrong.
var convergenceRepairTables = map[string]bool{"vms": true}

// printConvergence groups the per-host digests by table and reports each table's convergence,
// distinguishing real drift from deliberate safety-fault ties. Converged tables are summarized,
// not listed. Comparison is version-aware (see digestVersions): v2 iff every host emits it.
func printConvergence(dig *pb.ClusterStateDigestResponse) {
	ver := digestVersions(dig)
	tables := map[string]map[string]string{}  // table -> host -> version-appropriate hash
	ties := map[string]int32{}                // table -> total unresolved ties across hosts
	acked := map[string]int32{}               // table -> the acknowledged subset of ties
	residuals := map[string]map[string]bool{} // table -> distinct acknowledged residuals
	unproven := map[string]bool{}             // table -> some host cannot vouch for a residual
	var order []string
	for _, h := range dig.GetHosts() {
		for _, t := range h.GetTables() {
			name := t.GetName()
			if _, ok := tables[name]; !ok {
				tables[name] = map[string]string{}
				residuals[name] = map[string]bool{}
				order = append(order, name)
			}
			tables[name][h.GetHostName()] = ver.hash(name, t)
			ties[name] += t.GetUnresolvedTies()
			a := t.GetAcknowledgedTies()
			if a > t.GetUnresolvedTies() {
				a = t.GetUnresolvedTies()
			}
			acked[name] += a
			// Every host must vouch: hold ties here, all of them acknowledged,
			// and a residual. A host that tracks nothing for the table cannot
			// say its difference is the acknowledged rows.
			if t.GetUnresolvedTies() == 0 || a != t.GetUnresolvedTies() || t.GetAcknowledgedResidual() == "" {
				unproven[name] = true
			} else {
				residuals[name][t.GetAcknowledgedResidual()] = true
			}
		}
	}
	sort.Strings(order)

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "\nTABLE\tVER\tSTATUS\tDETAIL\n")
	converged := 0
	for _, name := range order {
		hosts := tables[name]
		hashes := map[string]bool{}
		for _, h := range hosts {
			hashes[h] = true
		}
		live := ties[name] - acked[name]
		switch {
		case len(hashes) <= 1:
			converged++
		case live == 0 && acked[name] > 0 && !unproven[name] && len(residuals[name]) == 1:
			// Held apart only by ties every host has acknowledged, and every
			// host's residual (the table with those rows masked) agrees, so
			// nothing else differs. Converged, and listed, because the two
			// claims are still there and still evidence.
			converged++
			fmt.Fprintf(w, "%s\t%s\tACKNOWLEDGED\t%d acknowledged tie(s) — both claims kept; nothing else differs\n",
				name, ver.label(name), acked[name])
		case ties[name] > 0:
			remedy := "run `lv doctor divergence` and apply the table-specific remediation"
			if convergenceRepairTables[name] {
				remedy = "run `lv doctor repair-owner`"
			}
			var detail string
			switch {
			case acked[name] == 0:
				detail = fmt.Sprintf("%d unresolved tie(s) — deliberate", ties[name])
			case live > 0:
				detail = fmt.Sprintf("%d unacknowledged tie(s) and %d acknowledged — deliberate", live, acked[name])
			default:
				// Every tie acknowledged, but some host could not vouch that
				// nothing else differs, or the hosts disagree on what else is
				// there. Not converged: that is where drift would hide.
				detail = fmt.Sprintf("%d acknowledged tie(s), but the rest of the table is not proven equal on every host", acked[name])
			}
			fmt.Fprintf(w, "%s\t%s\tSAFETY-FAULT\t%s; %s\n", name, ver.label(name), detail, remedy)
		default:
			fmt.Fprintf(w, "%s\t%s\tDIVERGENT\thashes differ across %d hosts (drift)\n", name, ver.label(name), len(hosts))
		}
	}
	w.Flush()
	fmt.Printf("\n%d/%d table(s) converged across %d reporting host(s).\n", converged, len(order), len(dig.GetHosts()))
	printCoverageGaps(dig)
}

func printCoverageGaps(dig *pb.ClusterStateDigestResponse) {
	if len(dig.GetUnreachable()) > 0 {
		fmt.Printf("⚠ unreachable (state NOT verified): %s\n", strings.Join(dig.GetUnreachable(), ", "))
	}
	if len(dig.GetUnsupported()) > 0 {
		fmt.Printf("⚠ older binary (no cluster-digest RPC): %s\n", strings.Join(dig.GetUnsupported(), ", "))
	}
}
