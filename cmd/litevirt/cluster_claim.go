package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// lv cluster claim <kind>/<name> — diagnose a workload's recovery claim
// (docs/design/recovery-claims.md §5.4).
func newClusterClaimCmd() *cobra.Command {
	var epoch int64
	cmd := &cobra.Command{
		Use:   "claim <kind>/<name>",
		Short: "Show every voter's recorded state for a workload's recovery claim",
		Long: `A recovery claim is decided by a majority of the explicit voter set before a
coordinator mints a reschedule, promote or relocate proof. This asks every member of
the adopted voter generation for its recorded state for the workload's claim keys —
(kind, name, owner_epoch, attempt) — and prints, per attempt and per voter, the promised
and accepted ballot, the accepted value's digest, destination and source, whether the
voter's incarnation matches its entry, and its last refusal with the detail (for example
"node-3 still reaches node-2"). It is where a stuck claim is diagnosed.

  kind      vm or container
  --epoch   inspect this owner epoch instead of the workload's current one`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kind, name, ok := strings.Cut(args[0], "/")
			if !ok || name == "" {
				return fmt.Errorf("want <kind>/<name>, for example vm/db-1")
			}
			req := &pb.InspectRecoveryClaimRequest{Kind: kind, Name: name}
			if cmd.Flags().Changed("epoch") {
				req.OwnerEpoch, req.EpochSet = epoch, true
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.InspectRecoveryClaim(ctx, req)
				if err != nil {
					return fmt.Errorf("cluster claim: %w", err)
				}
				printClaimInspection(resp)
				return nil
			})
		},
	}
	cmd.Flags().Int64Var(&epoch, "epoch", 0, "owner epoch to inspect (default: the workload's current one)")
	return cmd
}

// lv cluster claim-release <kind>/<name> — release one workload's legacy-held
// claim (docs/design/recovery-claims.md §10 item 37).
func newClusterClaimReleaseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "claim-release <kind>/<name>",
		Short: "Release a recovery held by a legacy decision stuck in flight on a live destination",
		Long: `For one workload that ha.claim.legacy_held holds: its recovery claim re-proposed a
decision made before claim_incarnation_v1 latched, and that decision's proof is stuck
in flight on a destination that is still up, so the destination cannot show it will
never run.

The destination does the release, not this command. It is asked to confirm, from
its own state and under the workload's own locks, that nothing runs the proof — no
start or operation holds the workload and no live domain or container of its name
exists there — and only then to sign that it will never run it. Once that is
recorded no runner can take the proof again, the destination's own included. The
next recovery tick then decides the workload afresh.

It is refused when the destination does not answer: only the destination can
confirm the proof is not running. If it is gone for good, use
` + "`lv host fence-confirm <host>`" + ` once it is powered off, then
` + "`lv host rm --dead <host>`" + `. It is also refused when the destination finds
anything that might run the proof. When the request reached the destination but no
verified answer came back, the outcome is reported as unknown: run the command again
(a release already recorded is signed again) or check ` + "`lv cluster claim <kind>/<name>`" + `.
Every call is audited (recovery_claim.release: ok, refused or unknown).

  kind   vm or container

Requires the admin role.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kind, name, ok := strings.Cut(args[0], "/")
			if !ok || name == "" {
				return fmt.Errorf("want <kind>/<name>, for example vm/db-1")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ReleaseLegacyHeldClaim(ctx, &pb.ReleaseLegacyHeldClaimRequest{Kind: kind, Name: name})
				if err != nil {
					return fmt.Errorf("cluster claim-release: %w", err)
				}
				fmt.Printf("released: %s abandoned proof %s at %s\n", resp.GetDestHost(), resp.GetProofId(), resp.GetKey())
				fmt.Println(resp.GetDetail())
				return nil
			})
		},
	}
}

func printClaimInspection(resp *pb.InspectRecoveryClaimResponse) {
	fmt.Println(resp.GetDetail())
	for _, a := range resp.GetAttempts() {
		k := a.GetKey()
		if inc := k.GetIncarnation(); inc != "" {
			fmt.Printf("\nAttempt %d (key %s/%s(%s)@%d#%d)", k.GetAttempt(), k.GetTargetKind(), k.GetTargetName(), inc, k.GetOwnerEpoch(), k.GetAttempt())
		} else {
			fmt.Printf("\nAttempt %d (key %s/%s@%d#%d)", k.GetAttempt(), k.GetTargetKind(), k.GetTargetName(), k.GetOwnerEpoch(), k.GetAttempt())
		}
		if a.GetDecidedDigest() != "" {
			fmt.Printf(": DECIDED for %s (value %s)\n", a.GetDecidedDest(), shortDigest(a.GetDecidedDigest()))
		} else {
			fmt.Println(": no value accepted by a majority")
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintf(w, "VOTER\tPROMISED\tACCEPTED\tVALUE\tPROOF\tDEST\tSOURCE\tINCARNATION\tLAST REFUSAL\n")
		for _, v := range a.GetVoters() {
			if !v.GetReachable() {
				fmt.Fprintf(w, "%s\t-\t-\t-\t-\t-\t-\t-\tunreachable: %s\n", v.GetVoter(), v.GetError())
				continue
			}
			inc := "ok"
			if !v.GetIncarnationOk() {
				inc = "MISMATCH (abstains)"
			}
			refusal := v.GetLastRefusal()
			if d := v.GetLastRefusalDetail(); d != "" {
				refusal += ": " + d
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", v.GetVoter(), dash(v.GetPromised()), dash(v.GetAccepted()),
				dash(shortDigest(v.GetValueDigest())), dash(v.GetProofId()), dash(v.GetDestHost()), dash(v.GetSourceHost()), inc, dash(refusal))
		}
		w.Flush()
	}
}

func shortDigest(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
