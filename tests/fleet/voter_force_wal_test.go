// Fleet scenario: a forced voter generation reaching a node over the WAL push
// path (docs/design/recovery-claims.md §4.6 "Adopting a forced row", §10
// items 26 and 31), colonelpanik/litevirt#250.
//
// TestFleet_VoterForceReconfigure covers the forced row on the survivors, and
// the voter_configs merge test covers it through anti-entropy. Neither pins
// what a node that is NOT a survivor does when the row arrives the ordinary
// way, as one entry of the driver's mutation_log over PushMutations. That is
// what this does, with no anti-entropy pass running anywhere until the
// scenario runs one.
//
// What the WAL path does: voter_configs is DispCustomMerge, so the insert is
// applied as INSERT OR IGNORE — the first row a node holds for a generation
// stays.
//
//   - With no row for the generation, the forced row lands by WAL alone, and
//     the node adopts it after its own checks (verifyForcedRow): the lost
//     hosts' fences, the survivors' unanimous signatures, and its own probes
//     of the lost hosts.
//   - Holding an ordinary row for the generation that it has not adopted, the
//     node keeps that row on WAL apply and the forced row is dropped there
//     without a conflict being flagged: the WAL path treats a row it already
//     holds as a re-delivery. The next anti-entropy pass replaces the
//     ordinary row with the forced one (voterConfigMergeKeepLocalRow), and
//     the node adopts it then. This is §10 item 26 as designed, not a gap: a
//     node holding an ordinary row it has not adopted votes under neither, so
//     waiting for the pass costs one anti-entropy interval of liveness and no
//     safety, and an ordinary row the node HAS adopted is never replaced on
//     either path (item 31).
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestFleet_VoterForcedRowOverTheWALPushPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		// ordinary: the receiver already holds an ordinary generation-2 row
		// it has not adopted — one whose certificate does not verify here,
		// standing in for a generation the lost majority decided and the
		// receiver cannot import for.
		ordinary bool
	}{
		{name: "no-local-row"},
		{name: "ordinary-row-held", ordinary: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 6, IndependentReplicas: true, FaultSeed: 2901})
			n0, n1, n2, n3, n4, r := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3], c.Nodes[4], c.Nodes[5]
			c.WaitConverged(t, convergeTimeout)
			initVoters(t, c, r, n0, n1, n2, n3, n4)

			if tc.ordinary {
				// Beneath the replicator: only r holds it.
				r.DB.Mu().Lock()
				_, err := r.DB.DB().Exec(`INSERT INTO voter_configs
					(generation, members_json, members_hash, change, certificate, created_by, created_at, updated_at)
					VALUES (2, ?, 'h', ?, '{}', 'the lost majority', 't', ?)`,
					`[{"name":"`+n2.Name+`"},{"name":"`+n3.Name+`"},{"name":"`+n4.Name+`"}]`,
					"rm:"+n0.Name, time.Now().UTC().Format(time.RFC3339Nano))
				r.DB.Mu().Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}

			for _, n := range []*Node{n2, n3, n4} {
				c.Kill(n)
			}
			for _, n := range []*Node{n2, n3, n4} {
				fenceConfirm(t, c, n0, n)
			}
			// r's seeded row is the one difference by construction.
			c.WaitConvergedExcept(t, convergeTimeout, []string{"voter_configs"}, n0, n1, r)
			if resp, err := forceErr(t, c, n0, false, n2, n3, n4); err != nil || resp.GetGeneration() != 2 {
				t.Fatalf("force-reconfigure: %+v %v", resp, err)
			}

			// From here nothing runs anti-entropy, so whatever reaches r comes
			// over PushMutations. A marker n0 writes after the forced row
			// arriving on r means the forced row's entry has been applied on r
			// (one origin's entries are applied in order).
			c.ResetAEStats()
			PublishHealth(t, n0, "wal-marker", 1, time.Now().UTC())
			eventually(t, convergeTimeout, "n0's marker to reach r by WAL", func() bool {
				rows, err := r.DB.Query(ctx, `SELECT 1 AS one FROM host_health WHERE observer = ? AND target = 'wal-marker'`, n0.Name)
				return err == nil && len(rows) == 1
			})
			if ae := AEStatsTotal(c.AEStats()); ae.Calls != 0 {
				t.Fatalf("anti-entropy ran (%d calls); this scenario is about the WAL path alone", ae.Calls)
			}

			row := voterRow(t, r, 2)
			if row == nil {
				t.Fatal("r holds no generation-2 row after the WAL push")
			}
			_, _ = r.Server.AdoptVoterConfigs(ctx)
			if !tc.ordinary {
				if !corrosion.IsForcedChange(row.Change) {
					t.Fatalf("r's generation-2 row is %q, not the forced one", row.Change)
				}
				if g := adoptedGen(t, r); g != 2 {
					t.Fatalf("r did not adopt the forced generation that reached it by WAL (adopted %d)", g)
				}
				if got := voterNames(t, r); len(got) != 2 {
					t.Fatalf("r counts voters %v after adopting the forced generation", got)
				}
				return
			}

			// WAL apply kept the ordinary row; r votes under neither.
			if corrosion.IsForcedChange(row.Change) {
				t.Fatalf("the WAL path replaced r's ordinary generation-2 row with the forced one (%q); "+
					"§10 item 26 says only anti-entropy does", row.Change)
			}
			if g := adoptedGen(t, r); g != 1 {
				t.Fatalf("r adopted generation %d from a row it cannot verify", g)
			}

			// One anti-entropy pass on r settles it.
			corrosion.NewAntiEntropy(r.DB, r.PKIDir, 0).RunOnce(ctx)
			if row := voterRow(t, r, 2); row == nil || !corrosion.IsForcedChange(row.Change) {
				t.Fatalf("anti-entropy did not replace r's unadopted ordinary row with the forced one: %+v", row)
			}
			if _, err := r.Server.AdoptVoterConfigs(ctx); err != nil {
				t.Fatalf("adopt after anti-entropy: %v", err)
			}
			if g := adoptedGen(t, r); g != 2 {
				t.Fatalf("r did not adopt the forced generation after anti-entropy (adopted %d)", g)
			}
		})
	}
}
