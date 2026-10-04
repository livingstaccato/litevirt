package corrosion

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// nWayContest gives local one lease term that three nodes claimed: local's own
// version plus the two peers', all met by anti-entropy.
func nWayContest(t *testing.T, local *Client) (peers []*Client) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	if held, term, err := AcquireLeaseWithTerm(ctx, local, LeaseKeyDualRun, "host-a", 30*time.Second, now); err != nil || !held || term != 1 {
		t.Fatalf("local acquire: held=%v term=%d err=%v", held, term, err)
	}
	for _, h := range []string{"host-b", "host-c"} {
		p := testClient(t)
		if held, term, err := AcquireLeaseWithTerm(ctx, p, LeaseKeyDualRun, h, 30*time.Second, now); err != nil || !held || term != 1 {
			t.Fatalf("%s acquire: held=%v term=%d err=%v", h, held, term, err)
		}
		peers = append(peers, p)
	}
	for _, p := range peers {
		if err := local.MergeStateBytesLWW(p.DumpStateBytes()); err != nil {
			t.Fatalf("anti-entropy: %v", err)
		}
	}
	if n := local.UnresolvedTieCount(); n != 1 {
		t.Fatalf("fixture: %d live ties, want the one contested row", n)
	}
	return peers
}

// One acknowledgement answers for the ROW as the operator saw it: every
// version of the contested term this node had met, not only the last peer.
//
// The register holds one pair per row, so in an N-way contest the pair names
// whichever peer anti-entropy met last. Acknowledging that pair left the
// others unanswered: the next pass against any other peer re-raised the tie,
// and after a restart the peers are met in whatever order the pass takes. On
// the lab, dual_run_detector term 2 (five claimants) needed four
// acknowledgements per node, an hour apart, before it stayed quiet.
func TestAcknowledgeLeaseTermTie_CoversEveryVersionSeenInAnNWayContest(t *testing.T) {
	ctx := context.Background()
	local := testClient(t)
	peers := nWayContest(t, local)

	if ok, err := local.AcknowledgeLeaseTermTie(ctx, LeaseKeyDualRun, 1, "op"); err != nil || !ok {
		t.Fatalf("acknowledge: ok=%v err=%v", ok, err)
	}
	// Meet the peers again, in both orders.
	for _, order := range [][]*Client{{peers[0], peers[1]}, {peers[1], peers[0]}} {
		for _, p := range order {
			if err := local.MergeStateBytesLWW(p.DumpStateBytes()); err != nil {
				t.Fatalf("anti-entropy: %v", err)
			}
			if n := local.UnresolvedTieCount(); n != 0 {
				t.Fatalf("a peer whose version this node had already met re-raised the acknowledged "+
					"term (live=%d): one acknowledgement must cover the row as the operator saw it", n)
			}
		}
	}
	if n := local.TrackedTieCount(); n != 1 {
		t.Errorf("TrackedTieCount = %d, want 1: the rows still disagree and the digest must say so", n)
	}
}

// The acknowledgement survives a restart, whichever peer the restarted node
// meets first, and a claim nobody saw is still raised.
func TestAcknowledgeLeaseTermTie_VersionSetSurvivesARestartInAnyOrder(t *testing.T) {
	ctx := context.Background()
	dsn := fmt.Sprintf("ackversions%d", testDBCounter.Add(1))
	before, err := NewSharedTestClient(dsn, "host-a")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer before.Close()
	if err := InitSchema(ctx, before); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	peers := nWayContest(t, before)
	if ok, err := before.AcknowledgeLeaseTermTie(ctx, LeaseKeyDualRun, 1, "op"); err != nil || !ok {
		t.Fatalf("acknowledge: ok=%v err=%v", ok, err)
	}

	after, err := NewSharedTestClient(dsn, "host-a")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer after.Close()
	if err := InitSchema(ctx, after); err != nil {
		t.Fatalf("InitSchema after restart: %v", err)
	}
	// The pair the operator acknowledged was (a, c). Meet c's peer LAST so the
	// first pair the restarted register sees is one the pair store never held.
	for _, p := range []*Client{peers[0], peers[1]} {
		if err := after.MergeStateBytesLWW(p.DumpStateBytes()); err != nil {
			t.Fatalf("post-restart anti-entropy: %v", err)
		}
		if n := after.UnresolvedTieCount(); n != 0 {
			t.Fatalf("the acknowledged term came back after a restart (live=%d)", n)
		}
	}
	if n := after.TrackedTieCount(); n != 1 {
		t.Fatalf("TrackedTieCount = %d after restart, want 1", n)
	}

	// A fourth claimant nobody acknowledged is new evidence.
	d := testClient(t)
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	if held, _, err := AcquireLeaseWithTerm(ctx, d, LeaseKeyDualRun, "host-d", 30*time.Second, now); err != nil || !held {
		t.Fatalf("host-d acquire: held=%v err=%v", held, err)
	}
	if err := after.MergeStateBytesLWW(d.DumpStateBytes()); err != nil {
		t.Fatalf("anti-entropy from host-d: %v", err)
	}
	if n := after.UnresolvedTieCount(); n != 1 {
		t.Fatalf("a new, different claim for the acknowledged term was covered by the old "+
			"acknowledgement (live=%d, want 1): evidence would be silently lost", n)
	}
	// And meeting an acknowledged peer afterwards must not hide it again.
	if err := after.MergeStateBytesLWW(peers[0].DumpStateBytes()); err != nil {
		t.Fatalf("anti-entropy: %v", err)
	}
	if n := after.UnresolvedTieCount(); n != 1 {
		t.Fatalf("re-meeting an acknowledged peer masked the unacknowledged claim (live=%d)", n)
	}
}

// A second acknowledgement of the same row, with nothing new seen, changes
// nothing and says so; once a new version has been seen, acknowledging again
// extends the answer to it.
func TestAcknowledgeLeaseTermTie_ReacknowledgingExtendsOnlyToNewVersions(t *testing.T) {
	ctx := context.Background()
	local := testClient(t)
	nWayContest(t, local)
	if ok, err := local.AcknowledgeLeaseTermTie(ctx, LeaseKeyDualRun, 1, "op"); err != nil || !ok {
		t.Fatalf("acknowledge: ok=%v err=%v", ok, err)
	}
	if ok, err := local.AcknowledgeLeaseTermTie(ctx, LeaseKeyDualRun, 1, "op"); err != nil || ok {
		t.Fatalf("a repeat acknowledgement with nothing new reported ok=%v err=%v, want false", ok, err)
	}
	rows, err := local.Query(ctx, `SELECT COUNT(*) AS n FROM acknowledged_tie_versions`)
	if err != nil {
		t.Fatalf("read acknowledged_tie_versions: %v", err)
	}
	if n := rows[0].Int("n"); n != 3 {
		t.Errorf("acknowledged_tie_versions holds %d version(s), want the 3 claims seen", n)
	}
}
