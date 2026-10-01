package corrosion

import (
	"context"
	"testing"
	"time"
)

// bothSidesContested is contestedTermFixture with the tie tracked on BOTH
// nodes, as it is on a real cluster: each has met the other's claim.
func bothSidesContested(t *testing.T) (a, b *Client) {
	t.Helper()
	a, b = contestedTermFixture(t)
	if err := b.MergeStateBytesLWW(a.DumpStateBytes()); err != nil {
		t.Fatalf("anti-entropy a→b: %v", err)
	}
	if n := b.UnresolvedTieCount(); n != 1 {
		t.Fatalf("fixture: b tracks %d ties, want 1", n)
	}
	return a, b
}

func leaseTableHash(t *testing.T, c *Client) string {
	t.Helper()
	ds, err := c.StateDigest(context.Background())
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	for _, d := range ds {
		if d.Name == "leader_lease_terms" {
			return d.Hash
		}
	}
	t.Fatal("no leader_lease_terms digest")
	return ""
}

// Two hosts holding one acknowledged contested term, and nothing else
// different, agree on the residual although their table hashes differ.
func TestAcknowledgedResiduals_AgreeWhenOnlyAcknowledgedTiesDiffer(t *testing.T) {
	ctx := context.Background()
	a, b := bothSidesContested(t)
	tables := []string{"leader_lease_terms"}

	if r := a.AcknowledgedResiduals(ctx, tables); len(r) != 0 {
		t.Fatalf("a residual was emitted for an UNACKNOWLEDGED tie (%v): the report would count "+
			"live evidence converged", r)
	}
	for _, c := range []*Client{a, b} {
		if ok, err := c.AcknowledgeLeaseTermTie(ctx, LeaseKeyFailover, 1, "op"); err != nil || !ok {
			t.Fatalf("acknowledge: ok=%v err=%v", ok, err)
		}
	}
	if leaseTableHash(t, a) == leaseTableHash(t, b) {
		t.Fatal("fixture: the table hashes agree, so the residual is not being tested")
	}
	if _, acked := a.TieTableCounts(); acked["leader_lease_terms"] != 1 {
		t.Errorf("TieTableCounts acknowledged = %v, want leader_lease_terms:1", acked)
	}
	ra, rb := a.AcknowledgedResiduals(ctx, tables)["leader_lease_terms"], b.AcknowledgedResiduals(ctx, tables)["leader_lease_terms"]
	if ra == "" || rb == "" {
		t.Fatalf("no residual after acknowledgement (a=%q b=%q)", ra, rb)
	}
	if ra != rb {
		t.Errorf("residuals differ (%s vs %s) although the only difference is the acknowledged tie", ra, rb)
	}
}

// Drift beside an acknowledged tie is not hidden by it: the residuals differ.
func TestAcknowledgedResiduals_DisagreeWhenAnotherRowDiffers(t *testing.T) {
	ctx := context.Background()
	a, b := bothSidesContested(t)
	for _, c := range []*Client{a, b} {
		if ok, err := c.AcknowledgeLeaseTermTie(ctx, LeaseKeyFailover, 1, "op"); err != nil || !ok {
			t.Fatalf("acknowledge: ok=%v err=%v", ok, err)
		}
	}
	// A row only a holds, written beneath the replicator.
	now := time.Now().UTC().Format(time.RFC3339Nano)
	a.mu.Lock()
	_, err := a.db.Exec(`INSERT INTO leader_lease_terms (key, term, holder, acquired_at, created_at, updated_at)
		VALUES ('rebalancer', 4, 'host-a', ?, ?, ?)`, now, now, now)
	a.mu.Unlock()
	if err != nil {
		t.Fatalf("seed drift: %v", err)
	}
	tables := []string{"leader_lease_terms"}
	ra, rb := a.AcknowledgedResiduals(ctx, tables)["leader_lease_terms"], b.AcknowledgedResiduals(ctx, tables)["leader_lease_terms"]
	if ra == "" || rb == "" {
		t.Fatalf("no residual (a=%q b=%q)", ra, rb)
	}
	if ra == rb {
		t.Error("the residuals agree although a holds a row b does not: drift would be counted " +
			"converged behind an acknowledged tie")
	}
}
