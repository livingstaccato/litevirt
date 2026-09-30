package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedUnreplicatedStack writes a stacks row on n beneath the replicator — no
// mutation_log entry, so only anti-entropy can carry it anywhere.
func seedUnreplicatedStack(t *testing.T, n *Node, name string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	n.DB.Mu().Lock()
	_, err := n.DB.DB().Exec(
		`INSERT INTO stacks (name, compose_hash, compose_yaml, state, created_at, updated_at)
		 VALUES (?, 'h', 'services: {}', 'active', ?, ?)`, name, now, now)
	n.DB.Mu().Unlock()
	if err != nil {
		t.Fatalf("seed stack %s on %s: %v", name, n.Name, err)
	}
}

func hasStack(t *testing.T, n *Node, name string) bool {
	t.Helper()
	return rowCount(t, n, `SELECT COUNT(*) AS n FROM stacks WHERE name = ?`, name) == 1
}

// A drifted table is repaired over the paged StreamTableRows, and the full
// dump is not
// pulled for it (#262).
func TestFleet_AntiEntropy_RepairsOverTheTableDump(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	b.DB.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: a.Name}} })
	seedUnreplicatedStack(t, a, "drifted-stack")

	c.ResetAEStats()
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunOnce(context.Background()) {
		t.Fatal("the pass did not run")
	}
	if !hasStack(t, b, "drifted-stack") {
		t.Fatal("b did not receive the drifted stacks row")
	}
	st := c.AEStats()
	if st["StreamTableRows"].Calls == 0 {
		t.Errorf("the repair did not use the paged table pull: %+v", st)
	}
	if st["StreamStateDump"].Calls != 0 || st["GetStateDump"].Calls != 0 {
		t.Errorf("the full dump was pulled although the peer serves table dumps: %+v", st)
	}
}

// A peer on an older build answers StreamTableDump with Unimplemented; the pass
// falls back to the full dump and still repairs.
func TestFleet_AntiEntropy_TableDumpFallsBackOnAnOlderPeer(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	b.DB.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: a.Name}} })
	seedUnreplicatedStack(t, a, "drifted-stack")
	defer a.DoNotImplement("StreamTableDump")()
	defer a.DoNotImplement("StreamTableRows")()
	defer a.DoNotImplement("GetTableBucketDigests")()

	c.ResetAEStats()
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunOnce(context.Background()) {
		t.Fatal("the pass did not run")
	}
	if !hasStack(t, b, "drifted-stack") {
		t.Fatal("b did not receive the drifted stacks row from a peer without StreamTableDump")
	}
	// The meter counts calls a handler served, so the refused table dump does
	// not appear; that it was attempted first is pinned by
	// TestFetchTableDump_FallsBackToTheFullDumpOnUnimplemented.
	st := c.AEStats()
	if st["StreamTableDump"].Calls != 0 {
		t.Errorf("precondition: a StreamTableDump was served by the peer standing in for an older build: %+v", st)
	}
	if st["StreamStateDump"].Calls == 0 {
		t.Errorf("no fallback to the full dump: %+v", st)
	}
}

// A peer that serves StreamTableDump but not the paged StreamTableRows (the
// release before paging) is repaired over the blob table dump.
func TestFleet_AntiEntropy_PagedPullFallsBackToTheTableDump(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	b.DB.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: a.Name}} })
	seedUnreplicatedStack(t, a, "drifted-stack")
	defer a.DoNotImplement("StreamTableRows")()
	defer a.DoNotImplement("StreamSensitiveTableRows")()

	c.ResetAEStats()
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunOnce(context.Background()) {
		t.Fatal("the pass did not run")
	}
	if !hasStack(t, b, "drifted-stack") {
		t.Fatal("b did not receive the drifted stacks row from a peer without StreamTableRows")
	}
	st := c.AEStats()
	if st["StreamTableDump"].Calls == 0 || st["StreamTableRows"].Calls != 0 {
		t.Errorf("want the blob table dump from a peer without paging: %+v", st)
	}
	if st["StreamStateDump"].Calls != 0 {
		t.Errorf("fell back past the table dump to the full dump: %+v", st)
	}
}
