package corrosion

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// caRetire records what `lv host rm` records for a removed host: a retirement of
// keyID at seq, signed with the cluster CA.
func caRetire(t *testing.T, c *Client, dir, host, keyID string, seq int64) {
	t.Helper()
	sig, err := SignLifecycleWithCA(dir, host, keyID, "retired", seq)
	if err != nil {
		t.Fatalf("SignLifecycleWithCA: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := c.Execute(context.Background(),
		`INSERT INTO audit_key_lifecycle
		   (host_name, key_id, event, at_seq, by_key_id, signature, created_at, updated_at, deleted_at)
		 VALUES (?, ?, 'retired', ?, 'cluster-ca', ?, ?, ?, NULL)`,
		host, keyID, seq, sig, now, now); err != nil {
		t.Fatalf("insert the CA retirement: %v", err)
	}
}

func auditSeqOf(t *testing.T, c *Client, id string) (int64, bool) {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT seq FROM audit_log WHERE id = ?`, id)
	if err != nil {
		t.Fatalf("read %s: %v", id, err)
	}
	if len(rows) == 0 {
		return 0, false
	}
	return rows[0].Int64("seq"), true
}

// TestAuditHold_AppendsOnlyAfterItsOwnHistoryHasArrived: a host whose replica
// has caught up but still lacks rows the cluster's records account for — here,
// the CA retirement `lv host rm` recorded at seq 3 — holds its rows until they
// arrive, then appends after them.
//
// Mutation: make auditCatchUpTarget return 0 — new-1 lands at seq 2, on top of
// the old machine's seq 2.
func TestAuditHold_AppendsOnlyAfterItsOwnHistoryHasArrived(t *testing.T) {
	ctx := context.Background()
	c, kr, dir := signedClient(t, "node-0")
	for i := 1; i <= 3; i++ {
		ins(t, c, fmt.Sprintf("old-%d", i), "node-0", "")
	}
	caRetire(t, c, dir, "node-0", kr.KeyID(), 3)

	// The rebuilt replica: the retirement has arrived, rows 2 and 3 have not.
	late := rowsByID(t, c, "old-2", "old-3")
	if err := c.Execute(ctx, `DELETE FROM audit_log WHERE id IN ('old-2', 'old-3')`); err != nil {
		t.Fatalf("drop the late rows: %v", err)
	}
	c.ResetAuditChainForTests()
	c.HoldAuditUntilCaughtUp(AuditHoldConfig{Host: "node-0", Joiner: true})
	c.MarkReplicaCaughtUpForTests("peer")

	ins(t, c, "new-1", "node-0", "")
	if seq, ok := auditSeqOf(t, c, "new-1"); ok {
		t.Fatalf("new-1 was appended at seq %d while the replica still lacked seq 2 and 3, "+
			"which a CA retirement at seq 3 accounts for", seq)
	}

	restoreRows(t, c, late)
	if c.AuditChainHeld(ctx, "node-0") {
		t.Fatal("still holding after the missing rows arrived")
	}
	if seq, ok := auditSeqOf(t, c, "new-1"); !ok || seq != 4 {
		t.Fatalf("new-1 at seq %d (present=%v), want 4, after the old machine's three rows", seq, ok)
	}
	if res := verify(t, c); res.BrokenAt != "" || len(res.SeqGaps) > 0 {
		t.Fatalf("the chain forked: broken_at=%q seq_gaps=%v", res.BrokenAt, res.SeqGaps)
	}
}

// TestAuditHold_OpensOnceTheTargetHasHadItsChance: a boundary no row will ever
// reach — an operator raised it past the real tail — does not hold the host's
// audit rows forever. Past auditCatchUpPatience of a caught-up replica they land.
func TestAuditHold_OpensOnceTheTargetHasHadItsChance(t *testing.T) {
	ctx := context.Background()
	defer func(p time.Duration) { auditCatchUpPatience = p }(auditCatchUpPatience)
	auditCatchUpPatience = 50 * time.Millisecond

	c, kr, dir := signedClient(t, "node-0")
	ins(t, c, "old-1", "node-0", "")
	caRetire(t, c, dir, "node-0", kr.KeyID(), 10)
	c.ResetAuditChainForTests()
	c.HoldAuditUntilCaughtUp(AuditHoldConfig{Host: "node-0", Joiner: true})
	c.MarkReplicaCaughtUpForTests("peer")

	ins(t, c, "new-1", "node-0", "")
	if _, ok := auditSeqOf(t, c, "new-1"); ok {
		t.Fatal("new-1 was appended at once, though the replica is short of the recorded boundary")
	}
	time.Sleep(100 * time.Millisecond)
	if c.AuditChainHeld(ctx, "node-0") {
		t.Fatal("still holding after the patience ran out; an unreachable target would hold the host's audit rows forever")
	}
	if seq, ok := auditSeqOf(t, c, "new-1"); !ok || seq != 2 {
		t.Fatalf("new-1 at seq %d (present=%v), want 2", seq, ok)
	}
}

// TestAuditHold_ClusterOfOne: with no peer anywhere, the founder of a cluster
// has nobody to catch up with and is not held; a node set up to JOIN a cluster
// that holds none of its own history is the rebuilt host and is, while one that
// already holds history of its own is not.
func TestAuditHold_ClusterOfOne(t *testing.T) {
	for _, tc := range []struct {
		name    string
		joiner  bool
		history bool
		held    bool
	}{
		{"founder", false, false, false},
		{"joiner with no history", true, false, true},
		{"joiner with its own history", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newAuditTestClient(t)
			if tc.history {
				ins(t, c, "old-1", "node-0", "")
				c.ResetAuditChainForTests()
			}
			c.HoldAuditUntilCaughtUp(AuditHoldConfig{Host: "node-0", Joiner: tc.joiner})
			ins(t, c, "new-1", "node-0", "")
			if _, ok := auditSeqOf(t, c, "new-1"); ok == tc.held {
				t.Fatalf("new-1 written=%v, want held=%v", ok, tc.held)
			}
		})
	}
}

// TestAuditHold_OnlyItsOwnHost: rows a client writes for another host name are
// never held — the hold is about the one chain this node authors.
func TestAuditHold_OnlyItsOwnHost(t *testing.T) {
	c := newAuditTestClient(t)
	c.HoldAuditUntilCaughtUp(AuditHoldConfig{Host: "node-0", Joiner: true})
	ins(t, c, "other-1", "node-9", "")
	if _, ok := auditSeqOf(t, c, "other-1"); !ok {
		t.Fatal("a row for another host was held")
	}
}

// TestAuditHold_SpooledRowsSurviveARestart: rows held when the daemon stops are
// in the spool, and land — in the order they were audited, with the stamp of
// the moment they were audited — once the next process has caught up.
//
// Mutation: ignore SpoolDir (hold in memory) — the restart loses both rows.
func TestAuditHold_SpooledRowsSurviveARestart(t *testing.T) {
	ctx := context.Background()
	spool := filepath.Join(t.TempDir(), AuditHoldDirName)
	cfg := AuditHoldConfig{Host: "node-0", Joiner: true, SpoolDir: spool}
	c := newAuditTestClient(t)
	c.HoldAuditUntilCaughtUp(cfg)

	before := time.Now().UTC()
	ins(t, c, "held-1", "node-0", "")
	heldBy := time.Now().UTC()
	const supplied = "2026-01-02T03:04:05Z"
	ins(t, c, "held-2", "node-0", supplied)
	ins(t, c, "held-1", "node-0", "") // the same id again: kept once
	if names, _ := filepath.Glob(filepath.Join(spool, "*.json")); len(names) != 2 {
		t.Fatalf("%d spool files, want 2", len(names))
	}

	// The restart: everything in memory is gone.
	c.ResetAuditChainForTests()
	c.HoldAuditUntilCaughtUp(cfg)
	time.Sleep(10 * time.Millisecond)
	c.MarkReplicaCaughtUpForTests("peer")
	ins(t, c, "after", "node-0", "")

	for want, id := range []string{"held-1", "held-2", "after"} {
		if seq, ok := auditSeqOf(t, c, id); !ok || seq != int64(want+1) {
			t.Errorf("%s at seq %d (present=%v), want %d", id, seq, ok, want+1)
		}
	}
	stamp := func(id string) string {
		rows, err := c.Query(ctx, `SELECT timestamp FROM audit_log WHERE id = ?`, id)
		if err != nil || len(rows) != 1 {
			t.Fatalf("read %s: %v", id, err)
		}
		return rows[0].String("timestamp")
	}
	if got := stamp("held-2"); got != supplied {
		t.Errorf("held-2's caller-supplied stamp is %q, want %q verbatim", got, supplied)
	}
	if at, err := time.Parse(time.RFC3339Nano, stamp("held-1")); err != nil || at.Before(before) || at.After(heldBy) {
		t.Errorf("held-1 is stamped %v (%v); want the moment it was audited, between %v and %v",
			at, err, before, heldBy)
	}
	if names, _ := filepath.Glob(filepath.Join(spool, "*.json")); len(names) != 0 {
		t.Errorf("%d spool files left after the rows landed", len(names))
	}
	if res := verify(t, c); res.Tampered() {
		t.Fatalf("verify: %+v", res)
	}
}

// TestAuditHold_RejectsASpoolFileForAnotherHost: the spool is not a side door
// into the log. A file naming another host is set aside, not appended.
func TestAuditHold_RejectsASpoolFileForAnotherHost(t *testing.T) {
	spool := t.TempDir()
	cfg := AuditHoldConfig{Host: "node-0", Joiner: true, SpoolDir: spool}
	c := newAuditTestClient(t)
	c.HoldAuditUntilCaughtUp(cfg)
	ins(t, c, "mine", "node-0", "")
	planted := heldAuditRow{Record: AuditRecord{ID: "planted", HostName: "node-9", Action: "vm.delete"}}
	if err := writeHeldAudit(spool, heldAuditPath(spool, "planted"), planted); err != nil {
		t.Fatal(err)
	}
	c.MarkReplicaCaughtUpForTests("peer")
	if c.AuditChainHeld(context.Background(), "node-0") {
		t.Fatal("still held")
	}
	if _, ok := auditSeqOf(t, c, "planted"); ok {
		t.Fatal("a spool file naming another host was appended")
	}
	if _, ok := auditSeqOf(t, c, "mine"); !ok {
		t.Fatal("the host's own held row did not land")
	}
	if names, _ := filepath.Glob(filepath.Join(spool, "*.rejected")); len(names) != 1 {
		t.Fatalf("%d rejected files, want the planted one set aside", len(names))
	}
}

// TestAdoptAuditKey_RefusesWhileHeld: a contract start is a sequence read from
// the local replica, so a key is not adopted while the host's chain is held.
func TestAdoptAuditKey_RefusesWhileHeld(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)
	dir := testPKI(t, "node-0")
	kr, err := LoadAuditKeyring(dir, "node-0")
	if err != nil {
		t.Fatal(err)
	}
	c.SetAuditKeyring(kr)
	c.HoldAuditUntilCaughtUp(AuditHoldConfig{Host: "node-0", Joiner: true})
	if _, err := AdoptAuditKey(ctx, c, kr, "node-0"); err != ErrAuditChainNotCaughtUp {
		t.Fatalf("AdoptAuditKey while held: %v, want ErrAuditChainNotCaughtUp", err)
	}
	if n := countRows(t, c, `SELECT host_name FROM audit_key_lifecycle`); n != 0 {
		t.Fatalf("%d lifecycle rows recorded while held", n)
	}
	c.MarkReplicaCaughtUpForTests("peer")
	if _, err := AdoptAuditKey(ctx, c, kr, "node-0"); err != nil {
		t.Fatalf("AdoptAuditKey once caught up: %v", err)
	}
}

// TestAdoptAuditKey_NeverStartsBelowACARetirement is Defect B on the lab: a key
// adopted on a replica still short of the host's history, after `lv host rm`
// retired every earlier key, started its contract below rows the removed machine
// wrote — so its unsigned ones became "unsigned after signed" findings. The CA's
// retirement boundary is the floor.
//
// Mutation: drop the caRetirementFloor raise in AdoptAuditKey — the adoption is
// recorded at 1.
func TestAdoptAuditKey_NeverStartsBelowACARetirement(t *testing.T) {
	ctx := context.Background()
	c, kr, dir := signedClient(t, "node-0")
	for i := 1; i <= 3; i++ {
		ins(t, c, fmt.Sprintf("old-%d", i), "node-0", "")
	}
	caRetire(t, c, dir, "node-0", kr.KeyID(), 3)
	if err := c.Execute(ctx, `DELETE FROM audit_log WHERE id IN ('old-2', 'old-3')`); err != nil {
		t.Fatal(err)
	}
	c.ResetAuditChainForTests()

	if err := regenHostCert(dir, "node-0"); err != nil {
		t.Fatal(err)
	}
	next, err := LoadAuditKeyring(dir, "node-0")
	if err != nil {
		t.Fatal(err)
	}
	c.SetAuditKeyring(next)
	if _, err := AdoptAuditKey(ctx, c, next, "node-0"); err != nil {
		t.Fatalf("AdoptAuditKey: %v", err)
	}
	rows, err := c.Query(ctx, `SELECT at_seq FROM audit_key_lifecycle
		WHERE host_name = 'node-0' AND key_id = ? AND event = 'adopted'`, next.KeyID())
	if err != nil || len(rows) != 1 {
		t.Fatalf("read the adoption: %v (rows=%d)", err, len(rows))
	}
	if got := rows[0].Int64("at_seq"); got < 3 {
		t.Fatalf("the new key's contract starts at seq %d, below the CA retirement at 3: rows the "+
			"removed machine wrote are claimed by a key adopted after it was gone", got)
	}
}
