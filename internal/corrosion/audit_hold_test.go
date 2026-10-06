package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
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

// writeRejoin writes the admission record `lv host add` would write for host
// into dir, signed with dir's cluster CA.
func writeRejoin(t *testing.T, dir, host string, seq int64, hash string) {
	t.Helper()
	serial, err := pki.CertSerial(filepath.Join(dir, "host.crt"))
	if err != nil {
		t.Fatal(err)
	}
	writeRejoinFor(t, dir, host, serial, seq, hash)
}

func writeRejoinFor(t *testing.T, dir, host, serial string, seq int64, hash string) {
	t.Helper()
	rj, err := SignAuditRejoin(dir, host, serial, seq, hash)
	if err != nil {
		t.Fatalf("SignAuditRejoin: %v", err)
	}
	data, err := json.Marshal(rj)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, AuditRejoinFileName), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// rebuiltClient is a host's history written on one client, with rows from
// keep onward missing — a replica that has received only part of it — and the
// admission record naming the full tail. Returns the client, the pki dir and
// the rows still to arrive.
func rebuiltClient(t *testing.T, n, keep int) (*Client, string, []map[string]string) {
	t.Helper()
	ctx := context.Background()
	c, _, dir := signedClient(t, "node-0")
	var ids []string
	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("old-%d", i)
		ins(t, c, id, "node-0", "")
		if i > keep {
			ids = append(ids, id)
		}
	}
	seq, hash, err := AuditChainTail(ctx, c, "node-0")
	if err != nil || seq != int64(n) {
		t.Fatalf("AuditChainTail = %d %q %v, want %d", seq, hash, err, n)
	}
	writeRejoin(t, dir, "node-0", seq, hash)
	var late []map[string]string
	if len(ids) > 0 {
		late = rowsByID(t, c, ids...)
		for _, id := range ids {
			if err := c.Execute(ctx, `DELETE FROM audit_log WHERE id = ?`, id); err != nil {
				t.Fatal(err)
			}
		}
	}
	c.ResetAuditChainForTests()
	return c, dir, late
}

func land(t *testing.T, c *Client) bool {
	t.Helper()
	held, err := c.LandHeldAudit(context.Background(), "node-0")
	if err != nil {
		t.Fatalf("LandHeldAudit: %v", err)
	}
	return held
}

// TestAuditHold_AppendsOnlyOnceTheAdmittedHistoryHasArrived: the admission
// record says the chain reached seq 3; a replica holding seq 1 holds its rows,
// even after an anti-entropy exchange completed (with a peer as empty as itself
// — drill 6 rebuilds three hosts at once), and appends after seq 3 once it has
// arrived.
//
// Mutation: ignore the target in auditTargetReached — new-1 lands at seq 2.
func TestAuditHold_AppendsOnlyOnceTheAdmittedHistoryHasArrived(t *testing.T) {
	ctx := context.Background()
	c, dir, late := rebuiltClient(t, 3, 1)
	cfg, err := ConfigureAuditHold(ctx, c, dir, "node-0", "")
	if err != nil || cfg.Target != 3 {
		t.Fatalf("ConfigureAuditHold = %+v, %v; want target 3", cfg, err)
	}
	c.MarkReplicaCaughtUpForTests("an-empty-peer")

	ins(t, c, "new-1", "node-0", "")
	if !land(t, c) {
		t.Fatal("the hold opened while the replica still lacked seq 2 and 3")
	}
	if seq, ok := auditSeqOf(t, c, "new-1"); ok {
		t.Fatalf("new-1 was appended at seq %d before the admitted history arrived", seq)
	}
	if _, err := AdoptAuditKey(ctx, c, c.AuditKeyringOf(), "node-0"); err != ErrAuditChainNotCaughtUp {
		t.Fatalf("AdoptAuditKey while held: %v, want ErrAuditChainNotCaughtUp", err)
	}

	restoreRows(t, c, late)
	if land(t, c) {
		t.Fatal("still holding after the admitted history arrived")
	}
	if seq, ok := auditSeqOf(t, c, "new-1"); !ok || seq != 4 {
		t.Fatalf("new-1 at seq %d (present=%v), want 4", seq, ok)
	}
	if res := verify(t, c); res.BrokenAt != "" || len(res.SeqGaps) > 0 {
		t.Fatalf("the chain forked: broken_at=%q seq_gaps=%v", res.BrokenAt, res.SeqGaps)
	}
}

// TestAuditHold_ADifferentHistoryAtTheTargetKeepsItHeld: a row at the admitted
// seq that does not hash as admitted is not the history the cluster had.
func TestAuditHold_ADifferentHistoryAtTheTargetKeepsItHeld(t *testing.T) {
	ctx := context.Background()
	c, dir, _ := rebuiltClient(t, 2, 2)
	writeRejoin(t, dir, "node-0", 2, strings.Repeat("ab", 32))
	if cfg, _ := ConfigureAuditHold(ctx, c, dir, "node-0", ""); cfg.Target != 2 {
		t.Fatalf("target %d, want 2: the row at seq 2 is not the admitted one", cfg.Target)
	}
	ins(t, c, "new-1", "node-0", "")
	if !land(t, c) {
		t.Fatal("opened on a row at the admitted seq whose hash is not the admitted one")
	}
	if held, _, why := c.AuditHoldStatus(ctx, "node-0"); !held || !strings.Contains(why, "does not hash") {
		t.Fatalf("status held=%v why=%q", held, why)
	}
}

// TestAuditHold_ANormalRestartNeverHolds: a replica that already holds the
// admitted tail — every restart after the first catch-up, record or not —
// writes at once, with no anti-entropy exchange behind it.
//
// Mutation: hold whenever a record exists (drop the local-tail check in
// ConfigureAuditHold) — the row is held.
func TestAuditHold_ANormalRestartNeverHolds(t *testing.T) {
	ctx := context.Background()
	c, dir, _ := rebuiltClient(t, 3, 3)
	c.MarkReplicaStale("restarted")
	if cfg, err := ConfigureAuditHold(ctx, c, dir, "node-0", t.TempDir()); err != nil || cfg.Target != 0 {
		t.Fatalf("ConfigureAuditHold = %+v, %v; want no target", cfg, err)
	}
	ins(t, c, "after-restart", "node-0", "")
	if seq, ok := auditSeqOf(t, c, "after-restart"); !ok || seq != 4 {
		t.Fatalf("after-restart at seq %d (present=%v), want written at once at 4", seq, ok)
	}
}

// TestAuditHold_ABrandNewNameNeverHolds: no admission record (or one at seq 0)
// is a name with no history, on an empty replica that has caught up with nobody.
func TestAuditHold_ABrandNewNameNeverHolds(t *testing.T) {
	ctx := context.Background()
	for _, withZero := range []bool{false, true} {
		c := newAuditTestClient(t)
		dir := testPKI(t, "node-0")
		if withZero {
			writeRejoin(t, dir, "node-0", 0, "")
		}
		c.MarkReplicaStale("fresh")
		if _, err := ConfigureAuditHold(ctx, c, dir, "node-0", ""); err != nil {
			t.Fatal(err)
		}
		ins(t, c, "first", "node-0", "")
		if seq, ok := auditSeqOf(t, c, "first"); !ok || seq != 1 {
			t.Fatalf("record at seq 0=%v: first at seq %d (present=%v), want written at once", withZero, seq, ok)
		}
	}
}

// TestAuditHold_AnUnsignedRecordIsNotActedOn: a record the cluster CA did not
// sign is reported, not trusted.
func TestAuditHold_AnUnsignedRecordIsNotActedOn(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)
	dir := testPKI(t, "node-0")
	data, _ := json.Marshal(AuditRejoin{Host: "node-0", Seq: 9, Hash: "x", Signature: "00"})
	if err := os.WriteFile(filepath.Join(dir, AuditRejoinFileName), data, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := ConfigureAuditHold(ctx, c, dir, "node-0", "")
	if err == nil || cfg.Target != 0 {
		t.Fatalf("ConfigureAuditHold = %+v, %v; want an error and no target", cfg, err)
	}
}

// TestAuditHold_OnlyItsOwnHost: rows for another host name are never held.
func TestAuditHold_OnlyItsOwnHost(t *testing.T) {
	c := newAuditTestClient(t)
	c.HoldAuditUntilCaughtUp(AuditHoldConfig{Host: "node-0", Target: 5})
	ins(t, c, "other-1", "node-9", "")
	if _, ok := auditSeqOf(t, c, "other-1"); !ok {
		t.Fatal("a row for another host was held")
	}
}

// TestAuditHold_RowsLandInTheOrderTheyWereHeld: held rows are numbered as they
// are held — across a restart, from the spool — and land in that order, each
// with the moment it was audited as its stamp. Not the wall clock, and not the
// spool's file order (file names are hashes).
//
// Mutation: drop the sort in landHeldAuditLocked — the rows land in file order.
func TestAuditHold_RowsLandInTheOrderTheyWereHeld(t *testing.T) {
	ctx := context.Background()
	c, dir, late := rebuiltClient(t, 2, 1)
	spool := filepath.Join(t.TempDir(), AuditHoldDirName)
	if _, err := ConfigureAuditHold(ctx, c, dir, "node-0", spool); err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC()
	ids := []string{"h-a", "h-z", "h-m", "h-b", "h-y"}
	for _, id := range ids[:3] {
		ins(t, c, id, "node-0", "")
	}
	heldBy := time.Now().UTC()
	const supplied = "2026-01-02T03:04:05Z"
	ins(t, c, "h-z", "node-0", "") // the same id again: kept once

	// The restart: everything in memory is gone; the spool carries on.
	c.ResetAuditChainForTests()
	if _, err := ConfigureAuditHold(ctx, c, dir, "node-0", spool); err != nil {
		t.Fatal(err)
	}
	ins(t, c, ids[3], "node-0", supplied)
	ins(t, c, ids[4], "node-0", "")
	restoreRows(t, c, late)
	time.Sleep(5 * time.Millisecond)
	if land(t, c) {
		t.Fatal("still held")
	}
	for i, id := range ids {
		if seq, ok := auditSeqOf(t, c, id); !ok || seq != int64(3+i) {
			t.Errorf("%s at seq %d (present=%v), want %d", id, seq, ok, 3+i)
		}
	}
	rows, err := c.Query(ctx, `SELECT id, timestamp FROM audit_log WHERE id IN ('h-a', 'h-b')`)
	if err != nil || len(rows) != 2 {
		t.Fatalf("read stamps: %v", err)
	}
	for _, r := range rows {
		switch r.String("id") {
		case "h-b":
			if r.String("timestamp") != supplied {
				t.Errorf("h-b's supplied stamp became %q", r.String("timestamp"))
			}
		case "h-a":
			at, err := time.Parse(time.RFC3339Nano, r.String("timestamp"))
			if err != nil || at.Before(before) || at.After(heldBy) {
				t.Errorf("h-a stamped %v (%v); want the moment it was audited", at, err)
			}
		}
	}
	if n := countSpool(spool); n != 0 {
		t.Errorf("%d spool files left", n)
	}
	if res := verify(t, c); res.BrokenAt != "" || len(res.SeqGaps) > 0 {
		t.Fatalf("verify: %+v", res)
	}
}

// TestAuditHold_LandingIsOffTheCallersPath: once the history has arrived, an
// audit write does not land the held rows — it queues behind them — and the
// poller lands them all, in order.
//
// Mutation: land from holdAuditLocked when the target is reached — the caller
// lands the backlog.
func TestAuditHold_LandingIsOffTheCallersPath(t *testing.T) {
	ctx := context.Background()
	c, dir, late := rebuiltClient(t, 2, 1)
	if _, err := ConfigureAuditHold(ctx, c, dir, "node-0", ""); err != nil {
		t.Fatal(err)
	}
	ins(t, c, "held-1", "node-0", "")
	restoreRows(t, c, late)
	ins(t, c, "after-arrival", "node-0", "")
	if _, ok := auditSeqOf(t, c, "held-1"); ok {
		t.Fatal("an RPC's audit write landed the held rows")
	}
	if land(t, c) {
		t.Fatal("still held")
	}
	for id, want := range map[string]int64{"held-1": 3, "after-arrival": 4} {
		if seq, ok := auditSeqOf(t, c, id); !ok || seq != want {
			t.Errorf("%s at seq %d (present=%v), want %d", id, seq, ok, want)
		}
	}
	ins(t, c, "open", "node-0", "")
	if seq, ok := auditSeqOf(t, c, "open"); !ok || seq != 5 {
		t.Errorf("open at seq %d (present=%v), want written at once at 5", seq, ok)
	}
}

// TestAuditHold_AFullHoldDropsNothing: past the limit the hold reports full —
// what the node refuses audited actions on — and every row still lands.
//
// Mutation: stop spooling past the limit — rows are lost.
func TestAuditHold_AFullHoldDropsNothing(t *testing.T) {
	SetMaxHeldAuditRowsForTest(t, 3)
	ctx := context.Background()
	c, dir, late := rebuiltClient(t, 2, 1)
	if _, err := ConfigureAuditHold(ctx, c, dir, "node-0", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		ins(t, c, fmt.Sprintf("bg-%d", i), "node-0", "")
		if full := c.AuditHoldFull("node-0"); full != (i >= 3) {
			t.Fatalf("after %d held rows full=%v", i, full)
		}
	}
	restoreRows(t, c, late)
	if land(t, c) {
		t.Fatal("still held")
	}
	for i := 1; i <= 5; i++ {
		if seq, ok := auditSeqOf(t, c, fmt.Sprintf("bg-%d", i)); !ok || seq != int64(2+i) {
			t.Errorf("bg-%d at seq %d (present=%v), want %d", i, seq, ok, 2+i)
		}
	}
	if c.AuditHoldFull("node-0") {
		t.Error("still full after landing")
	}
}

// TestAuditHold_DeniedLoginsAreCoalesced: an unauthenticated caller can repeat a
// denied login at will; while held, they fold into one row and cannot fill the
// hold — across a restart too.
//
// Mutation: hold denied logins as rows of their own — the hold fills.
func TestAuditHold_DeniedLoginsAreCoalesced(t *testing.T) {
	SetMaxHeldAuditRowsForTest(t, 3)
	ctx := context.Background()
	c, dir, late := rebuiltClient(t, 2, 1)
	spool := t.TempDir()
	if _, err := ConfigureAuditHold(ctx, c, dir, "node-0", spool); err != nil {
		t.Fatal(err)
	}
	deny := func(i int) {
		if err := InsertAuditLog(ctx, c, AuditRecord{Username: "", HostName: "node-0",
			Action: "auth.login", Target: fmt.Sprintf("user%d", i), Detail: "invalid credentials", Result: "denied"}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 30; i++ {
		deny(i)
	}
	c.ResetAuditChainForTests()
	if _, err := ConfigureAuditHold(ctx, c, dir, "node-0", spool); err != nil {
		t.Fatal(err)
	}
	for i := 30; i < 50; i++ {
		deny(i)
	}
	if c.AuditHoldFull("node-0") {
		t.Fatal("denied logins filled the hold")
	}
	restoreRows(t, c, late)
	if land(t, c) {
		t.Fatal("still held")
	}
	rows, err := c.Query(ctx, `SELECT detail, target FROM audit_log WHERE action = 'auth.login'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%d login rows (%v), want one coalesced row", len(rows), err)
	}
	if d := rows[0].String("detail"); !strings.Contains(d, "50 denied attempts") || !strings.Contains(d, "user49") {
		t.Fatalf("coalesced row's detail %q does not carry the count and the last attempt", d)
	}
}

// TestAuditHold_RejectsASpoolFileForAnotherHost: the spool is not a side door
// into the log.
func TestAuditHold_RejectsASpoolFileForAnotherHost(t *testing.T) {
	ctx := context.Background()
	c, dir, late := rebuiltClient(t, 2, 1)
	spool := t.TempDir()
	if _, err := ConfigureAuditHold(ctx, c, dir, "node-0", spool); err != nil {
		t.Fatal(err)
	}
	ins(t, c, "mine", "node-0", "")
	planted := heldAuditRow{Record: AuditRecord{ID: "planted", HostName: "node-9", Action: "vm.delete"}, HeldSeq: 0}
	if err := writeHeldAudit(spool, heldAuditPath(spool, "planted"), planted); err != nil {
		t.Fatal(err)
	}
	restoreRows(t, c, late)
	if land(t, c) {
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

// TestAdoptAuditKey_NeverStartsBelowACARetirement is Defect B on the lab: a key
// adopted on a replica still short of the host's history, after `lv host rm`
// retired every earlier key, started its contract below rows the removed machine
// wrote — so its unsigned ones became "unsigned after signed" findings. The CA's
// retirement boundary is the floor.
//
// Mutation: drop the CARetirementFloor raise in AdoptAuditKey — the adoption is
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

// TestAuditHold_ARecordForAnotherCertificateIsIgnored: a record left in a
// reused pki dir by an earlier admission names that admission's certificate,
// not this machine's, and must not set this machine's target — an old, lower
// target would open the hold early.
//
// Mutation: drop the serial comparison in LoadAuditRejoin — the stale record
// sets a target.
func TestAuditHold_ARecordForAnotherCertificateIsIgnored(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)
	dir := testPKI(t, "node-0")
	writeRejoinFor(t, dir, "node-0", "0badc0ffee", 7, "ab")
	cfg, err := ConfigureAuditHold(ctx, c, dir, "node-0", "")
	if err == nil || !strings.Contains(err.Error(), "earlier admission") || cfg.Target != 0 {
		t.Fatalf("ConfigureAuditHold = %+v, %v; want the stale record ignored and reported", cfg, err)
	}
}

// TestAuditHold_TheLegacyResealWaitsForTheHistory is I-B: a rebuilt host whose
// replica holds unsigned rows 1 and 3 of its chain, and not 2, must not reseal
// them. The reseal would recompute row 3 against row 1 and replicate the
// rewrite over every peer's good copy.
//
// Mutations: drop the AuditChainHeld check in ResealAuditChain, or the
// completeness check in auditTargetReached — either way row 3 is rewritten.
func TestAuditHold_TheLegacyResealWaitsForTheHistory(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)
	dir := testPKI(t, "node-0")
	for i := 1; i <= 3; i++ {
		ins(t, c, fmt.Sprintf("old-%d", i), "node-0", "")
	}
	seq, hash, err := AuditChainTail(ctx, c, "node-0")
	if err != nil {
		t.Fatal(err)
	}
	writeRejoin(t, dir, "node-0", seq, hash)
	before := rowsByID(t, c, "old-3")[0]
	if err := c.Execute(ctx, `DELETE FROM audit_log WHERE id = 'old-2'`); err != nil {
		t.Fatal(err)
	}
	// Row 3 — the admitted row itself — has arrived; row 2 has not. The hold
	// has not opened: the history below the target is incomplete.
	c.ResetAuditChainForTests()
	if cfg, _ := ConfigureAuditHold(ctx, c, dir, "node-0", ""); cfg.Target == 0 {
		t.Fatal("fixture: no hold")
	}
	if held, _, why := c.AuditHoldStatus(ctx, "node-0"); !held || !strings.Contains(why, "seq 2 is missing") {
		t.Fatalf("status held=%v why=%q; want it to name the missing seq 2", held, why)
	}
	if n, err := ResealAuditChain(ctx, c, "node-0"); err != ErrAuditChainNotCaughtUp || n != 0 {
		t.Fatalf("ResealAuditChain while held = %d, %v; want ErrAuditChainNotCaughtUp", n, err)
	}
	after := rowsByID(t, c, "old-3")[0]
	if after["prev_hash"] != before["prev_hash"] || after["content_hash"] != before["content_hash"] {
		t.Fatalf("row 3 was rewritten by a reseal of a partial replica:\n  before %v\n  after  %v", before, after)
	}
}

// TestAuditHold_AnUnreadableTailHolds is M-B: when the check that would skip
// the hold cannot be made, the node holds rather than append to a tail it could
// not read.
//
// Mutation: return before installing the hold on a read error — no target.
func TestAuditHold_AnUnreadableTailHolds(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)
	dir := testPKI(t, "node-0")
	writeRejoin(t, dir, "node-0", 4, "ab")
	if _, err := c.DB().Exec(`ALTER TABLE audit_log RENAME TO audit_log_gone`); err != nil {
		t.Fatal(err)
	}
	cfg, err := ConfigureAuditHold(ctx, c, dir, "node-0", "")
	if err == nil || cfg.Target != 4 {
		t.Fatalf("ConfigureAuditHold = %+v, %v; want the record's target and the error", cfg, err)
	}
	if !c.AuditChainHeld(ctx, "node-0") {
		t.Fatal("not held after a failed tail read")
	}
}

// TestAuditHold_LandingDoesNotSpinOnAStuckSpoolFile is M-C: a spool file that
// is counted but can be neither read nor set aside lands nothing, and the land
// loop must return to its poll instead of spinning on the chain lock.
//
// Mutation: keep looping after a batch that landed nothing — LandHeldAudit
// never returns.
func TestAuditHold_LandingDoesNotSpinOnAStuckSpoolFile(t *testing.T) {
	ctx := context.Background()
	c, dir, late := rebuiltClient(t, 2, 1)
	spool := t.TempDir()
	if _, err := ConfigureAuditHold(ctx, c, dir, "node-0", spool); err != nil {
		t.Fatal(err)
	}
	// A directory named like a spool file, whose .rejected name is taken by a
	// non-empty directory: unreadable, and the rename aside fails.
	stuck := filepath.Join(spool, "00stuck.json")
	if err := os.MkdirAll(stuck, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(spool, "00stuck.rejected", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	ins(t, c, "held-1", "node-0", "")
	restoreRows(t, c, late)
	done := make(chan bool, 1)
	go func() {
		held, _ := c.LandHeldAudit(ctx, "node-0")
		done <- held
	}()
	select {
	case held := <-done:
		if !held {
			t.Fatal("reported nothing held while a spool file is still counted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LandHeldAudit spun on a spool file it could neither read nor set aside")
	}
	if _, ok := auditSeqOf(t, c, "held-1"); !ok {
		t.Fatal("the readable held row did not land")
	}
}

// TestAuditHold_DeniedActionsAreCoalescedPerAction is M-G: an authenticated
// caller repeating a refused action cannot fill the hold either. Each action's
// denials fold into one row.
func TestAuditHold_DeniedActionsAreCoalescedPerAction(t *testing.T) {
	SetMaxHeldAuditRowsForTest(t, 3)
	ctx := context.Background()
	c, dir, late := rebuiltClient(t, 2, 1)
	if _, err := ConfigureAuditHold(ctx, c, dir, "node-0", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		for _, action := range []string{"vm.delete", "ct.exec"} {
			if err := InsertAuditLog(ctx, c, AuditRecord{Username: "viewer", HostName: "node-0",
				Action: action, Target: fmt.Sprintf("x%d", i), Detail: "permission denied", Result: "denied"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if c.AuditHoldFull("node-0") {
		t.Fatal("denied actions filled the hold")
	}
	restoreRows(t, c, late)
	if land(t, c) {
		t.Fatal("still held")
	}
	for _, action := range []string{"vm.delete", "ct.exec"} {
		rows, err := c.Query(ctx, `SELECT detail FROM audit_log WHERE action = ?`, action)
		if err != nil || len(rows) != 1 || !strings.Contains(rows[0].String("detail"), "30 denied attempts") {
			t.Fatalf("%s: %d rows (%v), want one carrying 30 denied attempts", action, len(rows), err)
		}
	}
}
