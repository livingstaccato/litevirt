package corrosion

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// signedDaemonOnDir is the daemon's client on a real data directory: file
// backed, so a second NewLocalClient on the same dir is a genuine second
// process's view, with the host's signing key wired and adopted.
func signedDaemonOnDir(t *testing.T, dataDir, host string) *Client {
	t.Helper()
	ctx := context.Background()
	c, err := NewLocalClient(dataDir, host)
	if err != nil {
		t.Fatalf("NewLocalClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	kr, err := LoadAuditKeyring(testPKI(t, host), host)
	if err != nil {
		t.Fatalf("LoadAuditKeyring: %v", err)
	}
	c.SetAuditKeyring(kr)
	if _, err := AdoptAuditKey(ctx, c, kr, host); err != nil {
		t.Fatalf("AdoptAuditKey: %v", err)
	}
	return c
}

func assertCleanSignedChain(t *testing.T, c *Client) {
	t.Helper()
	res := verify(t, c)
	if res.Tampered() {
		t.Fatalf("`lv audit verify` would report tampering: %+v", res)
	}
	if res.Unsigned != 0 {
		t.Fatalf("%d unsigned rows; every row here should carry the host's signature: %+v", res.Unsigned, res)
	}
}

// TestAudit_SecondProcessRowForksTheChain is why nothing but the daemon may
// write audit_log, and why reset-admin does not simply add an InsertAuditLog to
// its own NewLocalClient.
//
// The daemon caches its host's chain tail. A row appended by another process
// links correctly to what is on disk, but the daemon's next row links to the
// tail it remembers and reuses the sequence number: a fork. The other process
// also has no key, so its row is unsigned under a signing contract. Both are
// reported as tampering.
func TestAudit_SecondProcessRowForksTheChain(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	d := signedDaemonOnDir(t, dir, "node-0")
	ins(t, d, "d1", "node-0", "")

	cli, err := NewLocalClient(dir, "node-0")
	if err != nil {
		t.Fatalf("NewLocalClient: %v", err)
	}
	ins(t, cli, "from-cli", "node-0", "")
	cli.Close()
	ins(t, d, "d2", "node-0", "")

	res := verify(t, d)
	if res.BrokenAt != "d2" {
		t.Errorf("BrokenAt = %q, want d2: the daemon's next row should link past the other process's", res.BrokenAt)
	}
	if len(res.SeqGaps) == 0 {
		t.Errorf("no sequence finding; the daemon should have reused the other process's seq: %+v", res)
	}
	if len(res.UnsignedAfterSigned) == 0 {
		t.Errorf("the other process's row was not reported as unsigned under a contract: %+v", res)
	}
	_ = ctx
}

// TestFoldPendingAudit_OneSignedRowAtTheTimeItHappened is the daemon-down path:
// an entry journalled while the daemon was not running becomes exactly one
// signed row, stamped when the action happened, and the chain stays clean
// through the fold and the daemon's next row.
func TestFoldPendingAudit_OneSignedRowAtTheTimeItHappened(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	d := signedDaemonOnDir(t, dir, "node-0")
	ins(t, d, "before", "node-0", "")

	happened := time.Now().Add(-3 * time.Hour).UTC().Truncate(time.Microsecond)
	j, err := OpenPendingAuditJournal(dir)
	if err != nil {
		t.Fatalf("OpenPendingAuditJournal: %v", err)
	}
	e := PendingAuditEntry{
		Timestamp: happened.Format(time.RFC3339Nano),
		Action:    "user.reset-admin", Target: "admin",
		Detail: "via=cli os_user=tim", Result: "ok",
	}
	if err := j.Record(&e); err != nil {
		t.Fatalf("Record: %v", err)
	}
	j.Close()

	n, err := FoldPendingAudit(ctx, d, dir, "node-0")
	if err != nil || n != 1 {
		t.Fatalf("FoldPendingAudit = %d, %v; want 1, nil", n, err)
	}
	rows, err := d.Query(ctx, `SELECT id, timestamp, username, host_name, action, target, result, signature
		FROM audit_log WHERE action = 'user.reset-admin'`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d user.reset-admin rows, want exactly 1", len(rows))
	}
	r := rows[0]
	if r.String("id") != e.ID {
		t.Errorf("id = %q, want the journal entry's %q", r.String("id"), e.ID)
	}
	if got, err := time.Parse(time.RFC3339Nano, r.String("timestamp")); err != nil || !got.Equal(happened) {
		t.Errorf("timestamp = %q, want when it happened (%s), not when it was folded", r.String("timestamp"), happened)
	}
	if r.String("username") != "root@node-0" || r.String("host_name") != "node-0" {
		t.Errorf("attributed to %q on %q, want root@node-0 on node-0", r.String("username"), r.String("host_name"))
	}
	if r.String("signature") == "" {
		t.Error("the folded row is unsigned; the daemon must sign it")
	}
	if _, err := os.Stat(filepath.Join(dir, PendingAuditDirName, e.ID+".json")); !os.IsNotExist(err) {
		t.Errorf("journal entry still present after the fold (stat err %v)", err)
	}

	ins(t, d, "after", "node-0", "")
	assertCleanSignedChain(t, d)
}

// TestFoldPendingAudit_RefoldAfterACrashWritesNothing: a daemon that died
// between inserting the row and removing the file folds the same entry again on
// its next start. That must write nothing and must not move the chain tail —
// InsertAuditLog advances it whether or not the INSERT OR IGNORE took, so a
// blind re-insert would break the link of the next row.
func TestFoldPendingAudit_RefoldAfterACrashWritesNothing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	d := signedDaemonOnDir(t, dir, "node-0")

	j, err := OpenPendingAuditJournal(dir)
	if err != nil {
		t.Fatalf("OpenPendingAuditJournal: %v", err)
	}
	e := PendingAuditEntry{Action: "user.reset-admin", Target: "admin", Result: "ok"}
	if err := j.Record(&e); err != nil {
		t.Fatalf("Record: %v", err)
	}
	path := filepath.Join(dir, PendingAuditDirName, e.ID+".json")
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read entry: %v", err)
	}
	j.Close()

	if n, err := FoldPendingAudit(ctx, d, dir, "node-0"); err != nil || n != 1 {
		t.Fatalf("first fold = %d, %v; want 1, nil", n, err)
	}
	// The crash: the file is back, the row is already in.
	if err := os.WriteFile(path, saved, 0o600); err != nil {
		t.Fatalf("restore entry: %v", err)
	}
	if n, err := FoldPendingAudit(ctx, d, dir, "node-0"); err != nil || n != 0 {
		t.Fatalf("re-fold = %d, %v; want 0, nil", n, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("re-fold left the entry in place (stat err %v)", err)
	}
	ins(t, d, "after", "node-0", "")
	assertCleanSignedChain(t, d)
	if got := oneCol(t, d, `SELECT COUNT(*) FROM audit_log WHERE action = 'user.reset-admin'`); got != "1" {
		t.Errorf("%s user.reset-admin rows, want 1", got)
	}
}

// TestFoldPendingAudit_LeavesAnEntryItsWriterStillHolds: the CLI records its
// intent BEFORE the reset and its outcome after. A fold in between would log
// the intent as the outcome, so the daemon skips a journal whose lock is held
// and takes the entry on a later pass.
func TestFoldPendingAudit_LeavesAnEntryItsWriterStillHolds(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	d := signedDaemonOnDir(t, dir, "node-0")

	j, err := OpenPendingAuditJournal(dir)
	if err != nil {
		t.Fatalf("OpenPendingAuditJournal: %v", err)
	}
	e := PendingAuditEntry{Action: "user.reset-admin", Target: "admin", Result: "interrupted"}
	if err := j.Record(&e); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if n, err := FoldPendingAudit(ctx, d, dir, "node-0"); err != nil || n != 0 {
		t.Fatalf("fold while the writer holds the journal = %d, %v; want 0, nil", n, err)
	}
	e.Result = "ok"
	if err := j.Record(&e); err != nil {
		t.Fatalf("Record outcome: %v", err)
	}
	j.Close()
	if n, err := FoldPendingAudit(ctx, d, dir, "node-0"); err != nil || n != 1 {
		t.Fatalf("fold after release = %d, %v; want 1, nil", n, err)
	}
	if got := oneCol(t, d, `SELECT result FROM audit_log WHERE action = 'user.reset-admin'`); got != "ok" {
		t.Errorf("result = %q, want the outcome (ok), not the intent", got)
	}
}

// TestFoldPendingAudit_RefusesActionsItDoesNotRecord: root can write the
// journal, and the daemon signs what it folds, so the journal must not become a
// way to put arbitrary signed rows in the log.
func TestFoldPendingAudit_RefusesActionsItDoesNotRecord(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	d := signedDaemonOnDir(t, dir, "node-0")

	j, err := OpenPendingAuditJournal(dir)
	if err != nil {
		t.Fatalf("OpenPendingAuditJournal: %v", err)
	}
	e := PendingAuditEntry{Action: "vm.delete", Target: "prod-db", Result: "ok"}
	if err := j.Record(&e); err != nil {
		t.Fatalf("Record: %v", err)
	}
	j.Close()
	if n, err := FoldPendingAudit(ctx, d, dir, "node-0"); err != nil || n != 0 {
		t.Fatalf("fold = %d, %v; want 0, nil", n, err)
	}
	if got := oneCol(t, d, `SELECT COUNT(*) FROM audit_log WHERE action = 'vm.delete'`); got != "0" {
		t.Errorf("a vm.delete row was folded from the journal")
	}
	if _, err := os.Stat(filepath.Join(dir, PendingAuditDirName, e.ID+".rejected")); err != nil {
		t.Errorf("the refused entry was not kept aside as .rejected: %v", err)
	}
}

// TestFoldPendingAudit_NoJournalIsNotAnError: the common case, every start.
func TestFoldPendingAudit_NoJournalIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	d := signedDaemonOnDir(t, dir, "node-0")
	if n, err := FoldPendingAudit(context.Background(), d, dir, "node-0"); err != nil || n != 0 {
		t.Fatalf("FoldPendingAudit with no journal = %d, %v; want 0, nil", n, err)
	}
}
