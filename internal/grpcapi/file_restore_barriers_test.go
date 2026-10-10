package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/filerestore"
)

func auditCount(t *testing.T, s *Server, action string) int {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT detail FROM audit_log WHERE action = ?`, action)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

// R3-M4: every extraction's audit row says what isolated its restore VM, and
// a restore VM started without one of its barriers is audited on its own —
// browsing included, which writes no other row.
func TestFileRestore_AuditRecordsBarriers(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	const ts = "2026-10-10T01:00:00Z"
	repoDir := ctBackup(t, s, ts)
	s.SetBackupRepos(map[string]string{"r": repoDir})
	fr := &fakeRestorer{barriers: "sandbox=off apparmor=absent landlock=off uid=3800000001", reduced: true}
	s.setFileRestorer(fr, FileRestoreOptions{})
	ctx := adminCtx()

	if _, err := s.ListBackupFiles(ctx, &pb.ListBackupFilesRequest{RepoPath: "r", Name: "box", DiskName: "rootfs", Timestamp: ts}); err != nil {
		t.Fatalf("list: %v", err)
	}
	u := lastAuditRow(t, s, "backup.file_restore_unsandboxed")
	if !u.found || u.target != "box" || !strings.Contains(u.detail, "sandbox=off apparmor=absent landlock=off uid=3800000001") ||
		!strings.Contains(u.detail, "project=a") || !strings.Contains(u.detail, "ts="+ts) {
		t.Fatalf("browsing on a restore VM without its barriers: audit row %+v", u)
	}
	extract := func() {
		t.Helper()
		st := &progressStream[pb.RestoreBackupFilesChunk]{ctx: ctx}
		if err := s.RestoreBackupFiles(&pb.RestoreBackupFilesRequest{
			RepoPath: "r", Name: "box", DiskName: "rootfs", Timestamp: ts, Paths: []string{"/rootfs/root/notes.txt"},
		}, st); err != nil {
			t.Fatalf("RestoreBackupFiles: %v", err)
		}
	}
	extract()
	if a := lastAuditRow(t, s, "backup.file_restore"); !strings.Contains(a.detail, "sandbox=off apparmor=absent landlock=off uid=3800000001") {
		t.Fatalf("the extraction's audit row does not say what isolated it: %+v", a)
	}
	if n := auditCount(t, s, "backup.file_restore_unsandboxed"); n != 2 {
		t.Fatalf("%d unsandboxed-VM rows, want one per VM started (browse + extraction)", n)
	}
	fr.mu.Lock()
	fr.barriers, fr.reduced = "sandbox=on apparmor=on landlock=6 uid=3800000002", false
	fr.mu.Unlock()
	extract()
	if a := lastAuditRow(t, s, "backup.file_restore"); !strings.Contains(a.detail, "sandbox=on apparmor=on landlock=6 uid=3800000002") {
		t.Fatalf("audit row %+v", a)
	}
	if n := auditCount(t, s, "backup.file_restore_unsandboxed"); n != 2 {
		t.Fatalf("a fully confined restore VM was audited as unsandboxed (%d rows)", n)
	}
}

// R3-M4: while a key that removes a restore VM barrier is set, this host
// carries an informational file_restore_unsandboxed condition; it resolves
// once the keys are gone.
func TestFileRestoreCondition_RaisedAndResolved(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	get := func() (corrosion.HealthCondition, bool) {
		t.Helper()
		row, ok, err := corrosion.GetHealthCondition(ctx, s.db, "file_restore", "file_restore_unsandboxed", "host", s.hostName)
		if err != nil {
			t.Fatal(err)
		}
		return row, ok
	}
	s.ReconcileFileRestoreCondition(ctx, nil)
	if _, ok := get(); ok {
		t.Fatal("a condition was written with no key set")
	}
	s.ReconcileFileRestoreCondition(ctx, []string{"allow_unsandboxed: [seccomp]", "allow_shared_run_as"})
	row, ok := get()
	if !ok || row.Lifecycle != corrosion.ConditionConfirmed || row.Severity != corrosion.SeverityInfo ||
		!strings.Contains(row.Evidence, "allow_unsandboxed: [seccomp]") || !strings.Contains(row.Evidence, "allow_shared_run_as") {
		t.Fatalf("raised: %+v (found %v)", row, ok)
	}
	s.ReconcileFileRestoreCondition(ctx, nil)
	if row, ok = get(); !ok || row.Lifecycle != corrosion.ConditionResolved || row.ResolvedAt == "" {
		t.Fatalf("after the keys were removed: %+v", row)
	}
}

// cancelOnDone is a stream whose client goes away as soon as it has the
// final frame — what a real client does once it has its archive.
type cancelOnDone struct {
	progressStream[pb.RestoreBackupFilesChunk]
	cancel context.CancelFunc
}

func (c *cancelOnDone) Send(m *pb.RestoreBackupFilesChunk) error {
	_ = c.progressStream.Send(m)
	if m.Done {
		c.cancel()
	}
	return nil
}

// Lab 2: a successful extraction is audited although the client has gone
// by the time the row is written (its stream context is cancelled).
func TestFileRestore_AuditedAfterTheClientWentAway(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	const ts = "2026-10-10T01:00:00Z"
	s.SetBackupRepos(map[string]string{"r": ctBackup(t, s, ts)})
	s.setFileRestorer(&fakeRestorer{barriers: "sandbox=on apparmor=on landlock=4 uid=3800000000"}, FileRestoreOptions{})
	ctx, cancel := context.WithCancel(adminCtx())
	defer cancel()
	st := &cancelOnDone{progressStream: progressStream[pb.RestoreBackupFilesChunk]{ctx: ctx}, cancel: cancel}
	if err := s.RestoreBackupFiles(&pb.RestoreBackupFilesRequest{
		RepoPath: "r", Name: "box", DiskName: "rootfs", Timestamp: ts, Paths: []string{"/rootfs/root/notes.txt"},
	}, st); err != nil {
		t.Fatalf("RestoreBackupFiles: %v", err)
	}
	if ctx.Err() == nil {
		t.Fatal("control: the client never went away")
	}
	a := lastAuditRow(t, s, "backup.file_restore")
	if !a.found || a.result != "ok" || !strings.Contains(a.detail, "landlock=4") || !strings.Contains(a.detail, "paths=/rootfs/root/notes.txt") {
		t.Fatalf("a successful extraction whose client left: audit row %+v", a)
	}
}

// cancellingRestorer's client goes away while its restore VM starts.
type cancellingRestorer struct {
	*fakeRestorer
	cancel context.CancelFunc
}

func (c *cancellingRestorer) Open(ctx context.Context, dev filerestore.BlockDevice, kind, format string) (fileRestoreConn, error) {
	conn, err := c.fakeRestorer.Open(ctx, dev, kind, format)
	c.cancel()
	return conn, err
}

// Lab 2: a restore VM started without one of its barriers is audited even
// when the caller that started it has already gone.
func TestFileRestore_UnsandboxedAuditedAfterTheClientWentAway(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	const ts = "2026-10-10T01:00:00Z"
	s.SetBackupRepos(map[string]string{"r": ctBackup(t, s, ts)})
	ctx, cancel := context.WithCancel(adminCtx())
	defer cancel()
	s.setFileRestorer(&cancellingRestorer{
		fakeRestorer: &fakeRestorer{barriers: "sandbox=off apparmor=absent landlock=off uid=3800000001", reduced: true},
		cancel:       cancel,
	}, FileRestoreOptions{})
	_, _ = s.ListBackupFiles(ctx, &pb.ListBackupFilesRequest{RepoPath: "r", Name: "box", DiskName: "rootfs", Timestamp: ts})
	if u := lastAuditRow(t, s, "backup.file_restore_unsandboxed"); !u.found || !strings.Contains(u.detail, "sandbox=off") {
		t.Fatalf("a restore VM without its barriers, whose caller left: audit row %+v", u)
	}
}
