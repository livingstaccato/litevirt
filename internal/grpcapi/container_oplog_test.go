package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"strings"
	"sync"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// opLogCapture swaps the slog default for a JSON recorder for one test. The
// stdlib log output is restored as well, because slog.SetDefault rewires it
// and restoring the stock default does not undo that.
type opLogCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *opLogCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func captureOpLog(t *testing.T) *opLogCapture {
	t.Helper()
	c := &opLogCapture{}
	prev, prevW, prevF := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewJSONHandler(c, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() {
		slog.SetDefault(prev)
		log.SetOutput(prevW)
		log.SetFlags(prevF)
	})
	return c
}

// record returns the first record with message msg whose attributes include
// every key/value in want, or nil.
func (c *opLogCapture) record(msg string, want map[string]string) map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, line := range strings.Split(c.buf.String(), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil || rec["msg"] != msg {
			continue
		}
		ok := true
		for k, v := range want {
			if s, _ := rec[k].(string); s != v {
				ok = false
			}
		}
		if ok {
			return rec
		}
	}
	return nil
}

func (c *opLogCapture) must(t *testing.T, level, msg string, want map[string]string) {
	t.Helper()
	rec := c.record(msg, want)
	if rec == nil {
		t.Fatalf("no %q record with %v in:\n%s", msg, want, c.buf.String())
	}
	if rec["level"] != level {
		t.Fatalf("%q logged at %v, want %s", msg, rec["level"], level)
	}
}

// Snapshot create, revert and delete each log a start and a completion on the
// host that runs them, the way VM snapshot operations log.
func TestContainerOpLog_SnapshotLifecycle(t *testing.T) {
	s, _ := snapTestServer(t, "running")
	logs := captureOpLog(t)

	if _, err := s.SnapshotContainer(adminCtx(), &pb.SnapshotContainerRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"}); err != nil {
		t.Fatalf("SnapshotContainer: %v", err)
	}
	if _, err := s.RevertContainerSnapshot(adminCtx(), &pb.RevertContainerSnapshotRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"}); err != nil {
		t.Fatalf("RevertContainerSnapshot: %v", err)
	}
	if _, err := s.DeleteContainerSnapshot(adminCtx(), &pb.DeleteContainerSnapshotRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"}); err != nil {
		t.Fatalf("DeleteContainerSnapshot: %v", err)
	}
	attrs := map[string]string{"name": "ct1", "host": "host-a", "snapshot": "s1"}
	for _, op := range []string{"snapshot", "snapshot revert", "snapshot delete"} {
		logs.must(t, "INFO", "container "+op+" started", attrs)
		logs.must(t, "INFO", "container "+op+" completed", attrs)
	}
}

// A snapshot the runtime cannot export is an ERROR with the cause.
func TestContainerOpLog_SnapshotFailureIsError(t *testing.T) {
	s, rt := snapTestServer(t, "stopped")
	rt.exportErr = errors.New("tar read error")
	logs := captureOpLog(t)

	if _, err := s.SnapshotContainer(adminCtx(), &pb.SnapshotContainerRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"}); err == nil {
		t.Fatal("snapshot with a failing export succeeded")
	}
	logs.must(t, "ERROR", "container snapshot failed", map[string]string{"name": "ct1", "snapshot": "s1"})
	if rec := logs.record("container snapshot failed", nil); !strings.Contains(rec["error"].(string), "tar read error") {
		t.Fatalf("failure record does not carry the cause: %v", rec)
	}
}

// Backup and restore log start and completion; a restore refused because the
// name is live is a WARN (the operator's request, not a fault).
func TestContainerOpLog_BackupAndRestore(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	ctx := context.Background()
	repo := ctTestRepo(t)
	s.SetContainerRuntime(&fakeCTRuntime{exportPayload: []byte("rootfs")})
	_ = corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "stopped", Project: "acme",
	})
	logs := captureOpLog(t)

	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "ct1", HostName: "host-a", RepoPath: repo, Timestamp: "2026-10-08T12:48:39Z",
	}, bk); err != nil {
		t.Fatalf("BackupContainer: %v", err)
	}
	logs.must(t, "INFO", "container backup started", map[string]string{"name": "ct1", "host": "host-a"})
	logs.must(t, "INFO", "container backup completed", map[string]string{"name": "ct1", "timestamp": "2026-10-08T12:48:39Z"})

	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "ct1", RepoPath: repo, Timestamp: "2026-10-08T12:48:39Z",
	}, rs); err == nil {
		t.Fatal("restore over a live container succeeded")
	}
	logs.must(t, "WARN", "container restore failed", map[string]string{"name": "ct1", "code": "AlreadyExists"})

	_ = corrosion.DeleteContainer(ctx, s.db, "host-a", "ct1")
	rs = &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "ct1", RepoPath: repo, Timestamp: "2026-10-08T12:48:39Z",
	}, rs); err != nil {
		t.Fatalf("RestoreContainer: %v", err)
	}
	logs.must(t, "INFO", "container restore completed", map[string]string{"name": "ct1", "timestamp": "2026-10-08T12:48:39Z"})
}

// Migrate logs start and completion on the source with the target named, and
// a failed archive is an ERROR.
func TestContainerOpLog_Migrate(t *testing.T) {
	s, _, repo := migrateTestServer(t, "running")
	ctx := context.Background()
	s.migrateRestoreOverride = func(_ context.Context, target, _, name, _ string, _ bool) (corrosion.RestoreOutcome, error) {
		if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
			HostName: target, Name: name, State: "running", Project: "acme",
		}); err != nil {
			return corrosion.RestoreNotAttempted, err
		}
		return corrosion.RestoreLanded, nil
	}
	logs := captureOpLog(t)
	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	if err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo,
	}, st); err != nil {
		t.Fatalf("MigrateContainer: %v", err)
	}
	logs.must(t, "INFO", "container migrate started", map[string]string{"name": "ct1", "host": "host-a", "target": "host-b"})
	logs.must(t, "INFO", "container migrate completed", map[string]string{"name": "ct1", "target": "host-b"})

	s2, rt2, repo2 := migrateTestServer(t, "running")
	rt2.exportErr = errors.New("tar read error")
	st = &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	if err := s2.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo2,
	}, st); err == nil {
		t.Fatal("migrate with a failing archive succeeded")
	}
	logs.must(t, "ERROR", "container migrate failed", map[string]string{"name": "ct1", "target": "host-b", "code": "Internal"})
}

// A caller refused by RBAC writes no op line: the line starts only after
// authorization.
func TestContainerOpLog_DeniedCallerWritesNothing(t *testing.T) {
	s, _ := snapTestServer(t, "running")
	other := grantUser(t, s, "mallory", "/projects/beta", "Operator")
	logs := captureOpLog(t)
	if _, err := s.SnapshotContainer(other, &pb.SnapshotContainerRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"}); err == nil {
		t.Fatal("out-of-project snapshot succeeded")
	}
	if rec := logs.record("container snapshot started", nil); rec != nil {
		t.Fatalf("a denied caller wrote an op line: %v", rec)
	}
}

// The node that forwards a call to the container's owner logs nothing for
// it; the owner logs it once, where it runs.
func TestContainerOpLog_ForwardingNodeLogsNothing(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	s.SetContainerRuntime(&fakeCTRuntime{})
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-b", Name: "ctb", State: "running", Project: "acme",
	}); err != nil {
		t.Fatal(err)
	}
	logs := captureOpLog(t)
	_, _ = s.SnapshotContainer(adminCtx(), &pb.SnapshotContainerRequest{Name: "ctb", Snapshot: "s1"})
	_, _ = s.RevertContainerSnapshot(adminCtx(), &pb.RevertContainerSnapshotRequest{Name: "ctb", Snapshot: "s1"})
	_, _ = s.DeleteContainerSnapshot(adminCtx(), &pb.DeleteContainerSnapshotRequest{Name: "ctb", Snapshot: "s1"})
	for _, op := range []string{"snapshot", "snapshot revert", "snapshot delete"} {
		if rec := logs.record("container "+op+" started", nil); rec != nil {
			t.Fatalf("the forwarding node logged %q: %v", op, rec)
		}
	}
}

// Each operation logs its start and its outcome exactly once.
func TestContainerOpLog_EachLineOnce(t *testing.T) {
	s, _ := snapTestServer(t, "running")
	logs := captureOpLog(t)
	if _, err := s.SnapshotContainer(adminCtx(), &pb.SnapshotContainerRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"}); err != nil {
		t.Fatal(err)
	}
	for _, msg := range []string{"container snapshot started", "container snapshot completed"} {
		if n := logs.count(msg); n != 1 {
			t.Fatalf("%q logged %d times, want 1", msg, n)
		}
	}
}

func (c *opLogCapture) count(msg string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, line := range strings.Split(c.buf.String(), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil && rec["msg"] == msg {
			n++
		}
	}
	return n
}
