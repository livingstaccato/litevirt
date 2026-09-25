package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// replicaPoolDir seeds a file-based "dir" pool on this host and returns the
// directory the replicas land in.
func replicaPoolDir(t *testing.T, s *Server, pool string) string {
	t.Helper()
	dir := t.TempDir()
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: pool, Driver: "dir", Target: dir, State: "active",
	}); err != nil {
		t.Fatalf("UpsertStoragePool: %v", err)
	}
	return dir
}

// promotableIn lists the files in dir that promotion would consider a replica
// of (vm, disk) — the exact predicate findReplicaHost selects the newest from.
func promotableIn(t *testing.T, dir, vm, disk string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var out []string
	for _, e := range ents {
		if isReplicaOf(e.Name(), vm, disk) {
			out = append(out, e.Name())
		}
	}
	return out
}

// A copy that fails must leave nothing promotable behind.
//
// The replica was written straight to its final `<vm>-<disk>-<ts>.qcow2` name,
// so a crash, a cancellation or a conversion error left a truncated file under
// a name promotion accepts — and promotion picks the lexically newest match,
// which is exactly the half-written one. Publication has to be a rename.
func TestReplicateLocal_AFailedCopyLeavesNothingPromotable(t *testing.T) {
	s := testServer(t)
	dir := replicaPoolDir(t, s, "dr")
	srcPath := filepath.Join(t.TempDir(), "root.qcow2")
	if err := os.WriteFile(srcPath, []byte("source"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	// A copier that gets partway — the file exists and is short — then fails.
	tornCopy := func(_ context.Context, _, dst string, _ func(*pb.MoveVolumeProgress) error) error {
		if err := os.WriteFile(dst, []byte("half a qcow2 header"), 0o600); err != nil {
			return err
		}
		return errors.New("conversion interrupted")
	}

	err := s.replicateLocalWith(context.Background(),
		corrosion.BackupScheduleRecord{VMName: "web-1", TargetPool: "dr", KeepReplicas: 3},
		&corrosion.DiskRecord{DiskName: "root", Path: srcPath, StorageType: "dir"},
		"20260101-000000", tornCopy)

	if err == nil {
		t.Fatal("replicateLocalWith returned nil for a failed copy")
	}
	if left := promotableIn(t, dir, "web-1", "root"); len(left) != 0 {
		t.Errorf("a failed copy left %v in the pool; promotion selects the newest match and would take it", left)
	}
}

// The temp file must not survive either, or every failed run leaks one into the
// pool directory an operator reads.
func TestReplicateLocal_AFailedCopyLeavesNoTempBehind(t *testing.T) {
	s := testServer(t)
	dir := replicaPoolDir(t, s, "dr")
	srcPath := filepath.Join(t.TempDir(), "root.qcow2")
	if err := os.WriteFile(srcPath, []byte("source"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	tornCopy := func(_ context.Context, _, dst string, _ func(*pb.MoveVolumeProgress) error) error {
		_ = os.WriteFile(dst, []byte("partial"), 0o600)
		return errors.New("conversion interrupted")
	}

	_ = s.replicateLocalWith(context.Background(),
		corrosion.BackupScheduleRecord{VMName: "web-1", TargetPool: "dr", KeepReplicas: 3},
		&corrosion.DiskRecord{DiskName: "root", Path: srcPath, StorageType: "dir"},
		"20260101-000000", tornCopy)

	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(ents) != 0 {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("failed run left %v in the pool directory; nothing should remain", names)
	}
}

// A copy that succeeds publishes under the final name. Without this, "never
// rename" passes both tests above.
func TestReplicateLocal_ASuccessfulCopyIsPublished(t *testing.T) {
	s := testServer(t)
	dir := replicaPoolDir(t, s, "dr")
	srcPath := filepath.Join(t.TempDir(), "root.qcow2")
	if err := os.WriteFile(srcPath, []byte("source"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	goodCopy := func(_ context.Context, _, dst string, _ func(*pb.MoveVolumeProgress) error) error {
		return os.WriteFile(dst, []byte("a whole replica"), 0o600)
	}

	if err := s.replicateLocalWith(context.Background(),
		corrosion.BackupScheduleRecord{VMName: "web-1", TargetPool: "dr", KeepReplicas: 3},
		&corrosion.DiskRecord{DiskName: "root", Path: srcPath, StorageType: "dir"},
		"20260101-000000", goodCopy); err != nil {
		t.Fatalf("replicateLocalWith: %v", err)
	}

	want := "web-1-root-20260101-000000.qcow2"
	if got := promotableIn(t, dir, "web-1", "root"); len(got) != 1 || got[0] != want {
		t.Errorf("published %v, want [%s]", got, want)
	}
}

// A copier that reports success but produced nothing is not a replica. An empty
// file under a final name is promotable and boots nothing.
func TestReplicateLocal_AnEmptyResultIsNotPublished(t *testing.T) {
	s := testServer(t)
	dir := replicaPoolDir(t, s, "dr")
	srcPath := filepath.Join(t.TempDir(), "root.qcow2")
	if err := os.WriteFile(srcPath, []byte("source"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	emptyCopy := func(_ context.Context, _, dst string, _ func(*pb.MoveVolumeProgress) error) error {
		return os.WriteFile(dst, nil, 0o600)
	}

	if err := s.replicateLocalWith(context.Background(),
		corrosion.BackupScheduleRecord{VMName: "web-1", TargetPool: "dr", KeepReplicas: 3},
		&corrosion.DiskRecord{DiskName: "root", Path: srcPath, StorageType: "dir"},
		"20260101-000000", emptyCopy); err == nil {
		t.Error("an empty replica was accepted")
	}
	if left := promotableIn(t, dir, "web-1", "root"); len(left) != 0 {
		t.Errorf("an empty replica was published as %v", left)
	}
}
