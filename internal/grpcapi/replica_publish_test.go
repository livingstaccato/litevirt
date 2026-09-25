package grpcapi

import (
	"context"
	"errors"
	"fmt"
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

// A replica is durable before it becomes promotable.
//
// qemu-img convert does not flush its output by default, and a rename is only
// a metadata operation: after a power loss the final, promotable name can
// point at a file whose data never reached the disk — short or zero-filled,
// and the lexically newest candidate auto-promote will boot. So the .partial
// file is synced BEFORE the rename, and the directory after it, so the rename
// itself survives.
func TestPublishReplica_SyncsBeforeItIsPromotable(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "web-1-root-20260924T120000Z.qcow2")

	var order []string
	prev := syncPath
	t.Cleanup(func() { syncPath = prev })
	syncPath = func(p string) error {
		_, err := os.Stat(dst)
		order = append(order, fmt.Sprintf("%s published=%v", filepath.Base(p), err == nil))
		return nil
	}

	if err := publishReplica(context.Background(), dst, func(tmp string) error {
		return os.WriteFile(tmp, []byte("qcow2"), 0o600)
	}); err != nil {
		t.Fatalf("publishReplica: %v", err)
	}
	want := []string{
		"." + filepath.Base(dst) + ".partial published=false", // the data, before the rename
		filepath.Base(dir) + " published=true",                // the rename itself
	}
	if fmt.Sprint(order) != fmt.Sprint(want) {
		t.Fatalf("sync order = %v, want %v", order, want)
	}
}

// A replica whose data could not be made durable is not published: a sync
// failure is the storage saying it cannot promise the bytes.
func TestPublishReplica_ASyncFailurePublishesNothing(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "web-1-root-20260924T120000Z.qcow2")
	prev := syncPath
	t.Cleanup(func() { syncPath = prev })
	syncPath = func(string) error { return errors.New("EIO") }

	err := publishReplica(context.Background(), dst, func(tmp string) error {
		return os.WriteFile(tmp, []byte("qcow2"), 0o600)
	})
	if err == nil {
		t.Fatal("publishReplica succeeded although the replica could not be synced")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("left %d file(s) behind after a failed sync; want none", len(entries))
	}
}
