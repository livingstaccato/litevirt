package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// Round 1 M-4: the start's watcher writes on a fresh bounded context, not the
// mount's own: a start that is all but out of time (it waited for nfsMu, say)
// still records the pool degraded while its mount hangs past that time.
//
// Mutation "the watcher writes on the mount's context" — the write fails on
// the spent context and the pool reads active: red.
func TestPrepareHardwareForStart_AWatcherOnASpentContextStillRecords(t *testing.T) {
	s, _ := provableCreateServer(t)
	m := installHostMounts(t)
	release := make(chan struct{})
	t.Cleanup(storage.OverrideNFSMountCommandForTest(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "mount" {
			<-release // blocked in the kernel: the deadline does not end it
		}
		return m.run(ctx, name, args...)
	}))
	prev := nfsMountSlowAfter
	nfsMountSlowAfter = 400 * time.Millisecond
	t.Cleanup(func() { nfsMountSlowAfter = prev })
	dir := nfsPoolRow(t, s, "shared")
	vm := nfsDiskVM(t, s, "shared", dir)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := make(chan struct{})
	go func() {
		_, _ = s.PrepareHardwareForStart(ctx, &vm)
		close(started)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for poolState(t, s, "shared") != PoolStateDegraded {
		if time.Now().After(deadline) {
			close(release)
			<-started
			t.Fatal("the watcher of a start past its deadline did not record the pool degraded")
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(release)
	<-started
}

// Round 1 M-3: a cutover cleanup whose volumes are on storage that does not
// answer is deferred before it takes its VMs' locks, not run under them.
//
// Mutation "no probe" (vmReplaceCleanupStorageAnswers returns nil) — red.
func TestVMReplaceCleanup_StorageThatDoesNotAnswerDefersIt(t *testing.T) {
	s := testServer(t)
	mnt := t.TempDir()
	overrideMounts(t, nfsMountLine(mnt, "nas:/vm"))
	t.Cleanup(storage.OverrideFSCallBoundForTest(200 * time.Millisecond))
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	// An earlier call under the mount went unanswered: the server is dead.
	if _, err := storage.Bounded("stat", filepath.Join(mnt, "x"), func() (int, error) { <-release; return 0, nil }); !storage.IsFSNoAnswer(err) {
		t.Fatalf("setup: %v", err)
	}
	pool := filepath.Join(mnt, "pool")
	if err := os.MkdirAll(pool, 0o755); err != nil {
		t.Fatal(err)
	}
	cl := corrosion.VMReplaceCleanup{Manifest: corrosion.VMReplaceManifest{
		ReplacedVM: "old", Replacement: "new",
		Disks: []corrosion.DiskRecord{{VMName: "old", DiskName: "root", Path: filepath.Join(pool, "old-root.qcow2")}},
	}}
	if err := s.vmReplaceCleanupStorageAnswers(cl); !storage.IsFSNoAnswer(err) {
		t.Fatalf("probe of a cleanup on a dead store = %v; want it deferred", err)
	}
	local := corrosion.VMReplaceCleanup{Manifest: corrosion.VMReplaceManifest{
		Disks: []corrosion.DiskRecord{{Path: filepath.Join(t.TempDir(), "d.qcow2")}},
	}}
	if err := s.vmReplaceCleanupStorageAnswers(local); err != nil {
		t.Fatalf("probe of a cleanup on local storage = %v", err)
	}
}
