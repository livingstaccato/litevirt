package daemon

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// blockingSweeper is a gRPC server whose startup sweep blocks, as one does
// reading a pool directory on an NFS mount whose server does not answer.
type blockingSweeper struct {
	release chan struct{}
	marked  chan struct{}
}

func (b *blockingSweeper) SweepStaleStaging(context.Context) { <-b.release }
func (b *blockingSweeper) RunPoolRecordsMarker(context.Context) {
	close(b.marked)
}

// F-1: the startup sweeps run off the start path. On lab 2 the sweep's
// os.ReadDir of an nfs pool's mount point, made before the gRPC server
// served, blocked the daemon's start for good, and the peers fenced the host.
// The marker still runs after the sweep, as it did.
//
// Mutation "sweep on the start path" (startStorageSweeps calls the sweep
// itself) — the start waits on the sweep: red.
func TestStartStorageSweeps_DoesNotHoldTheStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &blockingSweeper{release: make(chan struct{}), marked: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		startStorageSweeps(ctx, b)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(b.release)
		t.Fatal("the daemon's start waited on the startup sweep")
	}
	select {
	case <-b.marked:
		t.Fatal("the pool records marker ran before the sweep finished")
	default:
	}
	close(b.release)
	select {
	case <-b.marked:
	case <-time.After(2 * time.Second):
		t.Fatal("the pool records marker did not run after the sweep")
	}
}

// A startup step that does not finish is waited for only up to its bound.
//
// Mutation "wait for the step" — red.
func TestAwaitStartupStep_GivesUpAfterItsBound(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	t0 := time.Now()
	if awaitStartupStep("test", 200*time.Millisecond, func() { <-release }) {
		t.Fatal("a step that did not finish reported finished")
	}
	if d := time.Since(t0); d > 2*time.Second {
		t.Fatalf("waited %v for a step bounded at 200ms", d)
	}
	if !awaitStartupStep("test", time.Second, func() {}) {
		t.Fatal("a step that finished reported unfinished")
	}
}

// deadStatfs makes statfs block for target until the test ends, as on an NFS
// mount whose server does not answer, and fail with ENOENT elsewhere.
func deadStatfs(t *testing.T, target string) {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	t.Cleanup(storage.OverrideFSCallBoundForTest(200 * time.Millisecond))
	orig := statfsFn
	statfsFn = func(path string, st *syscall.Statfs_t) error {
		if path == target {
			<-release
		}
		return syscall.ENOENT
	}
	t.Cleanup(func() { statfsFn = orig })
}

// F-1: the statfs of a pool's directory at start — the host's disk total,
// the config pools' registration, the capacity refresh — gives up on one
// that does not answer (an nfs pool's --target, a dir pool on an fstab NFS
// mount) instead of holding the start.
//
// Mutation "unbounded statfs" (poolStatfs calls statfsFn directly) — each
// call hangs: red.
func TestPoolStatfs_ADirectoryThatDoesNotAnswerHoldsNoStartupStep(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "nfs-target")
	deadStatfs(t, target)
	pools := []StoragePoolConfig{{Name: "shared", Driver: "nfs", Source: "10.0.0.21:/srv/lv", Target: target}}
	d := &Daemon{db: db, cfg: &Config{HostName: "host-a", DataDir: t.TempDir(), StoragePools: pools}}
	for name, step := range map[string]func(){
		"sumPoolDiskTotalGiB":   func() { d.sumPoolDiskTotalGiB(ctx) },
		"registerStoragePools":  func() { d.registerStoragePools(ctx) },
		"refreshDBPoolCapacity": func() { d.refreshDBPoolCapacity(ctx) },
	} {
		done := make(chan struct{})
		go func() {
			step()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s waited on a statfs that does not return", name)
		}
	}
	rec, ok, err := corrosion.GetStoragePool(ctx, db, "host-a", "shared")
	if err != nil || !ok || rec.State != "error" {
		t.Fatalf("pool %+v found=%v err=%v; want registered, in state error", rec, ok, err)
	}
}

// A config directory pool on an NFS mount records the export it is on. When
// its directory does not resolve in time (the server does not answer), the
// registration keeps the export the row recorded instead of dropping it,
// which would let another host's pool be created on the same export.
//
// Mutation "a resolution that does not finish is no export" — the recorded
// export is dropped: red.
func TestRegisterStoragePools_KeepsTheRecordedExportWhileItCannotBeJudged(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	mnt := filepath.Join(t.TempDir(), "nfs")
	target := filepath.Join(mnt, "pool")
	t.Cleanup(storage.OverrideMountInfoForTest(func() ([]byte, error) {
		return []byte(fmt.Sprintf("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"+
			"40 1 0:60 / %s rw,nosuid,nodev,noexec,nosymfollow - nfs4 nas:/export rw\n", mnt)), nil
	}))
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	t.Cleanup(storage.OverrideFSCallBoundForTest(200 * time.Millisecond))
	t.Cleanup(storage.OverridePathResolverForTest(func(p string) string {
		if strings.HasPrefix(p, mnt) {
			<-release
		}
		return p
	}))
	deadStatfs(t, target)
	const recorded = "nas:/export/pool"
	if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{
		HostName: "host-a", Name: "fast", Driver: "dir", Target: target, State: "active",
		Options: map[string]string{storage.NFSExportOption: recorded},
	}); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{db: db, cfg: &Config{HostName: "host-a", DataDir: t.TempDir(),
		StoragePools: []StoragePoolConfig{{Name: "fast", Driver: "dir", Target: target}}}}
	done := make(chan struct{})
	go func() {
		d.registerStoragePools(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("registration waited on a directory that does not answer")
	}
	rec, ok, err := corrosion.GetStoragePool(ctx, db, "host-a", "fast")
	if err != nil || !ok || rec.Options[storage.NFSExportOption] != recorded {
		t.Fatalf("pool %+v found=%v err=%v; want the recorded export %q kept", rec, ok, err, recorded)
	}
}
