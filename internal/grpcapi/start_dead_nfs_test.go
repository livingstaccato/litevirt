package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/storage"
)

// deadMountSeams makes every symlink resolution under any of mnts block until
// the test ends, as a stat on a hard NFS mount whose server does not answer
// does, and records what it blocked.
func deadMountSeams(t *testing.T, mnts ...string) (touched func() []string) {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var mu sync.Mutex
	var seen []string
	block := func(p string) {
		for _, mnt := range mnts {
			if pathWithin(mnt, p) {
				mu.Lock()
				seen = append(seen, p)
				mu.Unlock()
				<-release
				return
			}
		}
	}
	t.Cleanup(storage.OverrideFSCallBoundForTest(300 * time.Millisecond))
	t.Cleanup(storage.OverrideEvalSymlinksForTest(func(p string) (string, error) {
		block(p)
		return filepath.EvalSymlinks(p)
	}))
	t.Cleanup(storage.OverridePathResolverForTest(func(p string) string {
		block(p)
		return p
	}))
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// startChainWithDeadNFS is the start-chain fixture plus an nfs pool, usable
// by every project, mounted at mnt (a hardened NFS mount the mount table
// names) whose server does not answer.
func startChainWithDeadNFS(t *testing.T) (*startChainFixture, string, func() []string) {
	t.Helper()
	f := newStartChainFixture(t)
	mnt := t.TempDir()
	overrideMounts(t, "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw", nfsMountLine(mnt, "nas:/vm"))
	if err := corrosion.UpsertStoragePool(context.Background(), f.s.db, corrosion.StoragePoolRecord{
		HostName: f.s.hostName, Name: "shared", Driver: "nfs", Source: "nas:/vm", Target: mnt, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	f.s.SetStoragePoolsByName(map[string]StoragePoolRef{
		"pa": {Driver: "dir", Target: f.pa}, "g": {Driver: "dir", Target: f.global},
		"shared": {Driver: "nfs", Source: "nas:/vm", Target: mnt},
	})
	return f, mnt, deadMountSeams(t, mnt)
}

// Lab 2 N-1: a start of a VM on local storage judges its chain against every
// pool directory of the host, the nfs pool's mount point included. While
// that pool's server does not answer, the start goes ahead promptly and makes
// no call on the dead mount: a mount point is its own resolution.
//
// Mutations: "resolvedOr unbounded" — the start hangs: red. "no mount-point
// shortcut" — the dead mount is stat'ed: red.
func TestStart_ALocalDiskVMStartsWhileAnNFSPoolDoesNotAnswer(t *testing.T) {
	f, mnt, touched := startChainWithDeadNFS(t)
	vm := f.mainEraVM(t, "web", f.pa, "pa")
	if err := qcow2.Create(filepath.Join(f.pa, "ubuntu"), 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	err := within(t, 10*time.Second, "a local-disk VM's start checks", func() error {
		return f.s.verifyImageBasesForStart(context.Background(), vm)
	})
	if err != nil {
		t.Fatalf("start of a local-disk VM while an nfs pool's server does not answer: %v", err)
	}
	if got := touched(); len(got) != 0 {
		t.Fatalf("the start touched the dead mount %s: %v", mnt, got)
	}
}

// The same, with a second nfs pool whose directory lies below the dead mount
// (not a mount point): its resolution needs the server, and is given up on
// within its bound, inside the start check's own longer bound — the start
// still goes ahead.
//
// Mutation "EvalSymlinksBounded unbounded" — that resolution holds the start
// check past its bound, and the local VM is refused: red.
func TestStart_ALocalDiskVMStartsBesideAPoolBelowADeadMount(t *testing.T) {
	f, mnt, _ := startChainWithDeadNFS(t)
	if err := corrosion.UpsertStoragePool(context.Background(), f.s.db, corrosion.StoragePoolRecord{
		HostName: f.s.hostName, Name: "inner", Driver: "nfs", Source: "nas:/vm/inner", Target: filepath.Join(mnt, "inner"), State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	vm := f.mainEraVM(t, "web", f.pa, "pa")
	if err := qcow2.Create(filepath.Join(f.pa, "ubuntu"), 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	err := within(t, 10*time.Second, "a local-disk VM's start checks", func() error {
		return f.s.verifyImageBasesForStart(context.Background(), vm)
	})
	if err != nil {
		t.Fatalf("start of a local-disk VM beside a pool below a dead mount: %v", err)
	}
}

// A VM whose disk is on the dead mount is refused, promptly and saying why
// (Unavailable: the start may be retried), instead of holding its VM lock —
// and the VM's stop behind it — for as long as the server does not answer.
//
// Mutation "the start's disk checks unbounded" — the start goes ahead on the
// dead disk (here: no refusal): red.
func TestStart_AVMOnADeadNFSPoolIsRefusedWithinTheBound(t *testing.T) {
	f, mnt, _ := startChainWithDeadNFS(t)
	disk := filepath.Join(mnt, "nvm-root.qcow2")
	if err := qcow2.CreateWithBacking(disk, "ubuntu", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	vm := f.insertVM(t, "nvm", "a", disk, "shared", "ubuntu")
	// An earlier call under the mount has gone unanswered: its server is dead.
	if _, err := storage.Bounded("stat", filepath.Join(mnt, "x"), func() (int, error) {
		time.Sleep(time.Hour)
		return 0, nil
	}); !storage.IsFSNoAnswer(err) {
		t.Fatalf("setup: %v", err)
	}
	t0 := time.Now()
	err := within(t, 10*time.Second, "a dead-pool VM's start checks", func() error {
		return f.s.verifyImageBasesForStart(context.Background(), vm)
	})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "does not answer") ||
		!strings.Contains(err.Error(), "retry once it answers") {
		t.Fatalf("start of a VM whose disk is on a dead mount: %v; want Unavailable saying its storage does not answer and to retry", err)
	}
	if took := time.Since(t0); took > 3*time.Second {
		t.Fatalf("the refusal took %v", took)
	}
}
