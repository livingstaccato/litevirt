package grpcapi

// Lab 2 F-3: a mount of an nfs pool's export against a server that does not
// answer runs to its timeout. While it runs, the pool must read degraded with
// the reason, not active with no condition.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

func hangingMounts(t *testing.T, m *hostMounts) (release func(fail bool)) {
	t.Helper()
	ch := make(chan bool, 1)
	t.Cleanup(storage.OverrideNFSMountCommandForTest(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "mount" {
			select {
			case fail := <-ch:
				if fail {
					return []byte("mount.nfs: Connection timed out"), errors.New("exit status 32")
				}
			case <-ctx.Done():
				return []byte("mount.nfs: Connection timed out"), ctx.Err()
			}
		}
		return m.run(ctx, name, args...)
	}))
	return func(fail bool) { ch <- fail }
}

// F-3: while a mount of an export runs without finishing, the pool reads
// degraded, with the reason, on its row and in nfs_mount_missing — not active
// with no condition until the mount gives up. Once it is mounted, active and
// resolved.
//
// Mutation "no watch" (mountNFSLocked runs the mount unwatched) — the pool
// reads active while the mount hangs: red.
func TestReconcileNFSMounts_AMountThatHangsDegradesThePoolWhileItRuns(t *testing.T) {
	s, _ := provableCreateServer(t)
	m := installHostMounts(t)
	release := hangingMounts(t, m)
	prev := nfsMountSlowAfter
	nfsMountSlowAfter = 100 * time.Millisecond
	t.Cleanup(func() { nfsMountSlowAfter = prev })
	dir := nfsPoolRow(t, s, "shared")
	pass := make(chan struct{})
	go func() {
		s.ReconcileNFSMounts(context.Background())
		close(pass)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, ok := mountCondition(t, s, "shared")
		if poolState(t, s, "shared") == PoolStateDegraded && ok && c.Lifecycle != corrosion.ConditionResolved &&
			strings.Contains(c.Evidence, "has been running since") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pool %q, condition %+v found=%v while its mount hangs; want degraded with the reason",
				poolState(t, s, "shared"), c, ok)
		}
		time.Sleep(20 * time.Millisecond)
	}
	release(false)
	<-pass
	if !m.mounted(dir) {
		t.Fatal("the export was not mounted once the server answered")
	}
	if st := poolState(t, s, "shared"); st != "active" {
		t.Fatalf("pool state %q once mounted, want active", st)
	}
	if c, _ := mountCondition(t, s, "shared"); c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition %q once mounted, want resolved", c.Lifecycle)
	}
}

// F-3, the start path: a start's own mount that hangs degrades the pool
// while it runs, and one that fails leaves it degraded with the reason at
// once, not only at the next pass.
//
// Mutations: "no watch on the start path", "no outcome recorded by a start" —
// red.
func TestPrepareHardwareForStart_AHangingMountDegradesThePool(t *testing.T) {
	s, _ := provableCreateServer(t)
	m := installHostMounts(t)
	release := hangingMounts(t, m)
	prev := nfsMountSlowAfter
	nfsMountSlowAfter = 100 * time.Millisecond
	t.Cleanup(func() { nfsMountSlowAfter = prev })
	dir := nfsPoolRow(t, s, "shared")
	vm := nfsDiskVM(t, s, "shared", dir)
	started := make(chan error, 1)
	go func() {
		_, err := s.PrepareHardwareForStart(context.Background(), &vm)
		started <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for poolState(t, s, "shared") != PoolStateDegraded {
		if time.Now().After(deadline) {
			t.Fatal("the pool read active while a start's mount of it hung")
		}
		time.Sleep(20 * time.Millisecond)
	}
	release(true)
	if err := <-started; err == nil {
		t.Fatal("a start whose mount failed went ahead")
	}
	if st := poolState(t, s, "shared"); st != PoolStateDegraded {
		t.Fatalf("pool state %q after a start's mount failed, want degraded", st)
	}
	if c, ok := mountCondition(t, s, "shared"); !ok || !strings.Contains(c.Evidence, "Connection timed out") {
		t.Fatalf("condition %+v found=%v; want the mount's reason", c, ok)
	}
}
