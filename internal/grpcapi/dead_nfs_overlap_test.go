package grpcapi

// Lab 2 F-2: an NFS server that stops answering while its export is mounted.
// A stat under the mount then blocks in the kernel until the server answers
// again; these tests stand that in with a path resolver that blocks until the
// test releases it.

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// deadServer makes every path resolution under one of roots block, as a
// stat on a hard NFS mount whose server does not answer does, until the test
// ends. It records the paths it blocked.
type deadServer struct {
	roots   []string
	release chan struct{}
	mu      sync.Mutex
	blocked []string
}

func installDeadServer(t *testing.T, roots ...string) *deadServer {
	t.Helper()
	d := &deadServer{roots: roots, release: make(chan struct{})}
	t.Cleanup(func() { close(d.release) })
	t.Cleanup(storage.OverrideFSCallBoundForTest(300 * time.Millisecond))
	t.Cleanup(storage.OverridePathResolverForTest(func(p string) string {
		for _, r := range d.roots {
			if pathWithin(r, p) {
				d.mu.Lock()
				d.blocked = append(d.blocked, p)
				d.mu.Unlock()
				<-d.release
				return p
			}
		}
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return p
	}))
	return d
}

func (d *deadServer) touched() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.blocked...)
}

// within runs fn and fails the test when it has not returned within limit.
func within[T any](t *testing.T, limit time.Duration, what string, fn func() T) T {
	t.Helper()
	ch := make(chan T, 1)
	go func() { ch <- fn() }()
	select {
	case v := <-ch:
		return v
	case <-time.After(limit):
		t.Fatalf("%s did not return within %v (it waits on a server that does not answer)", what, limit)
	}
	var zero T
	return zero
}

// F-2: a dir pool created beside an nfs pool whose server does not answer
// neither hangs nor fails. The overlap with the nfs pool's mount point is
// decided with no system call on it: the mount table has it as a mount
// point, which is its own resolution.
//
// Mutations: "no mount-point shortcut" (resolveBounded resolves a mount
// point too) — the resolution blocks, the check cannot verify, and the
// create is refused: red. "unbounded resolution" — the create hangs: red.
func TestCreateStoragePool_ADirPoolBesideAnNFSPoolWhoseServerDoesNotAnswer(t *testing.T) {
	s := newPoolTestServer(t)
	m := installHostMounts(t)
	dir := nfsPoolRow(t, s, "shared")
	m.mu.Lock()
	m.dirs[dir] = nfsTestSource // mounted, and its server gone
	m.mu.Unlock()
	dead := installDeadServer(t, dir)
	target := t.TempDir()
	err := within(t, 10*time.Second, "a dir pool create", func() error {
		_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "local1", Driver: "dir", Target: target})
		return err
	})
	if err != nil {
		t.Fatalf("dir pool create beside an nfs pool whose server does not answer: %v", err)
	}
	if got := dead.touched(); len(got) != 0 {
		t.Fatalf("the create stat'ed the dead NFS mount: %v", got)
	}
	if _, ok, _ := corrosion.GetStoragePool(context.Background(), s.db, s.hostName, "local1"); !ok {
		t.Fatal("the pool was not created")
	}
}

// F-2, fail closed: when an overlap can only be decided by resolving a path
// on the dead mount (an nfs pool whose --target lies inside a parent export
// mounted by hand), the create is refused, promptly and with a reason —
// never allowed because the check timed out.
//
// Mutations: "a timed-out overlap is no overlap" (DirsOverlap returns false,
// nil) and "poolSharedWith ignores the error" — the pool is created: red.
func TestCreateStoragePool_RefusesWhenAnOverlapCannotBeVerified(t *testing.T) {
	s := newPoolTestServer(t)
	m := installHostMounts(t)
	parent := filepath.Join(t.TempDir(), "nfsroot")
	m.mu.Lock()
	m.dirs[parent] = "10.0.0.50:/root" // a parent export, mounted by hand
	m.mu.Unlock()
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "inner", Driver: "nfs", Source: "10.0.0.50:/root/lv", Target: filepath.Join(parent, "lv"), State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	installDeadServer(t, parent)
	target := t.TempDir()
	t0 := time.Now()
	err := within(t, 10*time.Second, "a dir pool create", func() error {
		_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "local2", Driver: "dir", Target: target})
		return err
	})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "cannot verify") {
		t.Fatalf("create while an overlap cannot be verified: %v; want Unavailable naming it", err)
	}
	if took := time.Since(t0); took > 5*time.Second {
		t.Fatalf("the refusal took %v", took)
	}
	if _, ok, _ := corrosion.GetStoragePool(context.Background(), s.db, s.hostName, "local2"); ok {
		t.Fatal("a pool was created although its overlap with another could not be verified")
	}
}

// F-2, the global ISO library's own overlap check: a library directory on an
// NFS mount whose server does not answer cannot be told apart from a new
// pool's, and the create is refused — never allowed because the check timed
// out.
//
// Mutation "refuseOverlap ignores the error" — the pool is created: red.
func TestCreateStoragePool_RefusesWhenTheISOLibraryOverlapCannotBeVerified(t *testing.T) {
	s := newPoolTestServer(t)
	m := installHostMounts(t)
	parent := filepath.Join(t.TempDir(), "nfsroot")
	m.mu.Lock()
	m.dirs[parent] = "10.0.0.50:/root" // an fstab NFS mount
	m.mu.Unlock()
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: globalISOLibrary, Driver: "dir", Target: filepath.Join(parent, "isos"),
		Options: GlobalISOLibraryOptions(), State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	installDeadServer(t, parent)
	target := t.TempDir()
	err := within(t, 10*time.Second, "a dir pool create", func() error {
		_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "local3", Driver: "dir", Target: target})
		return err
	})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "cannot be verified") {
		t.Fatalf("create while the ISO library's overlap cannot be verified: %v; want Unavailable naming it", err)
	}
	if _, ok, _ := corrosion.GetStoragePool(context.Background(), s.db, s.hostName, "local3"); ok {
		t.Fatal("a pool was created although its overlap with the ISO library could not be verified")
	}
}
