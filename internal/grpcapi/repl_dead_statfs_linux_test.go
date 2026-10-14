package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// statfsBlocksUnder makes a statfs of any path under mnt block until the test
// ends, as it does in the kernel on a hard NFS mount whose server does not
// answer (a statfs always goes to the server), and counts those calls. Other
// paths get the real statfs.
func statfsBlocksUnder(t *testing.T, mnt string) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	release := make(chan struct{})
	t.Cleanup(storage.OverrideStatfsForTest(func(p string) (uint32, string, error) {
		if pathWithin(mnt, p) {
			n.Add(1)
			<-release
			return 0, "", errors.New("the server does not answer")
		}
		var st syscall.Statfs_t
		if err := syscall.Statfs(p, &st); err != nil {
			return 0, "", err
		}
		return uint32(st.Type), fmt.Sprintf("%08x%08x", uint32(st.Fsid.X__val[0]), uint32(st.Fsid.X__val[1])), nil
	}))
	t.Cleanup(func() { close(release) })
	return &n
}

// Lab 2, 8600a939: with the NFS server blocked, replication into the nfs pool
// was never refused and held every schedule for the whole outage. Prepare
// passed — the mount point's stat and "mountpoint" were answered from the
// client's attribute cache — and the write after it blocked in the kernel
// (nfs4_proc_getattr). Here every stat-like answer comes back, as the cache
// gives it, and only the server round trip (statfs) blocks: the run is
// refused within the bound, the next one at once (latched), and a run into a
// healthy pool right after is not held.
//
// Mutation: no probe in prepareTargetPool — the run goes ahead into the dead
// pool: red.
func TestReplicateLocal_ADeadNFSPoolWhoseStatIsCachedIsRefusedWithinTheBound(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "web-1", HostName: s.hostName, State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	healthy := replicaPoolDir(t, s, "dr")
	mnt := t.TempDir()
	overrideMounts(t, "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw", nfsMountLine(mnt, "nas:/vm"))
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "nfsdr", Driver: "nfs", Source: "nas:/vm", Target: mnt, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	// "mountpoint" answers: mounted (from the attribute cache).
	t.Cleanup(storage.OverrideNFSMountCommandForTest(func(context.Context, string, ...string) ([]byte, error) { return nil, nil }))
	t.Cleanup(storage.OverrideFSCallBoundForTest(300 * time.Millisecond))
	probes := statfsBlocksUnder(t, mnt)
	srcPath := filepath.Join(t.TempDir(), "root.qcow2")
	if err := os.WriteFile(srcPath, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := within(t, 3*time.Second, "a replication run into a dead nfs pool", func() error { return replicateInto(s, "nfsdr", srcPath) })
	if !storage.IsFSNoAnswer(err) || !strings.Contains(err.Error(), "statfs") {
		t.Fatalf("a run into a dead nfs pool = %v, want a refusal that its server does not answer", err)
	}
	if left := filesUnder(t, mnt); len(left) != 0 {
		t.Fatalf("a refused run wrote %v into the dead pool", left)
	}

	start := time.Now()
	err = within(t, 3*time.Second, "a second run into the dead nfs pool", func() error { return replicateInto(s, "nfsdr", srcPath) })
	if !storage.IsFSNoAnswer(err) {
		t.Fatalf("a second run into the dead nfs pool = %v, want a refusal that it does not answer", err)
	}
	if el := time.Since(start); el > 200*time.Millisecond {
		t.Fatalf("a second run took %v; the latched mount should refuse it at once", el)
	}
	if n := probes.Load(); n != 1 {
		t.Fatalf("%d statfs calls started on the dead mount, want 1 (later ones refused by the latch)", n)
	}

	if err := within(t, 3*time.Second, "a run into a healthy pool after the dead one", func() error { return replicateInto(s, "dr", srcPath) }); err != nil {
		t.Fatalf("a run into a healthy pool after the dead one: %v", err)
	}
	if got := promotableIn(t, healthy, "web-1", "root"); len(got) != 1 {
		t.Fatalf("published %v into the healthy pool, want one replica", got)
	}
}

// A directory pool on a network mount (fstab) whose server does not answer
// is refused Unavailable by poolDirForWrite (every replica-area write, the
// incremental and mirror paths among them), within the bound.
//
// Mutation: no probe in poolDirForWrite for a directory pool — it returns
// the directory: red.
func TestPoolDirForWrite_ADirPoolOnADeadNetworkMountIsUnavailable(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	mnt := t.TempDir()
	overrideMounts(t, "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw", nfsMountLine(mnt, "nas:/vm"))
	t.Cleanup(storage.OverrideFSCallBoundForTest(300 * time.Millisecond))
	statfsBlocksUnder(t, mnt)
	dir := filepath.Join(mnt, "pool")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	err := within(t, 3*time.Second, "poolDirForWrite on a dir pool on a dead mount", func() error {
		_, err := s.poolDirForWrite(context.Background(), "fst", StoragePoolRef{Driver: "dir", Target: dir})
		return err
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("poolDirForWrite on a dir pool on a dead network mount = %v, want Unavailable", err)
	}
}
