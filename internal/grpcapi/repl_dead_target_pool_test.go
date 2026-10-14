package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// deadNFSTargetPool adds an nfs pool "nfsdr" mounted (hardened) at a fresh
// directory whose server does not answer: its mountpoint check blocks, as a
// stat of a hard NFS mount does in the kernel, whatever its context says,
// until the test ends. It returns the mount point and how many mountpoint
// checks were started.
func deadNFSTargetPool(t *testing.T, s *Server) (string, *atomic.Int32) {
	t.Helper()
	mnt := t.TempDir()
	overrideMounts(t, "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw", nfsMountLine(mnt, "nas:/vm"))
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "nfsdr", Driver: "nfs", Source: "nas:/vm", Target: mnt, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	var probes atomic.Int32
	release := make(chan struct{})
	t.Cleanup(storage.OverrideNFSMountCommandForTest(func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "mountpoint" {
			probes.Add(1)
			<-release
		}
		return nil, errors.New("the server does not answer")
	}))
	deadMountSeams(t, mnt)
	t.Cleanup(func() { close(release) })
	return mnt, &probes
}

func replicateInto(s *Server, pool, srcPath string) error {
	goodCopy := func(_ context.Context, _, dst string, _ func(*pb.MoveVolumeProgress) error) error {
		return os.WriteFile(dst, []byte("a whole replica"), 0o600)
	}
	return s.replicateLocalWith(context.Background(),
		corrosion.BackupScheduleRecord{VMName: "web-1", TargetPool: pool, KeepReplicas: 3},
		&corrosion.VMRecord{Name: "web-1"},
		&corrosion.DiskRecord{DiskName: "root", Path: srcPath, StorageType: "dir"},
		"20260101-000000", goodCopy)
}

// Lab 2: a replication run into an nfs pool whose server did not answer sat
// about 120 s in "prepare target pool: check nfs mountpoint", and the
// sequential scheduler held every other schedule behind it. The target pool's
// prepare is bounded: the run is refused within the bound, the next run into
// that pool at once (the mount is latched), and a run into a healthy pool
// right after it is not held.
//
// Mutation: "drv.Prepare unbounded" — the first run hangs: red.
func TestReplicateLocal_ADeadNFSTargetPoolIsRefusedWithinTheBound(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "web-1", HostName: s.hostName, State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	healthy := replicaPoolDir(t, s, "dr")
	_, probes := deadNFSTargetPool(t, s)
	srcPath := filepath.Join(t.TempDir(), "root.qcow2")
	if err := os.WriteFile(srcPath, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := within(t, 3*time.Second, "a replication run into a dead nfs pool", func() error { return replicateInto(s, "nfsdr", srcPath) })
	if err == nil || !storage.IsFSNoAnswer(err) || !strings.Contains(err.Error(), "prepare target pool") {
		t.Fatalf("a run into a dead nfs pool = %v, want a refusal that the pool does not answer", err)
	}
	if probes.Load() == 0 {
		t.Fatal("the run never reached the pool's mountpoint check; the test does not exercise the prepare")
	}

	start := time.Now()
	err = within(t, 3*time.Second, "a second run into the dead nfs pool", func() error { return replicateInto(s, "nfsdr", srcPath) })
	if !storage.IsFSNoAnswer(err) {
		t.Fatalf("a second run into the dead nfs pool = %v, want a refusal that the pool does not answer", err)
	}
	if el := time.Since(start); el > 200*time.Millisecond {
		t.Fatalf("a second run into the dead nfs pool took %v; the latched mount should refuse it at once", el)
	}
	if n := probes.Load(); n != 1 {
		t.Fatalf("%d mountpoint checks started on the dead mount, want 1 (later ones refused by the latch)", n)
	}

	// The next schedule, into a healthy pool, is not held behind it.
	if err := within(t, 3*time.Second, "a run into a healthy pool after the dead one", func() error { return replicateInto(s, "dr", srcPath) }); err != nil {
		t.Fatalf("a run into a healthy pool after the dead one: %v", err)
	}
	if got := promotableIn(t, healthy, "web-1", "root"); len(got) != 1 {
		t.Fatalf("published %v into the healthy pool, want one replica", got)
	}
}

// The write paths that resolve a pool directory for a write (poolDirForWrite)
// are bounded the same way, and refuse Unavailable, as a start on a dead
// mount is.
//
// Mutation: "drv.Prepare unbounded in poolDirForWrite" — hangs: red.
func TestPoolDirForWrite_ADeadNFSPoolIsUnavailableWithinTheBound(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	mnt, _ := deadNFSTargetPool(t, s)
	ref := StoragePoolRef{Driver: "nfs", Source: "nas:/vm", Target: mnt}
	err := within(t, 3*time.Second, "poolDirForWrite on a dead nfs pool", func() error {
		_, err := s.poolDirForWrite(context.Background(), "nfsdr", ref)
		return err
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("poolDirForWrite on a dead nfs pool = %v, want Unavailable", err)
	}
}

// Replicate and Move map a pool that does not answer to Unavailable and any
// other prepare failure to FailedPrecondition, as before.
func TestPrepareTargetPoolStatus(t *testing.T) {
	if c := status.Code(prepareTargetPoolStatus(&storage.FSNoAnswerError{Op: "prepare the pool at", Path: "/m"})); c != codes.Unavailable {
		t.Errorf("no answer -> %v, want Unavailable", c)
	}
	if c := status.Code(prepareTargetPoolStatus(errors.New("mount failed"))); c != codes.FailedPrecondition {
		t.Errorf("mount failure -> %v, want FailedPrecondition", c)
	}
}
