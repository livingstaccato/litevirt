package grpcapi

// The take-back of a cold copy placed as its source gave up
// (ReceiveMigrationDisk): the file it unlinks must be one nothing else has
// adopted in the meantime. Here the receive and EnsureDisks name the same
// file, which the fleet cannot arrange (it roots each node's disk files apart).

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// captureDiskUp records what the source sends and answers as a target that
// took all of it.
type captureDiskUp struct {
	grpc.ClientStream
	frames []*pb.ReceiveMigrationDiskRequest
	size   int64
}

func (u *captureDiskUp) Send(m *pb.ReceiveMigrationDiskRequest) error {
	u.frames = append(u.frames, proto.Clone(m).(*pb.ReceiveMigrationDiskRequest))
	return nil
}
func (u *captureDiskUp) CloseAndRecv() (*pb.ReceiveMigrationDiskResponse, error) {
	return &pb.ReceiveMigrationDiskResponse{SizeBytes: u.size}, nil
}

type captureDiskClient struct {
	pb.LiteVirtClient
	up *captureDiskUp
}

func (c *captureDiskClient) ReceiveMigrationDisk(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.ReceiveMigrationDiskRequest, pb.ReceiveMigrationDiskResponse], error) {
	return c.up, nil
}

// A receive that replaces this host's own stub with the copy, and whose source
// gives up while the copy is being placed, takes the copy back. Until it is
// known whether the source is still there, the placed file is not this host's
// stub: an EnsureDisks of a new storage migration of the VM meanwhile is
// refused (naming the way out), and never reuses the file the take-back then
// unlinks, which would leave QEMU mirroring the VM's disk into an unlinked
// inode.
//
// Mutation: keep the stub's ledger entry when the receive removes the stub —
// EnsureDisks reuses the placed copy and the take-back unlinks it, red.
func TestReceiveMigrationDisk_ATakeBackNeverUnlinksAFileEnsureDisksReused(t *testing.T) {
	f := newColdDiskFixture(t)
	const size = 4 << 20
	// The VM's disk: a qcow2, so the copy placed on the target is one of the
	// size a stub for it would be.
	sp := f.src.hostDiskFile(f.path)
	if err := os.MkdirAll(filepath.Dir(sp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(sp, size, nil); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(sp)
	if err != nil {
		t.Fatal(err)
	}
	stubReq := &pb.EnsureDisksRequest{VmName: "os1", Disks: []*pb.DiskStub{{Path: f.path, SizeBytes: size}}}
	// This host's stub for the VM, from the attempt the copy is part of.
	if _, err := f.dst.EnsureDisks(f.peer, stubReq); err != nil {
		t.Fatalf("EnsureDisks (the attempt's stub): %v", err)
	}
	if !f.dst.madeHere(context.Background(), &f.dst.migrationStubs, "os1", f.path) {
		t.Fatal("fixture: the stub is not recorded as this host's")
	}
	up := &captureDiskUp{size: st.Size()}
	if err := f.src.streamColdDisk(adminCtx(), &captureDiskClient{up: up}, "os1", f.disk, "raw"); err != nil {
		t.Fatalf("streamColdDisk: %v", err)
	}

	sctx, giveUp := context.WithCancel(f.peer)
	defer giveUp()
	var ensureErr error
	var reused []string
	f.dst.SetColdDiskPlacedHookForTest(func() {
		// The source gives up while the copy is placed, and a new storage
		// migration of the VM asks for its stub meanwhile.
		giveUp()
		resp, err := f.dst.EnsureDisks(f.peer, stubReq)
		ensureErr = err
		reused = resp.GetCreatedPaths()
	})
	err = f.dst.ReceiveMigrationDisk(&diskRecvStream{ctx: sctx, frames: up.frames})
	if status.Code(err) != codes.Canceled {
		t.Fatalf("receive whose source gave up = %v, want Canceled", err)
	}
	if len(reused) > 0 {
		t.Fatalf("EnsureDisks reused %v during the take-back window; the take-back then unlinked it", reused)
	}
	if status.Code(ensureErr) != codes.FailedPrecondition {
		t.Fatalf("EnsureDisks during the take-back window = %v, want FailedPrecondition (not this host's stub)", ensureErr)
	}
	if _, err := os.Lstat(f.path); !os.IsNotExist(err) {
		t.Fatalf("the copy placed after the source gave up is still at %s (stat: %v)", f.path, err)
	}
	if f.dst.madeHere(context.Background(), &f.dst.migrationStubs, "os1", f.path) {
		t.Fatal("the taken-back copy is still recorded as this host's stub")
	}
}

// A take-back removes the copy it placed only while that file is still at the
// path. Here, while the directory sync stalls, the placed copy is removed and
// a retried receive of the VM places its own copy at the path, given the
// freed inode: by device and inode it reads as the copy the take-back placed.
// After the retry commits, its copy is the VM's only one (the source copy is
// removed), so a take-back that unlinked it would lose the disk. The receive
// holds the copy it places open until it returns, so the inode stays that
// file's and no other can take it.
//
// Mutation: release the pin right after placing — the retry's copy takes the
// inode and the take-back unlinks it, red.
func TestReceiveMigrationDisk_ATakeBackNeverUnlinksARetrysCopyOnTheReusedInode(t *testing.T) {
	f := newColdDiskFixture(t)
	f.writeSource(t, []byte("the VM's disk"))
	requireInodeReuse(t, filepath.Join(filepath.Dir(f.path), "reuse-control"))
	up := &captureDiskUp{size: int64(len("the VM's disk"))}
	if err := f.src.streamColdDisk(adminCtx(), &captureDiskClient{up: up}, "os1", f.disk, "raw"); err != nil {
		t.Fatalf("streamColdDisk: %v", err)
	}

	sctx, giveUp := context.WithCancel(f.peer)
	defer giveUp()
	var reused bool
	f.dst.SetColdDiskPlacedHookForTest(func() {
		// The source gives up while the copy is placed; meanwhile the copy
		// goes and a retry's copy is placed at the path.
		giveUp()
		reused = replaceOnItsInode(t, f.path, "a retry's copy")
	})
	err := f.dst.ReceiveMigrationDisk(&diskRecvStream{ctx: sctx, frames: up.frames})
	if status.Code(err) != codes.Canceled {
		t.Fatalf("receive whose source gave up = %v, want Canceled", err)
	}
	t.Logf("the retry's copy took the placed copy's inode: %v", reused)
	got, rerr := os.ReadFile(f.path)
	if rerr != nil || string(got) != "a retry's copy" {
		t.Fatalf("the take-back removed a copy it did not place (it had the placed copy's inode: %v): read %q, %v", reused, got, rerr)
	}
}
