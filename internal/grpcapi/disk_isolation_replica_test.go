package grpcapi

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Replica selection in a shared pool (C2): which files the replication
// runner prunes and forks from, and which file a promotion boots, are chosen
// from the replica records of the caller's own VM and schedule — never by a
// "<vm>-<disk>-" name prefix over the pool directory. Fixture: poolFixture.

// C2 delete: A's own replication schedule, keep 1, must not prune B's replicas
// or B's live disk that share its old name prefix.
func TestReplicationPrune_NeverTouchesAnotherProjectsFiles(t *testing.T) {
	f := newPoolFixture(t)
	for i := 0; i < 2; i++ {
		runAt := time.Date(2026, 10, 5, 12, i, 0, 0, time.UTC)
		if err := f.s.RunReplication(context.Background(), corrosion.BackupScheduleRecord{
			VMName: "web", Repo: "dr", Type: "replication", TargetPool: "dr", KeepReplicas: 1,
		}, runAt); err != nil {
			t.Fatalf("RunReplication: %v", err)
		}
	}
	f.assertBIntact(t)
	// And A's own pruning still works: two runs, keep 1, one replica left.
	if recs, _ := listReplicaRecords(f.dr, "a", "web"); len(recs) != 1 || recs[0].Taken != "20261005-120100" {
		t.Errorf("A's replicas after two runs with keep 1 = %+v, want only the newest", recs)
	}
}

// C2 read: promoting A's VM from a file of B's that merely matches A's old
// replica name prefix must not boot A a VM on B's data.
func TestPromoteReplica_CannotSelectAnotherProjectsFile(t *testing.T) {
	f := newPoolFixture(t)
	err := f.s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "web", TargetPool: "dr", Replica: bReplicaQcow, NewName: "stolen", NoLocalize: true,
	}, &streamRecorder[pb.PromoteReplicaProgress]{ctx: f.alice})
	if status.Code(err) != codes.NotFound {
		t.Errorf("promote of another project's file: got %v, want NotFound", err)
	}
	if rec, _ := corrosion.GetVM(context.Background(), f.s.db, "stolen"); rec != nil {
		t.Errorf("a VM was promoted from project B's file: %+v", rec)
	}
	f.assertBIntact(t)
}

// C2 read: the incremental fork base of A's schedule must never be B's raw
// replica, which the next raw replica would otherwise be copied from.
func TestIncrementalForkBase_NeverAnotherProjectsFile(t *testing.T) {
	f := newPoolFixture(t)
	if base := f.s.newestRawReplica(context.Background(), "dr", f.s.hostName, "a", "web", "1", "web/dr"); base != "" {
		t.Errorf("A's incremental fork base is %q, a file A has no record of", base)
	}
}

// The executing host looks the replica up again among the VM's own records: a
// relayed or peer-direct promotion names a file, and the name of B's file in
// the shared pool is not enough to boot it.
func TestDoPromoteLocal_RechecksTheRecord(t *testing.T) {
	f := newPoolFixture(t)
	ctx := context.Background()
	vm, _ := corrosion.GetVM(ctx, f.s.db, "web")
	disks, _ := corrosion.GetVMDisks(ctx, f.s.db, "web")
	err := f.s.doPromoteLocal(adminCtx(), &pb.PromoteReplicaRequest{VmName: "web", NewName: "stolen", NoLocalize: true},
		vm, &disks[0], "dr", bReplicaQcow, false, func(*pb.PromoteReplicaProgress) error { return nil })
	if status.Code(err) != codes.NotFound {
		t.Errorf("doPromoteLocal of a file A has no record of: got %v, want NotFound", err)
	}
	f.assertBIntact(t)
}

// A replica is a host's alone: a project Operator — even one with write on
// the pool — cannot push one into the replica area.
func TestPushReplica_IsPeerOnly(t *testing.T) {
	f := newPoolFixture(t)
	f.grantPoolWrite(t)
	rec := newReplicaRecord("b", "web-1", "root", "web-1/dr", "20261009-000000", "qcow2")
	st := &fakePushReplicaStream{ctx: f.alice, msgs: []*pb.PushReplicaRequest{
		{PoolName: "dr", Replica: rec.toPB()},
		{Chunk: []byte("forged replica")},
	}}
	if err := f.s.PushReplica(st); status.Code(err) != codes.PermissionDenied {
		t.Errorf("operator PushReplica: got %v, want PermissionDenied", err)
	}
	if st.idx > 0 {
		t.Errorf("a refused push read %d message(s); it must refuse before reading any", st.idx)
	}
	if recs, _ := listReplicaRecords(f.dr, "b", "web-1"); len(recs) != 0 {
		t.Errorf("a forged replica was recorded for project B: %+v", recs)
	}
}

// From a peer, the replica lands in the VM's own directory with its record.
func TestPushReplica_PeerReplicaIsRecordedInTheOwnersDirectory(t *testing.T) {
	f := newPoolFixture(t)
	rec := newReplicaRecord("a", "web", "1", "web/dr", "20261009-000000", "qcow2")
	st := &fakePushReplicaStream{ctx: peerCtxFor(t, f.s, "peer-host"), msgs: []*pb.PushReplicaRequest{
		{PoolName: "dr", Replica: rec.toPB()},
		{Chunk: []byte("replica bytes")},
	}}
	if err := f.s.PushReplica(st); err != nil {
		t.Fatalf("peer PushReplica: %v", err)
	}
	recs, _ := listReplicaRecords(f.dr, "a", "web")
	if len(recs) != 1 || recs[0].File != rec.File || recs[0].Schedule != "web/dr" || recs[0].SizeBytes != int64(len("replica bytes")) {
		t.Errorf("records of (a, web) = %+v, want the pushed replica", recs)
	}
	// A second push of the same record is refused, not replaced.
	st = &fakePushReplicaStream{ctx: peerCtxFor(t, f.s, "peer-host2"), msgs: []*pb.PushReplicaRequest{
		{PoolName: "dr", Replica: rec.toPB()}, {Chunk: []byte("other bytes")},
	}}
	if err := f.s.PushReplica(st); status.Code(err) != codes.AlreadyExists {
		t.Errorf("second push of the same replica: got %v, want AlreadyExists", err)
	}
	f.assertBIntact(t)
}

// fakePushReplicaStream scripts a client-streaming PushReplica.
type fakePushReplicaStream struct {
	grpc.ServerStream
	ctx  context.Context
	msgs []*pb.PushReplicaRequest
	idx  int
	resp *pb.PushReplicaResponse
}

func (f *fakePushReplicaStream) Context() context.Context { return f.ctx }
func (f *fakePushReplicaStream) Recv() (*pb.PushReplicaRequest, error) {
	if f.idx >= len(f.msgs) {
		return nil, io.EOF
	}
	m := f.msgs[f.idx]
	f.idx++
	return m, nil
}
func (f *fakePushReplicaStream) SendAndClose(r *pb.PushReplicaResponse) error {
	f.resp = r
	return nil
}

// ListReplicas and PruneReplicas are host-certificate only.
func TestReplicaRPCs_ArePeerOnly(t *testing.T) {
	f := newPoolFixture(t)
	if _, err := f.s.ListReplicas(f.alice, &pb.ListReplicasRequest{PoolName: "dr", Project: "b", Vm: "web-1"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("ListReplicas as an operator: got %v, want PermissionDenied", err)
	}
	if _, err := f.s.PruneReplicas(f.alice, &pb.PruneReplicasRequest{PoolName: "dr", Project: "b", Vm: "web-1", Disk: "root", Schedule: "web-1/dr", Keep: 1}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("PruneReplicas as an operator: got %v, want PermissionDenied", err)
	}
}

// An incremental push forks only from a recorded raw replica of the same disk
// and schedule — never from a file named in the request, like B's raw replica.
func TestPushReplicaIncrement_BaseMustBeARecordedReplica(t *testing.T) {
	f := newPoolFixture(t)
	rec := newReplicaRecord("a", "web", "1", "web/dr", "20261009-000000", "raw")
	st := &fakePushStream{ctx: peerCtxFor(t, f.s, "peer-host"), msgs: []*pb.PushReplicaIncrementRequest{
		{PoolName: "dr", Filename: rec.File, Base: bReplicaRaw, TotalSize: 1 << 16, Replica: rec.toPB()},
	}}
	if err := f.s.PushReplicaIncrement(st); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("push forked from B's raw file: got %v, want FailedPrecondition", err)
	}
	// And a push without a record is refused outright.
	st = &fakePushStream{ctx: peerCtxFor(t, f.s, "peer-host2"), msgs: []*pb.PushReplicaIncrementRequest{
		{PoolName: "dr", Filename: "web-1-20261009-000000.raw", TotalSize: 1 << 16},
	}}
	if err := f.s.PushReplicaIncrement(st); status.Code(err) != codes.InvalidArgument {
		t.Errorf("push without a replica record: got %v, want InvalidArgument", err)
	}
	if recs, _ := listReplicaRecords(f.dr, "a", "web"); len(recs) != 0 {
		t.Errorf("a refused push recorded %+v", recs)
	}
	f.assertBIntact(t)
}

// fakePushStream scripts a client-streaming PushReplicaIncrement.
type fakePushStream struct {
	grpc.ServerStream
	ctx  context.Context
	msgs []*pb.PushReplicaIncrementRequest
	idx  int
	resp *pb.PushReplicaIncrementResponse
}

func (f *fakePushStream) Context() context.Context { return f.ctx }
func (f *fakePushStream) Recv() (*pb.PushReplicaIncrementRequest, error) {
	if f.idx >= len(f.msgs) {
		return nil, io.EOF
	}
	m := f.msgs[f.idx]
	f.idx++
	return m, nil
}
func (f *fakePushStream) SendAndClose(r *pb.PushReplicaIncrementResponse) error {
	f.resp = r
	return nil
}

// A --no-localize promotion boots an overlay on the replica; the disk record
// names the replica as its backing_disk, which is what keeps pruning (and pool
// content delete) off a file a running VM reads through.
func TestPromoteReplica_OverlayPinsItsReplica(t *testing.T) {
	f := newPoolFixture(t)
	own := seedOwnReplica(t, f, "web", "1")
	if err := f.s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "web", TargetPool: "dr", Replica: own, NewName: "web-dr", NoLocalize: true,
	}, &streamRecorder[pb.PromoteReplicaProgress]{ctx: f.alice}); err != nil {
		t.Fatalf("promote A's own replica: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), f.s.db, "web-dr")
	_, replicaPath, _ := recordedReplica(f.dr, "a", "web", own)
	if len(disks) != 1 || replicaPath == "" || disks[0].BackingDisk != replicaPath {
		t.Fatalf("promoted disk rows = %+v, want backing_disk %q", disks, replicaPath)
	}
	// A newer replica of the same schedule makes the pinned one prunable by age.
	newer := newReplicaRecord("a", "web", "1", "web/dr", "20261004-000000", "qcow2")
	if _, err := publishRecordedReplica(context.Background(), f.dr, newer, func(tmp string) error {
		return os.WriteFile(tmp, []byte("newer"), 0o600)
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := f.s.pruneRecordedReplicas(context.Background(), "dr", "a", "web", "1", "web/dr", 1); err != nil || n != 0 {
		t.Errorf("prune deleted %d (%v), want 0: the older replica backs a running VM", n, err)
	}
	if _, err := os.Stat(replicaPath); err != nil {
		t.Errorf("the pinned replica is gone: %v", err)
	}
}
