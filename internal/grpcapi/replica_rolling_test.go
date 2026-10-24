package grpcapi

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A replica goes only to a host that records it, in its replica area. A host
// on a build that predates replica records (no ListReplicas) is refused,
// never sent a runner-named file for its pool's top level.

// olderReceiver is a host on a build without ListReplicas. It counts every
// call that would carry replica bytes to it.
type olderReceiver struct {
	pb.LiteVirtClient
	sent int
}

func (o *olderReceiver) ListReplicas(context.Context, *pb.ListReplicasRequest, ...grpc.CallOption) (*pb.ListReplicasResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unknown method ListReplicas for service litevirt.v1.LiteVirt")
}

func (o *olderReceiver) PushReplica(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.PushReplicaRequest, pb.PushReplicaResponse], error) {
	o.sent++
	return nil, status.Error(codes.Unimplemented, "unknown method PushReplica for service litevirt.v1.LiteVirt")
}

func (o *olderReceiver) UploadStoragePoolContent(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.UploadStoragePoolContentRequest, pb.UploadStoragePoolContentResponse], error) {
	o.sent++
	return nil, status.Error(codes.Internal, "an older receiver was sent an upload")
}

func (o *olderReceiver) PushReplicaIncrement(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.PushReplicaIncrementRequest, pb.PushReplicaIncrementResponse], error) {
	o.sent++
	return nil, status.Error(codes.Internal, "an older receiver was sent an increment")
}

// unsureReceiver cannot be asked whether it records replicas.
type unsureReceiver struct{ pb.LiteVirtClient }

func (unsureReceiver) ListReplicas(context.Context, *pb.ListReplicasRequest, ...grpc.CallOption) (*pb.ListReplicasResponse, error) {
	return nil, status.Error(codes.Unavailable, "connection refused")
}

// A full replica to a host without ListReplicas is refused, and nothing is
// sent to it.
//
// Mutation "Unimplemented proves" (proveReplicaRecords returns nil for
// Unimplemented) — red: the run goes on to PushReplica.
func TestReplicateCrossHost_AnOlderReceiverIsRefused(t *testing.T) {
	f := newPoolFixture(t)
	old := &olderReceiver{}
	f.s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return old, func() {}, nil }
	ctx := context.Background()
	vm, _ := corrosion.GetVM(ctx, f.s.db, "web")
	disks, _ := corrosion.GetVMDisks(ctx, f.s.db, "web")
	err := f.s.replicateCrossHost(ctx, corrosion.BackupScheduleRecord{
		VMName: "web", Repo: "dr", Type: "replication", TargetPool: "dr", KeepReplicas: 1,
	}, vm, &disks[0], "old-host", "20260910-000000", true)
	if err == nil || !strings.Contains(err.Error(), "predates replica records") {
		t.Fatalf("replicating to an older host: got %v, want it refused as predating replica records", err)
	}
	if old.sent != 0 {
		t.Errorf("%d replica call(s) reached a host that cannot record replicas", old.sent)
	}
}

// ... and so is an incremental push.
func TestApplyIncrementRemote_AnOlderReceiverIsRefused(t *testing.T) {
	f := newPoolFixture(t)
	old := &olderReceiver{}
	f.s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return old, func() {}, nil }
	rec := newReplicaRecord("a", "web", "1", "web/dr", "20260910-000000", "raw")
	err := f.s.applyIncrementRemote(context.Background(), "old-host", "dr", rec, "", 4,
		bytes.NewReader([]byte("data")), [][2]int64{{0, 4}})
	if err == nil || !strings.Contains(err.Error(), "predates replica records") {
		t.Fatalf("an incremental push to an older host: got %v, want it refused", err)
	}
	if old.sent != 0 {
		t.Errorf("%d replica call(s) reached a host that cannot record replicas", old.sent)
	}
}

// A host that cannot say whether it records replicas is sent nothing.
func TestApplyIncrementRemote_AReceiverThatCannotAnswerIsSentNothing(t *testing.T) {
	f := newPoolFixture(t)
	f.s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return unsureReceiver{}, func() {}, nil
	}
	rec := newReplicaRecord("a", "web", "1", "web/dr", "20260910-000000", "raw")
	if err := f.s.applyIncrementRemote(context.Background(), "x", "dr", rec, "", 4,
		bytes.NewReader([]byte("data")), [][2]int64{{0, 4}}); err == nil {
		t.Fatal("a push to a host that could not answer went ahead")
	}
}

// An incremental push without its replica record is refused: nothing lands
// at the pool's top level under a runner name.
//
// Three checks each refuse it (replicaRecordFromPB's nil record, the empty
// record's validation, the filename against the record's file), so removing
// any one alone stays green: this pins the outcome, not one check.
func TestPushReplicaIncrement_ARecordlessPushIsRefused(t *testing.T) {
	f := newPoolFixture(t)
	peer := peerCtxFor(t, f.s, "peer-host")
	st := &fakePushStream{ctx: peer, msgs: []*pb.PushReplicaIncrementRequest{
		{PoolName: "dr", Filename: "web-1-20260910-000000.raw", TotalSize: 8},
		{Offset: 0, Data: []byte("full....")},
	}}
	err := f.s.PushReplicaIncrement(st)
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "replica record") {
		t.Fatalf("a record-less push: got %v, want InvalidArgument naming the replica record", err)
	}
	if _, serr := os.Stat(filepath.Join(f.dr, "web-1-20260910-000000.raw")); serr == nil {
		t.Error("a record-less push was written at the pool's top level")
	}
	f.assertBIntact(t)
}

// A replica content call's upload is refused: a replica is sent with
// PushReplica, with its record, never uploaded to the pool's top level.
//
// Mutation "take the replica upload" (the viewReplicas refusal removed) —
// red: the upload is written.
func TestUploadStoragePoolContent_AReplicaUploadIsRefused(t *testing.T) {
	f := newPoolFixture(t)
	ctx := replicaContentCtx(peerCtxFor(t, f.s, "peer-host"), "web", "a", "1")
	st := &fakeUploadStream{ctx: ctx, msgs: []*pb.UploadStoragePoolContentRequest{
		{PoolName: "dr", Filename: "web-1-20260910-000000.qcow2"},
		{Chunk: []byte("replica bytes")},
	}}
	err := f.s.UploadStoragePoolContent(st)
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "PushReplica") {
		t.Fatalf("a replica upload: got %v, want InvalidArgument pointing at PushReplica", err)
	}
	if _, serr := os.Stat(filepath.Join(f.dr, "web-1-20260910-000000.qcow2")); serr == nil {
		t.Error("a replica upload was written at the pool's top level")
	}
}
