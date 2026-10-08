package grpcapi

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// I-3. Replication across a rolling upgrade, with main-build (3e4ba50b)
// peers. A main build has no ListReplicas and no replica area: it receives a
// replica as a runner-named file at its pool's top level (an upload, or a
// record-less incremental push), and its failover coordinator promotes only
// such files.

// legacyReceiver is a host on main's build: ListReplicas is Unimplemented,
// an upload or incremental push lands the runner name at its pool's top
// level, and a listing shows every top-level file.
type legacyReceiver struct {
	pb.LiteVirtClient
	files      []string
	uploaded   *pb.UploadStoragePoolContentRequest
	uploadData int
	pushed     *pb.PushReplicaIncrementRequest
	area       int // PushReplica calls: must stay 0
	deleted    []string
}

func (o *legacyReceiver) ListReplicas(context.Context, *pb.ListReplicasRequest, ...grpc.CallOption) (*pb.ListReplicasResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unknown method ListReplicas for service litevirt.v1.LiteVirt")
}

func (o *legacyReceiver) PruneReplicas(context.Context, *pb.PruneReplicasRequest, ...grpc.CallOption) (*pb.PruneReplicasResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unknown method PruneReplicas for service litevirt.v1.LiteVirt")
}

func (o *legacyReceiver) PushReplica(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.PushReplicaRequest, pb.PushReplicaResponse], error) {
	o.area++
	return nil, status.Error(codes.Unimplemented, "unknown method PushReplica for service litevirt.v1.LiteVirt")
}

func (o *legacyReceiver) ListStoragePoolContents(context.Context, *pb.ListStoragePoolContentsRequest, ...grpc.CallOption) (*pb.ListStoragePoolContentsResponse, error) {
	resp := &pb.ListStoragePoolContentsResponse{}
	for _, n := range o.files {
		resp.Contents = append(resp.Contents, &pb.StoragePoolContent{Name: n})
	}
	return resp, nil
}

func (o *legacyReceiver) DeleteStoragePoolContent(_ context.Context, in *pb.DeleteStoragePoolContentRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	o.deleted = append(o.deleted, in.GetFilename())
	o.files = slices.DeleteFunc(o.files, func(n string) bool { return n == in.GetFilename() })
	return &emptypb.Empty{}, nil
}

func (o *legacyReceiver) UploadStoragePoolContent(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.UploadStoragePoolContentRequest, pb.UploadStoragePoolContentResponse], error) {
	return &recvStream[pb.UploadStoragePoolContentRequest, pb.UploadStoragePoolContentResponse]{on: func(m *pb.UploadStoragePoolContentRequest) {
		if o.uploaded == nil {
			o.uploaded = m
			o.files = append(o.files, m.GetFilename())
		}
		o.uploadData += len(m.GetChunk())
	}}, nil
}

func (o *legacyReceiver) PushReplicaIncrement(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.PushReplicaIncrementRequest, pb.PushReplicaIncrementResponse], error) {
	return &recvStream[pb.PushReplicaIncrementRequest, pb.PushReplicaIncrementResponse]{on: func(m *pb.PushReplicaIncrementRequest) {
		if o.pushed == nil {
			o.pushed = m
		}
	}}, nil
}

type recvStream[Req, Resp any] struct {
	grpc.ClientStream
	on func(*Req)
}

func (c *recvStream[Req, Resp]) Send(m *Req) error { c.on(m); return nil }
func (c *recvStream[Req, Resp]) CloseAndRecv() (*Resp, error) {
	var r Resp
	return &r, nil
}

// unsureReceiver cannot be asked whether it records replicas.
type unsureReceiver struct{ pb.LiteVirtClient }

func (unsureReceiver) ListReplicas(context.Context, *pb.ListReplicasRequest, ...grpc.CallOption) (*pb.ListReplicasResponse, error) {
	return nil, status.Error(codes.Unavailable, "connection refused")
}

// newReceiver is a host on this build that holds no replica records.
type newReceiver struct{ pb.LiteVirtClient }

func (newReceiver) ListReplicas(context.Context, *pb.ListReplicasRequest, ...grpc.CallOption) (*pb.ListReplicasResponse, error) {
	return nil, status.Error(codes.NotFound, `pool "litevirt-probe" not configured`)
}

// A new source replicating to a main-build target sends main's full replica:
// the runner name, uploaded to the pool's top level, where that build keeps
// and promotes it. Nothing goes to the replica area it does not have.
func TestReplicateCrossHost_ToAMainBuildSendsMainsReplica(t *testing.T) {
	f := newPoolFixture(t)
	old := &legacyReceiver{}
	f.s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return old, func() {}, nil }
	ctx := context.Background()
	vm, _ := corrosion.GetVM(ctx, f.s.db, "web")
	disks, _ := corrosion.GetVMDisks(ctx, f.s.db, "web")
	if err := f.s.replicateCrossHost(ctx, corrosion.BackupScheduleRecord{
		VMName: "web", Repo: "dr", Type: "replication", TargetPool: "dr", KeepReplicas: 1,
	}, vm, &disks[0], "old-host", "20260910-000000"); err != nil {
		t.Fatalf("replicating to a main-build host: %v", err)
	}
	if old.uploaded == nil || old.uploaded.GetFilename() != "web-1-20260910-000000.qcow2" || old.uploaded.GetPoolName() != "dr" || old.uploadData == 0 {
		t.Fatalf("upload = %+v (%d bytes), want web-1-20260910-000000.qcow2 into dr with its data", old.uploaded, old.uploadData)
	}
	if old.area != 0 {
		t.Error("a replica was pushed to the replica area of a host that has none")
	}
}

// ... and its incremental push is main's: the runner name, no record, forked
// from the newest top-level raw replica of the same disk there. The
// receiver's answer carries no "recorded" (main's has none), and is taken.
func TestReplicateIncremental_ToAMainBuildPushesMainsIncrement(t *testing.T) {
	f := newPoolFixture(t)
	old := &legacyReceiver{files: []string{
		"web-1-20260908-000000.raw", "web-1-20260909-000000.raw", "web-1-20260909-000000.qcow2",
		bReplicaRaw, // web-1's (project B), never web's base
	}}
	f.s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return old, func() {}, nil }
	ctx := context.Background()
	vm, _ := corrosion.GetVM(ctx, f.s.db, "web")
	if base := f.s.newestLegacyRawReplica(ctx, "dr", "old-host", replicaKeyOf(vm, "1")); base != "web-1-20260909-000000.raw" {
		t.Fatalf("fork base on a main-build host = %q, want web-1-20260909-000000.raw", base)
	}
	rec := newReplicaRecord("a", "web", "1", "web/dr", "20260910-000000", "raw")
	if err := f.s.applyIncrementRemote(ctx, "old-host", "dr", rec, "web-1-20260909-000000.raw", 4,
		bytes.NewReader([]byte("data")), [][2]int64{{0, 4}}); err != nil {
		t.Fatalf("an incremental push to a main-build host: %v", err)
	}
	h := old.pushed
	if h == nil || h.GetFilename() != "web-1-20260910-000000.raw" || h.GetReplica() != nil || h.GetBase() != "web-1-20260909-000000.raw" || h.GetTotalSize() != 4 {
		t.Fatalf("push header = %+v, want main's: web-1-20260910-000000.raw, no record, base web-1-20260909-000000.raw", h)
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

// A new target takes a main-build source's record-less incremental push as
// main took it: the runner name at the pool's top level, recorded as a
// peer's, forked from a top-level raw replica of the same disk — and a
// promotion matches it as that disk's replica. Anything else is refused.
func TestPushReplicaIncrement_TakesAMainBuildPush(t *testing.T) {
	f := newPoolFixture(t)
	ctx := context.Background()
	peer := peerCtxFor(t, f.s, "main-host")
	push := func(name, base string, data []byte) error {
		st := &fakePushStream{ctx: peer, msgs: []*pb.PushReplicaIncrementRequest{
			{PoolName: "dr", Filename: name, Base: base, TotalSize: 8},
			{Offset: 0, Data: data},
		}}
		return f.s.PushReplicaIncrement(st)
	}
	if err := push("web-1-20260910-000000.raw", "", []byte("full....")); err != nil {
		t.Fatalf("a main-build full push: %v", err)
	}
	if err := push("web-1-20260911-000000.raw", "web-1-20260910-000000.raw", []byte("incr")); err != nil {
		t.Fatalf("a main-build incremental push: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(f.dr, "web-1-20260911-000000.raw"))
	if err != nil || string(got) != "incr...." {
		t.Fatalf("forked replica holds %q (%v), want the base with the increment applied", got, err)
	}
	vm, _ := corrosion.GetVM(ctx, f.s.db, "web")
	names := f.s.localReplicaNames(ctx, f.dr, replicaKeyOf(vm, "1"), "", false)
	if !slices.Contains(names, "web-1-20260910-000000.raw") || !slices.Contains(names, "web-1-20260911-000000.raw") {
		t.Fatalf("web's replicas = %v, want both pushed files", names)
	}
	for _, c := range []struct {
		name, base string
		code       codes.Code
	}{
		{"web-1-20260912-000000.raw", bReplicaRaw, codes.FailedPrecondition}, // B's file as the base
		{"nosuchvm-root-20260912-000000.raw", "", codes.InvalidArgument},     // no such VM disk
		{"web-1-20260912-000000.qcow2", "", codes.InvalidArgument},           // not a raw replica
		{"web-1-root.qcow2", "", codes.InvalidArgument},                      // not a runner name
		{"web-1-20260910-000000.raw", "", codes.AlreadyExists},               // never over a file
	} {
		err := push(c.name, c.base, []byte("x"))
		if status.Code(err) != c.code && !(c.code == codes.AlreadyExists && err != nil) {
			t.Errorf("record-less push %s (base %q): got %v, want %v", c.name, c.base, err, c.code)
		}
	}
	if got, _ := os.ReadFile(filepath.Join(f.dr, "web-1-20260910-000000.raw")); string(got) != "full...." {
		t.Errorf("an existing replica was replaced: %q", got)
	}
	f.assertBIntact(t)
}

// While any host is on a build without the replica area (its failover
// coordinator promotes only top-level replicas), the top-level replicas are
// kept as main kept them, not cut to make room for the area's. Once every
// host answers ListReplicas, they are.
func TestPruneEarlierReplicas_KeptWhileAHostCannotSeeTheArea(t *testing.T) {
	f := newPoolFixture(t)
	ctx := context.Background()
	seedOwnReplica(t, f, "web", "1") // the area holds keep (1)
	top := filepath.Join(f.dr, "web-1-20261001-000000.qcow2")
	if err := os.WriteFile(top, []byte("main-era replica"), 0o600); err != nil {
		t.Fatal(err)
	}
	membersHosts(t, f.s, []string{"peer-host"}, "peer-host")
	vm, _ := corrosion.GetVM(ctx, f.s.db, "web")

	f.s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &legacyReceiver{}, func() {}, nil
	}
	if n := f.s.pruneEarlierReplicasAnywhere(ctx, "dr", f.s.hostName, vm, "1", 1); n != 0 {
		t.Fatalf("pruned %d top-level replica(s) while a main-build host cannot see the area", n)
	}
	if _, err := os.Stat(top); err != nil {
		t.Fatalf("the top-level replica a main-build coordinator promotes is gone: %v", err)
	}
	// A host that cannot be asked is taken to be one.
	replicaPeersMemos.Delete(f.s)
	f.s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return unsureReceiver{}, func() {}, nil
	}
	if n := f.s.pruneEarlierReplicasAnywhere(ctx, "dr", f.s.hostName, vm, "1", 1); n != 0 {
		t.Fatalf("pruned %d top-level replica(s) while a host could not be asked", n)
	}

	replicaPeersMemos.Delete(f.s)
	f.s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return newReceiver{}, func() {}, nil }
	if n := f.s.pruneEarlierReplicasAnywhere(ctx, "dr", f.s.hostName, vm, "1", 1); n != 1 {
		t.Fatalf("pruned %d top-level replica(s) once every host sees the area, want 1", n)
	}
}
