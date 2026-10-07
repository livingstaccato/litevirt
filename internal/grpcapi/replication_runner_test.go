package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestPruneReplicas(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	dir := t.TempDir()
	// Five timestamped replicas of vm1/root, plus an unrelated file.
	names := []string{
		"vm1-root-20260101-000000.qcow2",
		"vm1-root-20260102-000000.qcow2",
		"vm1-root-20260103-000000.qcow2",
		"vm1-root-20260104-000000.qcow2",
		"vm1-root-20260105-000000.qcow2",
	}
	for _, n := range names {
		os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644)
	}
	os.WriteFile(filepath.Join(dir, "other-vm-root-20260105-000000.qcow2"), []byte("x"), 0o644)

	// Keep newest 2 → delete the 3 oldest.
	k := replicaKey{VM: "vm1", Disk: "root"}
	if got := s.pruneLocalReplicas(context.Background(), dir, k, 2); got != 3 {
		t.Fatalf("pruned %d, want 3", got)
	}
	// The two newest survive; the unrelated file is untouched.
	for _, keep := range []string{"vm1-root-20260104-000000.qcow2", "vm1-root-20260105-000000.qcow2", "other-vm-root-20260105-000000.qcow2"} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Errorf("expected %s to survive: %v", keep, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "vm1-root-20260101-000000.qcow2")); !os.IsNotExist(err) {
		t.Errorf("oldest replica should have been pruned")
	}
	// keepN=0 keeps all.
	if got := s.pruneLocalReplicas(context.Background(), dir, k, 0); got != 0 {
		t.Errorf("keepN=0 should prune nothing, got %d", got)
	}
}

func TestIsSharedDriver(t *testing.T) {
	for _, d := range []string{"nfs", "ceph", "iscsi"} {
		if !isSharedDriver(d) {
			t.Errorf("%s should be shared", d)
		}
	}
	for _, d := range []string{"local", "dir", "btrfs", ""} {
		if isSharedDriver(d) {
			t.Errorf("%s should not be shared", d)
		}
	}
}

// fakeReplClient implements just the two RPCs pruneReplicasRemote uses.
type fakeReplClient struct {
	pb.LiteVirtClient
	contents []*pb.StoragePoolContent
	deleted  []string
}

func (f *fakeReplClient) ListStoragePoolContents(_ context.Context, _ *pb.ListStoragePoolContentsRequest, _ ...grpc.CallOption) (*pb.ListStoragePoolContentsResponse, error) {
	return &pb.ListStoragePoolContentsResponse{Contents: f.contents}, nil
}
func (f *fakeReplClient) DeleteStoragePoolContent(_ context.Context, in *pb.DeleteStoragePoolContentRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	f.deleted = append(f.deleted, in.Filename)
	return &emptypb.Empty{}, nil
}

func TestPruneReplicasRemote(t *testing.T) {
	c := &fakeReplClient{contents: []*pb.StoragePoolContent{
		{Name: "vm1-root-20260101-000000.qcow2"},
		{Name: "vm1-root-20260102-000000.qcow2"},
		{Name: "vm1-root-20260103-000000.qcow2"},
		{Name: "other-root-20260103-000000.qcow2"}, // different VM — must be ignored
	}}
	s := testServer(t)
	n := s.pruneReplicasRemote(context.Background(), c, "dr", "host-b", replicaKey{VM: "vm1", Disk: "root"}, 1)
	if n != 2 {
		t.Fatalf("pruned %d, want 2", n)
	}
	want := map[string]bool{"vm1-root-20260101-000000.qcow2": true, "vm1-root-20260102-000000.qcow2": true}
	for _, d := range c.deleted {
		if !want[d] {
			t.Errorf("deleted unexpected %q (should keep newest + other VM)", d)
		}
	}
}

// viewRecordingClient records the replica view each content call carried
// (poolContentViewMDKey and the replica keys), and answers a listing as a
// host that matched it by record.
type viewRecordingClient struct {
	pb.LiteVirtClient
	marked map[string]string // rpc → "view vm disk project"
}

func (f *viewRecordingClient) note(ctx context.Context, rpc string) {
	md, _ := metadata.FromOutgoingContext(ctx)
	one := func(k string) string {
		if v := md.Get(k); len(v) > 0 {
			return v[0]
		}
		return "-"
	}
	f.marked[rpc] = one(poolContentViewMDKey) + " " + one(replicaVMMDKey) + " " + one(replicaDiskMDKey) + " " + one(replicaProjectMDKey)
}

func (f *viewRecordingClient) ListStoragePoolContents(ctx context.Context, _ *pb.ListStoragePoolContentsRequest, opts ...grpc.CallOption) (*pb.ListStoragePoolContentsResponse, error) {
	f.note(ctx, "list")
	for _, o := range opts {
		if h, ok := o.(grpc.HeaderCallOption); ok {
			*h.HeaderAddr = metadata.Pairs(replicaListingMDKey, "matched")
		}
	}
	return &pb.ListStoragePoolContentsResponse{Contents: []*pb.StoragePoolContent{
		{Name: "vm1-root-20260101-000000.qcow2"}, {Name: "vm1-root-20260102-000000.qcow2"},
	}}, nil
}

func (f *viewRecordingClient) DeleteStoragePoolContent(ctx context.Context, _ *pb.DeleteStoragePoolContentRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	f.note(ctx, "delete")
	return &emptypb.Empty{}, nil
}

type nopUploadClient struct {
	grpc.ClientStream
}

func (nopUploadClient) Send(*pb.UploadStoragePoolContentRequest) error { return nil }
func (nopUploadClient) CloseAndRecv() (*pb.UploadStoragePoolContentResponse, error) {
	return &pb.UploadStoragePoolContentResponse{}, nil
}

func (f *viewRecordingClient) UploadStoragePoolContent(ctx context.Context, _ ...grpc.CallOption) (grpc.ClientStreamingClient[pb.UploadStoragePoolContentRequest, pb.UploadStoragePoolContentResponse], error) {
	f.note(ctx, "upload")
	return nopUploadClient{}, nil
}

// Replication's and promote's content calls on a peer's pool — the replica
// upload, pruning's listing and deletes, promote's listing — say they are the
// daemon's, about this VM's disk in this VM's project: the pool's host then
// places, matches and deletes by that VM's replica records, never by name
// across the whole directory.
func TestReplicationContentCallsAreTheDaemons(t *testing.T) {
	s := testServer(t)
	k := replicaKey{VM: "vm1", Disk: "root", Project: "acme"}
	want := "replicas vm1 root acme"

	c := &viewRecordingClient{marked: map[string]string{}}
	s.pruneReplicasRemote(context.Background(), c, "dr", "host-b", k, 1)
	f := filepath.Join(t.TempDir(), "vm1-root-20260101-000000.qcow2")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := streamFileToPool(context.Background(), c, f, "dr", "host-b", "vm1-root-20260101-000000.qcow2", k); err != nil {
		t.Fatal(err)
	}
	for _, rpc := range []string{"list", "delete", "upload"} {
		if c.marked[rpc] != want {
			t.Errorf("replication's %s call carries %q, want %q", rpc, c.marked[rpc], want)
		}
	}

	// Promote's listing (findReplicaHost on a peer).
	c = &viewRecordingClient{marked: map[string]string{}}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return c, func() {}, nil }
	vm := &corrosion.VMRecord{Name: "vm1", Project: "acme"}
	host, reps, err := s.findReplicaHost(context.Background(), &pb.PromoteReplicaRequest{VmName: "vm1"}, vm, "root", "dr", "host-b")
	if err != nil || host != "host-b" || len(reps) != 2 || reps[0] != "vm1-root-20260102-000000.qcow2" {
		t.Fatalf("findReplicaHost = %s %v %v, want host-b's two replicas, newest first", host, reps, err)
	}
	if c.marked["list"] != want {
		t.Errorf("promote's listing carries %q, want %q", c.marked["list"], want)
	}
}
