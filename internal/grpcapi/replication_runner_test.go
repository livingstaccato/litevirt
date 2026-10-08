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

// Pruning the top-level replicas written before replicas moved into the
// replica area (pool-recorded or legacy by exact name).
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

// Pruning keeps the newest N of ONE schedule's recorded replicas of one disk
// and touches nothing else: not another schedule's, not another disk's, not a
// file with no record, and not one a VM disk is backed by.
func TestPruneRecordedReplicas(t *testing.T) {
	s := testServer(t)
	dir := replicaPoolDir(t, s, "dr")
	ctx := context.Background()
	seed := func(disk, sched, taken string) string {
		rec := newReplicaRecord("", "vm1", disk, sched, taken, "qcow2")
		path, err := publishRecordedReplica(ctx, dir, rec, func(tmp string) error {
			return os.WriteFile(tmp, []byte("x"), 0o600)
		})
		if err != nil {
			t.Fatal(err)
		}
		return path
	}
	var mine []string
	for _, ts := range []string{"20260101-000000", "20260102-000000", "20260103-000000", "20260104-000000", "20260105-000000"} {
		mine = append(mine, seed("root", "vm1/dr", ts))
	}
	otherSched := seed("root", "fleet/dr", "20260101-000001")
	otherDisk := seed("data", "vm1/dr", "20260101-000000")
	unrecorded := filepath.Join(replicaOwnerDir(dir, "", "vm1"), "root-20251231-000000.qcow2")
	if err := os.WriteFile(unrecorded, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The second-oldest is the base of a --no-localize promotion's overlay.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm1-promoted", HostName: s.hostName, State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1-promoted", DiskName: "root", HostName: s.hostName, Path: "/live.qcow2", BackingDisk: mine[1]}}); err != nil {
		t.Fatal(err)
	}

	// Keep the newest 2: the three oldest are candidates, the pinned one stays.
	got, err := s.pruneRecordedReplicas(ctx, "dr", "", "vm1", "root", "vm1/dr", 2)
	if err != nil || got != 2 {
		t.Fatalf("pruned %d (%v), want 2", got, err)
	}
	for _, p := range []string{mine[1], mine[3], mine[4], otherSched, otherDisk, unrecorded} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s should survive: %v", filepath.Base(p), err)
		}
	}
	for _, p := range []string{mine[0], mine[2]} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s should have been pruned", filepath.Base(p))
		}
		if _, err := os.Stat(p + ".json"); !os.IsNotExist(err) {
			t.Errorf("%s's record should have been removed", filepath.Base(p))
		}
	}
	// keep=0 keeps all.
	if got, _ := s.pruneRecordedReplicas(ctx, "dr", "", "vm1", "root", "vm1/dr", 0); got != 0 {
		t.Errorf("keep=0 should prune nothing, got %d", got)
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

// fakeReplClient implements the RPCs a prune makes: a legacy top-level prune's
// listing and deletes (pruneReplicasRemote), and the PruneReplicas call a
// replica-area prune makes.
type fakeReplClient struct {
	pb.LiteVirtClient
	contents []*pb.StoragePoolContent
	deleted  []string
	got      *pb.PruneReplicasRequest
}

func (f *fakeReplClient) ListStoragePoolContents(_ context.Context, _ *pb.ListStoragePoolContentsRequest, _ ...grpc.CallOption) (*pb.ListStoragePoolContentsResponse, error) {
	return &pb.ListStoragePoolContentsResponse{Contents: f.contents}, nil
}
func (f *fakeReplClient) DeleteStoragePoolContent(_ context.Context, in *pb.DeleteStoragePoolContentRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	f.deleted = append(f.deleted, in.Filename)
	return &emptypb.Empty{}, nil
}
func (f *fakeReplClient) PruneReplicas(_ context.Context, in *pb.PruneReplicasRequest, _ ...grpc.CallOption) (*pb.PruneReplicasResponse, error) {
	f.got = in
	return &pb.PruneReplicasResponse{Deleted: 2}, nil
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

// A cross-host prune names the VM's project, the disk and the schedule, so the
// peer prunes exactly that schedule's records — never a listing by name.
func TestPruneReplicasAnywhere_Remote(t *testing.T) {
	s := testServer(t)
	c := &fakeReplClient{}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return c, func() {}, nil
	}
	n := s.pruneReplicasAnywhere(context.Background(), "dr", "host-b", "acme", "vm1", "root", "vm1/dr", 1)
	if n != 2 || c.got == nil {
		t.Fatalf("pruned %d, request %+v", n, c.got)
	}
	if c.got.GetProject() != "acme" || c.got.GetVm() != "vm1" || c.got.GetDisk() != "root" ||
		c.got.GetSchedule() != "vm1/dr" || c.got.GetKeep() != 1 || c.got.GetHost() != "host-b" {
		t.Errorf("PruneReplicas request = %+v", c.got)
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

// ListReplicas answers that host-b holds no replica-area records, so promote's
// candidates are the top-level replicas its listing matched.
func (f *viewRecordingClient) ListReplicas(ctx context.Context, _ *pb.ListReplicasRequest, _ ...grpc.CallOption) (*pb.ListReplicasResponse, error) {
	return &pb.ListReplicasResponse{}, nil
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

// Replication's and promote's content calls on a peer's pool — a legacy
// prune's listing and deletes, promote's listing — say they are the
// daemon's, about this VM's disk in this VM's project: the pool's host then
// places, matches and deletes by that VM's replica records, never by name
// across the whole directory.
func TestReplicationContentCallsAreTheDaemons(t *testing.T) {
	s := testServer(t)
	k := replicaKey{VM: "vm1", Disk: "root", Project: "acme"}
	want := "replicas vm1 root acme"

	// (A replica itself now travels on the peer-only PushReplica, with its
	// record: replica_records.go.)
	c := &viewRecordingClient{marked: map[string]string{}}
	s.pruneReplicasRemote(context.Background(), c, "dr", "host-b", k, 1)
	for _, rpc := range []string{"list", "delete"} {
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
