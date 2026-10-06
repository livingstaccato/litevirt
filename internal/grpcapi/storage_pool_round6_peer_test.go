package grpcapi

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// poolHostClient is a peer's client for the pool's host, served in-process:
// each call reaches pool's handler as a verified peer carrying the metadata
// the caller put on it, and the handler's response header comes back.
type poolHostClient struct {
	pb.LiteVirtClient
	pool *Server
	peer context.Context
}

type headerCapture struct{ md metadata.MD }

func (h *headerCapture) Method() string                  { return "" }
func (h *headerCapture) SetHeader(md metadata.MD) error  { h.md = metadata.Join(h.md, md); return nil }
func (h *headerCapture) SendHeader(md metadata.MD) error { return h.SetHeader(md) }
func (h *headerCapture) SetTrailer(metadata.MD) error    { return nil }

func (c *poolHostClient) incoming(ctx context.Context) (context.Context, *headerCapture) {
	out, _ := metadata.FromOutgoingContext(ctx)
	h := &headerCapture{}
	return grpc.NewContextWithServerTransportStream(metadata.NewIncomingContext(c.peer, out.Copy()), h), h
}

func (c *poolHostClient) ListStoragePoolContents(ctx context.Context, req *pb.ListStoragePoolContentsRequest, opts ...grpc.CallOption) (*pb.ListStoragePoolContentsResponse, error) {
	in, h := c.incoming(ctx)
	resp, err := c.pool.ListStoragePoolContents(in, req)
	for _, o := range opts {
		if ho, ok := o.(grpc.HeaderCallOption); ok {
			*ho.HeaderAddr = h.md
		}
	}
	return resp, err
}

func (c *poolHostClient) DeleteStoragePoolContent(ctx context.Context, req *pb.DeleteStoragePoolContentRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	in, _ := c.incoming(ctx)
	return c.pool.DeleteStoragePoolContent(in, req)
}

// I-B, CR2 across hosts: promote's and pruning's peer calls ask the pool's
// host for one VM's replicas in that VM's project, and the host answers by
// record. acme's VM web has a disk prod-root; bravo has a VM web-prod, so the
// name web-prod-root-<stamp> alone cannot say whose a file is. Only acme's
// recorded replicas are listed and pruned — not bravo's, not one recorded for
// an earlier VM named web in bravo, not an unrecorded file of that name.
func TestPoolRound6_PeerReplicaCallsAreTheVMsInItsProject(t *testing.T) {
	pool, disks := disksPoolServer(t)
	insertProjectVM(t, pool, "web", "acme", "prod-root", filepath.Join(disks, "web-prod-root.qcow2"), "default")
	insertProjectVM(t, pool, "web-prod", "bravo", "root", filepath.Join(disks, "web-prod-root.qcow2"), "default")
	files := map[string]string{ // name → recorded project ("" = unrecorded)
		"web-prod-root-20261006-090000.qcow2": "acme",
		"web-prod-root-20261006-100000.qcow2": "",
		"web-prod-root-20261006-110000.qcow2": "bravo",
		"web-prod-root-20261006-120000.qcow2": "acme",
	}
	for n, project := range files {
		p := filepath.Join(disks, n)
		writePoolFile(t, p, n)
		if project != "" {
			if err := pool.recordPoolReplica("default", replicaKey{VM: "web", Disk: "prod-root", Project: project}, p); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A replica is only ever in the pool's own directory; one recorded in
	// disks/uploads is not promotable there and not listed.
	up := filepath.Join(disks, "uploads", "web-prod-root-20261006-130000.qcow2")
	if err := os.MkdirAll(filepath.Dir(up), 0o755); err != nil {
		t.Fatal(err)
	}
	writePoolFile(t, up, "x")
	if err := pool.recordPoolReplica("default", replicaKey{VM: "web", Disk: "prod-root", Project: "acme"}, up); err != nil {
		t.Fatal(err)
	}

	// The coordinator: another host, reading the same cluster state.
	coord := &Server{hostName: "host-c", dataDir: t.TempDir(), db: pool.db}
	client := &poolHostClient{pool: pool, peer: peerCtxFor(t, pool, "host-c")}
	coord.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return client, func() {}, nil }
	vm, err := corrosion.GetVM(context.Background(), pool.db, "web")
	if err != nil || vm == nil {
		t.Fatal(err)
	}
	k := replicaKeyOf(vm, "prod-root")

	want := []string{"web-prod-root-20261006-090000.qcow2", "web-prod-root-20261006-120000.qcow2"}
	if got := coord.replicaNames(context.Background(), "default", pool.hostName, k); !slices.Equal(got, want) {
		t.Fatalf("promote's listing of acme's web/prod-root on the pool's host = %v, want %v", got, want)
	}
	if n := coord.pruneReplicasAnywhere(context.Background(), "default", pool.hostName, k, 1); n != 1 {
		t.Errorf("pruned %d, want 1 (acme's older replica)", n)
	}
	for n := range files {
		_, err := os.Stat(filepath.Join(disks, n))
		if gone := err != nil; gone != (n == want[0]) {
			t.Errorf("after pruning, %s gone = %v", n, gone)
		}
	}
}

// An older pool's host lists every file and matches nothing: the caller
// matches by exact name, and refuses a name another project's VM could have
// written.
func TestPoolRound6_AnOlderHostsListingIsMatchedByExactName(t *testing.T) {
	s := testServer(t)
	insertProjectVM(t, s, "bvm", "bravo", "root", "/x/bvm-root.qcow2", "default")
	c := &fakeReplClient{contents: []*pb.StoragePoolContent{
		{Name: "bvm-root-20261006-120000.qcow2"},          // bravo's bvm/root
		{Name: "bvm-root-20261006-20261006-120000.qcow2"}, // bvm/root-20261006 or bvm-root/20261006
		{Name: "debian.iso"},
	}}
	k := replicaKey{VM: "bvm-root", Disk: "20261006", Project: "acme"}
	if got := s.remoteReplicaNames(context.Background(), c, "default", "host-b", k); len(got) != 0 {
		t.Errorf("acme's bvm-root/20261006 matched %v on an older host", got)
	}
	if n := s.pruneReplicasRemote(context.Background(), c, "default", "host-b", k, 1); n != 0 || len(c.deleted) != 0 {
		t.Errorf("pruning deleted %v", c.deleted)
	}
	own := replicaKey{VM: "avm", Disk: "root", Project: "acme"}
	c.contents = append(c.contents, &pb.StoragePoolContent{Name: "avm-root-20261006-120000.qcow2"})
	if got := s.remoteReplicaNames(context.Background(), c, "default", "host-b", own); !slices.Equal(got, []string{"avm-root-20261006-120000.qcow2"}) {
		t.Errorf("acme's own replica on an older host: matched %v", got)
	}
}

// fakePushStream feeds PushReplicaIncrement its frames.
type fakePushStream struct {
	grpc.ServerStream
	ctx  context.Context
	msgs []*pb.PushReplicaIncrementRequest
}

func (f *fakePushStream) Context() context.Context { return f.ctx }
func (f *fakePushStream) Recv() (*pb.PushReplicaIncrementRequest, error) {
	if len(f.msgs) == 0 {
		return nil, io.EOF
	}
	m := f.msgs[0]
	f.msgs = f.msgs[1:]
	return m, nil
}
func (f *fakePushStream) SendAndClose(*pb.PushReplicaIncrementResponse) error { return nil }

// A replica the daemon uploads or pushes is named for the VM's disk it says
// it is of, in that VM's project, forks only from that disk's replicas, and
// is recorded as that VM's — which is what makes a name another project's VM
// could share promotable at all.
func TestPoolRound6_ReplicasArriveNamedAndRecordedForTheirVM(t *testing.T) {
	s, disks := disksPoolServer(t)
	insertProjectVM(t, s, "app", "acme", "x-root", filepath.Join(t.TempDir(), "app-x-root.qcow2"), "")
	insertProjectVM(t, s, "app-x", "bravo", "root", filepath.Join(disks, "app-x-root.qcow2"), "default")
	peer := bareEntryPeer(t, s)
	k := replicaKey{VM: "app", Disk: "x-root", Project: "acme"}
	as := func(project string) context.Context { return replicaContentCtx(peer, k.VM, project, k.Disk) }

	if err := uploadAs(as("acme"), s, "default", "other-root-20261006-120000.qcow2", "x"); status.Code(err) != codes.InvalidArgument {
		t.Errorf("a replica upload named for another disk: got %v, want InvalidArgument", err)
	}
	if err := uploadAs(as("bravo"), s, "default", "app-x-root-20261006-120000.qcow2", "x"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a replica upload in a project the VM is not in: got %v, want FailedPrecondition", err)
	}
	full := "app-x-root-20261006-120000.qcow2"
	if err := uploadAs(as("acme"), s, "default", full, "x"); err != nil {
		t.Fatalf("app's replica upload: %v", err)
	}
	push := func(name, base string) error {
		return s.PushReplicaIncrement(&fakePushStream{ctx: as("acme"), msgs: []*pb.PushReplicaIncrementRequest{
			{PoolName: "default", Filename: name, Base: base, TotalSize: 4},
			{Offset: 0, Data: []byte("data")},
		}})
	}
	theirs := "app-x-root-20261006-090000.raw"
	writePoolFile(t, filepath.Join(disks, theirs), "bravo")
	if err := s.recordPoolReplica("default", replicaKey{VM: "app-x", Disk: "root", Project: "bravo"}, filepath.Join(disks, theirs)); err != nil {
		t.Fatal(err)
	}
	if err := push("app-x-root-20261006-130000.raw", theirs); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a push forking from another VM's replica: got %v, want FailedPrecondition", err)
	}
	incr := "app-x-root-20261006-140000.raw"
	if err := push(incr, ""); err != nil {
		t.Fatalf("app's replica push: %v", err)
	}
	if got := s.replicaNames(context.Background(), "default", "", k); !slices.Equal(got, []string{full, incr}) {
		t.Errorf("app's replicas = %v, want [%s %s]", got, full, incr)
	}
}

// m2: in a shared directory, a project's users see and delete their VMs'
// recorded replicas; nobody else's, and not one recorded for an earlier VM
// of the same name in another project.
func TestPoolRound6_UsersOwnTheirVMsRecordedReplicas(t *testing.T) {
	s, disks := twoProjectsOnDisks(t)
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	bob := hostPathEngineCtx(t, s, "bob", "Operator", projectRBACBase("bravo"))
	mine, stale := "avm-root-20261006-120000.qcow2", "avm-root-20261006-110000.qcow2"
	for n, project := range map[string]string{mine: "acme", stale: "bravo"} {
		writePoolFile(t, filepath.Join(disks, n), n)
		if err := s.recordPoolReplica("pa", replicaKey{VM: "avm", Disk: "root", Project: project}, filepath.Join(disks, n)); err != nil {
			t.Fatal(err)
		}
	}
	if got := listNames(t, s, pat, "pa"); !slices.Contains(got, mine) || slices.Contains(got, stale) {
		t.Errorf("acme's listing = %v, want %s and not %s", got, mine, stale)
	}
	if got := listNames(t, s, bob, "pb"); slices.Contains(got, mine) || slices.Contains(got, stale) {
		t.Errorf("bravo's listing = %v, includes avm's replicas", got)
	}
	if _, err := s.DeleteStoragePoolContent(pat, &pb.DeleteStoragePoolContentRequest{PoolName: "pa", Filename: mine}); err != nil {
		t.Errorf("acme deleting its VM's replica: %v", err)
	}
}
