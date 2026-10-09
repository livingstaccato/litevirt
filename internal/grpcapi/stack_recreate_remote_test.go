package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// peerBridge carries a forwarded container call from an entry server to the
// member's server the way the wire does: the entry's outgoing metadata
// arrives as the target's incoming metadata, on the entry's authenticated
// peer identity.
type peerBridge struct {
	pb.LiteVirtClient
	to   *Server
	peer context.Context
}

func (b *peerBridge) in(ctx context.Context) context.Context {
	md, _ := metadata.FromOutgoingContext(ctx)
	return metadata.NewIncomingContext(b.peer, md)
}

func (b *peerBridge) DeleteContainer(ctx context.Context, in *pb.DeleteContainerRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return b.to.DeleteContainer(b.in(ctx), in)
}

func (b *peerBridge) CreateContainer(ctx context.Context, in *pb.CreateContainerRequest, _ ...grpc.CallOption) (*pb.Container, error) {
	return b.to.CreateContainer(b.in(ctx), in)
}

func (b *peerBridge) StartContainer(ctx context.Context, in *pb.StartContainerRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return b.to.StartContainer(b.in(ctx), in)
}

// remoteEntry is a two-host setup sharing one replicated database: the
// member web of stack st lives on host-a (tgt, with its own data directory
// and runtime), and the deploy enters on host-b (entry), which forwards to
// host-a. Returns carl's context on the entry.
func remoteEntry(t *testing.T) (entry, tgt *Server, rt *fakeCTRuntime, carl context.Context) {
	t.Helper()
	return remoteEntryAs(t, false)
}

// remoteEntryAs is remoteEntry; with forwardedIdentity, host-a sees the
// forwarded calls as auth.forwarded_identity makes it: a peer (its
// certificate's CN preserved) promoted to the deployer, carl.
func remoteEntryAs(t *testing.T, forwardedIdentity bool) (entry, tgt *Server, rt *fakeCTRuntime, carl context.Context) {
	t.Helper()
	tgt, rt = ctPathServer(t)
	carl = carlCtx(t, tgt)
	entry = testServer(t)
	entry.db = tgt.db
	entry.hostName = "host-b"
	entry.dataDir = t.TempDir()
	entry.pkiDir = filepath.Join(t.TempDir(), "pki")
	entry.SetAuthEngine(tgt.authEngine)
	for _, h := range []string{"host-a", "host-b"} {
		if err := corrosion.InsertHost(context.Background(), tgt.db, corrosion.HostRecord{Name: h, Address: "10.0.0.9", State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.SetHostLabel(context.Background(), tgt.db, "host-a", corrosion.LabelLXCCapable, "true"); err != nil {
		t.Fatal(err)
	}
	// The entry's forward reaches host-a as the peer host-b, which the auth
	// interceptor makes admin (auth.forwarded_identity off, the default): the
	// owner rules bind it only through the owner-strict marker.
	peer := context.WithValue(context.WithValue(mtlsCtx("host-b"), ctxKeyUsername, "admin"), ctxKeyRole, "admin")
	if forwardedIdentity {
		peer = carlPeerCtx()
	}
	bridge := &peerBridge{to: tgt, peer: peer}
	entry.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return bridge, func() {}, nil }
	return entry, tgt, rt, carl
}

// seedRemoteMember records st's member web on host-a, as compose creates it,
// from image (a rootfs path on host-a).
func seedRemoteMember(t *testing.T, tgt *Server, rt *fakeCTRuntime, image string) {
	t.Helper()
	seedSecCT(t, tgt, rt, "web", "stopped", corrosion.ContainerCreateSpec{})
	if err := corrosion.UpsertContainer(context.Background(), tgt.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "web", State: "stopped", Project: "", Image: image,
		Labels:     map[string]string{corrosion.LabelStack: "st"},
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: image, Arch: "amd64"}),
	}); err != nil {
		t.Fatal(err)
	}
}

func redeployFromEntry(entry *Server, carl context.Context, image string) error {
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: image, CPU: 4}}}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	return recreateMember(carl, entry, upd, f)
}

func refusedKeepingTheMember(t *testing.T, err error, rt *fakeCTRuntime, tgt *Server, wants ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("the redeploy went ahead")
	}
	for _, w := range append(wants, "left as it is") {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("refusal %q does not say %q", err.Error(), w)
		}
	}
	memberExists(t, tgt, rt)
	if len(rt.createCalls) != 0 {
		t.Fatalf("created: %+v", rt.createCalls)
	}
}

// Review I5: a non-admin's unchanged redeploy that enters on another host
// than the member's, whose item on the member's host another project owns
// (an Admin's claim, or a member moved onto a host where x pulled its own
// item of the name), is refused by the member's host before it deletes.
func TestComposeRecreate_RemoteEntry_AnotherProjectsItemKeepsTheMember(t *testing.T) {
	entry, tgt, rt, carl := remoteEntry(t)
	image := "rootfs:" + mkCTRootfs(t, filepath.Join(tgt.dataDir, "oci", "web-img", "rootfs"))
	seedRemoteMember(t, tgt, rt, image)
	if err := tgt.writeOCIOwner("web-img", "x"); err != nil {
		t.Fatal(err)
	}
	err := redeployFromEntry(entry, carl, image)
	refusedKeepingTheMember(t, err, rt, tgt, `project "x"`, "Admin")
}

// Review M5: the member's host refuses a template in a protected place on
// its own disk before it deletes, when the deploy entered elsewhere.
func TestComposeRecreate_RemoteEntry_AProtectedTemplateKeepsTheMember(t *testing.T) {
	entry, tgt, rt, carl := remoteEntry(t)
	path := filepath.Join(tgt.dataDir, "images", "ct-root")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	seedRemoteMember(t, tgt, rt, path)
	err := redeployFromEntry(entry, carl, path)
	refusedKeepingTheMember(t, err, rt, tgt)
}

// An item with no owner, or the member's own project's, still backs the
// member's redeploy from another entry host, as on main.
func TestComposeRecreate_RemoteEntry_AnOwnerlessOrOwnItemStillBacksItsMember(t *testing.T) {
	for _, owner := range []string{"", "_default"} {
		t.Run("owner="+owner, func(t *testing.T) {
			entry, tgt, rt, carl := remoteEntry(t)
			image := "rootfs:" + mkCTRootfs(t, filepath.Join(tgt.dataDir, "oci", "web-img", "rootfs"))
			seedRemoteMember(t, tgt, rt, image)
			if owner != "" {
				if err := tgt.writeOCIOwner("web-img", owner); err != nil {
					t.Fatal(err)
				}
			}
			if err := redeployFromEntry(entry, carl, image); err != nil {
				t.Fatalf("unchanged redeploy from another entry host, item owned by %q: %v", owner, err)
			}
			if len(rt.deleteCalls) != 1 || len(rt.createCalls) != 1 {
				t.Fatalf("deletes %v creates %d, want 1 and 1", rt.deleteCalls, len(rt.createCalls))
			}
			if row, _ := corrosion.GetContainer(context.Background(), tgt.db, "host-a", "web"); row == nil {
				t.Fatal("the member is gone after its redeploy")
			}
		})
	}
}

// The recreate preflight is honoured only from an authenticated peer: a
// client's DeleteContainer carrying it is the plain delete it always was.
func TestComposeRecreate_AClientCannotSendTheRecreatePreflight(t *testing.T) {
	tgt, rt := ctPathServer(t)
	image := "rootfs:" + mkCTRootfs(t, filepath.Join(tgt.dataDir, "oci", "web-img", "rootfs"))
	seedRemoteMember(t, tgt, rt, image)
	if err := tgt.writeOCIOwner("web-img", "x"); err != nil {
		t.Fatal(err)
	}
	md := metadata.Pairs("x-litevirt-recreate-template-bin", image, "x-litevirt-recreate-project-bin", "beta", ownerStrictMDKey, "1")
	ctx := metadata.NewIncomingContext(ctOperatorCtx(), md)
	if _, err := tgt.DeleteContainer(ctx, &pb.DeleteContainerRequest{Name: "web", HostName: "host-a", Force: true}); err != nil {
		t.Fatalf("a client's delete carrying recreate metadata: %v", err)
	}
	if len(rt.deleteCalls) != 1 {
		t.Fatalf("deletes = %v, want the one delete", rt.deleteCalls)
	}
}
