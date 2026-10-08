package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// An OCI library item belongs to the project that pulled it. A non-admin may
// create a container from it only in that project; one pulled before owners
// were recorded is everyone's, as it was; the Admin may use any.
func TestOCILibrary_ImageOwnedByThePullingProject(t *testing.T) {
	s, rt := ctPathServer(t)
	if _, err := s.PullOCIImage(ctOperatorCtx(), &pb.PullOCIImageRequest{Image: "ghcr.io/acme/api:1", Dest: "api", Project: "acme"}); err != nil {
		t.Fatalf("pull: %v", err)
	}
	// The fake runtime unpacks nothing; lay the bundle down as umoci would.
	item := mkCTRootfs(t, filepath.Join(s.dataDir, "oci", "api", "rootfs"))

	create := func(ctx context.Context, name, project string) error {
		_, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{Name: name, Template: item, Project: project})
		return err
	}
	if err := create(ctOperatorCtx(), "mine", "acme"); err != nil {
		t.Fatalf("acme from acme's image: %v", err)
	}
	if err := create(ctOperatorCtx(), "theirs", "beta"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("beta from acme's image: got %v, want PermissionDenied", err)
	}
	if err := create(adminCtx(), "admin", "beta"); err != nil {
		t.Fatalf("admin, beta, from acme's image: %v", err)
	}
	// Another project may not pull over acme's image either.
	if _, err := s.PullOCIImage(ctOperatorCtx(), &pb.PullOCIImageRequest{Image: "ghcr.io/beta/x:1", Dest: "api", Project: "beta"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("beta pulling over acme's image: %v", err)
	}
	if len(rt.pullCalls) != 1 {
		t.Fatalf("pull calls = %d, want 1", len(rt.pullCalls))
	}
}

func TestOCILibrary_UnownedImageStaysEveryones(t *testing.T) {
	s, _ := ctPathServer(t)
	// Pulled by an earlier build: no owner record.
	item := mkCTRootfs(t, filepath.Join(s.dataDir, "oci", "old", "rootfs"))
	if _, err := os.Stat(filepath.Join(s.dataDir, ociOwnersDir, "old")); !os.IsNotExist(err) {
		t.Fatal("fixture has an owner")
	}
	for i, p := range []string{"acme", "beta", ""} {
		if _, err := s.CreateContainer(ctOperatorCtx(), &pb.CreateContainerRequest{Name: []string{"a", "b", "c"}[i], Template: item, Project: p}); err != nil {
			t.Fatalf("project %q from an unowned image: %v", p, err)
		}
	}
}

// fakeOwnerPeer records the outgoing metadata of forwarded calls.
type fakeOwnerPeer struct {
	pb.LiteVirtClient
	strict []bool
}

func (f *fakeOwnerPeer) mark(ctx context.Context) {
	md, _ := metadata.FromOutgoingContext(ctx)
	v := md.Get(ownerStrictMDKey)
	f.strict = append(f.strict, len(v) == 1 && v[0] == "1")
}

func (f *fakeOwnerPeer) CreateContainer(ctx context.Context, _ *pb.CreateContainerRequest, _ ...grpc.CallOption) (*pb.Container, error) {
	f.mark(ctx)
	return nil, status.Error(codes.Unavailable, "fake")
}

func (f *fakeOwnerPeer) PullOCIImage(ctx context.Context, _ *pb.PullOCIImageRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	f.mark(ctx)
	return &emptypb.Empty{}, nil
}

// A non-admin's create or pull forwarded to the host holding the library is
// marked, so that host applies the owner rule to the forwarding peer.
func TestOCILibrary_ForwardCarriesTheOwnerRule(t *testing.T) {
	s, _ := ctPathServer(t)
	peer := &fakeOwnerPeer{}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return peer, func() {}, nil }
	_, _ = s.CreateContainer(ctOperatorCtx(), &pb.CreateContainerRequest{Name: "c", HostName: "host-b", Template: "download", Distro: "alpine"})
	_, _ = s.PullOCIImage(ctOperatorCtx(), &pb.PullOCIImageRequest{Image: "alpine:3", Dest: "x", HostName: "host-b"})
	_, _ = s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{Name: "d", HostName: "host-b", Template: "download", Distro: "alpine"})
	if len(peer.strict) != 3 || !peer.strict[0] || !peer.strict[1] || peer.strict[2] {
		t.Fatalf("forwarded owner marks = %v, want [true true false]", peer.strict)
	}
}
