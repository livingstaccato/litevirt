package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// absencePeer answers ListContainers with the live rows its view holds, or
// fails as an unreachable host does.
type absencePeer struct {
	pb.LiteVirtClient
	liveOn string // "" = sees none
	err    error
}

func (p *absencePeer) ListContainers(context.Context, *pb.ListContainersRequest, ...grpc.CallOption) (*pb.ListContainersResponse, error) {
	if p.err != nil {
		return nil, p.err
	}
	if p.liveOn == "" {
		return &pb.ListContainersResponse{}, nil
	}
	return &pb.ListContainersResponse{Containers: []*pb.Container{{Name: "web", Project: "_default", HostName: p.liveOn}}}, nil
}

// absenceServer is the replica host "self" in a cluster of self, src, h2, h3
// (all voters), whose peers answer as views says; a host missing from views is
// unreachable.
func absenceServer(t *testing.T, views map[string]*absencePeer) *Server {
	t.Helper()
	s := testServer(t)
	s.hostName = "self"
	for _, h := range []string{"self", "src", "h2", "h3"} {
		addHost(t, s, h)
	}
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		if p, ok := views[host]; ok {
			return p, func() {}, nil
		}
		return nil, nil, status.Errorf(codes.Unavailable, "%s is down", host)
	}
	return s
}

// R3-I1: a replica restore needs a positive "no live copy" from the replica's
// source, from every host holding a row of the name (tombstones included), and
// from a voter majority. No row is never absence, and no answer never counts
// as one.
func TestConfirmNoLiveCopy_PositiveAnswersOnly(t *testing.T) {
	ctx := context.Background()
	none := func() *absencePeer { return &absencePeer{} }
	down := status.Error(codes.Unavailable, "down")

	t.Run("no row and the source cannot be asked", func(t *testing.T) {
		s := absenceServer(t, map[string]*absencePeer{"h2": none(), "h3": none()})
		err := s.confirmNoLiveCopy(ctx, "_default", "web", "src")
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cannot confirm with src") {
			t.Fatalf("no row, source down: %v, want refused naming src", err)
		}
	})
	t.Run("every host answers none", func(t *testing.T) {
		s := absenceServer(t, map[string]*absencePeer{"src": none(), "h2": none(), "h3": none()})
		if err := s.confirmNoLiveCopy(ctx, "_default", "web", "src"); err != nil {
			t.Fatalf("every host sees none: %v", err)
		}
	})
	t.Run("a member that holds no row here still sees it live", func(t *testing.T) {
		s := absenceServer(t, map[string]*absencePeer{"src": none(), "h2": {liveOn: "h2"}, "h3": none()})
		err := s.confirmNoLiveCopy(ctx, "_default", "web", "src")
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "h2 still sees web live on h2") {
			t.Fatalf("h2 runs it: %v, want refused because h2 still sees it", err)
		}
	})
	t.Run("a host that held a row cannot be asked", func(t *testing.T) {
		s := absenceServer(t, map[string]*absencePeer{"src": none(), "h2": none(), "h3": {err: down}})
		if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{HostName: "h3", Name: "web", State: "stopped"}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.DeleteContainer(ctx, s.db, "h3", "web"); err != nil {
			t.Fatal(err)
		}
		// self, src and h2 are a voter majority (3 of 4); h3 is still required.
		err := s.confirmNoLiveCopy(ctx, "_default", "web", "src")
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cannot confirm with h3") {
			t.Fatalf("a row holder down: %v, want refused naming h3", err)
		}
	})
	t.Run("no voter majority answers", func(t *testing.T) {
		s := absenceServer(t, map[string]*absencePeer{"src": none()})
		// self and src: 2 of 4 voters.
		err := s.confirmNoLiveCopy(ctx, "_default", "web", "src")
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "only 2 of 4 voters") {
			t.Fatalf("2 of 4 voters: %v, want refused for want of a majority", err)
		}
	})
	t.Run("a removed source is not asked", func(t *testing.T) {
		s := absenceServer(t, map[string]*absencePeer{"h2": none(), "h3": none()})
		if err := corrosion.DeleteHost(ctx, s.db, "src"); err != nil {
			t.Fatal(err)
		}
		if err := s.confirmNoLiveCopy(ctx, "_default", "web", "src"); err != nil {
			t.Fatalf("the source was removed from the cluster: %v", err)
		}
	})
	t.Run("another project's container is not this one", func(t *testing.T) {
		// h2 runs _default's web; acme's web is another container.
		s := absenceServer(t, map[string]*absencePeer{"src": none(), "h2": {liveOn: "h2"}, "h3": none()})
		if err := s.confirmNoLiveCopy(ctx, "acme", "web", "src"); err != nil {
			t.Fatalf("web of _default does not block a restore of acme's web: %v", err)
		}
	})
}
