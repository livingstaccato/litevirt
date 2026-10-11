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
	"github.com/litevirt/litevirt/internal/health"
)

// absencePeer answers ListContainers with the live rows its view holds, and
// GetRuntimeInventory with its own runtime, or fails as an unreachable host
// does.
type absencePeer struct {
	pb.LiteVirtClient
	liveOn  string // "" = sees none
	project string // the live row's project; "" = _default
	err     error
	// runtime is the host's container inventory for the name asked; nil is a
	// complete inventory without it.
	runtime    *pb.RuntimeInventory
	runtimeErr error
}

func (p *absencePeer) GetRuntimeInventory(_ context.Context, req *pb.GetRuntimeInventoryRequest, _ ...grpc.CallOption) (*pb.RuntimeInventory, error) {
	if p.err != nil {
		return nil, p.err
	}
	if p.runtimeErr != nil {
		return nil, p.runtimeErr
	}
	if req.GetKind() != corrosion.WorkloadContainer || req.GetName() != "web" {
		return nil, status.Errorf(codes.InvalidArgument, "asked for %s %q, want the container web", req.GetKind(), req.GetName())
	}
	if p.runtime == nil {
		return &pb.RuntimeInventory{Complete: true}, nil
	}
	return p.runtime, nil
}

// ctRuntime is a complete inventory holding the container web in state.
func ctRuntime(state string) *pb.RuntimeInventory {
	return &pb.RuntimeInventory{Complete: true, Workloads: []*pb.RuntimeWorkload{
		{Kind: corrosion.WorkloadContainer, Name: "web", State: state},
	}}
}

func (p *absencePeer) ListContainers(context.Context, *pb.ListContainersRequest, ...grpc.CallOption) (*pb.ListContainersResponse, error) {
	if p.err != nil {
		return nil, p.err
	}
	if p.liveOn == "" {
		return &pb.ListContainersResponse{}, nil
	}
	project := p.project
	if project == "" {
		project = "_default"
	}
	return &pb.ListContainersResponse{Containers: []*pb.Container{{Name: "web", Project: project, HostName: p.liveOn}}}, nil
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
	t.Run("a member that holds no row cannot be asked", func(t *testing.T) {
		// R4-m1: self, src and h3 are a voter majority, and h2 holds no row
		// here. It could still run the container (a migrate onto it whose row
		// never left it), so no answer is not absence.
		s := absenceServer(t, map[string]*absencePeer{"src": none(), "h3": none()})
		err := s.confirmNoLiveCopy(ctx, "_default", "web", "src")
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cannot confirm with h2") {
			t.Fatalf("h2 down, a voter majority answers: %v, want refused naming h2", err)
		}
	})
	t.Run("a member that is not a voter cannot be asked", func(t *testing.T) {
		// R4-m1: n5, in maintenance, is no voter and holds no row here.
		s := absenceServer(t, map[string]*absencePeer{"src": none(), "h2": none(), "h3": none()})
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "n5", Address: "127.0.0.1", State: "maintenance"}); err != nil {
			t.Fatal(err)
		}
		err := s.confirmNoLiveCopy(ctx, "_default", "web", "src")
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cannot confirm with n5") {
			t.Fatalf("a non-voter down: %v, want refused naming n5", err)
		}
	})
	t.Run("a source this cluster has no record of", func(t *testing.T) {
		// R4-n2: it cannot be removed, so the refusal must not say to.
		s := absenceServer(t, map[string]*absencePeer{"src": none(), "h2": none(), "h3": none()})
		err := s.confirmNoLiveCopy(ctx, "_default", "web", "gone")
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cannot confirm with gone") ||
			!strings.Contains(err.Error(), "no record of") || strings.Contains(err.Error(), "remove it") {
			t.Fatalf("an unknown source: %v, want refused naming gone as unknown, with no removal remedy", err)
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
		// Its runtime is named web too: runtime names are not project-scoped.
		s := absenceServer(t, map[string]*absencePeer{"src": none(), "h2": {liveOn: "h2", runtime: ctRuntime(health.RuntimeRunning)}, "h3": none()})
		if err := s.confirmNoLiveCopy(ctx, "acme", "web", "src"); err != nil {
			t.Fatalf("web of _default does not block a restore of acme's web: %v", err)
		}
	})

	// R4-I1: a host's runtime is asked as well as its rows. A container that
	// runs with no live row anywhere (a stale delete tombstoned it, or a create
	// or migrate stopped between the runtime and the row) is a live copy, and
	// may be the newest one.
	t.Run("a host that sees no row runs it", func(t *testing.T) {
		for _, state := range []string{health.RuntimeRunning, health.RuntimeDefinedStopped} {
			s := absenceServer(t, map[string]*absencePeer{"src": none(), "h2": {runtime: ctRuntime(state)}, "h3": none()})
			err := s.confirmNoLiveCopy(ctx, "_default", "web", "src")
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "h2 runs web with no live row") {
				t.Fatalf("h2 holds web %s with no row: %v, want refused because h2 runs it", state, err)
			}
		}
	})
	t.Run("a runtime that cannot be read is no answer", func(t *testing.T) {
		for what, p := range map[string]*absencePeer{
			"unknown state":        {runtime: ctRuntime(health.RuntimeUnknown)},
			"incomplete inventory": {runtime: &pb.RuntimeInventory{Complete: false, Errors: []string{"list containers: boom"}}},
			"inventory error":      {runtimeErr: status.Error(codes.Unavailable, "boom")},
		} {
			s := absenceServer(t, map[string]*absencePeer{"src": none(), "h2": p, "h3": none()})
			err := s.confirmNoLiveCopy(ctx, "_default", "web", "src")
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cannot confirm with h2") {
				t.Fatalf("%s on h2: %v, want refused because h2 cannot vouch", what, err)
			}
		}
	})
	t.Run("this host runs it with no row", func(t *testing.T) {
		s := absenceServer(t, map[string]*absencePeer{"src": none(), "h2": none(), "h3": none()})
		s.containersRoot = t.TempDir()
		s.SetLXCCapableForTest(true)
		s.SetContainerRuntime(&fakeCT{names: []string{"web"}, states: map[string]string{"web": "stopped"}})
		err := s.confirmNoLiveCopy(ctx, "_default", "web", "src")
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "self runs web with no live row") {
			t.Fatalf("self holds web with no row: %v, want refused because self runs it", err)
		}
	})
}
