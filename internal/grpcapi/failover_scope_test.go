package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func setRegionScope(t *testing.T, s *Server) {
	t.Helper()
	s.db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.SetFailoverScope(context.Background(), s.db, corrosion.FailoverScopeRegion, "test"); err != nil {
		t.Fatalf("SetFailoverScope: %v", err)
	}
}

func scopeServer(t *testing.T) *Server {
	t.Helper()
	s := testServer(t)
	ctx := context.Background()
	for h, r := range map[string]string{"test-host": "east", "e2": "east", "e3": "east", "w1": "west", "w2": "west"} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", State: "active", CertSerial: "s-" + h,
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
		if err := corrosion.UpdateHostRegion(ctx, s.db, h, r); err != nil {
			t.Fatalf("UpdateHostRegion %s: %v", h, err)
		}
	}
	return s
}

var allPeers = []string{"e2", "e3", "w1", "w2"}

func latchedGate(healthy []string) fakeServerGate {
	return fakeServerGate{healthy: healthy,
		durablyLatchedTok: map[string]bool{capabilities.FailoverScopeV1: true}}
}

// TestSetFailoverScope_RefusedBeforeTheLatch: nothing may be written until
// every host runs a build that decodes the table and honours the policy.
func TestSetFailoverScope_RefusedBeforeTheLatch(t *testing.T) {
	s := scopeServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	s.SetGate(fakeServerGate{healthy: allPeers, durablyLatchedTok: map[string]bool{}})
	_, err := s.SetFailoverScope(adminCtx(), &pb.SetFailoverScopeRequest{Scope: corrosion.FailoverScopeRegion})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), capabilities.FailoverScopeV1) {
		t.Fatalf("SetFailoverScope before the latch: %v, want FailedPrecondition naming %s", err, capabilities.FailoverScopeV1)
	}
	if p, _ := corrosion.GetFailoverScope(context.Background(), s.db); p.Region() {
		t.Fatalf("a refused change was written")
	}
	st, err := s.GetFailoverScope(adminCtx(), &emptypb.Empty{})
	if err != nil || st.GetSettable() {
		t.Fatalf("GetFailoverScope before the latch: settable=%v err=%v, want false", st.GetSettable(), err)
	}
}

// TestSetFailoverScope_RefusedWhileAVoterIsUnreachable: a change made from one
// side of a partition reaches only that side, so it is refused, naming who is
// out of reach.
func TestSetFailoverScope_RefusedWhileAVoterIsUnreachable(t *testing.T) {
	s := scopeServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	s.SetGate(latchedGate([]string{"e2", "e3"}))
	_, err := s.SetFailoverScope(adminCtx(), &pb.SetFailoverScopeRequest{Scope: corrosion.FailoverScopeRegion})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "w1, w2") {
		t.Fatalf("SetFailoverScope with west unreachable: %v, want FailedPrecondition naming w1, w2", err)
	}
	if p, _ := corrosion.GetFailoverScope(context.Background(), s.db); p.Region() {
		t.Fatalf("a refused change was written")
	}
}

// TestSetFailoverScope_WholeCluster sets the policy, records who did, and
// reports each region's strength.
func TestSetFailoverScope_WholeCluster(t *testing.T) {
	s := scopeServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	s.SetGate(latchedGate(allPeers))
	st, err := s.SetFailoverScope(adminCtx(), &pb.SetFailoverScopeRequest{Scope: corrosion.FailoverScopeRegion})
	if err != nil {
		t.Fatalf("SetFailoverScope: %v", err)
	}
	if st.GetScope() != corrosion.FailoverScopeRegion || st.GetSetBy() != "admin" || !st.GetSettable() {
		t.Fatalf("status after set: %+v", st)
	}
	got := map[string]*pb.FailoverScopeRegion{}
	for _, r := range st.GetRegions() {
		got[r.GetName()] = r
	}
	if e := got["east"]; e == nil || e.GetVoters() != 3 || e.GetQuorum() != 2 || !e.GetCanFenceOwn() {
		t.Errorf("east: %+v, want 3 voters, quorum 2, can fence its own", e)
	}
	if w := got["west"]; w == nil || w.GetVoters() != 2 || w.GetCanFenceOwn() {
		t.Errorf("west: %+v, want 2 voters and unable to fence its own", w)
	}
	if _, err := s.SetFailoverScope(adminCtx(), &pb.SetFailoverScopeRequest{Scope: "zone"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("an unknown scope: %v, want InvalidArgument", err)
	}
}

// TestSetFailoverScope_ClientGateStillHolds: the handler's latch check is not
// the only gate. corrosion refuses on its own if the daemon never opened it.
func TestSetFailoverScope_ClientGateStillHolds(t *testing.T) {
	s := scopeServer(t)
	s.SetGate(latchedGate(allPeers))
	_, err := s.SetFailoverScope(adminCtx(), &pb.SetFailoverScopeRequest{Scope: corrosion.FailoverScopeRegion})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("with the corrosion gate closed: %v, want FailedPrecondition", err)
	}
}

// TestConfigureHost_RegionChangeUnderRegionScope: relabelling a host changes
// two regions' voter sets, so under region scope it needs every voter
// reachable, as changing the policy does. Under the cluster scope a region is
// only a label and changes freely.
func TestConfigureHost_RegionChangeUnderRegionScope(t *testing.T) {
	ctx := context.Background()
	s := scopeServer(t)
	s.SetGate(latchedGate([]string{"e2", "e3"}))
	if _, err := s.ConfigureHost(adminCtx(), &pb.ConfigureHostRequest{Name: "w2", Region: "east"}); err != nil {
		t.Fatalf("cluster scope: a region change must not need reachability: %v", err)
	}
	if err := corrosion.UpdateHostRegion(ctx, s.db, "w2", "west"); err != nil {
		t.Fatalf("UpdateHostRegion: %v", err)
	}

	setRegionScope(t, s)
	_, err := s.ConfigureHost(adminCtx(), &pb.ConfigureHostRequest{Name: "w2", Region: "east"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("region scope with west unreachable: relabel returned %v, want FailedPrecondition", err)
	}
	if h, _ := corrosion.GetHost(ctx, s.db, "w2"); h == nil || h.Region != "west" {
		t.Fatalf("a refused relabel changed the region: %+v", h)
	}
	// Other fields still change freely under region scope.
	if _, err := s.ConfigureHost(adminCtx(), &pb.ConfigureHostRequest{Name: "w2", FenceStrategy: "manual"}); err != nil {
		t.Fatalf("region scope: a non-region change was refused: %v", err)
	}

	s.SetGate(latchedGate(allPeers))
	if _, err := s.ConfigureHost(adminCtx(), &pb.ConfigureHostRequest{Name: "w2", Region: "east"}); err != nil {
		t.Fatalf("region scope with every voter reachable: %v", err)
	}
}
