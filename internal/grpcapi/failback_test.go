package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The policy is a cluster_policies write, so it waits for the same latch every
// such write waits for, and nothing is written before it.
//
// Mutation: drop the failoverScopeSettable check in SetFailbackPolicy — the
// first call succeeds (and writes) with the gate unwired.
func TestSetFailbackPolicy_RefusedBeforeTheLatchThenRoundTrips(t *testing.T) {
	s := scopeServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	s.SetGate(fakeServerGate{durablyLatchedTok: map[string]bool{}})
	_, err := s.SetFailbackPolicy(adminCtx(), &pb.SetFailbackPolicyRequest{Enabled: true})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), capabilities.FailoverScopeV1) {
		t.Fatalf("SetFailbackPolicy before the latch: %v, want FailedPrecondition naming %s", err, capabilities.FailoverScopeV1)
	}
	if p, _ := corrosion.GetFailbackPolicy(context.Background(), s.db); p.Enabled {
		t.Fatal("a refused change was written")
	}
	st, err := s.GetFailbackPolicy(adminCtx(), &emptypb.Empty{})
	if err != nil || st.GetEnabled() || st.GetSettable() {
		t.Fatalf("GetFailbackPolicy before the latch = %+v, %v; want off and not settable", st, err)
	}

	s.SetGate(latchedGate(allPeers))
	st, err = s.SetFailbackPolicy(adminCtx(), &pb.SetFailbackPolicyRequest{Enabled: true})
	if err != nil || !st.GetEnabled() || !st.GetSettable() || st.GetUpdatedAt() == "" {
		t.Fatalf("SetFailbackPolicy after the latch = %+v, %v", st, err)
	}
	if p, _ := corrosion.GetFailbackPolicy(context.Background(), s.db); !p.Enabled {
		t.Fatal("the policy was not stored")
	}
	if st, _ = s.SetFailbackPolicy(adminCtx(), &pb.SetFailbackPolicyRequest{Enabled: false}); st.GetEnabled() {
		t.Fatal("the policy did not turn off")
	}
}

func TestFailbackRPCs_NeedTheRightRole(t *testing.T) {
	s := scopeServer(t)
	s.SetGate(latchedGate(allPeers))
	s.db.SetClusterPolicyGate(func() bool { return true })
	viewer := viewerCtx()
	if _, err := s.SetFailbackPolicy(viewer, &pb.SetFailbackPolicyRequest{Enabled: true}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("SetFailbackPolicy as a viewer = %v, want PermissionDenied", err)
	}
	if _, err := s.GetFailbackPolicy(viewer, &emptypb.Empty{}); err != nil {
		t.Errorf("GetFailbackPolicy as a viewer = %v, want allowed", err)
	}
	if err := s.FailbackHost(&pb.FailbackHostRequest{Name: "x"}, &failbackTestStream{ctx: viewer}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("FailbackHost as a viewer = %v, want PermissionDenied", err)
	}
}

type failbackTestStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (f *failbackTestStream) Context() context.Context        { return f.ctx }
func (f *failbackTestStream) Send(*pb.FailbackProgress) error { return nil }
