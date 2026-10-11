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
// such write waits for, and it is data of the drain_failback release feature,
// so it also waits for that feature's gate; nothing is written before both.
//
// Mutations: drop the failoverScopeSettable check in SetFailbackPolicy — the
// first call is refused only by the release gate, not naming failover_scope_v1;
// call corrosion.SetFailbackPolicy outside WithReleaseFeature — the write runs
// with the release gate refusing; drop the release term from Settable.
func TestSetFailbackPolicy_RefusedBeforeTheLatchThenRoundTrips(t *testing.T) {
	s := scopeServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: true})
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

	// failover_scope_v1 latched, the release token not: the release gate's
	// refusal is the answer, and nothing is written.
	s.SetGate(latchedGate(allPeers))
	refusal := status.Error(codes.FailedPrecondition, "the cluster upgrade must finish first (drain_failback needs "+capabilities.ReleaseToken+")")
	s.SetReleaseFeatureGate(fakeFeatureGate{err: refusal})
	if _, err = s.SetFailbackPolicy(adminCtx(), &pb.SetFailbackPolicyRequest{Enabled: true}); err == nil || err.Error() != refusal.Error() {
		t.Fatalf("SetFailbackPolicy before the release token latched: %v, want %v", err, refusal)
	}
	if p, _ := corrosion.GetFailbackPolicy(context.Background(), s.db); p.Enabled || p.SetBy != "" {
		t.Fatalf("a change the release gate refused was written: %+v", p)
	}
	if st, _ = s.GetFailbackPolicy(adminCtx(), &emptypb.Empty{}); st.GetSettable() {
		t.Fatalf("settable before the release token latched: %+v", st)
	}
	// No gate wired at all: refused, fail closed.
	s.SetReleaseFeatureGate(nil)
	if _, err = s.SetFailbackPolicy(adminCtx(), &pb.SetFailbackPolicyRequest{Enabled: true}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("SetFailbackPolicy with no release gate: %v, want FailedPrecondition", err)
	}

	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: true})
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
