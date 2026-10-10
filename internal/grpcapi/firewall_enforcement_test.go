package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
)

// TestSetFirewallEnforcement (ruling 1): switching per-NIC enforcement is
// admin-only, audited, and recorded in the replicated policy; it is refused
// while the policy table cannot be written.
func TestSetFirewallEnforcement(t *testing.T) {
	ctx := context.Background()
	closed := guardServer(t, false)
	if _, err := closed.SetFirewallEnforcement(adminCtx(), &pb.SetFirewallEnforcementRequest{Mode: "enforce"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("before the policy gate: %v, want FailedPrecondition", err)
	}
	s := guardServer(t, true)
	if _, err := s.SetFirewallEnforcement(userCtx("op", "operator"), &pb.SetFirewallEnforcementRequest{Mode: "enforce"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("an operator switching enforcement: %v, want PermissionDenied", err)
	}
	if _, err := s.SetFirewallEnforcement(adminCtx(), &pb.SetFirewallEnforcementRequest{Mode: "strict"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("an unknown mode: %v, want InvalidArgument", err)
	}
	st, err := s.SetFirewallEnforcement(adminCtx(), &pb.SetFirewallEnforcementRequest{Mode: "enforce"})
	if err != nil || st.Mode != "enforce" {
		t.Fatalf("SetFirewallEnforcement = %+v, %v", st, err)
	}
	wantAudit(t, s, "firewall.enforcement", "admin", "cluster", "before=unset after=enforce")
	if enf, _ := corrosion.GetFirewallEnforcement(ctx, s.db); enf.Mode != corrosion.FirewallEnforce || enf.SetBy != "admin" {
		t.Errorf("stored policy = %+v", enf)
	}
}

// TestRecordFirewallState (ruling 1, 6): a host observing, or unable to
// enforce, raises a health condition; enforcing resolves it.
func TestRecordFirewallState(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	active := func(code string) bool {
		row, ok, err := corrosion.GetHealthCondition(ctx, s.db, FirewallEvaluator, code, "host", s.hostName)
		return err == nil && ok && row.Lifecycle != corrosion.ConditionResolved
	}
	s.RecordFirewallState(ctx, firewall.AppliedState{Mode: firewall.NICModeObserve})
	if !active(CondFirewallObserve) {
		t.Error("observe mode raised no condition")
	}
	s.RecordFirewallState(ctx, firewall.AppliedState{Mode: firewall.NICModeGuardsOnly})
	if !active(CondFirewallUnavailable) || active(CondFirewallObserve) {
		t.Error("guards-only did not raise the unavailable condition (and resolve observe)")
	}
	s.RecordFirewallState(ctx, firewall.AppliedState{Mode: firewall.NICModeEnforce, NICTableError: "boom"})
	if !active(CondFirewallRefused) || active(CondFirewallUnavailable) {
		t.Error("a refused table raised no condition")
	}
	s.RecordFirewallState(ctx, firewall.AppliedState{Mode: firewall.NICModeEnforce})
	for _, c := range []string{CondFirewallObserve, CondFirewallUnavailable, CondFirewallRefused} {
		if active(c) {
			t.Errorf("%s still active while enforcing cleanly", c)
		}
	}
}
