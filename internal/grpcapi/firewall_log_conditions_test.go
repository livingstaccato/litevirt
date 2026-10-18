package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
)

// C4b (spec §3.5): a listener that cannot bind its group raises
// firewall.log.listener (warning) naming why; once bound it resolves.
//
// Mutation: never resolve — the condition stays active, red.
func TestRecordFirewallLogListener(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	cond := func() (corrosion.HealthCondition, bool) {
		t.Helper()
		c, ok, err := corrosion.GetHealthCondition(ctx, s.db, FirewallEvaluator, CondFirewallLogListener, "host", s.hostName)
		if err != nil {
			t.Fatal(err)
		}
		return c, ok && c.Lifecycle != corrosion.ConditionResolved
	}
	s.RecordFirewallLogListener(ctx, errors.New("bind group 27: device or resource busy"))
	c, active := cond()
	if !active || c.Severity != corrosion.SeverityWarning || !strings.Contains(c.Evidence, "device or resource busy") ||
		!strings.Contains(c.Evidence, "firewall.log_group") {
		t.Fatalf("after a failed bind: %+v active=%v", c, active)
	}
	s.RecordFirewallLogListener(ctx, nil)
	if _, active := cond(); active {
		t.Error("still active once bound")
	}
}

// C6 (spec §3.4, §3.3): a host whose kernel refuses the logging forms raises
// firewall.log.unavailable (warning); an unreadable policy row raises
// firewall.policy.unreadable naming the key, and both resolve when the cause
// goes.
//
// Mutation: never raise firewall.policy.unreadable — red.
func TestFirewallLogConditions(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	active := func(code string) (corrosion.HealthCondition, bool) {
		t.Helper()
		c, ok, err := corrosion.GetHealthCondition(ctx, s.db, FirewallEvaluator, code, "host", s.hostName)
		if err != nil {
			t.Fatal(err)
		}
		return c, ok && c.Lifecycle != corrosion.ConditionResolved
	}
	s.RecordFirewallLogAvailability(ctx, errors.New("nft refused probe table: No such file or directory"))
	if c, ok := active(CondFirewallLogUnavailable); !ok || c.Severity != corrosion.SeverityWarning || !strings.Contains(c.Evidence, "No such file") {
		t.Errorf("unavailable = %+v %v", c, ok)
	}
	s.RecordFirewallLogAvailability(ctx, nil)
	if _, ok := active(CondFirewallLogUnavailable); ok {
		t.Error("unavailable still active after a passing probe")
	}
	s.RecordFirewallState(ctx, firewall.AppliedState{UnreadablePolicies: []string{"unreadable firewall policy: firewall_log holds \"{\""}})
	if c, ok := active(CondFirewallPolicyUnreadable); !ok || c.Severity != corrosion.SeverityWarning || !strings.Contains(c.Evidence, "firewall_log") {
		t.Errorf("policy unreadable = %+v %v", c, ok)
	}
	s.RecordFirewallState(ctx, firewall.AppliedState{})
	if _, ok := active(CondFirewallPolicyUnreadable); ok {
		t.Error("policy unreadable still active")
	}
}
