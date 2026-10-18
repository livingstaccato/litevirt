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

// Round 1 I-2: one raiser for firewall.policy.unreadable names every
// unreadable row with its own effect (log: off; SYN-flood: on), and makes no
// log-only claim.
//
// Round 1 I-1: the listener condition says records are not logged (no log
// line is rendered while the group is held elsewhere), never "discarded".
//
// Mutations: name only the first row — red; keep the log-specific wording —
// red; say "discarded" — red.
func TestFirewallConditions_Round1Texts(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	evidence := func(code string) string {
		t.Helper()
		c, ok, err := corrosion.GetHealthCondition(ctx, s.db, FirewallEvaluator, code, "host", s.hostName)
		if err != nil || !ok {
			t.Fatalf("%s: %v %v", code, ok, err)
		}
		return c.Evidence
	}
	logRow := `firewall_log holds "{": read as logging off at 5/10`
	synRow := `firewall_synflood/test-host holds "{": read as on at 200/1000`
	s.RecordFirewallState(ctx, firewall.AppliedState{UnreadablePolicies: []string{synRow, logRow}})
	ev := evidence(CondFirewallPolicyUnreadable)
	if !strings.Contains(ev, logRow) || !strings.Contains(ev, synRow) || strings.Contains(ev, "the log policy as off") {
		t.Errorf("policy unreadable evidence = %q, want both rows with their own effects", ev)
	}
	s.RecordFirewallLogListener(ctx, errors.New("bind group 27: operation not permitted"))
	ev = evidence(CondFirewallLogListener)
	if strings.Contains(ev, "discarded") || !strings.Contains(ev, "not logged") || !strings.Contains(ev, "firewall.log_group") {
		t.Errorf("listener evidence = %q", ev)
	}
}
