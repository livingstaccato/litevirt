package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
)

// A host whose kernel refused the SYN-flood probe raises
// firewall.synflood.unavailable, and a policy row it cannot read raises
// firewall.policy.unreadable naming the key; both warnings, both resolved
// once the pass no longer reports them.
func TestRecordFirewallState_SynFloodConditions(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	cond := func(code string) (corrosion.HealthCondition, bool) {
		row, ok, err := corrosion.GetHealthCondition(ctx, s.db, FirewallEvaluator, code, "host", s.hostName)
		return row, err == nil && ok && row.Lifecycle != corrosion.ConditionResolved
	}
	s.RecordFirewallState(ctx, firewall.AppliedState{Mode: firewall.NICModeEnforce,
		SynFloodUnavailable: "nft refused probe table lv_probe_1: no nft_limit",
		UnreadablePolicies:  []string{`unreadable firewall policy: firewall_synflood holds "x"`}})
	row, on := cond(CondFirewallSynfloodUnavailable)
	if !on || row.Severity != corrosion.SeverityWarning || !strings.Contains(row.Evidence, "no nft_limit") {
		t.Errorf("refused probe: %s = %+v (active %v), want an active warning naming the refusal", CondFirewallSynfloodUnavailable, row, on)
	}
	row, on = cond(CondFirewallPolicyUnreadable)
	if !on || row.Severity != corrosion.SeverityWarning || !strings.Contains(row.Evidence, "firewall_synflood") {
		t.Errorf("unreadable row: %s = %+v (active %v), want an active warning naming the key", CondFirewallPolicyUnreadable, row, on)
	}
	s.RecordFirewallState(ctx, firewall.AppliedState{Mode: firewall.NICModeEnforce})
	for _, c := range []string{CondFirewallSynfloodUnavailable, CondFirewallPolicyUnreadable} {
		if _, on := cond(c); on {
			t.Errorf("%s still active after a clean pass", c)
		}
	}
}
