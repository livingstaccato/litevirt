package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
)

// A host whose kernel refused the SYN-flood probe raises
// firewall.synflood.unavailable (warning, naming the refusal), resolved once
// the pass no longer reports it. firewall.policy.unreadable is NOT raised
// here: one raiser (the log policy's recorder) names every unreadable policy
// with its effect from AppliedState.UnreadablePolicies.
//
// Mutations: drop the call from RecordFirewallState — red; raise
// firewall.policy.unreadable here — red.
func TestRecordFirewallState_SynFloodConditions(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	cond := func(code string) (corrosion.HealthCondition, bool) {
		row, ok, err := corrosion.GetHealthCondition(ctx, s.db, FirewallEvaluator, code, "host", s.hostName)
		return row, err == nil && ok && row.Lifecycle != corrosion.ConditionResolved
	}
	s.recordSynFloodState(ctx, firewall.AppliedState{Mode: firewall.NICModeEnforce,
		SynFloodUnavailable: "nft refused probe table lv_probe_1: no nft_limit",
		UnreadablePolicies:  []string{`unreadable firewall policy: firewall_synflood holds "x"`}})
	row, on := cond(CondFirewallSynfloodUnavailable)
	if !on || row.Severity != corrosion.SeverityWarning || !strings.Contains(row.Evidence, "no nft_limit") {
		t.Errorf("refused probe: %s = %+v (active %v), want an active warning naming the refusal", CondFirewallSynfloodUnavailable, row, on)
	}
	if _, on := cond("firewall.policy.unreadable"); on {
		t.Error("the SYN-flood recorder raised firewall.policy.unreadable; its one raiser is the log policy's")
	}
	s.RecordFirewallState(ctx, firewall.AppliedState{Mode: firewall.NICModeEnforce,
		SynFloodUnavailable: "nft refused probe table lv_probe_1: no nft_limit"})
	if _, on := cond(CondFirewallSynfloodUnavailable); !on {
		t.Error("RecordFirewallState does not record the SYN-flood conditions")
	}
	s.RecordFirewallState(ctx, firewall.AppliedState{Mode: firewall.NICModeEnforce})
	if _, on := cond(CondFirewallSynfloodUnavailable); on {
		t.Errorf("%s still active after a clean pass", CondFirewallSynfloodUnavailable)
	}
}
