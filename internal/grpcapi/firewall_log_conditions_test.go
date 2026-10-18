package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
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
