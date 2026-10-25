package grpcapi

import (
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// TestAdvertise_AutomationIsUnconditional: automation_v1 is a fact about the
// build. Ask where the guarantee is enforced: every voter refuses automation
// votes on its own authority row (corrosion admitAutomationTx), which only an
// ordinary adoption that imported the old majority's state carries, whatever
// enforcement.automation says. No node relies on a peer's flag, so
// withholding buys no safety, while a witness that never sets the flag would
// hold the latch off fleet-wide. The flag decides only this node's own
// enforcement, which not_enforcing reports.
func TestAdvertise_AutomationIsUnconditional(t *testing.T) {
	for _, on := range []bool{false, true} {
		s := testServer(t)
		s.SetAutomationEnforce(on)
		if !slices.Contains(s.advertisedCapabilities(), capabilities.AutomationV1) {
			t.Fatalf("%s is not advertised with enforcement.automation=%v", capabilities.AutomationV1, on)
		}
		if s.tokenEnabled(capabilities.AutomationV1) != on {
			t.Fatalf("tokenEnabled(%s) = %v with the flag %v", capabilities.AutomationV1, !on, on)
		}
		if got := slices.Contains(s.notEnforcingTokens(), capabilities.AutomationV1); got == on {
			t.Fatalf("not_enforcing lists %s = %v with the flag %v", capabilities.AutomationV1, got, on)
		}
	}
}
