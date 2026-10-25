package grpcapi

import (
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// TestAdvertise_AutomationWithheldWhileOff: every voter relies on every peer
// refusing automation votes until its membership import is complete, so the
// automation_v1 latch has to mean config uniformity, not just a uniform build.
func TestAdvertise_AutomationWithheldWhileOff(t *testing.T) {
	t.Run("flag off", func(t *testing.T) {
		s := testServer(t)
		s.SetAutomationEnforce(false)
		if slices.Contains(s.advertisedCapabilities(), capabilities.AutomationV1) {
			t.Fatalf("%s is advertised with enforcement.automation off", capabilities.AutomationV1)
		}
		if s.tokenEnabled(capabilities.AutomationV1) {
			t.Fatalf("tokenEnabled(%s) is true with the flag off", capabilities.AutomationV1)
		}
	})
	t.Run("flag on", func(t *testing.T) {
		s := testServer(t)
		s.SetAutomationEnforce(true)
		if !slices.Contains(s.advertisedCapabilities(), capabilities.AutomationV1) {
			t.Fatalf("a flag-on node does not advertise %s", capabilities.AutomationV1)
		}
		if !s.tokenEnabled(capabilities.AutomationV1) {
			t.Fatalf("tokenEnabled(%s) is false with the flag on", capabilities.AutomationV1)
		}
	})
}
