package firewall

import (
	"fmt"
	"strings"
	"testing"
)

// TestRender_GuestVRRPToTheHostDropped: in enforce and observe mode alike, the
// bridge input hook marks VRRP a guest sends the host (or to be routed),
// before anything can accept it, and the inet input hook drops what is marked
// — only the host's own copy, so routed VRRP is untouched. Guards-only renders
// neither (no bridge input chain), and neither does a plan with no guest NIC
// or a bridge table not in force.
//
// Mutation: render the mark after bridgeCommon's accepts — red; render the
// guest_vrrp chain's verdict as the mode's (a counter in observe) — red.
func TestRender_GuestVRRPToTheHostDropped(t *testing.T) {
	mark := fmt.Sprintf("meta l4proto 112 meta mark set meta mark | %#x\n", guestVRRPMark)
	drop := fmt.Sprintf("meta mark & %#x == %#x meta l4proto 112 drop\n", guestVRRPMark, guestVRRPMark)
	for _, mode := range []string{NICModeEnforce, NICModeObserve} {
		inet, nic, err := RenderParts(sgPlan(mode, true), true)
		if err != nil {
			t.Fatal(err)
		}
		in := chainBody(t, nic, "input")
		lines := strings.Split(strings.TrimSpace(in), "\n")
		if len(lines) < 3 || strings.TrimSpace(lines[2])+"\n" != mark {
			t.Errorf("%s: the bridge input chain does not mark a guest's VRRP right after its port scoping:\n%s", mode, in)
		}
		if body := chainBody(t, inet, "guest_vrrp"); !strings.Contains(body, "hook input priority filter; policy accept;") || !strings.Contains(body, strings.TrimSuffix(drop, "\n")) {
			t.Errorf("%s: guest_vrrp chain:\n%s", mode, body)
		}
	}
	inet, nic, err := RenderParts(sgPlan(NICModeGuardsOnly, true), true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(nic, "l4proto 112") || strings.Contains(inet, "guest_vrrp") {
		t.Errorf("guards-only renders the guest-VRRP drop, which rests on the bridge input chain it does not render")
	}
	if inet, _, _ := RenderParts(Plan{}, true); strings.Contains(inet, "guest_vrrp") {
		t.Errorf("a plan with no guest NIC renders the guest_vrrp chain")
	}
	if inet, _, _ := RenderParts(sgPlan(NICModeEnforce, true), false); strings.Contains(inet, "guest_vrrp") {
		t.Errorf("the guest_vrrp chain is rendered with the bridge table that marks for it not in force")
	}
}
