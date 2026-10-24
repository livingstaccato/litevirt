package compose

import (
	"strings"
	"testing"
)

func rebalanceModeYAML(mode string) string {
	return `
name: mystack
vms:
  web:
    image: nginx
    placement:
      rebalance:
        mode: ` + mode + `
`
}

// An unknown mode is refused, on-demand among them (a mode folded into
// dry-run before v1.10).
//
// Mutation: accept on-demand in rebalanceModeProblem — red.
func TestParse_RebalanceModeUnknownRejected(t *testing.T) {
	for _, mode := range []string{"sometimes", "on-demand"} {
		_, err := ParseBytes([]byte(rebalanceModeYAML(mode)))
		if err == nil {
			t.Fatalf("placement.rebalance.mode: %s was accepted; want a validation error", mode)
		}
		if !strings.Contains(err.Error(), "off, dry-run, auto") {
			t.Errorf("error %q does not list the valid modes", err)
		}
	}
}

func TestParse_RebalanceModeValidAccepted(t *testing.T) {
	for _, mode := range []string{"off", "dry-run", "auto"} {
		if _, err := ParseBytes([]byte(rebalanceModeYAML(mode))); err != nil {
			t.Errorf("mode %q rejected: %v", mode, err)
		}
	}
}

// TestExpandPlacementMode_HACriticalIsDryRun: the ha-critical preset expands
// to the one propose-only mode.
func TestExpandPlacementMode_HACriticalIsDryRun(t *testing.T) {
	p := &PlacementDef{Mode: "ha-critical"}
	ExpandPlacementMode(p)
	if p.Policy != "spread-strict" {
		t.Errorf("Policy = %q, want spread-strict", p.Policy)
	}
	if p.Rebalance == nil || p.Rebalance.Mode != "dry-run" {
		t.Errorf("Rebalance = %+v, want mode dry-run", p.Rebalance)
	}
}
