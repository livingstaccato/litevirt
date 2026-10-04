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

// TestParse_RebalanceModeOnDemandRejected: on-demand was removed (it behaved
// exactly like dry-run). A config naming it must fail, and the message must
// name the replacement so the operator knows what to write instead.
func TestParse_RebalanceModeOnDemandRejected(t *testing.T) {
	_, err := ParseBytes([]byte(rebalanceModeYAML("on-demand")))
	if err == nil {
		t.Fatal("placement.rebalance.mode: on-demand was accepted; want a validation error")
	}
	msg := err.Error()
	for _, want := range []string{"placement.rebalance.mode", "on-demand", "dry-run"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}
}

func TestParse_RebalanceModeUnknownRejected(t *testing.T) {
	_, err := ParseBytes([]byte(rebalanceModeYAML("sometimes")))
	if err == nil {
		t.Fatal("placement.rebalance.mode: sometimes was accepted; want a validation error")
	}
	if !strings.Contains(err.Error(), "off, dry-run, auto") {
		t.Errorf("error %q does not list the valid modes", err)
	}
}

func TestParse_RebalanceModeValidAccepted(t *testing.T) {
	for _, mode := range []string{"off", "dry-run", "auto"} {
		if _, err := ParseBytes([]byte(rebalanceModeYAML(mode))); err != nil {
			t.Errorf("mode %q rejected: %v", mode, err)
		}
	}
}

func TestValidatePlacement_OnDemandRejected(t *testing.T) {
	_, errs := ValidatePlacement(&PlacementDef{Rebalance: &RebalanceDef{Mode: "on-demand"}})
	if len(errs) == 0 || !strings.Contains(strings.Join(errs, ";"), "dry-run") {
		t.Errorf("ValidatePlacement(on-demand) errs = %v, want an error naming dry-run", errs)
	}
}

// TestExpandPlacementMode_HACriticalIsDryRun: the ha-critical preset used to
// expand to on-demand; it now expands to the one propose-only mode.
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
