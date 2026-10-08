package compose

import (
	"bytes"
	"log/slog"
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

// TestParse_RebalanceModeOnDemandIsADryRunAlias: on-demand behaved exactly
// like dry-run and was folded into it. A compose file that still names it is
// not refused: it parses, the mode is stored as dry-run, and a WARN says
// on-demand is an alias of dry-run.
//
// Mutation: restore the refusal in rebalanceModeProblem — the parse fails.
// Mutation: drop the rewrite — the stored mode stays on-demand.
// Mutation: drop the WARN — the log assertion fails.
func TestParse_RebalanceModeOnDemandIsADryRunAlias(t *testing.T) {
	logs := captureComposeSlog(t)
	f, err := ParseBytes([]byte(rebalanceModeYAML("on-demand")))
	if err != nil {
		t.Fatalf("placement.rebalance.mode: on-demand was refused: %v", err)
	}
	vm := f.VMs["web"]
	if vm.Placement == nil || vm.Placement.Rebalance == nil || vm.Placement.Rebalance.Mode != "dry-run" {
		t.Fatalf("placement = %+v, want rebalance.mode dry-run", vm.Placement)
	}
	out := logs.String()
	for _, want := range []string{"level=WARN", "on-demand", "alias", "dry-run"} {
		if !strings.Contains(out, want) {
			t.Errorf("log does not mention %q:\n%s", want, out)
		}
	}
}

// A file that already says dry-run logs no alias WARN.
func TestParse_RebalanceModeDryRunNoAliasWarn(t *testing.T) {
	logs := captureComposeSlog(t)
	if _, err := ParseBytes([]byte(rebalanceModeYAML("dry-run"))); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "alias") {
		t.Errorf("alias WARN for dry-run:\n%s", logs.String())
	}
}

func captureComposeSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
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
	for _, mode := range []string{"off", "dry-run", "auto", "on-demand"} {
		if _, err := ParseBytes([]byte(rebalanceModeYAML(mode))); err != nil {
			t.Errorf("mode %q rejected: %v", mode, err)
		}
	}
}

// ValidatePlacement accepts on-demand with a warning naming dry-run, never an
// error.
func TestValidatePlacement_OnDemandIsAnAlias(t *testing.T) {
	warns, errs := ValidatePlacement(&PlacementDef{Rebalance: &RebalanceDef{Mode: "on-demand"}})
	if len(errs) != 0 {
		t.Errorf("ValidatePlacement(on-demand) errs = %v, want none", errs)
	}
	if !strings.Contains(strings.Join(warns, ";"), "dry-run") {
		t.Errorf("ValidatePlacement(on-demand) warnings = %v, want one naming dry-run", warns)
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
