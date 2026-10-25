package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/health"
)

// readyTask5Gate is a gate whose Task 5 inputs all hold: automation_v1
// latched and enforced, a founding origin, and a complete import at a
// three-voter generation. Only the later tasks' components are left.
func readyTask5Gate(mode string, voters int) *AutomationGate {
	return &AutomationGate{
		Mode:     mode,
		Enforced: func() bool { return true },
		Origin: func(context.Context) (bool, string, error) {
			return true, "", nil
		},
		Membership: func(context.Context) grpcapi.AutomationMembershipStatus {
			return grpcapi.AutomationMembershipStatus{Generation: 4, Voters: voters, ImportedVoters: voters, Imported: true}
		},
	}
}

func reasonFor(r AutomationReadiness, component string) (AutomationNotReady, bool) {
	for _, n := range r.Reasons {
		if n.Component == component {
			return n, true
		}
	}
	return AutomationNotReady{}, false
}

// Every Task 5 input holding is not activation: until Tasks 6–11 supply their
// readiness components the gate reports not ready, naming each missing one.
func TestAutomationGateFalseUntilPrerequisites(t *testing.T) {
	g := readyTask5Gate("", 3)
	r := g.Readiness(context.Background())
	if r.Ready {
		t.Fatal("automation reported ready with no Task 6–11 readiness component")
	}
	for _, c := range []string{capabilities.AutomationComponentRuntime, capabilities.AutomationComponentOrigin,
		capabilities.AutomationComponentMembership, capabilities.AutomationComponentDurability} {
		if n, ok := reasonFor(r, c); ok {
			t.Fatalf("Task 5 component %s reported not ready: %+v", c, n)
		}
	}
	for _, c := range capabilities.AutomationLaterComponents() {
		n, ok := reasonFor(r, c)
		if !ok || n.Code != "component_unavailable" || n.Detail == "" {
			t.Fatalf("later component %s: %+v (present %v), want component_unavailable with a detail", c, n, ok)
		}
	}
	// The gate is a conjunction, not a constant: with every component
	// supplied it reports ready (no such supplier exists in this build).
	g.Components = map[string]func(context.Context) (bool, string){}
	for _, c := range capabilities.AutomationLaterComponents() {
		g.Components[c] = func(context.Context) (bool, string) { return true, "" }
	}
	if r := g.Readiness(context.Background()); !r.Ready || r.Mode != capabilities.AutomationModeHAQuorum {
		t.Fatalf("every component ready: %+v", r)
	}
	g.Components[capabilities.AutomationLaterComponents()[0]] = func(context.Context) (bool, string) { return false, "not yet" }
	if r := g.Readiness(context.Background()); r.Ready {
		t.Fatal("one component not ready, gate ready")
	}
}

func TestAutomationGateHANeedsThreeDurableVoters(t *testing.T) {
	for _, tc := range []struct {
		voters int
		ok     bool
	}{{1, false}, {2, false}, {3, true}, {5, true}} {
		r := readyTask5Gate("", tc.voters).Readiness(context.Background())
		n, found := reasonFor(r, capabilities.AutomationComponentMembership)
		if tc.ok && found {
			t.Fatalf("%d voters: membership reported %+v", tc.voters, n)
		}
		if !tc.ok && (!found || n.Code != "ha_needs_three_voters") {
			t.Fatalf("%d voters: membership %+v (present %v), want ha_needs_three_voters", tc.voters, n, found)
		}
	}
	// Three members, but only two hold a carried import: the real quorum has
	// no fault tolerance.
	g2 := readyTask5Gate("", 3)
	g2.Membership = func(context.Context) grpcapi.AutomationMembershipStatus {
		return grpcapi.AutomationMembershipStatus{Generation: 4, Voters: 3, ImportedVoters: 2, Imported: true}
	}
	if n, ok := reasonFor(g2.Readiness(context.Background()), capabilities.AutomationComponentMembership); !ok || n.Code != "ha_needs_three_imported_voters" {
		t.Fatalf("two imported voters of three: %+v (present %v)", n, ok)
	}
	// A three-voter generation whose import is incomplete is not durable.
	g := readyTask5Gate("", 3)
	g.Membership = func(context.Context) grpcapi.AutomationMembershipStatus {
		return grpcapi.AutomationMembershipStatus{Generation: 4, Voters: 3, Code: "automation_import_absent", Detail: "no import"}
	}
	if n, ok := reasonFor(g.Readiness(context.Background()), capabilities.AutomationComponentMembership); !ok || n.Code != "automation_import_absent" {
		t.Fatalf("absent import: %+v", n)
	}
}

func TestAutomationGateDevelopmentNeedsExplicitOptIn(t *testing.T) {
	// The state a one-host cluster actually reaches: one voter, and no
	// automation authority (storage requires three members).
	single := func(mode string) *AutomationGate {
		g := readyTask5Gate(mode, 1)
		g.Membership = func(context.Context) grpcapi.AutomationMembershipStatus {
			return grpcapi.AutomationMembershipStatus{Generation: 1, Voters: 1, Code: "automation_import_absent", Detail: "no authority"}
		}
		return g
	}
	// No opt-in: the HA default refuses it.
	r := single("").Readiness(context.Background())
	if r.Mode != capabilities.AutomationModeHAQuorum {
		t.Fatalf("default mode %q, want %q", r.Mode, capabilities.AutomationModeHAQuorum)
	}
	if n, ok := reasonFor(r, capabilities.AutomationComponentMembership); !ok || n.Code != "ha_needs_three_voters" {
		t.Fatalf("single voter without opt-in: %+v", n)
	}
	// Explicitly opted in: the mode is reported, and the gate says plainly
	// that this build cannot serve it, rather than an HA reason.
	r = single(capabilities.AutomationModeSingleHostDevelopment).Readiness(context.Background())
	if r.Mode != capabilities.AutomationModeSingleHostDevelopment || r.Ready {
		t.Fatalf("opted-in: %+v", r)
	}
	if n, ok := reasonFor(r, capabilities.AutomationComponentDurability); !ok || n.Code != "development_mode_unsupported" {
		t.Fatalf("single-host development: %+v (present %v), want development_mode_unsupported", n, ok)
	}
	if n, ok := reasonFor(r, capabilities.AutomationComponentMembership); ok && n.Code == "ha_needs_three_voters" {
		t.Fatal("explicit single-host development still held to the HA voter rule")
	}
	// An unknown mode is a config error, never a silent default.
	if err := validateAutomationConfig(AutomationConfig{DurabilityMode: "fast"}); err == nil {
		t.Fatal("unknown durability mode accepted")
	}
	for _, ok := range []string{"", capabilities.AutomationModeHAQuorum, capabilities.AutomationModeSingleHostDevelopment} {
		if err := validateAutomationConfig(AutomationConfig{DurabilityMode: ok}); err != nil {
			t.Fatalf("mode %q refused: %v", ok, err)
		}
	}
}

// A host on a build without automation (or with the flag off) holds the
// automation_v1 latch off; the gate refuses on that alone.
func TestAutomationVoterRuntimeGuardRefusesOldHost(t *testing.T) {
	g := readyTask5Gate("", 3)
	g.Enforced = func() bool { return false }
	n, ok := reasonFor(g.Readiness(context.Background()), capabilities.AutomationComponentRuntime)
	if !ok || n.Code != "automation_v1_not_enforced" {
		t.Fatalf("runtime: %+v (present %v), want automation_v1_not_enforced", n, ok)
	}
	g.Enforced = nil
	if _, ok := reasonFor(g.Readiness(context.Background()), capabilities.AutomationComponentRuntime); !ok {
		t.Fatal("an unwired latch reader counted as enforced")
	}
}

// A cluster without the founding origin record — one founded before this
// build, or whose founder never recorded it — is not automation-ready; the
// gate does not adopt unknown older state.
func TestAutomationGateRefusesClusterWithoutOrigin(t *testing.T) {
	g := readyTask5Gate("", 3)
	g.Origin = func(context.Context) (bool, string, error) { return false, "no origin row", nil }
	if n, ok := reasonFor(g.Readiness(context.Background()), capabilities.AutomationComponentOrigin); !ok || n.Code != "origin_absent" {
		t.Fatalf("origin: %+v", n)
	}
	g.Origin = nil
	if _, ok := reasonFor(g.Readiness(context.Background()), capabilities.AutomationComponentOrigin); !ok {
		t.Fatal("an unwired origin reader counted as present")
	}
}

// What this pins: once automation_v1 has latched here, a rollback to any build
// that does not know the token quarantines, unconditionally — its marker
// carries no safe_if_unused rule, so no reading of the recorded release-feature
// uses (empty, failing, or naming an automation feature) turns it into a mere
// probation. It does not model managed resources: they can only exist after
// the latch, so "quarantine on every rollback below the latch" covers "after
// managed resources exist" by being stronger.
func TestAutomationVoterRollbackGuardQuarantinesBelowTheLatch(t *testing.T) {
	if !capabilities.Has(capabilities.All(), capabilities.AutomationV1) {
		t.Fatal("automation_v1 is not a declared token: a latched marker would quarantine this very build")
	}
	content := capabilities.MarkerContent(capabilities.AutomationV1)
	// What an older build sees: a marker it has no token for, with
	// automation_v1's exact content.
	const older = "automation_v1_as_seen_by_an_older_build"
	for _, uses := range []struct {
		name string
		fn   func() ([]corrosion.ReleaseFeatureUse, error)
	}{
		{"nothing used", func() ([]corrosion.ReleaseFeatureUse, error) { return nil, nil }},
		{"uses unreadable", func() ([]corrosion.ReleaseFeatureUse, error) { return nil, os.ErrPermission }},
		{"automation used", func() ([]corrosion.ReleaseFeatureUse, error) {
			return []corrosion.ReleaseFeatureUse{{Token: older, Feature: string(capabilities.FeatureAutomationStream)}}, nil
		}},
	} {
		t.Run(uses.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(health.ActivationMarkerPath(dir, older), content, 0o600); err != nil {
				t.Fatal(err)
			}
			q, probation := preflightRollback(dir, uses.fn)
			if len(q) != 1 || q[0] != older || len(probation) != 0 {
				t.Fatalf("rollback below automation_v1: quarantine %v probation %v, want quarantine of the token", q, probation)
			}
			// This build, which knows the token, is not a rollback.
			if err := os.WriteFile(health.ActivationMarkerPath(dir, capabilities.AutomationV1), content, 0o600); err != nil {
				t.Fatal(err)
			}
			if q, _ := preflightRollback(dir, uses.fn); len(q) != 1 || q[0] != older {
				t.Fatalf("this build quarantined on its own automation_v1 marker: %v", q)
			}
		})
	}
}

// The founding flow records the origin: `lv host init`'s founder marker makes
// seedAdminUser write the automation origin decision beside the admin mint, and
// a joiner (no marker) writes none.
func TestAutomationOriginWrittenByFounding(t *testing.T) {
	ctx := context.Background()
	for _, founding := range []bool{true, false} {
		dir := t.TempDir()
		if founding {
			if err := os.WriteFile(filepath.Join(dir, genesisMarkerName), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		d := &Daemon{cfg: &Config{HostName: "n1", DataDir: dir}, db: newHostTestClient(t),
			adminPasswordPath: filepath.Join(dir, "admin-password")}
		if err := d.seedAdminUser(ctx); err != nil {
			t.Fatal(err)
		}
		_, err := os.Stat(filepath.Join(dir, automationOriginName))
		if founding && err != nil {
			t.Fatalf("founder wrote no automation origin decision: %v", err)
		}
		if !founding && err == nil {
			t.Fatal("a non-founding node wrote an automation origin decision")
		}
	}
}
