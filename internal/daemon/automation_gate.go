package daemon

import (
	"context"
	"fmt"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// AutomationConfig is the `automation:` config block.
type AutomationConfig struct {
	// DurabilityMode is the durability the automation service reports:
	// "ha-quorum" (the default, also when empty) needs at least three durable
	// voters with a complete import; "single-host-development" is an explicit
	// opt-in for a one-host cluster, matched by the SDK's own opt-in.
	DurabilityMode string `yaml:"durability_mode,omitempty"`
}

func validateAutomationConfig(c AutomationConfig) error {
	switch c.DurabilityMode {
	case "", capabilities.AutomationModeHAQuorum, capabilities.AutomationModeSingleHostDevelopment:
		return nil
	}
	return fmt.Errorf("automation.durability_mode %q: want %s or %s", c.DurabilityMode,
		capabilities.AutomationModeHAQuorum, capabilities.AutomationModeSingleHostDevelopment)
}

// AutomationNotReady is one unmet readiness component.
type AutomationNotReady struct {
	Component string // capabilities.AutomationComponent*
	Code      string // stable machine-readable reason
	Detail    string
}

// AutomationReadiness is the gate's answer. Ready is true only when
// capabilities.AutomationActive holds for the components reported here.
type AutomationReadiness struct {
	Ready   bool
	Mode    string
	Reasons []AutomationNotReady
}

// AutomationGate decides whether this node may enable the automation service.
// Each input is a reader; an unwired reader is not ready. The readiness
// components later tasks own come from Components; this build registers none,
// so the gate reports not ready, naming each one missing.
type AutomationGate struct {
	// Mode is automation.durability_mode ("" = ha-quorum).
	Mode string
	// Enforced: automation_v1 latched cluster-wide and this node's
	// enforcement.automation on.
	Enforced func() bool
	// Origin reports the cluster's founding origin record (present, detail).
	Origin func(context.Context) (bool, string, error)
	// Membership is this voter's membership standing.
	Membership func(context.Context) grpcapi.AutomationMembershipStatus
	// Components are the later tasks' readiness components, by name.
	Components map[string]func(context.Context) (bool, string)
}

// Readiness evaluates every component. It never short-circuits, so the
// reasons name everything still missing.
func (g *AutomationGate) Readiness(ctx context.Context) AutomationReadiness {
	r := AutomationReadiness{Mode: capabilities.AutomationModeHAQuorum}
	if g.Mode != "" {
		r.Mode = g.Mode
	}
	ready := map[string]bool{}
	fail := func(component, code, detail string) {
		r.Reasons = append(r.Reasons, AutomationNotReady{Component: component, Code: code, Detail: detail})
	}

	latched := g.Enforced != nil && g.Enforced()
	if latched {
		ready[capabilities.AutomationComponentRuntime] = true
	} else {
		fail(capabilities.AutomationComponentRuntime, "automation_v1_not_enforced",
			"automation_v1 has not latched with enforcement.automation on here: a host runs a build without "+
				"automation, or has the flag off")
	}

	switch {
	case g.Origin == nil:
		fail(capabilities.AutomationComponentOrigin, "origin_unavailable", "no origin reader")
	default:
		have, detail, err := g.Origin(ctx)
		switch {
		case err != nil:
			fail(capabilities.AutomationComponentOrigin, "origin_unreadable", err.Error())
		case !have:
			if detail == "" {
				detail = "this cluster has no automation origin record: it was not founded by `lv host init` on a " +
					"build with automation"
			}
			fail(capabilities.AutomationComponentOrigin, "origin_absent", detail)
		default:
			ready[capabilities.AutomationComponentOrigin] = true
		}
	}

	var m grpcapi.AutomationMembershipStatus
	if g.Membership == nil {
		m.Code, m.Detail = "membership_unavailable", "no membership reader"
	} else {
		m = g.Membership(ctx)
	}
	dev := r.Mode == capabilities.AutomationModeSingleHostDevelopment
	switch {
	case r.Mode != capabilities.AutomationModeHAQuorum && !dev:
		fail(capabilities.AutomationComponentDurability, "unknown_durability_mode", r.Mode)
	case dev && m.Voters != 1:
		fail(capabilities.AutomationComponentDurability, "development_needs_single_host",
			fmt.Sprintf("single-host development needs exactly one voter, the adopted generation has %d", m.Voters))
	case dev:
		// Automation authority needs an electorate of three in storage, so a
		// one-voter cluster never holds it; single-host storage authority is
		// not built.
		fail(capabilities.AutomationComponentDurability, "development_mode_unsupported",
			"this build cannot serve single-host development: automation authority needs at least three voters")
	default:
		ready[capabilities.AutomationComponentDurability] = true
	}
	switch {
	case !dev && m.Voters < 3:
		fail(capabilities.AutomationComponentMembership, "ha_needs_three_voters",
			fmt.Sprintf("ha-quorum needs at least three durable voters, the adopted generation %d has %d",
				m.Generation, m.Voters))
	case m.Code != "":
		fail(capabilities.AutomationComponentMembership, m.Code, m.Detail)
	case !m.Imported:
		fail(capabilities.AutomationComponentMembership, "automation_import_absent", m.Detail)
	case !dev && m.ImportedVoters < 3:
		// Members are not durable voters: a member that holds no import
		// refuses every automation vote. Peers' authority rows are not
		// readable here, so only signatures this replica anchored at the
		// adopted generation count; until three exist it fails closed.
		fail(capabilities.AutomationComponentMembership, "ha_needs_three_imported_voters",
			fmt.Sprintf("ha-quorum needs three voters of generation %d with a complete import; %d are evidenced by "+
				"their signatures there", m.Generation, m.ImportedVoters))
	default:
		ready[capabilities.AutomationComponentMembership] = true
	}

	for _, c := range capabilities.AutomationLaterComponents() {
		fn := g.Components[c]
		if fn == nil {
			fail(c, "component_unavailable", "this build has no "+c+" readiness component")
			continue
		}
		if ok, detail := fn(ctx); ok {
			ready[c] = true
		} else {
			fail(c, "component_not_ready", detail)
		}
	}
	r.Ready = capabilities.AutomationActive(latched, ready)
	return r
}
