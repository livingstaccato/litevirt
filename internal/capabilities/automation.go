package capabilities

// AutomationV1 is the capability token of the automation service (the F1
// plan's `automation-v1`; repository tokens are snake_case).
//
// It is advertised UNCONDITIONALLY: it says this build keeps automation
// authority only across an adoption that imported the old majority's state,
// and refuses automation votes without it (corrosion admitAutomationTx) — a
// fact about the binary, enforced at every voter whatever its flag says, so
// no node relies on a peer's enforcement.automation. That flag (default off)
// decides only whether this node enforces automation_v1 (tokenEnabled,
// not_enforcing) and is one input of the readiness gate. It is
// ReplicationGated: a host parked in maintenance on an older build may still
// run a managed VM, so it holds the latch off.
//
// Because it latches on every cluster, its marker carries safe_if_unused
// (release_features.go): a rollback below it proceeds, on release probation,
// while no use of its feature automation_state is recorded, and quarantines
// once one is. Every first write of automation state must record that use
// through WithFeature before it writes; no writer in this build creates
// automation state.
//
// Holding the token is not activation. The service is enabled only when the
// latch holds AND every readiness component reports ready (AutomationActive);
// a token, a flag or a host label alone enables nothing.
const AutomationV1 = "automation_v1"

// The durability modes automation reports. HA is the default; single-host
// development is explicit on both ends: the daemon's
// automation.durability_mode, and the SDK's own opt-in.
const (
	AutomationModeHAQuorum              = "ha-quorum"
	AutomationModeSingleHostDevelopment = "single-host-development"
)

// The readiness components automation activation requires. The first four are
// Task 5's: the runtime (automation_v1 latched and enforced here), the
// cluster's founding origin, this voter's membership (adopted generation and a
// complete import) and the durability mode. The rest are supplied by later
// tasks; until a supplier exists the gate reports each as unavailable.
const (
	AutomationComponentRuntime    = "runtime"
	AutomationComponentOrigin     = "origin"
	AutomationComponentMembership = "membership"
	AutomationComponentDurability = "durability_mode"

	AutomationComponentIdentity   = "identity_migration" // Task 6
	AutomationComponentCustody    = "secret_custody"     // Task 7
	AutomationComponentPublic     = "public_service"     // Task 8
	AutomationComponentExecution  = "vm_execution"       // Task 10
	AutomationComponentRetirement = "retirement_guards"  // Task 11
)

var automationLaterComponents = []string{
	AutomationComponentIdentity,
	AutomationComponentCustody,
	AutomationComponentPublic,
	AutomationComponentExecution,
	AutomationComponentRetirement,
}

// AutomationLaterComponents is the readiness components supplied by tasks
// after Task 5, in order.
func AutomationLaterComponents() []string {
	return append([]string(nil), automationLaterComponents...)
}

// AutomationComponents is every readiness component activation requires.
func AutomationComponents() []string {
	return append([]string{AutomationComponentRuntime, AutomationComponentOrigin,
		AutomationComponentMembership, AutomationComponentDurability}, automationLaterComponents...)
}

// AutomationActive reports whether the automation service may be enabled:
// the token latched (and enforced here) AND every component in
// AutomationComponents reported ready. A missing entry is not ready.
func AutomationActive(latched bool, ready map[string]bool) bool {
	if !latched {
		return false
	}
	for _, c := range AutomationComponents() {
		if !ready[c] {
			return false
		}
	}
	return true
}
