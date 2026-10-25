package capabilities

// AutomationV1 is the capability token of the automation service (the F1
// plan's `automation-v1`; repository tokens are snake_case).
//
// It is advertised CONDITIONALLY, on enforcement.automation (default off), and
// withheld while the flag is off. Where is the guarantee enforced? At every
// voter: an automation command is chosen by a voter majority, and each voter
// relies on every peer refusing to vote until its own adoption carried the
// complete certified prefix and claim state across each membership change
// (grpcapi automation_membership.go). A flag-off or older-build peer would vote
// from whatever its replica holds — not merely permissive, but a second,
// incomplete electorate — so the latch has to mean build AND config
// uniformity. It is ReplicationGated: a host parked in maintenance on an older
// build may still run a managed VM, so it holds the latch off.
//
// It carries no rollback rule, so a rollback below it always quarantines,
// whether or not a managed resource exists yet.
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
