package capabilities

import "testing"

// automation_v1 is the capability "label" for automation. Holding it — the
// token latched cluster-wide, this node's flag on — proves a uniform build and
// configuration and nothing more: the service is enabled only when every
// readiness component is also reported ready.
func TestAutomationCapabilityLabelAloneDoesNotEnable(t *testing.T) {
	if !Has(All(), AutomationV1) || !Has(Supported(), AutomationV1) {
		t.Fatal("automation_v1 is not a declared, supported token")
	}
	if Mandatory(AutomationV1) {
		t.Fatal("automation_v1 is mandatory: it would latch with no operator opt-in")
	}
	if !ReplicationGated(AutomationV1) {
		t.Fatal("automation_v1 is not replication-gated: a parked host on an older build would not hold it off")
	}
	if RollbackRule(AutomationV1) != "" {
		t.Fatal("automation_v1 carries a rollback rule: a rollback below it could start without quarantine")
	}
	if AutomationActive(true, nil) {
		t.Fatal("the latched label alone enabled automation")
	}
	all := map[string]bool{}
	for _, c := range AutomationComponents() {
		all[c] = true
	}
	if !AutomationActive(true, all) {
		t.Fatal("latched with every component ready, still not active")
	}
	if AutomationActive(false, all) {
		t.Fatal("every component ready without the latch enabled automation")
	}
	for c := range all {
		missing := map[string]bool{}
		for k := range all {
			missing[k] = k != c
		}
		if AutomationActive(true, missing) {
			t.Fatalf("enabled with component %s not ready", c)
		}
	}
	for _, c := range AutomationLaterComponents() {
		if !all[c] {
			t.Fatalf("later component %s is not required for activation", c)
		}
	}
	if len(AutomationComponents()) != len(AutomationLaterComponents())+4 {
		t.Fatalf("components %v: want the four Task 5 components plus the later ones", AutomationComponents())
	}
}
