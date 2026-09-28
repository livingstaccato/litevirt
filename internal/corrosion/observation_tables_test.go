package corrosion

import (
	"slices"
	"testing"
)

// Every observation table is a public anti-entropy table. One that is not in
// tableNames — renamed, or moved to the sensitive lane — would make the
// deferral silently apply to nothing, or to a table whose repair it was never
// argued for.
func TestObservationTables_ArePublicAntiEntropyTables(t *testing.T) {
	for name := range observationTables {
		if !slices.Contains(tableNames, name) {
			t.Errorf("observation table %q is not in tableNames", name)
		}
		if slices.Contains(sensitiveTableNames, name) {
			t.Errorf("observation table %q is on the sensitive lane", name)
		}
	}
}

// The classification is the argued list and nothing more. A table added here
// has its repair deferred by minutes, so it needs the argument in
// observation_tables.go first; this pins the set so adding one is a visible
// decision, not a one-word diff.
func TestObservationTables_AreExactlyTheArguedSet(t *testing.T) {
	want := []string{"health_evaluator_status", "host_capacity_observations", "host_health"}
	var got []string
	for name := range observationTables {
		got = append(got, name)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("observationTables = %v, want %v", got, want)
	}
}

func TestSplitObservations_KeepsOrderAndPartitions(t *testing.T) {
	control, obs := splitObservations([]string{"vms", "host_health", "stacks", "host_capacity_observations"})
	if !slices.Equal(control, []string{"vms", "stacks"}) {
		t.Errorf("control = %v", control)
	}
	if !slices.Equal(obs, []string{"host_health", "host_capacity_observations"}) {
		t.Errorf("observations = %v", obs)
	}
}
