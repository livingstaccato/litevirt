package health

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A start is held for an unresolved move only when all three hold: the
// domain here is paused, vm.migration_unresolved is open, and it names THIS
// host as the move's target. A shut-off domain, a move toward another host,
// a resolved condition or none at all leave the start as it was.
//
// What cannot be read holds (fail closed): the domain's state while the
// condition names this host, and the condition's evidence. A condition that
// names no target is taken to name this host.
//
// Mutations: drop the target check — "toward another host" red; hold any
// existing domain (drop the paused check) — "shut off" red; ignore the
// lifecycle (OpenMigrationUnresolved returns open for a resolved row) —
// "resolved" red; fail open on a state-read error — "state unreadable,
// toward here" red; fail open on unparsable evidence — "evidence unreadable"
// red.
func TestUnresolvedMoveHolds(t *testing.T) {
	for _, tc := range []struct {
		name      string
		state     libvirtfake.State
		target    string
		lifecycle string // "" no condition
		want      bool
		failState bool   // the domain's state cannot be read
		evidence  string // raw evidence instead of one naming target
	}{
		{"paused, toward here", libvirtfake.StatePaused, "node-a", corrosion.ConditionObserved, true, false, ""},
		{"paused, toward another host", libvirtfake.StatePaused, "node-c", corrosion.ConditionObserved, false, false, ""},
		{"paused, resolved", libvirtfake.StatePaused, "node-a", corrosion.ConditionResolved, false, false, ""},
		{"paused, no condition", libvirtfake.StatePaused, "node-a", "", false, false, ""},
		{"shut off, toward here", libvirtfake.StateShutdown, "node-a", corrosion.ConditionObserved, false, false, ""},
		{"running, toward here", libvirtfake.StateRunning, "node-a", corrosion.ConditionObserved, false, false, ""},
		// Fail closed: what cannot be read keeps the domain.
		{"state unreadable, toward here", libvirtfake.StatePaused, "node-a", corrosion.ConditionObserved, true, true, ""},
		{"state unreadable, toward another host", libvirtfake.StatePaused, "node-c", corrosion.ConditionObserved, false, true, ""},
		{"state unreadable, no condition", libvirtfake.StatePaused, "node-a", "", false, true, ""},
		{"evidence unreadable", libvirtfake.StateShutdown, "", corrosion.ConditionObserved, true, false, "{not json"},
		{"paused, no target named", libvirtfake.StatePaused, "", corrosion.ConditionObserved, true, false, ""},
		{"shut off, no target named", libvirtfake.StateShutdown, "", corrosion.ConditionObserved, false, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := testReconcilerDB(t)
			fake := libvirtfake.New()
			fake.SetState("mg1", tc.state)
			if tc.failState {
				fake.FailDomainStateReason = func(string) error { return errors.New("libvirt: no answer") }
			}
			if tc.lifecycle != "" {
				ev := `{"source":"node-b","target":"` + tc.target + `"}`
				if tc.evidence != "" {
					ev = tc.evidence
				}
				if err := corrosion.UpsertHealthCondition(ctx, db, corrosion.HealthCondition{
					Evaluator: corrosion.DrainEvaluator, Code: corrosion.CondMigrationUnresolved,
					SubjectKind: "vm", SubjectID: "mg1", Lifecycle: tc.lifecycle, Severity: corrosion.SeverityCritical,
					Evidence: ev,
				}); err != nil {
					t.Fatal(err)
				}
			}
			r := NewReconciler("node-a", t.TempDir(), db, fake)
			if got, why := r.unresolvedMoveHolds(ctx, "mg1"); got != tc.want {
				t.Fatalf("held = %v (%s), want %v", got, why, tc.want)
			}
		})
	}
}
