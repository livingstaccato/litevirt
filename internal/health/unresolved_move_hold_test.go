package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A start is held for an unresolved move only when all three hold: the
// domain here is paused, vm.migration_unresolved is open, and it names THIS
// host as the move's target. A shut-off domain, a move toward another host,
// a resolved condition or none at all leave the start as it was.
//
// Mutations: drop the target check — "toward another host" red; hold any
// existing domain (drop the paused check) — "shut off" red; ignore the
// lifecycle (OpenMigrationUnresolved returns open for a resolved row) —
// "resolved" red.
func TestUnresolvedMoveHolds(t *testing.T) {
	for _, tc := range []struct {
		name      string
		state     libvirtfake.State
		target    string
		lifecycle string // "" no condition
		want      bool
	}{
		{"paused, toward here", libvirtfake.StatePaused, "node-a", corrosion.ConditionObserved, true},
		{"paused, toward another host", libvirtfake.StatePaused, "node-c", corrosion.ConditionObserved, false},
		{"paused, resolved", libvirtfake.StatePaused, "node-a", corrosion.ConditionResolved, false},
		{"paused, no condition", libvirtfake.StatePaused, "node-a", "", false},
		{"shut off, toward here", libvirtfake.StateShutdown, "node-a", corrosion.ConditionObserved, false},
		{"running, toward here", libvirtfake.StateRunning, "node-a", corrosion.ConditionObserved, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := testReconcilerDB(t)
			fake := libvirtfake.New()
			fake.SetState("mg1", tc.state)
			if tc.lifecycle != "" {
				if err := corrosion.UpsertHealthCondition(ctx, db, corrosion.HealthCondition{
					Evaluator: corrosion.DrainEvaluator, Code: corrosion.CondMigrationUnresolved,
					SubjectKind: "vm", SubjectID: "mg1", Lifecycle: tc.lifecycle, Severity: corrosion.SeverityCritical,
					Evidence: `{"source":"node-b","target":"` + tc.target + `"}`,
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
