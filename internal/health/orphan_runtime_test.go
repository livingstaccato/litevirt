package health

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

func ctOrphanConditions(t *testing.T, db *corrosion.Client, includeResolved bool) map[string]corrosion.HealthCondition {
	t.Helper()
	all, err := corrosion.ListHealthConditions(context.Background(), db, includeResolved)
	if err != nil {
		t.Fatalf("ListHealthConditions: %v", err)
	}
	out := map[string]corrosion.HealthCondition{}
	for _, c := range all {
		if c.Evaluator == OrphanRuntimeEvaluator {
			out[c.SubjectKind+"/"+c.SubjectID] = c
		}
	}
	return out
}

// The container half of the orphan-runtime report. node1 runs:
//   - gone: litevirt's (owner-epoch marker), no row anywhere;
//   - tomb: litevirt's, its only row tombstoned;
//   - moved: litevirt's, with a live row on node2 — an ownership question for
//     the re-key, not an orphan;
//   - handct: made by hand (no marker), no row.
func TestContainerOrphanRuntime_ReportsOnlyLitevirtContainersWithNoLiveRow(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	root := t.TempDir()
	rt := newFakeCtRuntime()
	for _, n := range []string{"gone", "tomb", "moved", "handct"} {
		rt.states[n] = lxc.StateRunning
	}
	for _, n := range []string{"gone", "tomb", "moved"} {
		if err := WriteContainerOwnerEpochMarker(root, n, 3); err != nil {
			t.Fatal(err)
		}
	}
	insertCt(t, db, corrosion.ContainerRecord{HostName: "node2", Name: "moved", State: "running"})
	insertCt(t, db, corrosion.ContainerRecord{HostName: "node1", Name: "tomb", State: "running"})
	if err := corrosion.DeleteContainer(ctx, db, "node1", "tomb"); err != nil {
		t.Fatalf("DeleteContainer: %v", err)
	}

	c := NewContainerChecker("node1", db, rt)
	c.SetContainersRoot(root)
	var observed []OrphanRuntime
	c.SetOrphanRuntimeObserver(func(kind string, found []OrphanRuntime) {
		if kind != "ct" {
			t.Errorf("observer kind %q, want ct", kind)
		}
		observed = found
	})

	c.SweepOnce(ctx)
	if got := ctOrphanConditions(t, db, true); len(got) != 0 {
		t.Fatalf("one sweep must not report anything, got %v", got)
	}
	c.SweepOnce(ctx)
	got := ctOrphanConditions(t, db, false)
	if len(got) != 2 {
		t.Fatalf("want gone and tomb reported, got %v", got)
	}
	for key, row := range map[string]string{"container/gone@node1": "missing", "container/tomb@node1": "tombstoned"} {
		cond, ok := got[key]
		if !ok {
			t.Errorf("%s not reported", key)
			continue
		}
		var ev map[string]interface{}
		if err := json.Unmarshal([]byte(cond.Evidence), &ev); err != nil {
			t.Fatal(err)
		}
		if cond.Code != CondCTOrphanRuntime || ev["row"] != row || ev["runtime_state"] != "running" {
			t.Errorf("%s: code=%s evidence=%v, want %s row=%s", key, cond.Code, ev, CondCTOrphanRuntime, row)
		}
	}
	if len(observed) != 2 {
		t.Errorf("observer saw %v, want 2 orphans", observed)
	}
	for n, st := range rt.states {
		if st != lxc.StateRunning {
			t.Errorf("%s: state %v — the report must never touch the runtime", n, st)
		}
	}
}
