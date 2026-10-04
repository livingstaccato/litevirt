// A litevirt-managed domain whose VM row is missing or tombstoned must be
// reported, and must never be destroyed automatically.
//
// Observed on the kvm003-f3 lab, 2026-09-30: a stale delete tombstoned
// claimvm on every replica while the VM kept running on node-4 (see
// stale_replica_delete_test.go). selfFence and the owner-assert both skip a
// domain with no live row as "external/manual", so nothing reported it: the
// VM ran with no record, consuming capacity nobody accounted for.
package fleet

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

type orphanScenario struct {
	c                 *Cluster
	owner, bystander  *Node
	rec               *health.Reconciler
	observed          []health.OrphanRuntime
	observedKinds     []string
	observerCallCount int
}

// newOrphanScenario: `owner` runs three domains.
//   - claimvm: litevirt's (owner-epoch metadata), its row tombstoned
//     cluster-wide by a delete served elsewhere, as on the lab;
//   - ghostvm: litevirt's, with no row anywhere;
//   - handvm: made by hand (no litevirt metadata) and reusing the name of a
//     tombstoned VM, which must not make it look like litevirt's.
func newOrphanScenario(t *testing.T) *orphanScenario {
	t.Helper()
	s := &orphanScenario{c: New(t, Options{Nodes: 2})}
	s.owner, s.bystander = s.c.Nodes[0], s.c.Nodes[1]
	ctx := context.Background()

	for _, name := range []string{"claimvm", "handvm"} {
		if err := corrosion.InsertVM(ctx, s.owner.DB, corrosion.VMRecord{
			Name: name, HostName: s.owner.Name, State: "running", Spec: `{}`,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", name, err)
		}
	}
	pumpMutations(t, s.c, s.owner, s.bystander)
	for _, name := range []string{"claimvm", "handvm"} {
		if err := corrosion.DeleteVM(ctx, s.bystander.DB, name); err != nil {
			t.Fatalf("DeleteVM %s: %v", name, err)
		}
	}
	spreadFrom(t, s.c, s.bystander)

	for _, name := range []string{"claimvm", "ghostvm", "handvm"} {
		if err := s.owner.Virt.DefineDomain(`<domain><name>` + name + `</name></domain>`); err != nil {
			t.Fatal(err)
		}
		s.owner.Virt.SetState(name, libvirtfake.StateRunning)
	}
	for _, name := range []string{"claimvm", "ghostvm"} {
		if err := s.owner.Virt.SetDomainOwnerEpoch(name, 2, true); err != nil {
			t.Fatal(err)
		}
	}

	s.rec = health.NewReconciler(s.owner.Name, t.TempDir(), s.owner.DB, s.owner.Virt)
	s.rec.SetReplicaFreshness(s.owner.DB.ReplicaCaughtUp)
	s.rec.SetOrphanRuntimeObserver(func(kind string, found []health.OrphanRuntime) {
		s.observerCallCount++
		s.observedKinds = append(s.observedKinds, kind)
		s.observed = found
	})
	return s
}

func orphanConditions(t *testing.T, n *Node, includeResolved bool) map[string]corrosion.HealthCondition {
	t.Helper()
	all, err := corrosion.ListHealthConditions(context.Background(), n.DB, includeResolved)
	if err != nil {
		t.Fatalf("%s: ListHealthConditions: %v", n.Name, err)
	}
	out := map[string]corrosion.HealthCondition{}
	for _, c := range all {
		if c.Evaluator == health.OrphanRuntimeEvaluator {
			out[c.SubjectKind+"/"+c.SubjectID] = c
		}
	}
	return out
}

func TestFleet_OrphanRuntime_ReportedNeverDestroyed(t *testing.T) {
	s := newOrphanScenario(t)
	ctx := context.Background()
	claim := "vm/claimvm@" + s.owner.Name
	ghost := "vm/ghostvm@" + s.owner.Name

	// One pass is a sighting, not a finding: a delete in flight undefines its
	// domain a moment after the tombstone lands.
	s.rec.ReconcileOnce(ctx)
	if got := orphanConditions(t, s.owner, true); len(got) != 0 {
		t.Fatalf("a single pass must not raise anything, got %v", got)
	}

	s.rec.ReconcileOnce(ctx)
	got := orphanConditions(t, s.owner, false)
	if len(got) != 2 {
		t.Fatalf("want exactly claimvm and ghostvm reported, got %v", got)
	}
	for key, row := range map[string]string{claim: "tombstoned", ghost: "missing"} {
		c, ok := got[key]
		if !ok {
			t.Errorf("%s not reported", key)
			continue
		}
		if c.Code != health.CondVMOrphanRuntime || c.Lifecycle != corrosion.ConditionConfirmed ||
			c.Severity != corrosion.SeverityWarning || len(c.Hosts) != 1 || c.Hosts[0] != s.owner.Name {
			t.Errorf("%s: condition = %+v", key, c)
		}
		var ev map[string]interface{}
		if err := json.Unmarshal([]byte(c.Evidence), &ev); err != nil {
			t.Fatalf("%s: evidence: %v", key, err)
		}
		if ev["row"] != row || ev["host"] != s.owner.Name || ev["runtime_state"] != "running" {
			t.Errorf("%s: evidence = %v, want row=%s host=%s runtime_state=running", key, ev, row, s.owner.Name)
		}
	}
	if s.observerCallCount == 0 || len(s.observed) != 2 {
		t.Errorf("metric observer saw %d orphans over %d calls, want 2", len(s.observed), s.observerCallCount)
	}

	// Report-only: every domain is still there and still running, the
	// hand-made one included.
	for _, name := range []string{"claimvm", "ghostvm", "handvm"} {
		if st, _ := s.owner.Virt.DomainState(name); st != "running" {
			t.Errorf("%s: domain state %q — an orphan report must never touch the runtime", name, st)
		}
	}

	// The condition is replicated, so an operator sees it from any node.
	spreadFrom(t, s.c, s.owner)
	if _, ok := orphanConditions(t, s.bystander, false)[claim]; !ok {
		t.Error("the bystander does not see the owner's orphan report")
	}

	// The operator reaps claimvm (the documented procedure): the next pass
	// resolves its condition, and ghostvm's stays open.
	if err := s.owner.Virt.DestroyDomain("claimvm"); err != nil {
		t.Fatal(err)
	}
	if err := s.owner.Virt.UndefineDomain("claimvm", false); err != nil {
		t.Fatal(err)
	}
	s.rec.ReconcileOnce(ctx)
	all := orphanConditions(t, s.owner, true)
	if c := all[claim]; c.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("reaped claimvm: lifecycle %q, want resolved", c.Lifecycle)
	}
	if c := all[ghost]; c.Lifecycle != corrosion.ConditionConfirmed {
		t.Errorf("ghostvm: lifecycle %q, want still confirmed", c.Lifecycle)
	}
	if len(s.observed) != 1 || s.observed[0].Name != "ghostvm" {
		t.Errorf("metric observer after the reap: %+v, want ghostvm only", s.observed)
	}
}

// A replica that has not caught up cannot tell a missing row from one it has
// not received yet, so it reports nothing — and resolves nothing.
func TestFleet_OrphanRuntime_StaleReplicaReportsNothing(t *testing.T) {
	s := newOrphanScenario(t)
	ctx := context.Background()
	s.owner.DB.MarkReplicaStale("process restarted (fleet: modelled reboot)")
	s.rec.ReconcileOnce(ctx)
	s.rec.ReconcileOnce(ctx)
	if got := orphanConditions(t, s.owner, true); len(got) != 0 {
		t.Errorf("a stale replica raised orphan conditions: %v", got)
	}
}
