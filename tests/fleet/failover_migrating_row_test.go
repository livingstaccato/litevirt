// Fleet scenarios: failover of a host whose VM row is still `migrating`
// (lab2-diskfull-rca.md, S1).
//
// A live migration cuts over in libvirt — the guest now runs on the target —
// and the source's daemon dies before the ownership commit lands. The row
// still names the source, `migrating`, with the target in its detail. The
// source is then judged failed and fenced. Recovery must not start the guest
// anywhere while it may run on the target: that would be two running copies
// of one VM. The coordinator asks the target first (failover's
// SettleMigratingRow):
//
//   - the target runs it: the row is re-pointed there, nothing is started;
//   - the target has no domain of it: recovered as any running VM is;
//   - anything else (a paused domain, no answer): held, with
//     vm.migration_unresolved raised for an operator.
package fleet

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// migratingRowFleet is three hosts: a (a survivor that could take the VM),
// b (the migration's target) and victim (the migration's source, whose
// daemon died before the ownership commit). mg1's row names victim,
// `migrating` toward b, and b's libvirt holds mg1 in targetState ("" for no
// domain at all). rv1 is an ordinary running VM on victim with the same
// policy: the control that recovery did run.
func migratingRowFleet(t *testing.T, clock *VirtualClock, claims bool, targetState libvirtfake.State) (c *Cluster, a, b, victim *Node) {
	t.Helper()
	setup := func(_ *Cluster, a, b, victim *Node) {
		ctx := context.Background()
		if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
			Name: "mg1", HostName: victim.Name, Spec: `{"on_host_failure":"restart-any"}`,
			State: "migrating", StateDetail: "→ " + b.Name,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM mg1: %v", err)
		}
		insertVM(t, a, "rv1", victim.Name)
		if targetState != "" {
			b.Virt.SetState("mg1", targetState)
		}
	}
	if claims {
		return claimFleetWith(t, clock, 1701, setup)
	}
	c = New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 1701})
	a, b, victim = c.Nodes[0], c.Nodes[1], c.Nodes[2]
	setup(c, a, b, victim)
	c.WaitConverged(t, convergeTimeout)
	c.Kill(victim)
	c.SetLinkFaultBoth(a, b, slowLink)
	PublishHealth(t, a, victim.Name, 5, clock.Now())
	PublishHealth(t, b, victim.Name, 5, clock.Now())
	c.WaitConverged(t, convergeTimeout, a, b)
	return c, a, b, victim
}

// runRecovery runs a's coordinator and both survivors' reconcilers for
// enough cycles that recovery has acted on everything it will act on.
func runRecovery(t *testing.T, c *Cluster, clock *VirtualClock, claims bool, a, b *Node) *Coordinators {
	t.Helper()
	ctx := context.Background()
	cs := c.NewCoordinators(clock)
	if claims {
		cs.ByNode[a.Name].Gate = quorateGate{}
	}
	for i := 0; i < 4; i++ {
		cs.Tick(ctx, a)
		c.WaitConverged(t, convergeTimeout, a, b)
		for _, n := range []*Node{a, b} {
			var rec *health.Reconciler
			if claims {
				rec = claimReconciler(t, n)
			} else {
				rec = health.NewReconciler(n.Name, t.TempDir(), n.DB, n.Virt)
			}
			rec.ReconcileOnce(ctx)
		}
		c.WaitConverged(t, convergeTimeout, a, b)
		clock.Advance(contentionPoll)
	}
	if len(cs.Fences()) == 0 {
		t.Fatalf("victim was never fenced; without a fence there is no recovery and this proves nothing")
	}
	return cs
}

// assertControlRecovered: rv1, on the victim with mg1's policy, was
// recovered off it and runs on exactly one survivor — recovery did run.
func assertControlRecovered(t *testing.T, c *Cluster, a, victim *Node) {
	t.Helper()
	if rv := vmOn(t, a, "rv1"); rv.HostName == victim.Name {
		t.Fatalf("the control rv1 was not recovered (%+v): the scenario never reached recovery", rv)
	}
	if on := runningOn(c, "rv1"); len(on) != 1 {
		t.Fatalf("the control rv1 runs on %v, want exactly one survivor", on)
	}
}

// mg1Views is each survivor's row and libvirt view of mg1, for a failure.
func mg1Views(t *testing.T, nodes ...*Node) string {
	t.Helper()
	var views []string
	for _, n := range nodes {
		vm := vmOn(t, n, "mg1")
		st, _ := n.Virt.DomainState("mg1")
		views = append(views, fmt.Sprintf("%s: row host=%s state=%s detail=%q proof=%q; libvirt=%q",
			n.Name, vm.HostName, vm.State, vm.StateDetail, vm.PendingActionID, st))
	}
	return strings.Join(views, "\n  ")
}

// migrationUnresolvedOpen reports whether n's replica holds mg1's
// vm.migration_unresolved open.
func migrationUnresolvedOpen(t *testing.T, n *Node) bool {
	t.Helper()
	row, ok, err := corrosion.GetHealthCondition(context.Background(), n.DB, "drain", "vm.migration_unresolved", "vm", "mg1")
	if err != nil {
		t.Fatalf("%s: read vm.migration_unresolved: %v", n.Name, err)
	}
	return ok && row.Lifecycle != corrosion.ConditionResolved
}

// TestFleet_Failover_MigratingRowRunningOnTargetIsRepointed: the source of
// a cut-over migration is fenced while the guest runs on the target. mg1 is
// never started on a third host and no second domain of it exists anywhere,
// across enough coordinator cycles and reconciles for recovery to have acted
// (rv1, the control, is recovered in the same cycles). Its row is re-pointed
// to the target, where it runs.
//
// Run with recovery claims off (the legacy reschedule) and on (claim before
// mint, verify before execute).
//
// Mutation: drop the migrating check in recoverWorkloads — mg1 is
// rescheduled to a and started there beside b's copy, in both arms.
func TestFleet_Failover_MigratingRowRunningOnTargetIsRepointed(t *testing.T) {
	for _, claims := range []bool{false, true} {
		t.Run(map[bool]string{false: "claims-off", true: "claims-on"}[claims], func(t *testing.T) {
			clock := NewVirtualClock(time.Now().UTC())
			c, a, b, victim := migratingRowFleet(t, clock, claims, libvirtfake.StateRunning)
			runRecovery(t, c, clock, claims, a, b)
			assertControlRecovered(t, c, a, victim)

			detail := mg1Views(t, a, b)
			for _, n := range []*Node{a, b} {
				if n != b && n.Virt.DomainExists("mg1") {
					t.Errorf("%s holds a domain of mg1, which runs on %s\n  %s", n.Name, b.Name, detail)
				}
			}
			for _, ev := range a.Virt.EventLog() {
				if ev.Domain == "mg1" {
					t.Errorf("%s acted on mg1 (%s at %s): it runs on %s\n  %s", a.Name, ev.Op, ev.When, b.Name, detail)
				}
			}
			if on := runningOn(c, "mg1"); len(on) != 1 || on[0] != b.Name {
				t.Fatalf("mg1 runs on %v, want only the migration target %s\n  %s", on, b.Name, detail)
			}
			if ids := proofsNaming(t, a, "mg1", a.Name); len(ids) != 0 {
				t.Errorf("a proof sends mg1 to %s while it runs on %s: %v\n  %s", a.Name, b.Name, ids, detail)
			}
			for _, n := range []*Node{a, b} {
				if vm := vmOn(t, n, "mg1"); vm.HostName != b.Name || vm.State != "running" {
					t.Errorf("%s's replica records mg1 on %s %s; want it re-pointed to %s, running, where it runs\n  %s",
						n.Name, vm.HostName, vm.State, b.Name, detail)
				}
			}
			if migrationUnresolvedOpen(t, a) {
				t.Errorf("vm.migration_unresolved is open for mg1 after its row was settled\n  %s", detail)
			}
		})
	}
}

// TestFleet_Failover_MigratingRowHeldWhileTargetIsUnsettled: the target
// holds mg1 paused — a guest whose migration may not have finished, or that
// is paused after the cutover. Recovery cannot tell, so mg1 is held: its row
// stays on the fenced source, migrating, nothing of it is started on a, and
// vm.migration_unresolved names why.
//
// Mutation: as above — mg1 is rescheduled to a and started there.
func TestFleet_Failover_MigratingRowHeldWhileTargetIsUnsettled(t *testing.T) {
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, victim := migratingRowFleet(t, clock, false, libvirtfake.StatePaused)
	runRecovery(t, c, clock, false, a, b)
	assertControlRecovered(t, c, a, victim)

	detail := mg1Views(t, a, b)
	if a.Virt.DomainExists("mg1") {
		t.Fatalf("%s holds a domain of mg1 while %s holds it paused\n  %s", a.Name, b.Name, detail)
	}
	if vm := vmOn(t, a, "mg1"); vm.HostName != victim.Name || vm.State != "migrating" || vm.PendingActionID != "" {
		t.Fatalf("mg1 was moved or settled while its target holds it paused; want it held on %s\n  %s", victim.Name, detail)
	}
	if !migrationUnresolvedOpen(t, a) {
		t.Fatalf("mg1 is held with no vm.migration_unresolved for an operator\n  %s", detail)
	}
}

// TestFleet_Failover_MigratingRowWithNoCopyOnTargetIsRecovered: the target
// has no domain of mg1 — the migration never cut over. The guest died with
// the source, so mg1 is recovered as any running VM is: it runs on exactly
// one survivor. The hold must not strand a VM that has no running copy.
func TestFleet_Failover_MigratingRowWithNoCopyOnTargetIsRecovered(t *testing.T) {
	for _, claims := range []bool{false, true} {
		t.Run(map[bool]string{false: "claims-off", true: "claims-on"}[claims], func(t *testing.T) {
			clock := NewVirtualClock(time.Now().UTC())
			c, a, b, victim := migratingRowFleet(t, clock, claims, "")
			runRecovery(t, c, clock, claims, a, b)
			assertControlRecovered(t, c, a, victim)

			detail := mg1Views(t, a, b)
			if vm := vmOn(t, a, "mg1"); vm.HostName == victim.Name {
				t.Fatalf("mg1 has no copy anywhere and was not recovered\n  %s", detail)
			}
			if on := runningOn(c, "mg1"); len(on) != 1 {
				t.Fatalf("mg1 runs on %v, want exactly one survivor\n  %s", on, detail)
			}
		})
	}
}
