// Fleet scenarios: failover of a host whose VM row is still `migrating`
// (lab2-diskfull-rca.md, S1).
//
// A live migration cuts over in libvirt — the guest now runs on the target —
// and the source's daemon dies before the ownership commit lands. The row
// still names the source, `migrating`, with the target in its detail. The
// source is then judged failed and fenced. Recovery must not start the guest
// anywhere while it may run on the target: that would be two running copies
// of one VM. The coordinator asks the target first (failover's
// SettleMigratingRows):
//
//   - the target runs it: the row is re-pointed there, nothing is started;
//   - the target has no domain of it: recovered as any running VM is;
//   - anything else (a paused domain, no answer, no target recorded): held,
//     with vm.migration_unresolved raised naming what settles it. Each hold's
//     scenario then takes that step and reaches exactly one running copy.
package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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
	return migratingRowFleetWith(t, clock, claims, targetState, func(b *Node) string { return "→ " + b.Name })
}

// mg1Spec is mg1's spec (migratingRowFleetWith); a scenario may set it before
// building the fleet.
var mg1Spec = `{"on_host_failure":"restart-any"}`

// migratingRowFleetWith is migratingRowFleet with mg1's state detail given by
// detail (b is the node its domain is on).
func migratingRowFleetWith(t *testing.T, clock *VirtualClock, claims bool, targetState libvirtfake.State,
	detail func(b *Node) string) (c *Cluster, a, b, victim *Node) {
	t.Helper()
	setup := func(_ *Cluster, a, b, victim *Node) {
		ctx := context.Background()
		if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
			Name: "mg1", HostName: victim.Name, Spec: mg1Spec,
			State: "migrating", StateDetail: detail(b),
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
	_, open := mg1Unresolved(t, n)
	return open
}

// mg1Unresolved is the detail of mg1's vm.migration_unresolved on n's
// replica, and whether it is open.
func mg1Unresolved(t *testing.T, n *Node) (string, bool) {
	t.Helper()
	row, ok, err := corrosion.GetHealthCondition(context.Background(), n.DB, "drain", "vm.migration_unresolved", "vm", "mg1")
	if err != nil {
		t.Fatalf("%s: read vm.migration_unresolved: %v", n.Name, err)
	}
	var ev struct {
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal([]byte(row.Evidence), &ev)
	return ev.Detail, ok && row.Lifecycle != corrosion.ConditionResolved
}

// requireHeldNaming checks mg1 is held on victim — its row there, migrating,
// nothing of it on a, the condition open — with the condition naming each of
// want (the step that settles the hold).
func requireHeldNaming(t *testing.T, a, b, victim *Node, want ...string) {
	t.Helper()
	detail := mg1Views(t, a, b)
	if a.Virt.DomainExists("mg1") {
		t.Fatalf("%s holds a domain of mg1 while it is held\n  %s", a.Name, detail)
	}
	for _, ev := range a.Virt.EventLog() {
		if ev.Domain == "mg1" {
			t.Fatalf("%s acted on mg1 (%s) while it is held\n  %s", a.Name, ev.Op, detail)
		}
	}
	if vm := vmOn(t, a, "mg1"); vm.HostName != victim.Name || vm.State != "migrating" || vm.PendingActionID != "" {
		t.Fatalf("mg1 was moved or settled while it is held; want it held on %s\n  %s", victim.Name, detail)
	}
	ev, open := mg1Unresolved(t, a)
	if !open {
		t.Fatalf("mg1 is held with no vm.migration_unresolved for an operator\n  %s", detail)
	}
	// `lv stop` forwards to the VM's host, the failed source: it cannot work.
	if strings.Contains(ev, "lv stop") {
		t.Errorf("vm.migration_unresolved names `lv stop`, which forwards to the failed %s: %s", victim.Name, ev)
	}
	for _, w := range want {
		if !strings.Contains(ev, w) {
			t.Errorf("vm.migration_unresolved does not name %q: %s", w, ev)
		}
	}
}

// tickA runs a's coordinator and reconciler alone, n times: b may be
// unreachable from a, so nothing waits for the two to converge.
func tickA(t *testing.T, cs *Coordinators, clock *VirtualClock, a *Node, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		cs.Tick(ctx, a)
		health.NewReconciler(a.Name, t.TempDir(), a.DB, a.Virt).ReconcileOnce(ctx)
		clock.Advance(contentionPoll)
	}
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
			// The re-point leaves the disk rows and replication on the source;
			// its event names the command that moves them.
			evs, err := corrosion.ListVMEvents(context.Background(), a.DB, "mg1", 20, "")
			if err != nil {
				t.Fatal(err)
			}
			named := false
			for _, e := range evs {
				named = named || (e.Type == "vm.failover.repointed" && strings.Contains(e.Detail, "lv doctor repair-owner mg1 "+b.Name))
			}
			if !named {
				t.Errorf("no vm.failover.repointed event naming `lv doctor repair-owner mg1 %s`: %+v", b.Name, evs)
			}
		})
	}
}

// TestFleet_Failover_MigratingRowHeldWhileTargetIsUnsettled: the target
// holds mg1 paused — a guest whose migration may not have finished, or that
// is paused after the cutover. Recovery cannot tell, so mg1 is held: its row
// stays on the fenced source, migrating, nothing of it is started on a, and
// vm.migration_unresolved names why and the step that settles it. No lv
// command settles it while the source is down: the step is resuming the
// guest on the target, and the next poll then re-points the row there and
// resolves the condition, with one running copy.
//
// Mutations: as above — mg1 is rescheduled to a and started there; drop the
// condition's resolution after a re-point — red in the second phase.
func TestFleet_Failover_MigratingRowHeldWhileTargetIsUnsettled(t *testing.T) {
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, victim := migratingRowFleet(t, clock, false, libvirtfake.StatePaused)
	cs := runRecovery(t, c, clock, false, a, b)
	assertControlRecovered(t, c, a, victim)
	// The guest stays paused on b; the runtime inventory reports every domain
	// that is not running as defined_stopped.
	requireHeldNaming(t, a, b, victim, "holds a domain of it in state", "virsh start mg1")

	// The operator resumes the guest on b; the next poll settles it there.
	b.Virt.SetState("mg1", libvirtfake.StateRunning)
	for i := 0; i < 2; i++ {
		cs.Tick(context.Background(), a)
		c.WaitConverged(t, convergeTimeout, a, b)
		clock.Advance(contentionPoll)
	}
	detail := mg1Views(t, a, b)
	if vm := vmOn(t, a, "mg1"); vm.HostName != b.Name || vm.State != "running" {
		t.Fatalf("mg1 was not re-pointed to %s once its guest ran there\n  %s", b.Name, detail)
	}
	if on := runningOn(c, "mg1"); len(on) != 1 || on[0] != b.Name {
		t.Fatalf("mg1 runs on %v, want only %s\n  %s", on, b.Name, detail)
	}
	if migrationUnresolvedOpen(t, a) {
		t.Fatalf("vm.migration_unresolved is still open after mg1 was re-pointed\n  %s", detail)
	}
}

// TestFleet_Failover_MigratingRowHeldWhileTargetIsUnreachable: the target
// still runs mg1 but a cannot reach it — the likeliest real shape of this
// failure, a rack or switch fault taking the source and the target out
// together. mg1 stays held for as long as recovery would have acted, and no
// second copy of it starts. The hold names `lv host fence-confirm` of the
// target: once it is powered off (its guest with it) and confirmed so, the
// next poll recovers mg1 onto a, with one running copy.
//
// Claims off only: with claims on, the claim's voters are a, b and the
// victim, and with b unreachable no claim forms, so the arm could not tell a
// hold from a refused claim.
//
// Mutation: a probe error recovers (MigratingRecover) — a starts mg1 while b
// runs it, red.
func TestFleet_Failover_MigratingRowHeldWhileTargetIsUnreachable(t *testing.T) {
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, victim := migratingRowFleet(t, clock, false, libvirtfake.StateRunning)
	c.SetLinkFaultBoth(a, b, LinkFault{BlockAll: true})
	cs := c.NewCoordinators(clock)
	tickA(t, cs, clock, a, 4)
	if len(cs.Fences()) == 0 {
		t.Fatal("victim was never fenced; without a fence there is no recovery and this proves nothing")
	}
	if rv := vmOn(t, a, "rv1"); rv.HostName != a.Name {
		t.Fatalf("the control rv1 = %+v, want it recovered to %s", rv, a.Name)
	}
	requireHeldNaming(t, a, b, victim, "cannot be asked", "lv host fence-confirm "+b.Name)
	if on := runningOn(c, "mg1"); len(on) != 1 || on[0] != b.Name {
		t.Fatalf("mg1 runs on %v, want only the unreachable %s", on, b.Name)
	}

	// The operator powers b off, its guest with it, and confirms it.
	c.Kill(b)
	_ = b.Virt.DestroyDomain("mg1")
	PublishHealth(t, a, b.Name, 5, clock.Now())
	mustFenceConfirm(t, a, b.Name)
	tickA(t, cs, clock, a, 3)
	detail := mg1Views(t, a)
	if on := runningOn(c, "mg1"); len(on) != 1 || on[0] != a.Name {
		t.Fatalf("after %s was confirmed off, mg1 runs on %v, want only %s\n  %s", b.Name, on, a.Name, detail)
	}
}

// TestFleet_Failover_MigratingRowWithNoTargetRecordedIsHeld: mg1's row says
// migrating but names no target (a legacy or hand-edited row: both of
// today's writers record it), and its guest runs on b. Nothing can be asked,
// so mg1 is held, the condition naming `lv doctor repair-owner`. That
// command, run against b, records mg1 there, with one running copy.
//
// Mutation: a row with no target recovers — a starts mg1 while b runs it,
// red.
func TestFleet_Failover_MigratingRowWithNoTargetRecordedIsHeld(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, victim := migratingRowFleetWith(t, clock, false, libvirtfake.StateRunning, func(*Node) string { return "" })
	runRecovery(t, c, clock, false, a, b)
	assertControlRecovered(t, c, a, victim)
	requireHeldNaming(t, a, b, victim, "names no target", "lv doctor repair-owner mg1 <host>")

	if _, err := c.SelfClient(a).RepairVMOwner(ctx, &pb.RepairVMOwnerRequest{Name: "mg1", Host: b.Name}); err != nil {
		t.Fatalf("lv doctor repair-owner mg1 %s: %v", b.Name, err)
	}
	c.WaitConverged(t, convergeTimeout, a, b)
	detail := mg1Views(t, a, b)
	if vm := vmOn(t, a, "mg1"); vm.HostName != b.Name || vm.State != "running" {
		t.Fatalf("repair-owner did not record mg1 on %s\n  %s", b.Name, detail)
	}
	if on := runningOn(c, "mg1"); len(on) != 1 || on[0] != b.Name {
		t.Fatalf("mg1 runs on %v, want only %s\n  %s", on, b.Name, detail)
	}
	if migrationUnresolvedOpen(t, a) {
		t.Fatalf("vm.migration_unresolved is still open after repair-owner\n  %s", detail)
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

// TestFleet_Failover_MigratingFirmwareRowWithBothHostsDownIsNotStarted: mg1
// is a Secure Boot / vTPM VM recorded migrating from the victim to b, and b
// does not answer. Its hold says no `lv` command starts it while both hosts
// are down, and that bringing one back is the remedy. Once b is powered off
// and confirmed so, the recovery goes on past the hold into failover's
// firmware skip: nothing of mg1 runs anywhere, its row stays migrating on
// the victim, the skip is audited, and the condition stays, saying what the
// victim's return then takes (internal/grpcapi TestFailedFirmwareSource_*
// follow it to one running copy).
//
// Mutations: resolve the condition when a firmware VM is recovered — red;
// give the unreachable firmware hold the paused advice — red.
func TestFleet_Failover_MigratingFirmwareRowWithBothHostsDownIsNotStarted(t *testing.T) {
	ctx := context.Background()
	old := mg1Spec
	mg1Spec = `{"on_host_failure":"restart-any","secure_boot":true,"tpm":true,"firmware":"uefi","uuid":"6f1c2d3e-4b5a-4c6d-8e7f-0011223344cc"}`
	t.Cleanup(func() { mg1Spec = old })
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, victim := migratingRowFleet(t, clock, false, libvirtfake.StateRunning)
	c.SetLinkFaultBoth(a, b, LinkFault{BlockAll: true})
	cs := c.NewCoordinators(clock)
	tickA(t, cs, clock, a, 3)
	if len(cs.Fences()) == 0 {
		t.Fatal("victim was never fenced; without a fence there is no recovery and this proves nothing")
	}
	requireHeldNaming(t, a, b, victim, "No `lv` command starts it", "both down", "Bring "+b.Name+" back",
		"Or bring "+victim.Name+" back", "lv start mg1")

	// b powered off, its guest with it, and confirmed so.
	c.Kill(b)
	_ = b.Virt.DestroyDomain("mg1")
	PublishHealth(t, a, b.Name, 5, clock.Now())
	mustFenceConfirm(t, a, b.Name)
	tickA(t, cs, clock, a, 3)

	if on := runningOn(c, "mg1"); len(on) != 0 {
		t.Fatalf("mg1 runs on %v; nothing can start a firmware VM whose source and target are both down", on)
	}
	if a.Virt.DomainExists("mg1") {
		t.Fatalf("%s defined mg1", a.Name)
	}
	if vm := vmOn(t, a, "mg1"); vm.HostName != victim.Name || vm.State != "migrating" {
		t.Fatalf("mg1 = %s %s, want its row left migrating on %s", vm.HostName, vm.State, victim.Name)
	}
	rows, err := a.DB.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'failover.skip' AND target = 'mg1'`)
	if err != nil || len(rows) == 0 {
		t.Fatalf("failover.skip audit rows for mg1 = %d (err %v): the recovery did not reach the firmware skip", len(rows), err)
	}
	detail, open := mg1Unresolved(t, a)
	if !open {
		t.Fatal("vm.migration_unresolved was resolved, though nothing brought mg1 back")
	}
	for _, w := range []string{"proven powered off", "No `lv` command starts it while " + victim.Name + " is down",
		"Power " + victim.Name + " back on", "lv start mg1"} {
		if !strings.Contains(detail, w) {
			t.Errorf("vm.migration_unresolved no longer names %q: %s", w, detail)
		}
	}
}
