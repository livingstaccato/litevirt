// A VM created before owner-epoch stamping carries no owner-epoch metadata,
// and neither does any shut-off VM or any VM whose row is still at the
// pre-epoch 0. The orphan-runtime report recognised only that metadata, so the
// lab's failure — a stale delete tombstoning a VM on every replica while it
// kept running — went unreported for exactly those VMs.
//
// The reconciler now adopts every domain it has a live row for into the
// managed stamp, and the report recognises that stamp as well. A domain that
// never had a live row here is never stamped, so a hand-made domain is still
// never reported, however litevirt-like its name and disk paths.
package fleet

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

type unstampedScenario struct {
	c                *Cluster
	owner, bystander *Node
	rec              *health.Reconciler
}

// newUnstampedScenario: `owner` runs
//   - oldvm: a pre-marker litevirt VM, running, row at epoch 0;
//   - oldoff: a pre-marker litevirt VM, shut off;
//   - web-1: made by hand after litevirt's VM of that name was deleted, with
//     its disk at litevirt's path. Its only row is that tombstone.
func newUnstampedScenario(t *testing.T) *unstampedScenario {
	t.Helper()
	s := &unstampedScenario{c: New(t, Options{Nodes: 2})}
	s.owner, s.bystander = s.c.Nodes[0], s.c.Nodes[1]
	ctx := context.Background()

	for _, rec := range []corrosion.VMRecord{
		{Name: "oldvm", HostName: s.owner.Name, State: "running", Spec: `{}`},
		{Name: "oldoff", HostName: s.owner.Name, State: "stopped", Spec: `{}`},
		{Name: "web-1", HostName: s.owner.Name, State: "running", Spec: `{}`},
	} {
		if err := corrosion.InsertVM(ctx, s.owner.DB, rec, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", rec.Name, err)
		}
	}
	pumpMutations(t, s.c, s.owner, s.bystander)
	if err := corrosion.DeleteVM(ctx, s.bystander.DB, "web-1"); err != nil {
		t.Fatal(err)
	}
	spreadFrom(t, s.c, s.bystander)

	for name, st := range map[string]libvirtfake.State{
		"oldvm": libvirtfake.StateRunning, "oldoff": libvirtfake.StateShutdown, "web-1": libvirtfake.StateRunning,
	} {
		xml := `<domain><name>` + name + `</name><devices><disk type="file"><source file="/var/lib/litevirt/disks/` +
			name + `-root.qcow2"/></disk></devices></domain>`
		if err := s.owner.Virt.DefineDomain(xml); err != nil {
			t.Fatal(err)
		}
		s.owner.Virt.SetState(name, st)
	}

	s.rec = health.NewReconciler(s.owner.Name, t.TempDir(), s.owner.DB, s.owner.Virt)
	s.rec.SetReplicaFreshness(s.owner.DB.ReplicaCaughtUp)
	return s
}

func (s *unstampedScenario) managed(t *testing.T, name string) bool {
	t.Helper()
	ok, err := s.owner.Virt.GetDomainManaged(name)
	if err != nil {
		t.Fatalf("GetDomainManaged %s: %v", name, err)
	}
	return ok
}

func TestFleet_OrphanRuntime_UnstampedVMIsAdoptedThenReported(t *testing.T) {
	s := newUnstampedScenario(t)
	ctx := context.Background()

	s.rec.ReconcileOnce(ctx)
	for name, want := range map[string]bool{"oldvm": true, "oldoff": true, "web-1": false} {
		if got := s.managed(t, name); got != want {
			t.Errorf("after one pass, %s managed = %v, want %v", name, got, want)
		}
	}
	// What made these VMs invisible before: no owner-epoch marker, and none is
	// written for them now either.
	for _, name := range []string{"oldvm", "oldoff"} {
		if _, ok, _ := s.owner.Virt.GetDomainOwnerEpoch(name); ok {
			t.Errorf("%s has an owner-epoch marker; the scenario needs one without", name)
		}
	}

	// The lab's failure: a delete served elsewhere tombstones both rows while
	// the domains stay on the owner.
	for _, name := range []string{"oldvm", "oldoff"} {
		if err := corrosion.DeleteVM(ctx, s.bystander.DB, name); err != nil {
			t.Fatalf("DeleteVM %s: %v", name, err)
		}
	}
	spreadFrom(t, s.c, s.bystander)

	s.rec.ReconcileOnce(ctx)
	s.rec.ReconcileOnce(ctx)
	got := orphanConditions(t, s.owner, false)
	if len(got) != 2 {
		t.Fatalf("want exactly oldvm and oldoff reported, got %v", got)
	}
	for key, sev := range map[string]string{
		"vm/oldvm@" + s.owner.Name:  corrosion.SeverityWarning,
		"vm/oldoff@" + s.owner.Name: corrosion.SeverityInfo,
	} {
		c, ok := got[key]
		if !ok {
			t.Errorf("%s not reported", key)
			continue
		}
		var ev map[string]interface{}
		if err := json.Unmarshal([]byte(c.Evidence), &ev); err != nil {
			t.Fatal(err)
		}
		if c.Severity != sev || ev["row"] != health.OrphanRowTombstoned ||
			ev["recognised_by"] != health.OrphanRecognisedByManagedStamp || ev["row_host"] != s.owner.Name {
			t.Errorf("%s: severity=%s evidence=%v", key, c.Severity, ev)
		}
	}

	// Report-only, and the hand-made domain is untouched and unstamped.
	for name, want := range map[string]string{"oldvm": "running", "oldoff": "shutoff", "web-1": "running"} {
		if st, _ := s.owner.Virt.DomainState(name); st != want {
			t.Errorf("%s: domain state %q, want %q", name, st, want)
		}
	}
	if s.managed(t, "web-1") {
		t.Error("the hand-made web-1 was stamped")
	}
}

// Adoption reads the replica, so it waits for the replica too.
func TestFleet_OrphanRuntime_StaleReplicaAdoptsNothing(t *testing.T) {
	s := newUnstampedScenario(t)
	s.owner.DB.MarkReplicaStale("process restarted (fleet: modelled reboot)")
	s.rec.ReconcileOnce(context.Background())
	for _, name := range []string{"oldvm", "oldoff"} {
		if s.managed(t, name) {
			t.Errorf("%s was stamped from a replica that has not caught up", name)
		}
	}
}

// litevirt deletes its VM (tombstone, domain undefined) and an operator then
// defines a domain of the same name by hand. The stamp went with the old
// domain, so the new one is not litevirt's and is never reported.
func TestFleet_OrphanRuntime_HandMadeNameReuseIsNotReported(t *testing.T) {
	s := newUnstampedScenario(t)
	ctx := context.Background()
	s.rec.ReconcileOnce(ctx)
	if !s.managed(t, "oldvm") {
		t.Fatal("oldvm was not adopted; the scenario needs it stamped first")
	}

	// litevirt's delete: tombstone the row and undefine the domain.
	if err := corrosion.DeleteVM(ctx, s.owner.DB, "oldvm"); err != nil {
		t.Fatal(err)
	}
	if err := s.owner.Virt.DestroyDomain("oldvm"); err != nil {
		t.Fatal(err)
	}
	if err := s.owner.Virt.UndefineDomain("oldvm", false); err != nil {
		t.Fatal(err)
	}
	// The operator's domain: same name, same disk path convention.
	if err := s.owner.Virt.DefineDomain(`<domain><name>oldvm</name><devices><disk type="file">` +
		`<source file="/var/lib/litevirt/disks/oldvm-root.qcow2"/></disk></devices></domain>`); err != nil {
		t.Fatal(err)
	}
	s.owner.Virt.SetState("oldvm", libvirtfake.StateRunning)

	s.rec.ReconcileOnce(ctx)
	s.rec.ReconcileOnce(ctx)
	if c, ok := orphanConditions(t, s.owner, true)["vm/oldvm@"+s.owner.Name]; ok {
		t.Errorf("a hand-made domain reusing a deleted VM's name was reported: %+v", c)
	}
	if s.managed(t, "oldvm") {
		t.Error("the hand-made domain was stamped")
	}
}
