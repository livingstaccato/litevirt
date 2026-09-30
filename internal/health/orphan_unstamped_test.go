package health

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/lxc"
)

// stampingCtRuntime is fakeCtRuntime plus lxc.ManagedStamper. The stamp is
// keyed to the container's presence, as the real one (a file inside the LXC
// directory) is: removing a container removes its stamp.
type stampingCtRuntime struct {
	*fakeCtRuntime
	managed map[string]bool
}

func newStampingCtRuntime() *stampingCtRuntime {
	return &stampingCtRuntime{fakeCtRuntime: newFakeCtRuntime(), managed: map[string]bool{}}
}

func (f *stampingCtRuntime) StampManaged(name string) error {
	if _, ok := f.states[name]; !ok {
		return lxc.ErrContainerNotFound
	}
	f.managed[name] = true
	return nil
}

func (f *stampingCtRuntime) IsManaged(name string) (bool, error) { return f.managed[name], nil }

var _ lxc.ManagedStamper = (*stampingCtRuntime)(nil)

// Adoption stamps exactly the domains this host has a live row for. The
// others are the cases that must stay unstamped:
//   - theirs: a live row naming ANOTHER host — an ownership question, not proof
//     that this host's domain is litevirt's;
//   - web-1: a hand-made domain that reuses a deleted VM's name and litevirt's
//     disk path convention. Its only row is a tombstone;
//   - stray: a hand-made domain with no row at all.
func TestAdoptManagedDomains_StampsOnlyDomainsWithALiveRowHere(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	for _, rec := range []corrosion.VMRecord{
		{Name: "mine", HostName: "node-a", State: "running", Spec: "{}"},
		{Name: "mineoff", HostName: "node-a", State: "stopped", Spec: "{}"},
		{Name: "theirs", HostName: "node-b", State: "running", Spec: "{}"},
		{Name: "web-1", HostName: "node-a", State: "running", Spec: "{}"},
	} {
		if err := corrosion.InsertVM(ctx, db, rec, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", rec.Name, err)
		}
	}
	if err := corrosion.DeleteVM(ctx, db, "web-1"); err != nil {
		t.Fatal(err)
	}

	fake := libvirtfake.New()
	for name, st := range map[string]libvirtfake.State{
		"mine": libvirtfake.StateRunning, "mineoff": libvirtfake.StateShutdown,
		"theirs": libvirtfake.StateShutdown, "web-1": libvirtfake.StateRunning, "stray": libvirtfake.StateRunning,
	} {
		xml := `<domain><name>` + name + `</name><devices><disk type="file"><source file="/var/lib/litevirt/disks/` +
			name + `-root.qcow2"/></disk></devices></domain>`
		if err := fake.DefineDomain(xml); err != nil {
			t.Fatal(err)
		}
		fake.SetState(name, st)
	}

	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.adoptManagedDomains(ctx)

	for name, want := range map[string]bool{"mine": true, "mineoff": true, "theirs": false, "web-1": false, "stray": false} {
		got, err := fake.GetDomainManaged(name)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s: managed stamp = %v, want %v", name, got, want)
		}
	}
	// The owner-epoch marker stays the executor's: adoption never writes one.
	if _, ok, _ := fake.GetDomainOwnerEpoch("mine"); ok {
		t.Error("adoption wrote an owner-epoch marker; it must write only the managed stamp")
	}
}

// The container half. node1 runs:
//   - old: a pre-marker litevirt container with a live row here — adopted, and
//     reported once its row is tombstoned;
//   - moved: a live row on node2 — not adopted;
//   - web-1: made by hand, reusing the name of a container deleted earlier —
//     never stamped, never reported.
func TestContainerOrphan_UnstampedContainerIsAdoptedThenReported(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newStampingCtRuntime()
	for _, n := range []string{"old", "moved", "web-1"} {
		rt.states[n] = lxc.StateRunning
	}
	insertCt(t, db, corrosion.ContainerRecord{HostName: "node1", Name: "old", State: "running"})
	insertCt(t, db, corrosion.ContainerRecord{HostName: "node2", Name: "moved", State: "running"})
	insertCt(t, db, corrosion.ContainerRecord{HostName: "node1", Name: "web-1", State: "running"})
	if err := corrosion.DeleteContainer(ctx, db, "node1", "web-1"); err != nil {
		t.Fatal(err)
	}

	c := NewContainerChecker("node1", db, rt)
	c.SetContainersRoot(t.TempDir()) // no owner-epoch marker anywhere
	c.SweepOnce(ctx)
	for n, want := range map[string]bool{"old": true, "moved": false, "web-1": false} {
		if rt.managed[n] != want {
			t.Errorf("%s: stamped = %v, want %v", n, rt.managed[n], want)
		}
	}

	if err := corrosion.DeleteContainer(ctx, db, "node1", "old"); err != nil {
		t.Fatal(err)
	}
	c.SweepOnce(ctx)
	c.SweepOnce(ctx)
	got := ctOrphanConditions(t, db, false)
	if len(got) != 1 {
		t.Fatalf("want only old reported, got %v", got)
	}
	cond, ok := got["container/old@node1"]
	if !ok {
		t.Fatalf("old not reported: %v", got)
	}
	var ev map[string]interface{}
	if err := json.Unmarshal([]byte(cond.Evidence), &ev); err != nil {
		t.Fatal(err)
	}
	if ev["row"] != OrphanRowTombstoned || ev["recognised_by"] != OrphanRecognisedByManagedStamp {
		t.Errorf("evidence = %v, want row=tombstoned recognised_by=%s", ev, OrphanRecognisedByManagedStamp)
	}
	if rt.managed["web-1"] {
		t.Error("the hand-made web-1 was stamped")
	}
}

// Container adoption waits for a caught-up replica, as VM adoption does.
func TestContainerOrphan_StaleReplicaAdoptsNothing(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	for _, h := range []string{"node1", "node2"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	rt := newStampingCtRuntime()
	rt.states["old"] = lxc.StateRunning
	insertCt(t, db, corrosion.ContainerRecord{HostName: "node1", Name: "old", State: "running"})

	c := NewContainerChecker("node1", db, rt)
	c.SetReplicaFreshness(func() (bool, string) { return false, "process restarted (test)" })
	c.SweepOnce(ctx)
	if rt.managed["old"] {
		t.Error("a container was stamped from a replica that has not caught up")
	}
}
