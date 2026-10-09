package health

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// ownerFakeRT is the fake runtime with an on-disk owner record.
type ownerFakeRT struct {
	*fakeCtRuntime
	owners    map[string]lxc.ContainerOwner
	createErr error // Create fails with it (a directory of the name already there)
	creates   int
}

func (f *ownerFakeRT) Create(ctx context.Context, opts lxc.CreateOpts) (*lxc.Container, error) {
	f.creates++
	if f.createErr != nil {
		return nil, f.createErr
	}
	return f.fakeCtRuntime.Create(ctx, opts)
}

func (f *ownerFakeRT) StampOwner(name string, o lxc.ContainerOwner) error {
	f.owners[name] = o
	return nil
}

func (f *ownerFakeRT) ReadOwner(name string) (*lxc.ContainerOwner, error) {
	if o, ok := f.owners[name]; ok {
		return &o, nil
	}
	return nil, nil
}

func relocatingRow(t *testing.T, db *corrosion.Client) {
	t.Helper()
	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "pending", Project: "acme",
		StateDetail: corrosion.ContainerRelocateRecreateDetail, Image: "alpine:3.19",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", Distro: "alpine", OwnerID: "own-1"}),
	})
}

// relocatingRowWithNIC is relocatingRow with a managed NIC whose address a
// live lease keyed (ct, node1, ct1) holds: the key a same-named directory on
// this host, the relocating row's or another's, shares.
func relocatingRowWithNIC(t *testing.T, db *corrosion.Client) {
	t.Helper()
	if err := db.Execute(context.Background(),
		`INSERT INTO ip_allocations (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
		 VALUES ('lxtnet', '172.16.77.50', 'mac-foreign', 'ct1', 'ct', 'node1', '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "pending", Project: "acme",
		StateDetail: corrosion.ContainerRelocateRecreateDetail, Image: "alpine:3.19",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{
			Template: "download", Distro: "alpine", OwnerID: "own-1",
			Networks: []corrosion.ContainerNetwork{{Name: "eth0", NetworkName: "lxtnet", Bridge: "br-lxt", IP: "172.16.77.50", MAC: "mac-acme"}},
		}),
	})
}

// leaseSnapshot is every ip_allocations row, every column, live or not.
func leaseSnapshot(t *testing.T, db *corrosion.Client) string {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT * FROM ip_allocations ORDER BY network, ip`)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%v", rows)
}

// nicRowCount counts container_interfaces rows, live or tombstoned.
func nicRowCount(t *testing.T, db *corrosion.Client) int {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT COUNT(*) AS n FROM container_interfaces`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("count container_interfaces: %v", err)
	}
	return rows[0].Int("n")
}

// A relocation finding a container of its name already on the survivor
// adopted it as "materialized by a prior tick". One whose owner record names
// another project or lineage is someone else's container: not adopted.
func TestContainerCheck_RelocateRecreate_ForeignContainerNotAdopted(t *testing.T) {
	for _, o := range []lxc.ContainerOwner{{Project: "beta", OwnerID: "x"}, {Project: "acme", OwnerID: "other"}} {
		db := testLogicDB(t)
		rt := &ownerFakeRT{fakeCtRuntime: newFakeCtRuntime(), owners: map[string]lxc.ContainerOwner{"ct1": o}}
		rt.states["ct1"] = lxc.StateStopped
		relocatingRow(t, db)
		c := NewContainerChecker("node1", db, rt)
		c.checkContainer(context.Background(), mustGetCt(t, db, "ct1"), time.Now())
		fresh := mustGetCt(t, db, "ct1")
		if fresh.StateDetail != corrosion.ContainerRelocateRecreateDetail {
			t.Fatalf("owner %+v: adopted someone else's container (detail %q)", o, fresh.StateDetail)
		}
	}
}

// The foreign directory is refused before anything is written for it: no NIC
// row for the relocating row, and its (ct, node1, ct1) lease untouched. A
// refusal placed after the adopt branch's NIC and lease writes would leave
// the detail pending too, so the detail alone does not pin the order.
func TestContainerCheck_RelocateRecreate_ForeignContainerNoNICOrLeaseWrite(t *testing.T) {
	for _, o := range []lxc.ContainerOwner{{Project: "beta", OwnerID: "x"}, {Project: "acme", OwnerID: "other"}} {
		db := testLogicDB(t)
		rt := &ownerFakeRT{fakeCtRuntime: newFakeCtRuntime(), owners: map[string]lxc.ContainerOwner{"ct1": o}}
		rt.states["ct1"] = lxc.StateStopped
		relocatingRowWithNIC(t, db)
		before := leaseSnapshot(t, db)
		c := NewContainerChecker("node1", db, rt)
		c.checkContainer(context.Background(), mustGetCt(t, db, "ct1"), time.Now())
		if d := mustGetCt(t, db, "ct1").StateDetail; d != corrosion.ContainerRelocateRecreateDetail {
			t.Fatalf("owner %+v: adopted someone else's container (detail %q)", o, d)
		}
		if n := nicRowCount(t, db); n != 0 {
			t.Errorf("owner %+v: %d NIC rows written for a foreign directory", o, n)
		}
		if after := leaseSnapshot(t, db); after != before {
			t.Errorf("owner %+v: leases changed for a foreign directory:\nbefore %s\nafter  %s", o, before, after)
		}
	}
}

// M1: a foreign directory whose state the runtime cannot report (lxc-info
// errors, or reports error/starting/stopping) is not taken for "nothing
// here": no Create over it, and so no failed-Create rollback releasing the
// (ct, node1, ct1) lease that directory may hold.
func TestContainerCheck_RelocateRecreate_ForeignContainerUnknownStateUntouched(t *testing.T) {
	for _, st := range []lxc.State{lxc.StateError, lxc.StateStarting, lxc.StateStopping} {
		db := testLogicDB(t)
		rt := &ownerFakeRT{
			fakeCtRuntime: newFakeCtRuntime(),
			owners:        map[string]lxc.ContainerOwner{"ct1": {Project: "beta", OwnerID: "x"}},
			createErr:     errors.New(`container "ct1" already exists`),
		}
		rt.states["ct1"] = st
		relocatingRowWithNIC(t, db)
		before := leaseSnapshot(t, db)
		c := NewContainerChecker("node1", db, rt)
		c.checkContainer(context.Background(), mustGetCt(t, db, "ct1"), time.Now())
		if rt.creates != 0 {
			t.Errorf("state %q: Create attempted over a foreign directory", st)
		}
		if after := leaseSnapshot(t, db); after != before {
			t.Errorf("state %q: leases changed for a foreign directory:\nbefore %s\nafter  %s", st, before, after)
		}
		if n := nicRowCount(t, db); n != 0 {
			t.Errorf("state %q: %d NIC rows written for a foreign directory", st, n)
		}
		if d := mustGetCt(t, db, "ct1").StateDetail; d != corrosion.ContainerRelocateRecreateDetail {
			t.Fatalf("state %q: detail %q, want still pending", st, d)
		}
	}
}

// With no owner record (an earlier build's directory, or none), the same
// unknown state takes the fresh-create path exactly as before this check
// moved: Create is attempted, and its failure rolls back the leases it
// reserved.
func TestContainerCheck_RelocateRecreate_NoRecordUnknownStateAsBefore(t *testing.T) {
	db := testLogicDB(t)
	rt := &ownerFakeRT{
		fakeCtRuntime: newFakeCtRuntime(),
		owners:        map[string]lxc.ContainerOwner{},
		createErr:     errors.New(`container "ct1" already exists`),
	}
	rt.states["ct1"] = lxc.StateError
	relocatingRowWithNIC(t, db)
	c := NewContainerChecker("node1", db, rt)
	c.checkContainer(context.Background(), mustGetCt(t, db, "ct1"), time.Now())
	if rt.creates != 1 {
		t.Fatalf("Create attempted %d times, want 1 (main's fresh-create path)", rt.creates)
	}
	rows, err := db.Query(context.Background(),
		`SELECT COUNT(*) AS n FROM ip_allocations WHERE vm_name = 'ct1' AND owner_host = 'node1' AND deleted_at IS NULL`)
	if err != nil {
		t.Fatal(err)
	}
	if n := rows[0].Int("n"); n != 0 {
		t.Fatalf("%d live leases after the failed create, want its rollback to release them", n)
	}
	if d := mustGetCt(t, db, "ct1").StateDetail; d != corrosion.ContainerRelocateRecreateDetail {
		t.Fatalf("detail %q, want still pending for a retry", d)
	}
}

// Its own (a prior tick's), or one with no record (an earlier build's), is
// adopted as before; a recreate stamps the row's owner.
func TestContainerCheck_RelocateRecreate_OwnContainerAdoptedAndStamped(t *testing.T) {
	for _, owners := range []map[string]lxc.ContainerOwner{{"ct1": {Project: "acme", OwnerID: "own-1"}}, {}} {
		db := testLogicDB(t)
		rt := &ownerFakeRT{fakeCtRuntime: newFakeCtRuntime(), owners: owners}
		rt.states["ct1"] = lxc.StateStopped
		relocatingRow(t, db)
		c := NewContainerChecker("node1", db, rt)
		c.checkContainer(context.Background(), mustGetCt(t, db, "ct1"), time.Now())
		if d := mustGetCt(t, db, "ct1").StateDetail; d == corrosion.ContainerRelocateRecreateDetail {
			t.Fatalf("owners %+v: own container not adopted", owners)
		}
	}
	db := testLogicDB(t)
	rt := &ownerFakeRT{fakeCtRuntime: newFakeCtRuntime(), owners: map[string]lxc.ContainerOwner{}}
	relocatingRow(t, db)
	c := NewContainerChecker("node1", db, rt)
	c.checkContainer(context.Background(), mustGetCt(t, db, "ct1"), time.Now())
	if got := rt.owners["ct1"]; got != (lxc.ContainerOwner{Project: "acme", OwnerID: "own-1"}) {
		t.Fatalf("recreate stamped %+v", got)
	}
}

// A host-loss recreate rebuilds the container with the privilege mode and
// confinement it had: the same range, the same profile. A container from an
// earlier build (neither recorded) is recreated as it was: privileged, legacy.
func TestContainerCheck_RelocateRecreate_KeepsSecurity(t *testing.T) {
	db := testLogicDB(t)
	rt := newFakeCtRuntime()
	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "pending",
		StateDetail: corrosion.ContainerRelocateRecreateDetail, Image: "alpine:3.19",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", Distro: "alpine",
			IDMapBase: 1_000_065_536, Confinement: lxc.ConfinementDefault}),
	})
	c := NewContainerChecker("node1", db, rt)
	c.checkContainer(context.Background(), mustGetCt(t, db, "ct1"), time.Now())
	if o := rt.lastCreate; o.IDMap == nil || o.IDMap.Base != 1_000_065_536 || o.IDMap.Size != lxc.IDMapSize || o.Confinement != lxc.ConfinementDefault {
		t.Fatalf("recreate opts = %+v (idmap %+v)", o, o.IDMap)
	}

	db2 := testLogicDB(t)
	rt2 := newFakeCtRuntime()
	insertCt(t, db2, corrosion.ContainerRecord{
		HostName: "node1", Name: "old", State: "pending",
		StateDetail: corrosion.ContainerRelocateRecreateDetail, Image: "alpine:3.19",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", Distro: "alpine"}),
	})
	NewContainerChecker("node1", db2, rt2).checkContainer(context.Background(), mustGetCt(t, db2, "old"), time.Now())
	if o := rt2.lastCreate; o.IDMap != nil || o.Confinement != "" {
		t.Fatalf("an earlier build's container was recreated as %+v", o)
	}
}
