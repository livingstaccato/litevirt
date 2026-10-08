package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// ownerFakeRT is the fake runtime with an on-disk owner record.
type ownerFakeRT struct {
	*fakeCtRuntime
	owners map[string]lxc.ContainerOwner
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
