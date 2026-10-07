package grpcapi

import (
	"context"
	"os"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Replica ownership (replicaOwner) reads both replica records: a pool
// record of a replica at the pool's top level, and the record beside a
// replica in the pool's replica area (replica_records.go). An area replica
// is its VM's project's — visible and deletable to whoever reads the VM —
// and nobody else's.
func TestPoolConfinement_AReplicaAreaRecordGivesTheReplicaToItsVM(t *testing.T) {
	s, disks := twoProjectsOnDisks(t)
	ctx := context.Background()
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	bob := hostPathEngineCtx(t, s, "bob", "Operator", projectRBACBase("bravo"))
	rec := newReplicaRecord("acme", "avm", "root", "avm/pa", "20261006-120000", "qcow2")
	path, err := publishRecordedReplica(ctx, disks, rec, func(tmp string) error {
		return os.WriteFile(tmp, []byte("avm's replica"), 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	pool := func(name string) corrosion.StoragePoolRecord {
		r, ok, err := corrosion.GetStoragePool(ctx, s.db, s.hostName, name)
		if err != nil || !ok {
			t.Fatalf("pool %s: %v", name, err)
		}
		return r
	}
	conf := func(uctx context.Context, name string) *poolFileConfinement {
		c, err := s.poolConfinementFor(ctx, pool(name), poolContentCaller{ctx: uctx, view: viewCaller})
		if err != nil || c == nil {
			t.Fatalf("confinement of %s: %v %v", name, c, err)
		}
		return c
	}
	acme := conf(pat, "pa")
	if vm, project, ok := acme.replicaOwner(ctx, path); !ok || vm != "avm" || project != "acme" {
		t.Errorf("replicaOwner of avm's area replica = %q %q %v, want avm acme", vm, project, ok)
	}
	if !acme.visible(ctx, path) || !acme.deletable(ctx, path) {
		t.Errorf("acme's operator does not own avm's area replica")
	}
	if b := conf(bob, "pb"); b.visible(ctx, path) || b.deletable(ctx, path) {
		t.Errorf("bravo's operator owns acme's avm's area replica")
	}
}
