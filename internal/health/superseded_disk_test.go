package health

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// supersededFixture is host node-a holding a local disk file for vm1 at the
// image store's path, with the backing image present.
func supersededFixture(t *testing.T, state string) (*corrosion.Client, *libvirtfake.Fake, *Reconciler, string) {
	t.Helper()
	db := testReconcilerDB(t)
	ctx := context.Background()
	dataDir := t.TempDir()
	store := image.NewStore(dataDir)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(store.ImagePath("base"), 64<<20, nil); err != nil {
		t.Fatal(err)
	}
	path := store.DiskPath("vm1", "root")
	if err := qcow2.CreateWithBacking(path, store.ImagePath("base"), 1<<30, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node-a", Spec: `{"name":"vm1","cpu":1,"memory_mib":512}`, State: state,
	}, nil, []corrosion.DiskRecord{{
		VMName: "vm1", DiskName: "root", HostName: "node-a", Path: path,
		BackingImage: "base", SizeBytes: 1 << 30, StorageType: "local",
	}}); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	r := NewReconciler("node-a", dataDir, db, fake)
	r.SetAutoPullImage(func(context.Context, string) error { return nil })
	return db, fake, r, path
}

// A local start — the VM's own host restarting it, no transfer — keeps its
// disk: that file IS the VM's current disk.
//
// Mutation: treat every start as a transfer — the disk is set aside and the
// test goes red.
func TestStartPendingVM_LocalStartKeepsItsDisk(t *testing.T) {
	db, fake, r, path := supersededFixture(t, "starting")
	before, _ := os.Stat(path)
	fresh, _ := corrosion.GetVM(context.Background(), db, "vm1")
	r.startPendingVM(context.Background(), *fresh)

	if !startedOrDefined(fake, "vm1") {
		t.Fatal("vm1 was not started")
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("a local start replaced the VM's own disk (err %v)", err)
	}
	if aside, _ := filepath.Glob(path + ".superseded-*"); len(aside) != 0 {
		t.Fatalf("a local start set its disk aside: %v", aside)
	}
}

// A transfer re-armed after a transient start failure keeps the disk its
// first attempt rebuilt: setting it aside again would leave one more file
// beside the disk on every retry.
//
// Mutation: drop the transferDisks.note after the rebuild — the second
// attempt sets the rebuilt disk aside too, and the test goes red.
func TestStartPendingVM_RearmedTransferKeepsTheDiskItRebuilt(t *testing.T) {
	db, fake, r, path := supersededFixture(t, "running")
	ctx := context.Background()
	if err := corrosion.WriteVMRescheduleProof(ctx, db, corrosion.ActionProof{
		ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "node-a", Coordinator: "node-a",
	}, "vm1", "node-a"); err != nil {
		t.Fatal(err)
	}
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})

	fails := 1
	fake.FailStartDomain = func(string) error {
		if fails > 0 {
			fails--
			return errors.New("transient")
		}
		return nil
	}
	for i := 0; i < 2; i++ {
		fresh, _ := corrosion.GetVM(ctx, db, "vm1")
		r.startPendingVM(ctx, *fresh)
	}

	if vm, _ := corrosion.GetVM(ctx, db, "vm1"); vm.State != "running" {
		t.Fatalf("vm1 = %q / %q after the retry, want running", vm.State, vm.StateDetail)
	}
	aside, _ := filepath.Glob(path + ".superseded-*")
	if len(aside) != 1 {
		t.Fatalf("set-aside copies = %v, want exactly the one old copy", aside)
	}
}
