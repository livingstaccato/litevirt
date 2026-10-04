// Fleet scenario: a failover back onto a host that still holds an old copy of
// the VM's disk (drills 2 and 3 on main-b3368d7c).
//
// A host-local disk lives on the VM's host, so when the VM is rescheduled off
// a failed host the target never holds its current disk: any file at the
// disk's path there is from an earlier stay — the leftover cleanup removes
// the old domain and keeps its disk. The pending start rebuilt the overlay
// only when the file was MISSING, so it booted that superseded copy: pp5 and
// pp2 came up on 112 MiB disks holding old data instead of their 20 GiB disks.
//
// Multi-node by construction: the coordinator on one host fences the failed
// one and hands the VM to a third, whose reconciler starts it.

package fleet

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// A VM failed over back onto a host holding an old copy of its disk boots a
// disk rebuilt from its image at its recorded size — never the old copy — and
// the old copy is set aside beside it, not deleted.
//
// The disk row still names the host the VM was created on, the old host: the
// shape every failover left behind, and the one the drill hit.
//
// Mutation: drop the set-aside in startPendingVM — the old 112 MiB copy is
// booted and the test goes red on its size.
func TestFleet_FailoverBackOntoAnOldDiskCopyNeverBootsIt(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	old, victim, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	dataDir := filepath.Join(c.tmpRoot, old.Name, "data")
	store := image.NewStore(dataDir)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	path := store.DiskPath("pp5", "root")
	// The old copy: an overlay of the image at the image's own size, holding
	// data from the earlier stay.
	if err := qcow2.Create(store.ImagePath("base"), 112<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBacking(path, store.ImagePath("base"), 0, nil); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("data from the earlier stay")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	oldBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := corrosion.InsertVM(ctx, coord.DB, corrosion.VMRecord{
		Name: "pp5", HostName: victim.Name, State: "running", CPUActual: 1, MemActual: 256,
		Spec: `{"name":"pp5","cpu":1,"memory_mib":256,"on_host_failure":"restart-any","placement":{"host":"` + old.Name + `"}}`,
	}, nil, []corrosion.DiskRecord{{
		VMName: "pp5", DiskName: "root", HostName: old.Name, Path: path,
		BackingImage: "base", SizeBytes: 20 << 30, StorageType: "local", TargetDev: "vda",
	}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	if got := fenceVictim(t, c, coord, victim, old, coord); got != 1 {
		t.Fatalf("fencer fired %d times, want 1", got)
	}
	if vm, _ := corrosion.GetVM(ctx, old.DB, "pp5"); vm == nil || vm.HostName != old.Name || vm.State != "pending" {
		t.Fatalf("pp5 after the failover = %+v, want it pending on %s", vm, old.Name)
	}

	rec := health.NewReconciler(old.Name, dataDir, old.DB, old.Virt)
	rec.SetAutoPullImage(func(context.Context, string) error { return nil }) // the image is local
	rec.ReconcileOnce(ctx)

	if !strings.Contains(old.Virt.DefinedXML("pp5"), path) {
		t.Fatalf("pp5 was not started on %s with its disk at %s", old.Name, path)
	}
	info, err := qcow2.Info(path)
	if err != nil {
		t.Fatalf("pp5's disk: %v", err)
	}
	if info.VirtualSize != 20<<30 {
		t.Fatalf("pp5 booted a %d-byte disk, want its recorded 20 GiB — the old copy was booted", info.VirtualSize)
	}
	aside, _ := filepath.Glob(path + ".superseded-*")
	if len(aside) != 1 {
		t.Fatalf("set-aside copies = %v, want exactly one", aside)
	}
	if got, err := os.ReadFile(aside[0]); err != nil || !bytes.Equal(got, oldBytes) {
		t.Fatalf("the old copy was not kept intact beside the disk (err %v)", err)
	}
}
