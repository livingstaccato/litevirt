// Fleet scenario: `on-host-failure: restart-same` across a host failure.
//
// A restart-same VM with a host-local disk waits for its own host: before,
// the coordinator, which only ever sees a fenced (never active) original
// host, restarted it anywhere on a disk rebuilt blank from its image. A
// restart-same VM whose disks are all shared keeps being restarted on a
// healthy host, as before, its data intact.

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

// Mutations: drop the hold in recoverWorkloads — rs-local is rescheduled to
// another host and the test is red; hold every restart-same VM — rs-shared
// is left on the failed host and the test is red; never resolve the hold —
// the record stays open after home starts rs-local again and the test is red;
// drop the owed start in the reconciler — the shut-off domain a power fence
// leaves is synced to stopped, never started, and the test is red.
func TestFleet_RestartSameWaitsForItsHostOnlyWithALocalDisk(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	defer c.Stop()
	ctx := context.Background()
	other, home, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	homeData := filepath.Join(c.tmpRoot, home.Name, "data")
	store := image.NewStore(homeData)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(store.ImagePath("base"), 64<<20, nil); err != nil {
		t.Fatal(err)
	}
	path := store.DiskPath("rs-local", "root")
	if err := qcow2.CreateWithBacking(path, store.ImagePath("base"), 1<<30, nil); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("rs-local's real data")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	realBytes, _ := os.ReadFile(path)

	for _, v := range []struct{ name, path, storage string }{
		{"rs-local", path, "local"},
		{"rs-shared", "/mnt/nfs/rs-shared-root.qcow2", "nfs"},
	} {
		if err := corrosion.InsertVM(ctx, coord.DB, corrosion.VMRecord{
			Name: v.name, HostName: home.Name, State: "running", CPUActual: 1, MemActual: 256,
			Spec: `{"name":"` + v.name + `","cpu":1,"memory_mib":256,"on_host_failure":"restart-same","placement":{"host":"` + other.Name + `"}}`,
		}, nil, []corrosion.DiskRecord{{
			VMName: v.name, DiskName: "root", HostName: home.Name, Path: v.path,
			BackingImage: "base", SizeBytes: 1 << 30, StorageType: v.storage, TargetDev: "vda",
		}}); err != nil {
			t.Fatalf("InsertVM %s: %v", v.name, err)
		}
	}

	if got := fenceVictim(t, c, coord, home, other, coord); got != 1 {
		t.Fatalf("fencer fired %d times, want 1", got)
	}
	if vm, _ := corrosion.GetVM(ctx, coord.DB, "rs-local"); vm == nil || vm.HostName != home.Name || vm.State != "running" {
		t.Fatalf("rs-local = %+v, want it left on %s to wait for it", vm, home.Name)
	}
	if vm, _ := corrosion.GetVM(ctx, coord.DB, "rs-shared"); vm == nil || vm.HostName != other.Name || vm.State != "pending" {
		t.Fatalf("rs-shared = %+v, want it restarted on %s as before", vm, other.Name)
	}
	held, err := health.HeldForHostOf(ctx, coord.DB, "rs-local")
	if err != nil || held == nil || held.Host != home.Name {
		t.Fatalf("held record = %+v (err %v)", held, err)
	}
	evs, _ := corrosion.ListVMEvents(ctx, coord.DB, "rs-local", 10, "")
	if !hasEvent(evs, "vm.failover.held", home.Name) {
		t.Fatalf("no vm.failover.held event naming %s: %+v", home.Name, evs)
	}

	// home is back: it starts rs-local there, on its real disk, and clears
	// the hold.
	if err := coord.DB.Execute(ctx, `UPDATE hosts SET state = 'active', updated_at = ? WHERE name = ?`, coord.DB.NowTS(), home.Name); err != nil {
		t.Fatal(err)
	}
	// As on a real host after a power-off fence: the persistent domain is
	// still defined, shut off, with no reason libvirt kept across the
	// power loss.
	if err := home.Virt.DefineDomain(`<domain type='kvm'><name>rs-local</name></domain>`); err != nil {
		t.Fatal(err)
	}
	if st, _ := home.Virt.DomainStateReason("rs-local"); st.State != "stopped" || st.Reason != "unknown" {
		t.Fatalf("setup: rs-local on %s is %+v, want shut off with reason unknown", home.Name, st)
	}
	rec := health.NewReconciler(home.Name, homeData, home.DB, home.Virt)
	rec.ReconcileOnce(ctx)
	rec.ReconcileOnce(ctx)
	if vm, _ := corrosion.GetVM(ctx, coord.DB, "rs-local"); vm == nil || vm.State != "running" {
		t.Fatalf("rs-local = %+v after %s came back, want it started there (not synced to stopped)", vm, home.Name)
	}
	if st, _ := home.Virt.DomainStateReason("rs-local"); st.State != "running" {
		t.Fatalf("rs-local's domain on %s is %+v, want running", home.Name, st)
	}
	if !strings.Contains(home.Virt.DefinedXML("rs-local"), path) {
		t.Fatalf("rs-local was not started on %s on its disk at %s", home.Name, path)
	}
	if b, _ := os.ReadFile(path); !bytes.Equal(b, realBytes) {
		t.Fatal("rs-local's disk is not its real one")
	}
	if held, _ := health.HeldForHostOf(ctx, coord.DB, "rs-local"); held != nil {
		t.Fatalf("the hold is still open after %s started rs-local: %+v", home.Name, held)
	}
}
