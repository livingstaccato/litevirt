// A VM deleted after a failover leaves nothing on the host it failed over
// from.
//
// Observed on lab 1 (hdv-1, 2026-10-15): node-4 was fenced, hdv-1 restarted on
// node-1, node-4 came back and set hdv-1's real disk aside as
// hdv-1-root.qcow2.superseded-<time>. `lv rm hdv-1` then freed what node-1
// held, and node-4 kept the copy and cloudinit/hdv-1.iso, with
// vm_disk_stranded vm/hdv-1@node-4 raised, until they were removed by hand.
//
// The delete records its decision for the disks on the stranded record before
// the tombstone, and the old host, on its own reconciler pass, removes what
// the record names for that incarnation — whenever it next runs, so a host
// that was down during the delete does it when it is back.
package fleet

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// recoveredVM: rv ran on home with a host-local disk and a cloud-init seed;
// home failed, and rv was recovered onto other, where it runs.
type recoveredVM struct {
	c                  *Cluster
	other, home, coord *Node
	homeData           string
	homeRec            *health.Reconciler
	path, iso          string
}

func newRecoveredVM(t *testing.T) *recoveredVM {
	t.Helper()
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	t.Cleanup(c.Stop)
	r := &recoveredVM{c: c, other: c.Nodes[0], home: c.Nodes[1], coord: c.Nodes[2]}
	r.homeData = filepath.Join(c.tmpRoot, r.home.Name, "data")
	// One filesystem for every fleet node: other's files of rv live under
	// their own root, as they would on their own host.
	r.other.Server.SetHostDiskRootForTest(filepath.Join(c.tmpRoot, r.other.Name, "hostroot"))

	store := image.NewStore(r.homeData)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(store.ImagePath("base"), 64<<20, nil); err != nil {
		t.Fatal(err)
	}
	r.path = store.DiskPath("rv", "root")
	if err := qcow2.CreateWithBacking(r.path, store.ImagePath("base"), 1<<30, nil); err != nil {
		t.Fatal(err)
	}
	r.iso = filepath.Join(r.homeData, "cloudinit", "rv.iso")
	if err := os.MkdirAll(filepath.Dir(r.iso), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.iso, []byte("rv's cloud-init seed"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.insert(t, time.Now().Add(-time.Hour))

	if got := fenceVictim(t, c, r.coord, r.home, r.other, r.coord); got != 1 {
		t.Fatalf("fencer fired %d times, want 1", got)
	}
	r.runOnOther(t)
	r.homeRec = health.NewReconciler(r.home.Name, r.homeData, r.home.DB, r.home.Virt)
	r.homeRec.SetAutoPullImage(func(context.Context, string) error { return nil })
	return r
}

// insert writes rv's row on home, created at createdAt (an incarnation).
func (r *recoveredVM) insert(t *testing.T, createdAt time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, r.coord.DB, corrosion.VMRecord{
		Name: "rv", HostName: r.home.Name, State: "running", CPUActual: 1, MemActual: 256,
		Spec: `{"name":"rv","cpu":1,"memory_mib":256,"on_host_failure":"restart-any","placement":{"host":"` + r.other.Name + `"}}`,
	}, nil, []corrosion.DiskRecord{{
		VMName: "rv", DiskName: "root", HostName: r.home.Name, Path: r.path,
		BackingImage: "base", SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda",
	}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := r.coord.DB.Execute(ctx, `UPDATE vms SET created_at = ? WHERE name = 'rv'`,
		createdAt.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

// runOnOther is the recovery's start on other: rv pending there runs.
func (r *recoveredVM) runOnOther(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	vm, _ := corrosion.GetVM(ctx, r.coord.DB, "rv")
	if vm == nil || vm.HostName != r.other.Name {
		t.Fatalf("rv after the failover = %+v, want it on %s", vm, r.other.Name)
	}
	if err := r.coord.DB.Execute(ctx, `UPDATE vms SET state = 'running', updated_at = ? WHERE name = 'rv'`, r.coord.DB.NowTS()); err != nil {
		t.Fatal(err)
	}
	r.other.Virt.SetState("rv", libvirtfake.StateRunning)
}

// homeBack: home is active again and its reconciler runs a pass.
func (r *recoveredVM) homeBack(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if err := r.coord.DB.Execute(ctx, `UPDATE hosts SET state = 'active', updated_at = ? WHERE name = ?`, r.coord.DB.NowTS(), r.home.Name); err != nil {
		t.Fatal(err)
	}
	if err := r.coord.DB.Execute(ctx, `DELETE FROM host_health WHERE target = ?`, r.home.Name); err != nil {
		t.Fatal(err)
	}
	r.homeRec.ReconcileOnce(ctx)
}

// setAsideCopy is the copy home made of rv's real disk.
func (r *recoveredVM) setAsideCopy(t *testing.T) string {
	t.Helper()
	got, err := health.StrandedDisksOf(context.Background(), r.coord.DB, "rv")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Disks) != 1 || got[0].Disks[0].Copy == "" {
		t.Fatalf("stranded records of rv = %+v, want home's set-aside copy", got)
	}
	cp := got[0].Disks[0].Copy
	if !present(cp) || present(r.path) {
		t.Fatalf("home did not set rv's disk aside: copy %s present=%v, disk present=%v", cp, present(cp), present(r.path))
	}
	return cp
}

func (r *recoveredVM) rm(t *testing.T, keepDisks bool) {
	t.Helper()
	if _, err := r.c.SelfClient(r.other).DeleteVM(context.Background(), &pb.DeleteVMRequest{Name: "rv", KeepDisks: keepDisks}); err != nil {
		t.Fatalf("lv rm rv on %s: %v", r.other.Name, err)
	}
}

func (r *recoveredVM) strandedOpen(t *testing.T) []health.StrandedDisks {
	t.Helper()
	got, err := health.StrandedDisksOf(context.Background(), r.coord.DB, "rv")
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// TestFleet_RmAfterRecoveryLeavesNothingOnTheOldHost: rv fails over from home
// to other, home comes back and sets rv's real disk aside, and `lv rm rv` on
// other. home's next pass removes the copy and the seed, and the
// vm_disk_stranded record is resolved. With --keep-disks both stay, and the
// record is still resolved: rv is gone.
//
// Mutations: drop the delete's decision on the stranded record — the copy
// and the seed stay on home; drop the removal on home's pass — they stay;
// ignore a --keep-disks decision — the keep-disks subtest loses both.
func TestFleet_RmAfterRecoveryLeavesNothingOnTheOldHost(t *testing.T) {
	for _, keepDisks := range []bool{false, true} {
		t.Run(map[bool]string{false: "rm", true: "keep-disks"}[keepDisks], func(t *testing.T) {
			r := newRecoveredVM(t)
			r.homeBack(t)
			cp := r.setAsideCopy(t)
			if !present(r.iso) {
				t.Fatal("home's seed of rv is gone while rv exists")
			}
			// While rv exists, home keeps both, pass after pass.
			r.homeRec.ReconcileOnce(context.Background())
			if !present(cp) || !present(r.iso) {
				t.Fatalf("home removed rv's leftovers while rv exists: copy %v, seed %v", present(cp), present(r.iso))
			}

			r.rm(t, keepDisks)
			r.homeRec.ReconcileOnce(context.Background())

			if open := r.strandedOpen(t); len(open) != 0 {
				t.Fatalf("vm_disk_stranded is still open for the deleted rv: %+v", open)
			}
			if keepDisks {
				if !present(cp) || !present(r.iso) {
					t.Fatalf("a --keep-disks rm removed rv's leftovers on home: copy %v, seed %v", present(cp), present(r.iso))
				}
				return
			}
			if present(cp) {
				t.Fatalf("home still holds %s after rv was deleted", cp)
			}
			if present(r.iso) {
				t.Fatalf("home still holds %s after rv was deleted", r.iso)
			}
		})
	}
}

// TestFleet_RmAfterRecoveryKeepsAnotherIncarnationsCopy: rv's first
// incarnation fails over from home, and home sets its disk aside. It is
// deleted while home's reconciler is not running, and a VM of the same name is
// created, fails over from home in turn, and is deleted. The second delete
// removes the second incarnation's copy only: the first's is not its to remove.
// While the second exists, nothing of the first's is removed either.
//
// Mutation: drop the incarnation match on home's removal — the first
// incarnation's copy goes with the second's delete.
func TestFleet_RmAfterRecoveryKeepsAnotherIncarnationsCopy(t *testing.T) {
	ctx := context.Background()
	r := newRecoveredVM(t)
	r.homeBack(t)
	first := r.setAsideCopy(t)

	// The first incarnation is deleted with its disks; home does not run a
	// pass before the name is taken again.
	r.rm(t, false)
	r.other.Virt.UndefineDomain("rv", false)
	if err := os.WriteFile(r.path, []byte("the second rv's disk"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.insert(t, time.Now().Add(-30*time.Minute))
	if err := r.coord.DB.Execute(ctx, `UPDATE hosts SET state = 'active', updated_at = ? WHERE name = ?`, r.coord.DB.NowTS(), r.home.Name); err != nil {
		t.Fatal(err)
	}
	// The second rv runs on home; home's pass keeps the first's copy: a VM
	// of that name exists.
	r.home.Virt.SetState("rv", libvirtfake.StateRunning)
	r.homeRec.ReconcileOnce(ctx)
	if !present(first) {
		t.Fatal("home removed the first rv's copy while a VM of the name exists")
	}

	// The second rv fails over from home: the coordinator moves its row to
	// other and records the disk it leaves on home, as noteDiskStranded does
	// (driven directly: a second fence of the same host is not what this
	// pins). home comes back.
	r.home.Virt.UndefineDomain("rv", false)
	if err := r.coord.DB.Execute(ctx, `UPDATE vms SET host_name = ?, state = 'pending', updated_at = ? WHERE name = 'rv'`,
		r.other.Name, r.coord.DB.NowTS()); err != nil {
		t.Fatal(err)
	}
	disks, err := corrosion.GetVMDisks(ctx, r.coord.DB, "rv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := health.RecordStrandedDisks(ctx, r.coord.DB, r.coord.Name, "rv", r.home.Name, r.other.Name, disks, time.Now()); err != nil {
		t.Fatal(err)
	}
	r.runOnOther(t)
	r.homeBack(t)
	var second string
	for _, rec := range r.strandedOpen(t) {
		for _, d := range rec.Disks {
			if d.Copy != "" && d.Copy != first {
				second = d.Copy
			}
		}
	}
	if second == "" || !present(second) {
		t.Fatalf("home did not set the second rv's disk aside: %+v", r.strandedOpen(t))
	}

	r.rm(t, false)
	r.homeRec.ReconcileOnce(ctx)
	if present(second) {
		t.Fatalf("home still holds the second rv's copy %s after its delete", second)
	}
	if !present(first) {
		t.Fatalf("the second rv's delete removed %s, the first rv's copy", first)
	}
}

// TestFleet_RmWhileTheOldHostIsDownCleansUpWhenItIsBack: rv fails over from
// home, and is deleted while home is still down: home still has rv's real
// disk at its path, its seed, and the domain it was fenced with, shut off.
// When home is back its first pass removes the disk and the seed; the domain
// is left to the operator (vm_orphan_runtime), and nothing is started.
//
// Mutations: drop the removal of a disk still at its path — it stays on home;
// remove under a running domain — the running-domain step loses the disk.
func TestFleet_RmWhileTheOldHostIsDownCleansUpWhenItIsBack(t *testing.T) {
	ctx := context.Background()
	r := newRecoveredVM(t)
	r.home.Virt.DefineStoppedDomain("rv", "52:54:00:00:00:01")
	r.rm(t, false)
	if !present(r.path) || !present(r.iso) {
		t.Fatal("the delete reached home while it was down")
	}

	// home is back, but the domain it kept runs: nothing is removed under it.
	r.home.Virt.SetState("rv", libvirtfake.StateRunning)
	r.homeBack(t)
	if !present(r.path) || !present(r.iso) {
		t.Fatalf("home removed rv's disk or seed under a running domain: disk %v, seed %v", present(r.path), present(r.iso))
	}
	if len(r.strandedOpen(t)) != 1 {
		t.Fatal("the record of rv's disk on home was resolved while it is kept")
	}

	// Shut off, as a fenced host's domain is after its reboot.
	r.home.Virt.SetState("rv", libvirtfake.StateShutdown)
	r.homeRec.ReconcileOnce(ctx)
	if present(r.path) {
		t.Fatalf("home still holds rv's disk %s after rv was deleted", r.path)
	}
	if present(r.iso) {
		t.Fatalf("home still holds %s after rv was deleted", r.iso)
	}
	if open := r.strandedOpen(t); len(open) != 0 {
		t.Fatalf("vm_disk_stranded is still open for the deleted rv: %+v", open)
	}
	if st, _ := r.home.Virt.RawState("rv"); st == libvirtfake.StateRunning {
		t.Fatal("home started rv's domain")
	}
}
