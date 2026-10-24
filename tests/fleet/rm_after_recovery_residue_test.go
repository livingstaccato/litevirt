// A VM deleted after a failover: what the host it failed over from keeps,
// and what it does with it.
//
// Observed on lab 1 (hdv-1, 2026-10-15): node-4 was fenced, hdv-1 restarted on
// node-1, node-4 came back and set hdv-1's real disk aside as
// hdv-1-root.qcow2.superseded-<time>. `lv rm hdv-1` freed what node-1 held,
// and node-4 kept the copy and cloudinit/hdv-1.iso, with vm_disk_stranded
// vm/hdv-1@node-4 raised, until they were removed by hand.
//
// Now the old host, on its own pass, resolves the record, removes the deleted
// VM's own seed, and sets aside a disk still at its path. Every copy stays
// for the retention (superseded_disk_retention_days): it is the undo for
// `lv rm`. And a seed left on a host is never booted by another VM of the
// name: a start reuses a seed only when it is stamped as that VM's.
package fleet

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

const retention = 7 * 24 * time.Hour

// recoveredVM: rv ran on home with a host-local disk and a cloud-init seed;
// home failed, and rv was recovered onto other, where it runs.
type recoveredVM struct {
	c                  *Cluster
	other, home, coord *Node
	homeData           string
	homeRec            *health.Reconciler
	path, iso          string
	realBytes          []byte
	// extra holds the path of each further disk rv had on home, by name.
	extra map[string]string
}

func newRecoveredVM(t *testing.T) *recoveredVM {
	t.Helper()
	return newRecoveredVMWith(t)
}

// newRecoveredVMWith is newRecoveredVM with rv holding, besides its root
// disk, a host-local disk of each name in extra on home.
func newRecoveredVMWith(t *testing.T, extra ...string) *recoveredVM {
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
	appendTo(t, r.path, "rv's real data")
	r.realBytes = readFileT(t, r.path)
	r.iso = filepath.Join(r.homeData, "cloudinit", "rv.iso")
	if err := os.MkdirAll(filepath.Dir(r.iso), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.iso, []byte("rv's cloud-init seed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cloudinit.StampSeed(r.iso, "rv-1"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	disks := []corrosion.DiskRecord{{
		VMName: "rv", DiskName: "root", HostName: r.home.Name, Path: r.path,
		BackingImage: "base", SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda",
	}}
	r.extra = map[string]string{}
	for i, name := range extra {
		p := store.DiskPath("rv", name)
		if err := os.WriteFile(p, []byte("rv's "+name+" data"), 0o600); err != nil {
			t.Fatal(err)
		}
		r.extra[name] = p
		disks = append(disks, corrosion.DiskRecord{
			VMName: "rv", DiskName: name, HostName: r.home.Name, Path: p,
			SizeBytes: 1 << 20, StorageType: "local", TargetDev: "vd" + string(rune('b'+i)),
		})
	}
	if err := corrosion.InsertVM(ctx, r.coord.DB, corrosion.VMRecord{
		Name: "rv", HostName: r.home.Name, State: "running", CPUActual: 1, MemActual: 256,
		Spec: `{"name":"rv","cpu":1,"memory_mib":256,"uuid":"rv-1","on_host_failure":"restart-any","placement":{"host":"` + r.other.Name + `"}}`,
	}, nil, disks); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := r.coord.DB.Execute(ctx, `UPDATE vms SET created_at = ? WHERE name = 'rv'`,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	if got := fenceVictim(t, c, r.coord, r.home, r.other, r.coord); got != 1 {
		t.Fatalf("fencer fired %d times, want 1", got)
	}
	vm, _ := corrosion.GetVM(ctx, r.coord.DB, "rv")
	if vm == nil || vm.HostName != r.other.Name {
		t.Fatalf("rv after the failover = %+v, want it on %s", vm, r.other.Name)
	}
	if err := r.coord.DB.Execute(ctx, `UPDATE vms SET state = 'running', updated_at = ? WHERE name = 'rv'`, r.coord.DB.NowTS()); err != nil {
		t.Fatal(err)
	}
	r.other.Virt.SetState("rv", libvirtfake.StateRunning)
	r.homeRec = health.NewReconciler(r.home.Name, r.homeData, r.home.DB, r.home.Virt)
	r.homeRec.SetAutoPullImage(func(context.Context, string) error { return nil })
	return r
}

func appendTo(t *testing.T, p, data string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(data); err != nil {
		t.Fatal(err)
	}
}

func readFileT(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
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

// supersededCopies lists rv's set-aside copies on home.
func (r *recoveredVM) supersededCopies(t *testing.T) []string {
	t.Helper()
	m, err := filepath.Glob(r.path + ".superseded-*")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// sweepAt runs home's retention sweep as the hourly one would, at now+after.
func (r *recoveredVM) sweepAt(t *testing.T, after time.Duration) {
	t.Helper()
	if _, err := health.PurgeSupersededDisks(context.Background(), r.home.DB, r.homeData, retention, time.Now().Add(after), nil); err != nil {
		t.Fatal(err)
	}
}

// keptForRetention checks that the one copy of rv's real disk on home is kept
// through the retention and removed by the sweep after it.
func (r *recoveredVM) keptForRetention(t *testing.T) {
	t.Helper()
	copies := r.supersededCopies(t)
	if len(copies) != 1 {
		t.Fatalf("copies of rv's disk on home = %v, want one", copies)
	}
	if b := readFileT(t, copies[0]); !bytes.HasPrefix(b, r.realBytes) {
		t.Fatal("the copy on home is not rv's real disk")
	}
	r.sweepAt(t, retention-24*time.Hour)
	if !present(copies[0]) {
		t.Fatalf("the sweep removed %s inside the retention", copies[0])
	}
	r.sweepAt(t, retention+24*time.Hour)
	if present(copies[0]) {
		t.Fatalf("the sweep kept %s past the retention", copies[0])
	}
}

// TestFleet_RmAfterRecoveryKeepsTheCopyForRetention: rv fails over from home
// to other, home comes back and sets rv's real disk aside, and `lv rm rv` on
// other. home's next pass resolves vm_disk_stranded and removes rv's seed;
// the copy stays, and the retention sweep removes it only once it is older
// than superseded_disk_retention_days. --keep-disks does the same with the
// copy, which is retained either way, and keeps rv's seed: a seed a
// --keep-disks delete kept is never removed (review m8), and
// `lv host superseded-disks` lists it (re-review N2).
//
// (superseded_disk_retention_days: 0 starts no sweep at all
// (daemon.runSupersededDiskSweep), so a copy then stays until
// `lv host superseded-disks --purge` or `--remove`.)
//
// Mutations: remove a copy on the deleted-VM pass — the copy is gone after
// rm; drop the seed removal — the seed stays after rm; remove it after
// --keep-disks too — the seed is gone; keep the record open while a copy
// exists — vm_disk_stranded stays.
func TestFleet_RmAfterRecoveryKeepsTheCopyForRetention(t *testing.T) {
	for _, keepDisks := range []bool{false, true} {
		t.Run(map[bool]string{false: "rm", true: "keep-disks"}[keepDisks], func(t *testing.T) {
			r := newRecoveredVM(t)
			r.homeBack(t)
			if len(r.supersededCopies(t)) != 1 || present(r.path) {
				t.Fatalf("home did not set rv's disk aside: copies %v", r.supersededCopies(t))
			}

			r.rm(t, keepDisks)
			r.homeRec.ReconcileOnce(context.Background())

			if open := r.strandedOpen(t); len(open) != 0 {
				t.Fatalf("vm_disk_stranded is still open for the deleted rv: %+v", open)
			}
			switch {
			case keepDisks && (!present(r.iso) || !present(cloudinit.SeedOwnerPath(r.iso))):
				t.Fatalf("home removed rv's seed %s after lv rm --keep-disks", r.iso)
			case !keepDisks && (present(r.iso) || present(cloudinit.SeedOwnerPath(r.iso))):
				t.Fatalf("home still holds rv's seed %s after rv was deleted", r.iso)
			}
			if keepDisks {
				// It can hold user-data: lv host superseded-disks lists it
				// (re-review N2).
				resp, err := r.c.SelfClient(r.home).SupersededDisks(context.Background(), &pb.SupersededDisksRequest{Host: r.home.Name})
				if err != nil {
					t.Fatalf("lv host superseded-disks: %v", err)
				}
				listed := false
				for _, d := range resp.Disks {
					listed = listed || (d.Path == r.iso && d.Kept && d.Seed)
				}
				if !listed {
					t.Errorf("lv host superseded-disks on home does not list rv's kept seed %s: %+v", r.iso, resp.Disks)
				}
			}
			r.keptForRetention(t)
		})
	}
}

// TestFleet_RmWhileTheOldHostIsDownSetsTheDiskAsideWhenItIsBack: rv fails over
// from home, and is deleted while home is still down: home still has rv's real
// disk at its path, its seed, and the domain it was fenced with. home comes
// back with that domain running, which writes to the disk after the
// tombstone: nothing is touched under it, and the record stays open. Once it
// is shut off, home's pass sets the disk aside — whatever was last written to
// it — removes the seed and resolves the record; the copy follows the
// retention. Nothing is started.
//
// Mutations: set the disk aside under a running domain — the running step
// loses it; refuse a disk written after the tombstone — the record stays
// open; drop the set-aside on the deleted-VM pass — the disk stays at its
// path.
func TestFleet_RmWhileTheOldHostIsDownSetsTheDiskAsideWhenItIsBack(t *testing.T) {
	ctx := context.Background()
	r := newRecoveredVM(t)
	r.home.Virt.DefineStoppedDomain("rv", "52:54:00:00:00:01")
	r.rm(t, false)
	if !present(r.path) || !present(r.iso) {
		t.Fatal("the delete reached home while it was down")
	}

	r.home.Virt.SetState("rv", libvirtfake.StateRunning)
	r.homeBack(t)
	appendTo(t, r.path, " and what the leftover wrote after the delete")
	r.realBytes = readFileT(t, r.path)
	r.homeRec.ReconcileOnce(ctx)
	if !present(r.path) || !present(r.iso) || len(r.supersededCopies(t)) != 0 {
		t.Fatalf("home moved rv's disk or seed under a running domain: disk %v, seed %v", present(r.path), present(r.iso))
	}
	if len(r.strandedOpen(t)) != 1 {
		t.Fatal("the record of rv's disk on home was resolved while the disk is still at its path")
	}

	// Shut off, as a fenced host's domain is after its reboot.
	r.home.Virt.SetState("rv", libvirtfake.StateShutdown)
	r.homeRec.ReconcileOnce(ctx)
	if present(r.path) {
		t.Fatalf("home still holds rv's disk at %s", r.path)
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
	r.keptForRetention(t)
}

// stageSeedWriter puts a stand-in genisoimage first on PATH that writes the
// user-data it is given as the seed, so a test can read which VM's it is.
func stageSeedWriter(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nout=\nfor a; do last=$a; done\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = \"-output\" ]; then out=$2; shift; fi\n  shift\ndone\ncat \"$last/user-data\" > \"$out\"\n"
	if err := os.WriteFile(filepath.Join(dir, "genisoimage"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestFleet_FailoverOntoAHostWithADeletedVMsSeedWritesItsOwn: a host holds
// the seed of sx, a VM since deleted, with sx's user-data. A new VM sx, with
// its own user-data, fails over onto that host: the start writes sx's own
// seed and boots that, never the deleted one's — whether the seed left there
// is stamped, or from before seeds were stamped and written moments before
// the new sx was created.
//
// Mutations: reuse any existing seed in domainXMLFor — the deleted sx's
// user-data boots; reuse an unstamped seed written recently — the unstamped
// subtest boots it.
func TestFleet_FailoverOntoAHostWithADeletedVMsSeedWritesItsOwn(t *testing.T) {
	for _, stamped := range []bool{true, false} {
		t.Run(map[bool]string{true: "stamped", false: "unstamped"}[stamped], func(t *testing.T) {
			stageSeedWriter(t)
			ctx := context.Background()
			c := New(t, Options{Nodes: 3, SharedCRDT: true})
			t.Cleanup(c.Stop)
			target, from, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]
			targetData := filepath.Join(c.tmpRoot, target.Name, "data")
			store := image.NewStore(targetData)
			if err := store.Init(); err != nil {
				t.Fatal(err)
			}
			if err := qcow2.Create(store.ImagePath("base"), 64<<20, nil); err != nil {
				t.Fatal(err)
			}

			// The deleted sx's seed, left on target.
			iso := filepath.Join(targetData, "cloudinit", "sx.iso")
			if err := os.MkdirAll(filepath.Dir(iso), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(iso, []byte("#cloud-config\n# the deleted sx's keys\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			// Unstamped, it was written just now: inside the hour before
			// the new sx's row, so no age can tell it from the new sx's own.
			if stamped {
				if err := cloudinit.StampSeed(iso, "sx-1"); err != nil {
					t.Fatal(err)
				}
			}

			// The new sx runs on from.
			if err := corrosion.InsertVM(ctx, coord.DB, corrosion.VMRecord{
				Name: "sx", HostName: from.Name, State: "running", CPUActual: 1, MemActual: 256,
				Spec: `{"name":"sx","cpu":1,"memory_mib":256,"uuid":"sx-2","on_host_failure":"restart-any",` +
					`"placement":{"host":"` + target.Name + `"},"cloud_init":{"userdata":"#cloud-config\n# the new sx's keys\n"}}`,
			}, nil, []corrosion.DiskRecord{{
				VMName: "sx", DiskName: "root", HostName: from.Name, Path: store.DiskPath("sx", "root"),
				BackingImage: "base", SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda",
			}}); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			from.Virt.SetState("sx", libvirtfake.StateRunning)

			if got := fenceVictim(t, c, coord, from, target, coord); got != 1 {
				t.Fatalf("fencer fired %d times, want 1", got)
			}
			rec := health.NewReconciler(target.Name, targetData, target.DB, target.Virt)
			rec.SetAutoPullImage(func(context.Context, string) error { return nil })
			rec.ReconcileOnce(ctx)
			if vm, _ := corrosion.GetVM(ctx, coord.DB, "sx"); vm == nil || vm.HostName != target.Name || vm.State != "running" {
				t.Fatalf("sx = %+v, want it running on %s", vm, target.Name)
			}
			if !strings.Contains(target.Virt.DefinedXML("sx"), iso) {
				t.Fatalf("sx is not defined on %s with its seed %s", target.Name, iso)
			}
			b := readFileT(t, iso)
			if !bytes.Contains(b, []byte("the new sx's keys")) || bytes.Contains(b, []byte("the deleted sx's keys")) {
				t.Fatalf("sx booted the seed %q, want its own", b)
			}
			if owner, ok, _ := cloudinit.SeedOwner(iso); !ok || owner != "sx-2" {
				t.Fatalf("the seed is stamped %q (%v), want sx-2", owner, ok)
			}
		})
	}
}

// TestFleet_RecreateOnTheOldHostKeepsTheDeletedVMsDisk: rv fails over from
// home and is deleted while home is down, so home still has rv's real disk at
// its path. home is back, and a new rv is created on home before home's pass
// has set that disk aside. The create clears what an earlier VM of the name
// left at its paths — and would unlink the deleted rv's real data. It sets
// that disk aside first instead: the new rv is created, and the deleted rv's
// disk is kept as a copy (here retained while a VM of the name exists).
//
// Mutation: drop SetAsideBeforeCreate from createVM — the create's
// debris sweep unlinks the deleted rv's disk.
func TestFleet_RecreateOnTheOldHostKeepsTheDeletedVMsDisk(t *testing.T) {
	stageFakeGenisoimage(t)
	ctx := context.Background()
	r := newRecoveredVM(t)
	r.home.Virt.DefineStoppedDomain("rv", "52:54:00:00:00:01")
	r.rm(t, false)
	if !present(r.path) {
		t.Fatal("the delete reached home while it was down")
	}
	if err := r.coord.DB.Execute(ctx, `UPDATE hosts SET state = 'active', updated_at = ? WHERE name = ?`, r.coord.DB.NowTS(), r.home.Name); err != nil {
		t.Fatal(err)
	}
	if err := r.coord.DB.Execute(ctx, `DELETE FROM host_health WHERE target = ?`, r.home.Name); err != nil {
		t.Fatal(err)
	}

	importImageOn(t, r.c, r.home, "ubuntu")
	if _, err := r.c.SelfClient(r.home).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "rv", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: r.home.Name}}}); err != nil {
		t.Fatalf("create rv again on %s: %v", r.home.Name, err)
	}
	if vm, _ := corrosion.GetVM(ctx, r.coord.DB, "rv"); vm == nil || vm.HostName != r.home.Name {
		t.Fatalf("the new rv = %+v, want it on %s", vm, r.home.Name)
	}
	copies := r.supersededCopies(t)
	if len(copies) != 1 {
		t.Fatalf("copies of the deleted rv's disk on home = %v, want one", copies)
	}
	if b := readFileT(t, copies[0]); !bytes.HasPrefix(b, r.realBytes) {
		t.Fatal("the copy is not the deleted rv's real disk")
	}
	if b, err := os.ReadFile(r.path); err == nil && bytes.HasPrefix(b, r.realBytes) {
		t.Fatal("the new rv's disk is the deleted rv's")
	}
	if open := r.strandedOpen(t); len(open) != 0 {
		t.Fatalf("vm_disk_stranded is still open: %+v", open)
	}
	r.sweepAt(t, retention+24*time.Hour)
	if !present(copies[0]) {
		t.Fatal("the sweep removed the copy while a VM of the name exists")
	}
}

// homeActive marks home active again, without running its pass.
func (r *recoveredVM) homeActive(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if err := r.coord.DB.Execute(ctx, `UPDATE hosts SET state = 'active', updated_at = ? WHERE name = ?`, r.coord.DB.NowTS(), r.home.Name); err != nil {
		t.Fatal(err)
	}
	if err := r.coord.DB.Execute(ctx, `DELETE FROM host_health WHERE target = ?`, r.home.Name); err != nil {
		t.Fatal(err)
	}
}

// createRVOnHome creates a new rv on home, as `lv create rv` placed there.
func (r *recoveredVM) createRVOnHome(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	importImageOn(t, r.c, r.home, "ubuntu")
	if _, err := r.c.SelfClient(r.home).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "rv", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: r.home.Name}}}); err != nil {
		t.Fatalf("create rv again on %s: %v", r.home.Name, err)
	}
	if vm, _ := corrosion.GetVM(ctx, r.coord.DB, "rv"); vm == nil || vm.HostName != r.home.Name {
		t.Fatalf("the new rv = %+v, want it on %s", vm, r.home.Name)
	}
}

func globT(t *testing.T, pattern string) []string {
	t.Helper()
	m, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestFleet_KeepDisksOnAFailoversOldHost: rv fails over from home, and is
// deleted with --keep-disks while home is down, so home still has rv's real
// root disk at its path, and a data disk (rv-data-1.qcow2, a name the
// create's debris sweep never clears). The operator kept them: nothing puts
// them on the retention clock.
//
//   - home's pass leaves both at their paths and resolves the record;
//   - a new rv created on home leaves the data disk untouched, as on main,
//     and moves the root disk, which the create's sweep would have unlinked
//     (as on main), to rv-root.qcow2.kept-<time>, with a VM event naming
//     both;
//   - the retention sweep, past superseded_disk_retention_days, removes
//     neither.
//
// Mutations: set a kept disk aside on the deleted-VM pass — "pass first"
// finds .superseded- copies; drop the kept move before the create — the
// root disk is unlinked; drop the kept-row check in SetAsideBeforeCreate —
// "create first" finds a .superseded- copy.
func TestFleet_KeepDisksOnAFailoversOldHost(t *testing.T) {
	for _, passFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "create first", true: "pass first"}[passFirst], func(t *testing.T) {
			keptOnAFailoversOldHost(t, passFirst, func(r *recoveredVM) { r.rm(t, true) })
		})
	}
}

// TestFleet_UndecidedDeleteOnAFailoversOldHost: as KeepDisksOnAFailoversOldHost,
// but home's record does not say what the delete decided: the delete was made
// by an earlier release, which marks nothing, or its --keep-disks mark was
// lost to a write of the record home made from before it (LWW). Absent the
// decision, nothing is put on the retention clock: the disks are kept, as
// after --keep-disks.
//
// Mutation: set a disk aside whenever KeptByDelete is unset (ignore
// DeleteDecided) on the pass and before the create — every subtest finds a
// .superseded- copy.
func TestFleet_UndecidedDeleteOnAFailoversOldHost(t *testing.T) {
	deletes := []struct {
		name string
		del  func(t *testing.T, r *recoveredVM)
	}{
		{"an earlier release's delete", func(t *testing.T, r *recoveredVM) {
			// It tombstones the row, and records nothing on home's record.
			if err := corrosion.DeleteVM(context.Background(), r.other.DB, "rv"); err != nil {
				t.Fatal(err)
			}
		}},
		{"the keep-disks mark lost", func(t *testing.T, r *recoveredVM) {
			ctx := context.Background()
			subject := "rv@" + r.home.Name
			rows, err := r.coord.DB.Query(ctx, `SELECT evidence FROM health_conditions WHERE code = 'vm_disk_stranded' AND subject_id = ?`, subject)
			if err != nil || len(rows) != 1 {
				t.Fatalf("home's record of rv: %v, %v", rows, err)
			}
			before := rows[0].String("evidence")
			r.rm(t, true)
			after, err := health.StrandedDisksOf(ctx, r.coord.DB, "rv")
			if err != nil || len(after) != 1 || !after[0].KeptByDelete {
				t.Fatalf("the delete did not mark home's record: %+v, %v", after, err)
			}
			// home's write of its record, made from what it read before the
			// mark, wins.
			if err := r.coord.DB.Execute(ctx, `UPDATE health_conditions SET evidence = ? WHERE code = 'vm_disk_stranded' AND subject_id = ?`,
				before, subject); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, d := range deletes {
		for _, passFirst := range []bool{false, true} {
			t.Run(d.name+"/"+map[bool]string{false: "create first", true: "pass first"}[passFirst], func(t *testing.T) {
				keptOnAFailoversOldHost(t, passFirst, func(r *recoveredVM) { d.del(t, r) })
			})
		}
	}
}

// keptOnAFailoversOldHost: rv, with a root and a data disk on home, fails
// over to other, and del deletes it while home is down; home's pass (when
// passFirst) and a create of rv on home then keep both disks off the
// retention clock.
func keptOnAFailoversOldHost(t *testing.T, passFirst bool, del func(*recoveredVM)) {
	t.Helper()
	stageFakeGenisoimage(t)
	ctx := context.Background()
	r := newRecoveredVMWith(t, "data-1")
	data := r.extra["data-1"]
	dataBytes := readFileT(t, data)
	r.home.Virt.DefineStoppedDomain("rv", "52:54:00:00:00:01")
	del(r)
	if !present(r.path) || !present(data) {
		t.Fatal("the delete reached home while it was down")
	}
	r.homeActive(t)
	if passFirst {
		r.home.Virt.SetState("rv", libvirtfake.StateShutdown)
		r.homeRec.ReconcileOnce(ctx)
		if !present(r.path) || !present(data) {
			t.Fatalf("home's pass moved a disk the delete kept: root %v, data %v", present(r.path), present(data))
		}
		if open := r.strandedOpen(t); len(open) != 0 {
			t.Fatalf("vm_disk_stranded is still open: %+v", open)
		}
	}
	r.createRVOnHome(t)

	if c := globT(t, filepath.Join(filepath.Dir(r.path), "*.superseded-*")); len(c) != 0 {
		t.Fatalf("a disk the delete kept was set aside for the retention: %v", c)
	}
	if b := readFileT(t, data); !bytes.Equal(b, dataBytes) {
		t.Fatalf("the kept data disk at %s holds %q", data, b)
	}
	kept := globT(t, r.path+".kept-*")
	if len(kept) != 1 {
		t.Fatalf("kept copies of the root disk = %v, want one", kept)
	}
	if b := readFileT(t, kept[0]); !bytes.HasPrefix(b, r.realBytes) {
		t.Fatal("the .kept- file is not the deleted rv's real root disk")
	}
	if b, err := os.ReadFile(r.path); err == nil && bytes.HasPrefix(b, r.realBytes) {
		t.Fatal("the new rv's disk is the deleted rv's")
	}
	if open := r.strandedOpen(t); len(open) != 0 {
		t.Fatalf("vm_disk_stranded is still open: %+v", open)
	}
	evs, err := corrosion.ListVMEvents(ctx, r.coord.DB, "rv", 50, "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(evs, func(e corrosion.VMEventRecord) bool {
		return e.Type == "vm.disk.kept" && strings.Contains(e.Detail, r.path) && strings.Contains(e.Detail, kept[0])
	}) {
		t.Fatalf("no vm.disk.kept event naming %s and %s: %+v", r.path, kept[0], evs)
	}
	r.sweepAt(t, retention+24*time.Hour)
	if !present(kept[0]) || !present(data) {
		t.Fatalf("the retention sweep removed a kept disk: %s %v, %s %v", kept[0], present(kept[0]), data, present(data))
	}
}

// TestFleet_KeepDisksThenCreateOnTheSameHost: `lv rm --keep-disks rv`, then
// `lv create rv` on the same host. The create clears <name>-*.qcow2, which
// unlinked the root disk the operator kept. It is moved to
// rv-root.qcow2.kept-<time> instead, with its bytes; the new rv is created,
// and neither the retention sweep nor deleting the new rv removes it.
//
// "after a VM of the name came and went elsewhere": a new rv was created on
// the other host and deleted there in between, so the deleted VM's rows no
// longer name this host's disk; the host's own note of what --keep-disks kept
// still does.
//
// Mutations: drop the kept move before the create — the kept disk is
// unlinked; drop the delete's note (noteKeptDisks) — the second subtest's
// disk is unlinked.
func TestFleet_KeepDisksThenCreateOnTheSameHost(t *testing.T) {
	for _, between := range []bool{false, true} {
		t.Run(map[bool]string{false: "next create", true: "after a VM of the name came and went elsewhere"}[between], func(t *testing.T) {
			_, _, _ = keepDisksThenCreate(t, between)
		})
	}
}

// keepDisksThenCreate returns the cluster, the node and the .kept- file.
func keepDisksThenCreate(t *testing.T, between bool) (*Cluster, *Node, string) {
	stageFakeGenisoimage(t)
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	n := c.Nodes[0]
	dataDir := filepath.Join(c.tmpRoot, n.Name, "data")
	importImageOn(t, c, n, "ubuntu")
	createOn := func(on *Node) {
		t.Helper()
		if _, err := c.SelfClient(on).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
			Name: "rv", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: on.Name}}}); err != nil {
			t.Fatalf("create rv on %s: %v", on.Name, err)
		}
	}
	create := func() { t.Helper(); createOn(n) }
	create()
	disks, err := corrosion.GetVMDisks(ctx, n.DB, "rv")
	if err != nil || len(disks) != 1 {
		t.Fatalf("rv's disks = %+v, %v", disks, err)
	}
	path := disks[0].Path
	appendTo(t, path, "what the operator kept")
	keptBytes := readFileT(t, path)
	if _, err := c.SelfClient(n).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "rv", KeepDisks: true}); err != nil {
		t.Fatalf("lv rm --keep-disks rv: %v", err)
	}
	if !bytes.Equal(readFileT(t, path), keptBytes) {
		t.Fatal("--keep-disks did not keep the disk")
	}
	if between {
		other := c.Nodes[1]
		importImageOn(t, c, other, "ubuntu")
		createOn(other)
		if _, err := c.SelfClient(other).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "rv"}); err != nil {
			t.Fatalf("lv rm rv on %s: %v", other.Name, err)
		}
		if !bytes.Equal(readFileT(t, path), keptBytes) {
			t.Fatal("the kept disk changed while rv came and went on the other host")
		}
	}

	create()
	kept := globT(t, path+".kept-*")
	if len(kept) != 1 {
		t.Fatalf("kept files = %v, want the root disk the operator kept", kept)
	}
	if !bytes.Equal(readFileT(t, kept[0]), keptBytes) {
		t.Fatal("the .kept- file is not the disk the operator kept")
	}
	if b, err := os.ReadFile(path); err != nil || bytes.Equal(b, keptBytes) {
		t.Fatalf("the new rv's disk at %s: %v (it must be the new VM's own)", path, err)
	}
	purge := func() {
		t.Helper()
		if _, err := health.PurgeSupersededDisks(ctx, n.DB, dataDir, retention, time.Now().Add(retention+24*time.Hour), nil); err != nil {
			t.Fatal(err)
		}
	}
	purge()
	if _, err := c.SelfClient(n).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "rv"}); err != nil {
		t.Fatalf("lv rm rv: %v", err)
	}
	purge()
	if !present(kept[0]) {
		t.Fatalf("%s was removed", kept[0])
	}
	return c, n, kept[0]
}

// TestFleet_SupersededDisksListsAKeptDisk: `lv host superseded-disks` lists a
// .kept- file a create made, read-only and marked kept, with the path it was
// moved from and its size; --purge, --remove and --restore never take it.
//
// Mutations: leave the kept files out of the answer — the listing misses it;
// drop Kept from the answer — it is not marked kept.
func TestFleet_SupersededDisksListsAKeptDisk(t *testing.T) {
	c, n, kept := keepDisksThenCreate(t, false)
	ctx := context.Background()
	cl := c.SelfClient(n)
	size := int64(len(readFileT(t, kept)))
	list := func() *pb.SupersededDisk {
		t.Helper()
		resp, err := cl.SupersededDisks(ctx, &pb.SupersededDisksRequest{Host: n.Name})
		if err != nil {
			t.Fatalf("lv host superseded-disks: %v", err)
		}
		for _, d := range resp.Disks {
			if d.Path == kept {
				return d
			}
		}
		return nil
	}
	d := list()
	if d == nil || !d.Kept || d.DiskPath != strings.SplitN(kept, ".kept-", 2)[0] || d.SizeBytes != size || d.Held == "" || d.Retained != "" {
		t.Fatalf("listing of %s = %+v, want it kept, from its disk path, %d bytes, held", kept, d, size)
	}
	if _, err := cl.SupersededDisks(ctx, &pb.SupersededDisksRequest{Host: n.Name, Purge: true}); err != nil {
		t.Fatalf("--purge: %v", err)
	}
	if _, err := cl.SupersededDisks(ctx, &pb.SupersededDisksRequest{Host: n.Name, Purge: true,
		OlderThanSec: grpcapi.SupersededNamedOnlySec, RemovePaths: []string{kept}}); err == nil {
		t.Fatal("--remove took a kept disk")
	} else if !strings.Contains(err.Error(), "a disk a deleted VM was kept with") {
		t.Fatalf("--remove refusal %v does not say it is a kept disk", err)
	}
	if _, err := cl.SupersededDisks(ctx, &pb.SupersededDisksRequest{Host: n.Name, Purge: true,
		OlderThanSec: grpcapi.SupersededNamedOnlySec, RestorePath: kept}); err == nil {
		t.Fatal("--restore took a kept disk")
	}
	if !present(kept) || list() == nil {
		t.Fatalf("%s is gone or no longer listed", kept)
	}
}

// TestFleet_KeepDisksRefusedOnAnUnreadableNote: a --keep-disks delete whose
// host's note of the disks deletes kept (<data_dir>/kept-disks/<vm>.json)
// cannot be parsed is refused, naming the file and the remedy, with nothing
// tombstoned and the disk in place; once the file is removed, it goes ahead.
//
// Mutation: drop the note's name from the refusal — the message names no
// file.
func TestFleet_KeepDisksRefusedOnAnUnreadableNote(t *testing.T) {
	stageFakeGenisoimage(t)
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	n := c.Nodes[0]
	importImageOn(t, c, n, "ubuntu")
	if _, err := c.SelfClient(n).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "rv", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n.Name}}}); err != nil {
		t.Fatalf("create rv: %v", err)
	}
	disks, err := corrosion.GetVMDisks(ctx, n.DB, "rv")
	if err != nil || len(disks) != 1 {
		t.Fatalf("rv's disks = %+v, %v", disks, err)
	}
	note := filepath.Join(c.tmpRoot, n.Name, "data", "kept-disks", "rv.json")
	if err := os.MkdirAll(filepath.Dir(note), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(note, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = c.SelfClient(n).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "rv", KeepDisks: true})
	if err == nil {
		t.Fatal("the --keep-disks delete went ahead with its note unreadable")
	}
	for _, w := range []string{note, "repair or remove that file", "nothing was tombstoned"} {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("refusal %q does not say %q", err, w)
		}
	}
	if vm, _ := corrosion.GetVM(ctx, n.DB, "rv"); vm == nil {
		t.Fatal("rv was tombstoned")
	}
	if !present(disks[0].Path) {
		t.Fatal("rv's disk is gone")
	}
	if err := os.Remove(note); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(n).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "rv", KeepDisks: true}); err != nil {
		t.Fatalf("the --keep-disks delete, the note removed: %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, n.DB, "rv"); vm != nil || !present(disks[0].Path) {
		t.Fatalf("after the delete: row %+v, disk present %v", vm, present(disks[0].Path))
	}
}

// TestFleet_RecreateOnTheOldHostWithTheDiskPathMissing: rv fails over from
// home and is deleted while home is down; when home is back its disks
// directory is empty, as an unmounted volume's mount point is. A create of rv
// on home goes ahead, the record stays open, and a vm.disk.path_missing event
// names the path.
//
// Mutation: drop the event — none is found.
func TestFleet_RecreateOnTheOldHostWithTheDiskPathMissing(t *testing.T) {
	stageFakeGenisoimage(t)
	ctx := context.Background()
	r := newRecoveredVM(t)
	r.home.Virt.DefineStoppedDomain("rv", "52:54:00:00:00:01")
	r.rm(t, false)
	if err := os.Rename(r.path, filepath.Join(t.TempDir(), "unmounted")); err != nil {
		t.Fatal(err)
	}
	if ents, err := os.ReadDir(filepath.Dir(r.path)); err != nil || len(ents) != 0 {
		t.Fatalf("home's disks directory = %v, %v; want it empty", ents, err)
	}
	r.homeActive(t)
	r.createRVOnHome(t)
	if len(r.strandedOpen(t)) != 1 {
		t.Fatal("the record of rv's disk on home was resolved while its path reads as missing")
	}
	evs, err := corrosion.ListVMEvents(ctx, r.coord.DB, "rv", 50, "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(evs, func(e corrosion.VMEventRecord) bool {
		return e.Type == "vm.disk.path_missing" && strings.Contains(e.Detail, r.path)
	}) {
		t.Fatalf("no vm.disk.path_missing event naming %s: %+v", r.path, evs)
	}
}

// TestFleet_RecreateOnTheOldHostLeavesALinkedCloneBase: rv fails over from
// home and is deleted while home is down. Its data disk on home
// (rv-data.qcow2, a name the create's sweep clears) is the base of a linked
// clone lc on home. A new rv created on home sets the real root disk aside,
// and leaves the base where it is, as its sweep does: lc's chain is intact.
//
// Mutation: drop the protected-path filter before SetAsideBeforeCreate — the
// base is renamed.
func TestFleet_RecreateOnTheOldHostLeavesALinkedCloneBase(t *testing.T) {
	stageFakeGenisoimage(t)
	ctx := context.Background()
	r := newRecoveredVMWith(t, "data")
	base := r.extra["data"]
	baseBytes := readFileT(t, base)
	r.home.Virt.DefineStoppedDomain("rv", "52:54:00:00:00:01")
	r.rm(t, false)
	if !present(base) {
		t.Fatal("the delete reached home while it was down")
	}
	lcDisk := filepath.Join(filepath.Dir(base), "lc-root.qcow2")
	if err := os.WriteFile(lcDisk, []byte("lc's overlay"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, r.coord.DB, corrosion.VMRecord{
		Name: "lc", HostName: r.home.Name, State: "stopped", CPUActual: 1, MemActual: 256,
		Spec: `{"name":"lc","cpu":1,"memory_mib":256}`,
	}, nil, []corrosion.DiskRecord{{
		VMName: "lc", DiskName: "root", HostName: r.home.Name, Path: lcDisk, BackingDisk: base,
		SizeBytes: 1 << 20, StorageType: "local", TargetDev: "vda",
	}}); err != nil {
		t.Fatal(err)
	}
	r.homeActive(t)
	r.createRVOnHome(t)

	if b, err := os.ReadFile(base); err != nil || !bytes.Equal(b, baseBytes) {
		t.Fatalf("lc's base at %s was moved or changed: %v", base, err)
	}
	if c := globT(t, base+".*"); len(c) != 0 {
		t.Fatalf("lc's base was set aside: %v", c)
	}
	copies := r.supersededCopies(t)
	if len(copies) != 1 || !bytes.HasPrefix(readFileT(t, copies[0]), r.realBytes) {
		t.Fatalf("the deleted rv's root disk was not set aside: %v", copies)
	}
}
