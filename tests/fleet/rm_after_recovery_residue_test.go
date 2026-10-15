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
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
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
	if err := corrosion.InsertVM(ctx, r.coord.DB, corrosion.VMRecord{
		Name: "rv", HostName: r.home.Name, State: "running", CPUActual: 1, MemActual: 256,
		Spec: `{"name":"rv","cpu":1,"memory_mib":256,"uuid":"rv-1","on_host_failure":"restart-any","placement":{"host":"` + r.other.Name + `"}}`,
	}, nil, []corrosion.DiskRecord{{
		VMName: "rv", DiskName: "root", HostName: r.home.Name, Path: r.path,
		BackingImage: "base", SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda",
	}}); err != nil {
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
	if _, err := health.PurgeSupersededDisks(context.Background(), r.home.DB, r.homeData, retention, time.Now().Add(after)); err != nil {
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
// than superseded_disk_retention_days. --keep-disks does the same: the copy
// is retained either way, and the seed is not a disk.
//
// (superseded_disk_retention_days: 0 starts no sweep at all
// (daemon.runSupersededDiskSweep), so a copy then stays until
// `lv host superseded-disks --purge` or `--remove`.)
//
// Mutations: remove a copy on the deleted-VM pass — the copy is gone after
// rm; drop the seed removal — the seed stays; keep the record open while a
// copy exists — vm_disk_stranded stays.
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
			if present(r.iso) || present(cloudinit.SeedOwnerPath(r.iso)) {
				t.Fatalf("home still holds rv's seed %s after rv was deleted", r.iso)
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
// is stamped, or from before seeds were stamped.
//
// Mutation: reuse any existing seed in domainXMLFor — the deleted sx's
// user-data boots.
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
			old := time.Now().Add(-3 * time.Hour)
			if err := os.Chtimes(iso, old, old); err != nil {
				t.Fatal(err)
			}
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
