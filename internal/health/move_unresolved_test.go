package health

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// moveDomainXML is a stopped domain whose disk vda names path.
func moveDomainXML(name, path string) string {
	return `<domain type="kvm"><name>` + name + `</name><devices><disk type="file" device="disk">` +
		`<source file="` + path + `"/><target dev="vda" bus="virtio"/></disk></devices></domain>`
}

// seedMovedVM inserts VM mv on node-a whose disk row names src, with both
// files present and the persistent config (in a fresh fake) naming configNames,
// and records an unresolved move of the disk to dst.
func seedMovedVM(t *testing.T, db *corrosion.Client, dataDir, configNames string, live, pivoted bool) (fake *libvirtfake.Fake, src, dst string) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	src, dst = filepath.Join(dir, "hot", "mv-root.qcow2"), filepath.Join(dir, "warm", "mv-root.qcow2")
	for _, p := range []string{src, dst} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if configNames == "src" {
		configNames = src
	} else {
		configNames = dst
	}
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "mv", HostName: "node-a", Spec: `{"name":"mv","cpu":1,"memory_mib":512}`, State: "running", CPUActual: 1, MemActual: 512},
		nil,
		[]corrosion.DiskRecord{{VMName: "mv", DiskName: "root", HostName: "node-a", Path: src, StorageType: "local",
			StorageVolume: "hot", SizeBytes: 1 << 30, TargetDev: "vda"}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake = libvirtfake.New()
	if err := fake.DefineDomain(moveDomainXML("mv", configNames)); err != nil {
		t.Fatal(err)
	}
	if err := RecordUnresolvedMove(dataDir, UnresolvedMove{VM: "mv", Disk: "root", TargetDev: "vda",
		Src: src, SrcType: "local", SrcPool: "hot", Dst: dst, DstType: "local", DstPool: "warm",
		Live: live, Pivoted: pivoted}); err != nil {
		t.Fatal(err)
	}
	return fake, src, dst
}

func movedRowPath(t *testing.T, db *corrosion.Client) string {
	t.Helper()
	disks, err := corrosion.GetVMDisks(context.Background(), db, "mv")
	if err != nil || len(disks) != 1 {
		t.Fatalf("disk rows: %+v %v", disks, err)
	}
	return disks[0].Path
}

// The reconciler's start (an HA restart, onboot, a self-heal) settles an
// unresolved move before it rebuilds the domain from the rows: the row is
// pointed at the file the persistent config names, so the rebuilt domain boots
// that file; or the start is refused when the copy may lack the guest's last
// writes.
func TestStartPendingVM_HonoursAnUnresolvedMove(t *testing.T) {
	t.Run("offline: the row follows the config", func(t *testing.T) {
		db := testReconcilerDB(t)
		r, _, _ := sharedDiskReconciler(t, db)
		fake, _, dst := seedMovedVM(t, db, r.dataDir, "dst", false, false)
		r.virt = fake
		fresh, _ := corrosion.GetVM(context.Background(), db, "mv")
		r.startPendingVM(context.Background(), *fresh)
		if got := movedRowPath(t, db); got != dst {
			t.Fatalf("disk row names %s, want the copy %s the config named", got, dst)
		}
		if x := fake.DefinedXML("mv"); !strings.Contains(x, dst) {
			t.Fatalf("the rebuilt domain does not boot the copy:\n%s", x)
		}
		if ms, _ := UnresolvedMovesOf(r.dataDir, "mv"); len(ms) != 0 {
			t.Fatalf("record kept after its resolution: %+v", ms)
		}
	})
	t.Run("live before the pivot, config names the copy: refused", func(t *testing.T) {
		db := testReconcilerDB(t)
		r, _, _ := sharedDiskReconciler(t, db)
		fake, src, dst := seedMovedVM(t, db, r.dataDir, "dst", true, false)
		r.virt = fake
		fresh, _ := corrosion.GetVM(context.Background(), db, "mv")
		r.startPendingVM(context.Background(), *fresh)
		if got := movedRowPath(t, db); got != src {
			t.Fatalf("disk row names %s, want it left on %s", got, src)
		}
		if st, _ := fake.DomainState("mv"); st == "running" {
			t.Fatal("the domain was started")
		}
		vm, _ := corrosion.GetVM(context.Background(), db, "mv")
		if vm.State != "error" || !strings.Contains(vm.StateDetail, dst) || !strings.Contains(vm.StateDetail, "stopped before a pivot") {
			t.Fatalf("VM state %q (%s), want error naming the copy", vm.State, vm.StateDetail)
		}
		if ms, _ := UnresolvedMovesOf(r.dataDir, "mv"); len(ms) != 1 {
			t.Fatalf("record dropped by a refused start: %+v", ms)
		}
	})
}

// The health check's restart honours the record too.
func TestStartGuarded_HonoursAnUnresolvedMove(t *testing.T) {
	db := testReconcilerDB(t)
	dataDir := t.TempDir()
	fake, src, dst := seedMovedVM(t, db, dataDir, "src", true, true)
	v := NewVMChecker("node-a", dataDir, db, nil)
	v.virt = fake
	err := v.startGuarded(context.Background(), "mv")
	if err == nil || !strings.Contains(err.Error(), dst) || !strings.Contains(err.Error(), src) || !strings.Contains(err.Error(), "was pivoted onto") {
		t.Fatalf("want the restart refused naming both files (the guest was pivoted, the config names the source), got %v", err)
	}
	if st, _ := fake.DomainState("mv"); st == "running" {
		t.Fatal("the domain was started")
	}

	// The operator points the config at the copy: the restart settles the row.
	if err := fake.DefineDomain(moveDomainXML("mv", dst)); err != nil {
		t.Fatal(err)
	}
	if err := v.startGuarded(context.Background(), "mv"); err != nil {
		t.Fatalf("startGuarded: %v", err)
	}
	if got := movedRowPath(t, db); got != dst {
		t.Fatalf("disk row names %s, want %s", got, dst)
	}
}

// An unreadable record refuses the VM's start rather than be ignored.
func TestResolveUnresolvedMoves_UnreadableRecordRefuses(t *testing.T) {
	db := testReconcilerDB(t)
	dataDir := t.TempDir()
	if err := RecordUnresolvedMove(dataDir, UnresolvedMove{VM: "mv", Disk: "root", Src: "/a", Dst: "/b"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(UnresolvedMoveFile(dataDir, "mv", "root"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := ResolveUnresolvedMoves(context.Background(), db, dataDir, "node-a", "mv", func() (string, error) { return "", nil })
	if err == nil {
		t.Fatal("an unreadable record was ignored")
	}
}
