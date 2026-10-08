package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// The lab (snapshot-lab.md): `lv rm -f` of a VM with two or more snapshots
// (here with their records already gone, as after deletes that went
// metadata-only — re-review R2-I1)
// left the middle overlay <vm>-root.m1 behind, backing onto a file the
// delete had removed. The recorded disk (the live layer) went by its row and
// <vm>-root.qcow2 by the debris glob, which matches .qcow2 names only.
// Deleting the VM removes every layer of its own chain and every overlay of
// its disk's name — and never one another VM backs on.
func TestDeleteVM_RemovesItsSnapshotOverlays(t *testing.T) {
	for _, tc := range []struct {
		name  string
		clone bool // another VM, unrecorded, backs on the middle overlay
	}{{"alone", false}, {"a clone backs on the middle overlay", true}} {
		t.Run(tc.name, func(t *testing.T) {
			needQemuImg(t)
			s, fake := provableCreateServer(t)
			fake.SetState("vm1", libvirtfake.StateRunning)
			dir := filepath.Join(s.dataDir, "disks")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(dir, "vm1-root.qcow2")
			m1 := filepath.Join(dir, "vm1-root.m1")
			m2 := filepath.Join(dir, "vm1-root.m2")
			stray := filepath.Join(dir, "vm1-root.m0") // out of the chain (a restored-older leftover)
			other := filepath.Join(dir, "vm1-x-root.m1")
			runQemuImg(t, "create", "-q", "-f", "qcow2", root, "1M")
			runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", root, m1)
			runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", m1, m2)
			runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", root, stray)
			runQemuImg(t, "create", "-q", "-f", "qcow2", other, "1M")
			ctx := adminCtx()
			if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "running"}, nil,
				[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "test-host", Path: m2, StorageType: "local"}}); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm1-x", HostName: "test-host", State: "stopped"}, nil,
				[]corrosion.DiskRecord{{VMName: "vm1-x", DiskName: "root", HostName: "test-host", Path: other, StorageType: "local"}}); err != nil {
				t.Fatal(err)
			}
			var clone string
			if tc.clone {
				clone = filepath.Join(dir, "cl-root.qcow2")
				runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", m1, clone)
				if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "cl", HostName: "test-host", State: "stopped"}, nil,
					[]corrosion.DiskRecord{{VMName: "cl", DiskName: "root", HostName: "test-host", Path: clone, StorageType: "local"}}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm1"}); err != nil {
				t.Fatalf("DeleteVM: %v", err)
			}
			gone := []string{m2, stray}
			kept := []string{other}
			if tc.clone {
				kept = append(kept, m1, root, clone)
			} else {
				gone = append(gone, m1, root)
			}
			for _, p := range gone {
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Errorf("%s outlived the VM (%v)", filepath.Base(p), err)
				}
			}
			for _, p := range kept {
				if _, err := os.Stat(p); err != nil {
					t.Errorf("%s was removed: another VM uses it (%v)", filepath.Base(p), err)
				}
			}
		})
	}
}

// overlayDeleteFixture is VM web on host test-host with a root disk on the
// snapshot overlay web-root.m2 over web-root.m1 over web-root.qcow2 in
// <data_dir>/disks, and snapshot records m1 and m2.
type overlayDeleteFixture struct {
	s            *Server
	dir          string
	root, m1, m2 string
}

func newOverlayDeleteFixture(t *testing.T, deleteWithVM bool) *overlayDeleteFixture {
	t.Helper()
	needQemuImg(t)
	s, fake := provableCreateServer(t)
	fake.SetState("web", libvirtfake.StateRunning)
	dir := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f := &overlayDeleteFixture{s: s, dir: dir,
		root: filepath.Join(dir, "web-root.qcow2"), m1: filepath.Join(dir, "web-root.m1"), m2: filepath.Join(dir, "web-root.m2")}
	runQemuImg(t, "create", "-q", "-f", "qcow2", f.root, "1M")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", f.root, f.m1)
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", f.m1, f.m2)
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "web", HostName: "test-host", State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{VMName: "web", DiskName: "root", HostName: "test-host",
		Path: f.m2, StorageType: "local", DeviceKind: "disk", DeleteWithVM: deleteWithVM}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"m1", "m2"} {
		if err := corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{ID: "web-" + n, VMName: "web", HostName: "test-host", Name: n, State: "ok", Type: "disk"}); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *overlayDeleteFixture) file(t *testing.T, name string, qcow2Over string) string {
	t.Helper()
	p := filepath.Join(f.dir, name)
	if qcow2Over == "" {
		if err := os.WriteFile(p, []byte("not an image: a user's file"), 0o600); err != nil {
			t.Fatal(err)
		}
	} else {
		runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", qcow2Over, p)
	}
	return p
}

func (f *overlayDeleteFixture) delete(t *testing.T) {
	t.Helper()
	if _, err := f.s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "web"}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
}

func fileThere(p string) bool { _, err := os.Stat(p); return err == nil }

// Re-review R1-C1: a VM delete removes only its own chain's layers and the
// overlays of its own snapshots — never a file that only shares the disk's
// name: a user's upload (recorded or not a qcow2 at all), an ISO, a qcow2
// that does not back into the VM's chain, or the out-of-chain overlay a
// recorded clone backs on.
func TestDeleteVM_RemovesOnlyItsOwnLayers(t *testing.T) {
	f := newOverlayDeleteFixture(t, true)
	stray := f.file(t, "web-root.m0", f.root)  // a restored-older leftover: backs into the chain
	strayUp := f.file(t, "web-root.k9", stray) // a later snapshot's layer above it, listed first
	iso := f.file(t, "web-root.iso", "")       // an ISO put here before uploads moved
	img := f.file(t, "web-root.img", "")       // a raw image
	otherBase := filepath.Join(f.dir, "other-base.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", otherBase, "1M")
	foreign := f.file(t, "web-root.bak", otherBase) // a qcow2 that does not back into the chain
	upload := f.file(t, "web-root.up", f.root)      // a qcow2 over the chain, but a recorded upload
	if err := f.s.recordPoolUpload(adminCtx(), "default", "_default", "pat@local", upload); err != nil {
		t.Fatal(err)
	}
	cloned := f.file(t, "web-root.m9", f.root) // out of chain, a recorded clone backs on it
	clone := filepath.Join(f.dir, "cl-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", cloned, clone)
	if err := corrosion.InsertVM(adminCtx(), f.s.db, corrosion.VMRecord{Name: "cl", HostName: "test-host", State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "cl", DiskName: "root", HostName: "test-host", Path: clone, StorageType: "local", BackingDisk: cloned}}); err != nil {
		t.Fatal(err)
	}
	f.delete(t)
	for _, p := range []string{f.m2, f.m1, stray, strayUp} {
		if fileThere(p) {
			t.Errorf("%s, the VM's own layer, outlived it", filepath.Base(p))
		}
	}
	// web-root.qcow2 too is kept: the clone reaches it through web-root.m9.
	for _, p := range []string{iso, img, foreign, upload, cloned, clone, f.root} {
		if !fileThere(p) {
			t.Errorf("%s was removed: it is not this VM's layer", filepath.Base(p))
		}
	}
}

// A disk recorded delete_with_vm=false (adopted) has none of its snapshot
// layers removed by the overlay cleanup. (The recorded file and the
// <vm>-<disk>.qcow2 the debris sweep matches go as they did on main.)
func TestDeleteVM_AKeptDiskKeepsItsLayers(t *testing.T) {
	f := newOverlayDeleteFixture(t, false)
	stray := f.file(t, "web-root.m0", f.root)
	f.delete(t)
	for _, p := range []string{f.m1, stray} {
		if !fileThere(p) {
			t.Errorf("%s was removed: the disk is kept with its VM deleted", filepath.Base(p))
		}
	}
}
