package libvirt

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// The scenarios of the lab reproduction (snapshot-repro.md) against the
// libvirt 10.0 model: markers A (0xaa at 1M) and B (0xbb at 2M) are written
// between steps, and every scenario ends with the domain shut off and started
// again, which opens every layer of its disk.

const (
	markA = 0xaa
	markB = 0xbb
)

func currentOf(t *testing.T, m *libvirt10) string {
	t.Helper()
	s, err := m.DomainSnapshotCurrent(golibvirt.Domain{Name: "vm"}, 0)
	if err != nil {
		return ""
	}
	return s.Name
}

func (m *libvirt10) revert(name string) {
	m.t.Helper()
	if err := revertToSnapshot(m, "vm", name, nil); err != nil {
		m.t.Fatalf("revert %s: %v", name, err)
	}
}

func (m *libvirt10) revertLive(name, save string) {
	m.t.Helper()
	if err := revertToLiveSnapshot(m, "vm", name, save, nil, nil); err != nil {
		m.t.Fatalf("revert (memory) %s: %v", name, err)
	}
}

// rm deletes the snapshot as litevirt does, and checks the files the
// delete wrote into or removed are among those SnapshotDiskFiles named
// before it — the files DeleteSnapshot's guard (b) asks other VMs about.
func (m *libvirt10) rm(name string) {
	m.t.Helper()
	files, ferr := snapshotDiskFiles(m, "vm", name)
	if ferr != nil {
		m.t.Fatalf("SnapshotDiskFiles %s: %v", name, ferr)
	}
	m.mu.Lock()
	before := len(m.touched)
	m.mu.Unlock()
	if err := deleteSnapshot(m, "vm", name); err != nil {
		m.t.Fatalf("delete %s: %v", name, err)
	}
	m.mu.Lock()
	touched := append([]string(nil), m.touched[before:]...)
	m.mu.Unlock()
	named := map[string]bool{}
	for _, f := range files {
		named[f] = true
	}
	for _, f := range touched {
		if !named[f] {
			m.t.Errorf("delete %s touched %s, which SnapshotDiskFiles (%v) did not name: guard (b) would not ask who backs on it", name, f, files)
		}
	}
	if _, err := m.DomainSnapshotLookupByName(golibvirt.Domain{Name: "vm"}, name, 0); err == nil {
		m.t.Fatalf("snapshot %s is still defined after its delete", name)
	}
}

// requireWhole stops and starts the domain and checks which markers it reads.
func (m *libvirt10) requireWhole(want map[byte]bool) {
	m.t.Helper()
	if err := m.stopAndStart(); err != nil {
		m.t.Fatalf("the domain does not start (libvirt unlinked %v): %v", m.unlinks, err)
	}
	for p, present := range want {
		if got := m.has(p, map[byte]int{markA: 1, markB: 2}[p]); got != present {
			m.t.Errorf("marker 0x%02x present=%v, want %v (active %s, unlinked %v)", p, got, present, m.active(), m.unlinks)
		}
	}
}

// A restore leaves the snapshot it restored current, as a snapshot is right
// after it is taken: libvirt decides between merging and unlinking on that.
func TestRevert_LeavesTheRestoredSnapshotCurrent(t *testing.T) {
	t.Run("disk", func(t *testing.T) {
		m := newLibvirt10(t)
		m.snapshot("d1")
		m.snapshot("d2")
		m.revert("d2")
		if got := currentOf(t, m); got != "d2" {
			t.Fatalf("after restoring d2 libvirt's current snapshot is %q", got)
		}
	})
	t.Run("memory", func(t *testing.T) {
		m := newLibvirt10(t)
		m.memorySnapshot("m1")
		save := m.memorySnapshot("m2")
		m.revertLive("m2", save)
		if got := currentOf(t, m); got != "m2" {
			t.Fatalf("after restoring m2 libvirt's current snapshot is %q", got)
		}
	})
	t.Run("only snapshot", func(t *testing.T) {
		m := newLibvirt10(t)
		save := m.memorySnapshot("m1")
		m.revertLive("m1", save)
		if got := currentOf(t, m); got != "m1" {
			t.Fatalf("after restoring m1 libvirt's current snapshot is %q", got)
		}
	})
}

// Scenario 1 (sr1): memory snapshots m1, A, m2, B, restore m2, rm m1, rm m2.
func TestSnapshotDelete_Scenario1_RestoreLaterThenDeleteBoth(t *testing.T) {
	m := newLibvirt10(t)
	m.memorySnapshot("m1")
	m.write(markA, 1)
	save := m.memorySnapshot("m2")
	m.write(markB, 2)
	m.revertLive("m2", save)
	m.rm("m1")
	m.rm("m2")
	m.requireWhole(map[byte]bool{markA: true, markB: false})
}

// Scenario 1 in lab-recheck-5's exact order (sr6): m1, restore m1, m2,
// restore m2, rm m1, rm m2.
func TestSnapshotDelete_Scenario1ExactOrder(t *testing.T) {
	m := newLibvirt10(t)
	m.write(markA, 1)
	s1 := m.memorySnapshot("m1")
	m.revertLive("m1", s1)
	s2 := m.memorySnapshot("m2")
	m.revertLive("m2", s2)
	m.rm("m1")
	m.rm("m2")
	m.requireWhole(map[byte]bool{markA: true})
}

// The minimal case (sr7): one memory snapshot, B, restore, rm. libvirt
// unlinked the VM's original root disk.
func TestSnapshotDelete_MinimalOneSnapshotRestoreDelete(t *testing.T) {
	m := newLibvirt10(t)
	m.write(markA, 1)
	save := m.memorySnapshot("m1")
	m.write(markB, 2)
	m.revertLive("m1", save)
	m.rm("m1")
	m.requireWhole(map[byte]bool{markA: true, markB: false})
}

// Scenario 2a (sr2): disk-only snapshots.
func TestSnapshotDelete_Scenario2a_DiskOnly(t *testing.T) {
	m := newLibvirt10(t)
	m.snapshot("d1")
	m.write(markA, 1)
	m.snapshot("d2")
	m.write(markB, 2)
	m.revert("d2")
	m.rm("d1")
	m.rm("d2")
	m.requireWhole(map[byte]bool{markA: true, markB: false})
}

// Scenario 2b (sr3): the restored snapshot deleted first.
func TestSnapshotDelete_Scenario2b_ReverseOrder(t *testing.T) {
	m := newLibvirt10(t)
	m.memorySnapshot("m1")
	m.write(markA, 1)
	save := m.memorySnapshot("m2")
	m.write(markB, 2)
	m.revertLive("m2", save)
	m.rm("m2")
	m.rm("m1")
	m.requireWhole(map[byte]bool{markA: true, markB: false})
}

// Scenario 2c (sr4, sr9): a stopped VM. The restore starts it; it is stopped
// again before the deletes, which libvirt then merges offline.
func TestSnapshotDelete_Scenario2c_StoppedVM(t *testing.T) {
	t.Run("two snapshots", func(t *testing.T) {
		m := newLibvirt10(t)
		m.setState(golibvirt.DomainShutoff)
		m.snapshot("s1")
		m.write(markA, 1)
		m.snapshot("s2")
		m.write(markB, 2)
		m.revert("s2")
		if err := m.DomainDestroy(golibvirt.Domain{Name: "vm"}); err != nil {
			t.Fatal(err)
		}
		m.rm("s1")
		m.rm("s2")
		m.requireWhole(map[byte]bool{markA: true, markB: false})
	})
	t.Run("one snapshot", func(t *testing.T) {
		m := newLibvirt10(t)
		m.setState(golibvirt.DomainShutoff)
		m.write(markA, 1)
		m.snapshot("d1")
		m.write(markB, 2)
		m.revert("d1")
		if err := m.DomainDestroy(golibvirt.Domain{Name: "vm"}); err != nil {
			t.Fatal(err)
		}
		m.rm("d1")
		m.requireWhole(map[byte]bool{markA: true, markB: false})
	})
}

// Scenario 2d (sr5) and 4: with no restore libvirt merges every time, and
// the chain stays one layer deep over many cycles. A control: it passes with
// or without the fix, and shows the model merges as the lab did.
func TestSnapshotDelete_WithoutRestoreLibvirtMerges(t *testing.T) {
	m := newLibvirt10(t)
	root := m.active()
	m.memorySnapshot("m1")
	m.write(markA, 1)
	m.memorySnapshot("m2")
	m.write(markB, 2)
	m.rm("m1")
	m.rm("m2")
	if got := m.active(); got != root {
		t.Fatalf("the domain is on %s, want merged back onto %s", got, root)
	}
	for i := 0; i < 20; i++ {
		m.snapshot("c")
		m.rm("c")
	}
	if got := m.active(); got != root {
		t.Fatalf("after 20 cycles the domain is on %s, want %s", got, root)
	}
	m.requireWhole(map[byte]bool{markA: true, markB: true})
}

// Guard (a): a snapshot libvirt holds as a non-current leaf — as every
// restore by an earlier build left one — is deleted as metadata only. libvirt
// would unlink the disk it was taken of, which is under the VM's live layer.
func TestSnapshotDelete_ANonCurrentLeafKeepsItsFiles(t *testing.T) {
	m := newLibvirt10(t)
	root := m.active()
	m.write(markA, 1)
	m.snapshot("m1")
	m.write(markB, 2)
	// What an earlier build's restore left: the metadata dropped and
	// redefined without CURRENT, so m1 is a leaf that is not current.
	snap, _ := m.DomainSnapshotLookupByName(golibvirt.Domain{Name: "vm"}, "m1", 0)
	x, _ := m.DomainSnapshotGetXMLDesc(snap, 0)
	if err := m.DomainSnapshotDelete(snap, golibvirt.DomainSnapshotDeleteMetadataOnly); err != nil {
		t.Fatal(err)
	}
	if _, err := m.DomainSnapshotCreateXML(golibvirt.Domain{Name: "vm"}, x, uint32(golibvirt.DomainSnapshotCreateRedefine)); err != nil {
		t.Fatal(err)
	}
	if currentOf(t, m) != "" {
		t.Fatal("setup: m1 is current")
	}
	m.rm("m1")
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("the VM's root disk %s is gone: %v", root, err)
	}
	m.requireWhole(map[byte]bool{markA: true, markB: true})
}

// SnapshotDiskFiles names each external disk's overlay and the disk it was
// taken of, which a delete commits into, and nothing for a disk the snapshot
// left alone (the model's sdb, snapshot='no').
func TestSnapshotDiskFiles_OverlayAndBase(t *testing.T) {
	m := newLibvirt10(t)
	root := m.active()
	m.snapshot("s1")
	s1 := m.active()
	m.snapshot("s2")
	got, err := snapshotDiskFiles(m, "vm", "s2")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{s1, m.active()}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("files of s2 = %v, want %v", got, want)
	}
	if got, _ := snapshotDiskFiles(m, "vm", "s1"); len(got) != 2 || got[0] != root || got[1] != s1 {
		t.Fatalf("files of s1 = %v, want [%s %s]", got, root, s1)
	}
}

// Scenario 1 and the minimal case on a VM with two disks: every disk's
// overlay is merged into its own base, and both disks keep their data.
func TestSnapshotDelete_MultiDisk(t *testing.T) {
	t.Run("scenario 1", func(t *testing.T) {
		m := newLibvirt10Disks(t, 2)
		roots := map[string]string{"vda": m.activeOf("vda"), "vdb": m.activeOf("vdb")}
		m.memorySnapshot("m1")
		m.writeOn("vda", markA, 1)
		m.writeOn("vdb", markA, 1)
		save := m.memorySnapshot("m2")
		m.writeOn("vda", markB, 2)
		m.writeOn("vdb", markB, 2)
		m.revertLive("m2", save)
		m.rm("m1")
		m.rm("m2")
		m.requireWhole(map[byte]bool{markA: true, markB: false})
		for dev, root := range roots {
			if got := m.activeOf(dev); got != root {
				t.Errorf("%s is on %s, want merged back onto %s", dev, got, root)
			}
			if !m.hasOn(dev, markA, 1) || m.hasOn(dev, markB, 2) {
				t.Errorf("%s: A present=%v B present=%v, want A only", dev, m.hasOn(dev, markA, 1), m.hasOn(dev, markB, 2))
			}
		}
	})
	t.Run("minimal", func(t *testing.T) {
		m := newLibvirt10Disks(t, 2)
		m.writeOn("vdb", markA, 1)
		save := m.memorySnapshot("m1")
		m.writeOn("vdb", markB, 2)
		m.revertLive("m1", save)
		m.rm("m1")
		m.requireWhole(nil)
		if !m.hasOn("vdb", markA, 1) || m.hasOn("vdb", markB, 2) {
			t.Errorf("vdb: A present=%v B present=%v, want A only", m.hasOn("vdb", markA, 1), m.hasOn("vdb", markB, 2))
		}
	})
}

// Guard (b)'s input on the model, scenario 3 (sr10c): a linked clone of the
// stopped VM backs on the snapshot's overlay, and an earlier clone on the
// disk the snapshot was taken of. SnapshotDiskFiles names both files, and
// the model's delete shows why it must: it removes the one and commits into
// the other, and the first clone cannot open its chain afterwards.
func TestSnapshotDiskFiles_NamesWhatALinkedCloneBacksOn(t *testing.T) {
	m := newLibvirt10(t)
	m.setState(golibvirt.DomainShutoff)
	root := m.active()
	early := filepath.Join(m.dir, "early-clone.qcow2")
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", root, early)
	m.snapshot("s1")
	clone := filepath.Join(m.dir, "clone.qcow2")
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", m.active(), clone)
	files, err := snapshotDiskFiles(m, "vm", "s1")
	if err != nil {
		t.Fatal(err)
	}
	named := map[string]bool{}
	for _, f := range files {
		named[f] = true
	}
	for _, c := range []string{clone, early} {
		layers, err := chain(c)
		if err != nil || len(layers) < 2 {
			t.Fatalf("setup: chain of %s = %v, %v", c, layers, err)
		}
		if !named[layers[1]] {
			t.Errorf("%s backs on %s, which SnapshotDiskFiles (%v) does not name", c, layers[1], files)
		}
	}
	m.rm("s1")
	if _, err := chain(clone); err == nil {
		t.Fatal("the model's delete left the clone's chain whole; the test no longer shows why guard (b) is needed")
	}
}

// Restoring an older snapshot while a later one exists (review I-2): the
// revert resets the live overlay over the older snapshot's base, so the
// restored snapshot's own overlay is out of the live chain. libvirt can
// never merge it (its overlay must be in the chain), so the delete was
// refused for good, and a snapshot record blocks migrate and move. It is
// deleted as metadata only, and the VM stays whole.
func TestSnapshotDelete_RestoreOlderThenDeleteBoth(t *testing.T) {
	for _, order := range [][2]string{{"m2", "m1"}, {"m1", "m2"}} {
		t.Run(order[0]+"-then-"+order[1], func(t *testing.T) {
			m := newLibvirt10(t)
			m.write(markA, 1)
			m.snapshot("m1")
			m.write(markB, 2)
			m.snapshot("m2")
			m.revert("m1")
			m.rm(order[0])
			m.rm(order[1])
			m.requireWhole(map[byte]bool{markA: true, markB: false})
		})
	}
}

// A libvirt that refuses REDEFINE|CURRENT (review I-1): the revert still
// succeeds and the snapshot is registered plain, but the revert says so with
// a RestoredNotCurrentError instead of hiding it in a log line, so the
// operator can tell the fix did not apply. Guard (a) then keeps the delete
// from unlinking anything: the VM stays whole.
func TestRevert_ARefusedCurrentIsReported(t *testing.T) {
	check := func(t *testing.T, err error) {
		t.Helper()
		var nc *RestoredNotCurrentError
		if !errors.As(err, &nc) {
			t.Fatalf("revert returned %v, want a RestoredNotCurrentError", err)
		}
		if nc.Snapshot != "m1" || !nc.Registered {
			t.Fatalf("RestoredNotCurrentError %+v, want snapshot m1 registered plain", nc)
		}
	}
	t.Run("disk", func(t *testing.T) {
		m := newLibvirt10(t)
		m.refuseCurrent = true
		m.write(markA, 1)
		m.snapshot("m1")
		m.write(markB, 2)
		check(t, revertToSnapshot(m, "vm", "m1", nil))
		if m.state() != golibvirt.DomainRunning {
			t.Fatal("the reverted domain is not running")
		}
		if _, err := m.DomainSnapshotLookupByName(golibvirt.Domain{Name: "vm"}, "m1", 0); err != nil {
			t.Fatalf("m1 is not registered after the revert: %v", err)
		}
		m.rm("m1")
		m.requireWhole(map[byte]bool{markA: true, markB: false})
	})
	t.Run("memory", func(t *testing.T) {
		m := newLibvirt10(t)
		m.refuseCurrent = true
		m.write(markA, 1)
		save := m.memorySnapshot("m1")
		m.write(markB, 2)
		check(t, revertToLiveSnapshot(m, "vm", "m1", save, nil, nil))
		m.rm("m1")
		m.requireWhole(map[byte]bool{markA: true, markB: false})
	})
}

// A snapshot over a raw base (review R1-I1): the overlay's own header names
// the base, which is raw and never parsed. libvirt merges it, as on main,
// and over many create/rm cycles the chain stays one overlay deep at most —
// no untracked layer piles up toward the 64-layer migrate limit.
func TestSnapshotDelete_ARawBaseIsMergedAsOnMain(t *testing.T) {
	for _, state := range []golibvirt.DomainState{golibvirt.DomainRunning, golibvirt.DomainShutoff} {
		t.Run(map[golibvirt.DomainState]string{golibvirt.DomainRunning: "running", golibvirt.DomainShutoff: "stopped"}[state], func(t *testing.T) {
			m := newLibvirt10Raw(t)
			m.setState(state)
			root := m.active()
			m.write(markA, 1)
			m.snapshot("s1")
			m.write(markB, 2)
			m.rm("s1")
			if got := m.active(); got != root {
				t.Fatalf("the domain is on %s, want merged back onto the raw base %s", got, root)
			}
			for i := 0; i < 5; i++ {
				m.snapshot("c")
				m.rm("c")
			}
			if got := m.active(); got != root {
				t.Fatalf("after 5 cycles the domain is on %s, want %s", got, root)
			}
			m.requireWhole(map[byte]bool{markA: true, markB: true})
		})
	}
}

// A block-device base (an LVM volume, a zvol): the chain lists it from the
// overlay's header and ends there, without opening it as an image.
func TestQcow2Chain_ABlockDeviceBaseEndsTheChain(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not installed")
	}
	dev := "/dev/null" // a device, as a block device is; no image header
	ov := filepath.Join(t.TempDir(), "vm-root.s1")
	run(t, "qemu-img", "create", "-q", "-u", "-f", "qcow2", "-F", "raw", "-b", dev, ov, "1M")
	layers, err := qcow2Chain(ov)
	if err != nil {
		t.Fatalf("qcow2Chain: %v", err)
	}
	if len(layers) != 2 || layers[0] != ov || layers[1] != dev {
		t.Fatalf("chain %v, want [%s %s]", layers, ov, dev)
	}
}
