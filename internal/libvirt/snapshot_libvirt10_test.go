package libvirt

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	markC = 0xcc
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
		if got := m.has(p, map[byte]int{markA: 1, markB: 2, markC: 3}[p]); got != present {
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

// Restoring an older snapshot while a later one exists (snapshot-lab.md,
// Round 1 row 5): the domain must then read exactly the older snapshot's
// state — in the chain qemu opens, which libvirt takes from the XML's
// <backingStore> when the XML gives one — in the running domain and after a
// stop and start, and the later snapshot must still restore its own state.
func TestRevert_AnOlderSnapshotRestoresItsState(t *testing.T) {
	for _, kind := range []string{"disk", "memory"} {
		for _, state := range []golibvirt.DomainState{golibvirt.DomainRunning, golibvirt.DomainShutoff} {
			if kind == "memory" && state == golibvirt.DomainShutoff {
				continue // a memory snapshot needs a running VM
			}
			name := kind + map[golibvirt.DomainState]string{golibvirt.DomainRunning: "/running", golibvirt.DomainShutoff: "/stopped"}[state]
			t.Run(name, func(t *testing.T) {
				m := newLibvirt10(t)
				m.setState(state)
				root := m.active()
				saves := map[string]string{}
				take := func(n string) {
					if kind == "memory" {
						saves[n] = m.memorySnapshot(n)
					} else {
						m.snapshot(n)
					}
				}
				restore := func(n string) {
					if kind == "memory" {
						m.revertLive(n, saves[n])
					} else {
						m.revert(n)
					}
				}
				check := func(when string, want map[byte]bool) {
					t.Helper()
					for p, present := range want {
						if got := m.has(p, map[byte]int{markA: 1, markB: 2, markC: 3}[p]); got != present {
							t.Errorf("%s: marker 0x%02x present=%v, want %v (qemu opens %s)", when, p, got, present, m.qemuSpec("vda"))
						}
					}
				}
				m.write(markA, 1)
				take("s1")
				s1 := m.active()
				m.write(markB, 2)
				take("s2")
				m.write(markC, 3)

				restore("s1")
				chain, err := m.dom.effective("vda")
				if err != nil {
					t.Fatal(err)
				}
				if len(chain) != 2 || chain[1] != root {
					t.Errorf("after restoring s1 qemu opens %v, want a fresh overlay directly on %s", chain, root)
				}
				check("after restoring s1", map[byte]bool{markA: true, markB: false, markC: false})
				if err := m.stopAndStart(); err != nil {
					t.Fatal(err)
				}
				check("after restoring s1 and a stop and start", map[byte]bool{markA: true, markB: false, markC: false})
				if _, err := os.Stat(s1); err != nil {
					t.Fatalf("s2's base %s is gone: %v", s1, err)
				}

				restore("s2")
				check("after restoring s2", map[byte]bool{markA: true, markB: true, markC: false})
			})
		}
	}
}

// Restoring the older snapshot again resets the overlay the first restore
// made, rather than leaving one more file each time; the later snapshot's
// overlay and base stay where they were.
func TestRevert_AnOlderSnapshotAgainReusesItsOverlay(t *testing.T) {
	m := newLibvirt10(t)
	m.write(markA, 1)
	m.snapshot("s1")
	s1 := m.active()
	m.write(markB, 2)
	m.snapshot("s2")
	s2 := m.active()
	m.revert("s1")
	first := m.active()
	if first == s1 || first == s2 {
		t.Fatalf("restoring s1 runs the VM on %s, a later snapshot's file", first)
	}
	m.write(markC, 3)
	m.revert("s1")
	if got := m.active(); got != first {
		t.Fatalf("the second restore runs on %s, want the first restore's overlay %s reset", got, first)
	}
	m.requireWhole(map[byte]bool{markA: true, markB: false, markC: false})
	for _, p := range []string{s1, s2} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("s2's file %s is gone: %v", p, err)
		}
	}
	matches, _ := filepath.Glob(filepath.Join(m.dir, "vm-root.s1-r*"))
	if len(matches) != 1 {
		t.Errorf("restore overlays %v, want one", matches)
	}
}

// repointRevertedDisk moves one disk onto the new overlay and drops its
// <backingStore> chain, as libvirt writes it; every other disk is left as
// it was, chain included.
func TestRepointRevertedDisk(t *testing.T) {
	in := `<domain type='kvm'><name>vm</name><devices>` +
		`<disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='/d/vm-root.s2' index='3'/>` +
		`<backingStore type='file' index='2'><format type='qcow2'/><source file='/d/vm-root.s1'/>` +
		`<backingStore type='file' index='1'><format type='qcow2'/><source file='/d/vm-root.qcow2'/><backingStore/></backingStore></backingStore>` +
		`<target dev='vda' bus='virtio'/></disk>` +
		`<disk type='file' device='disk'><source file='/d/vm-data.s2'/><backingStore type='file'><format type='qcow2'/><source file='/d/vm-data.qcow2'/></backingStore><target dev='vdb' bus='virtio'/></disk>` +
		`<disk type='file' device='cdrom'><source file='/c/vm.iso'/><target dev='sda' bus='sata'/></disk>` +
		`</devices></domain>`
	out, err := repointRevertedDisk(in, "vda", "/d/vm-root.s1-r1")
	if err != nil {
		t.Fatal(err)
	}
	if got := parseDomainDiskSources(out); got["vda"] != "/d/vm-root.s1-r1" || got["vdb"] != "/d/vm-data.s2" || got["sda"] != "/c/vm.iso" {
		t.Fatalf("disk sources %v", got)
	}
	chains := xmlBackingChains(out)
	if len(chains["vda"]) != 0 {
		t.Errorf("vda keeps a backingStore chain %v", chains["vda"])
	}
	if len(chains["vdb"]) != 1 || chains["vdb"][0] != "/d/vm-data.qcow2" {
		t.Errorf("vdb's chain changed: %v", chains["vdb"])
	}
	if _, err := repointRevertedDisk(in, "vdz", "/x"); err == nil {
		t.Error("a missing disk was not an error")
	}
}

func fileSum(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// Re-review R2-C1: restoring the same older memory snapshot again must
// bring its RAM back on the overlay the first restore made, not on the
// snapshot's own overlay the saved image names — that file is the later
// snapshot's base and holds the later writes. Every step reads the right
// markers, and the later snapshot's files never change.
func TestRevert_AnOlderMemorySnapshotAgainAndBack(t *testing.T) {
	m := newLibvirt10(t)
	m.write(markA, 1)
	save1 := m.memorySnapshot("m1")
	m1 := m.active()
	m.write(markB, 2)
	save2 := m.memorySnapshot("m2")
	m2 := m.active()
	m.write(markC, 3)
	sums := map[string]string{m1: fileSum(t, m1)}
	check := func(when string, want map[byte]bool) {
		t.Helper()
		for p, present := range want {
			if got := m.has(p, map[byte]int{markA: 1, markB: 2, markC: 3}[p]); got != present {
				t.Errorf("%s: marker 0x%02x present=%v, want %v (qemu opens %s)", when, p, got, present, m.qemuSpec("vda"))
			}
		}
		for f, sum := range sums {
			if got := fileSum(t, f); got != sum {
				t.Errorf("%s: %s, a later snapshot's file, changed", when, filepath.Base(f))
			}
		}
	}
	m.revertLive("m1", save1)
	check("restore m1", map[byte]bool{markA: true, markB: false, markC: false})
	m.write(markC, 3) // the guest writes after the restore
	m.revertLive("m1", save1)
	check("restore m1 again", map[byte]bool{markA: true, markB: false, markC: false})
	if got := m.active(); got == m1 {
		t.Fatalf("the second restore of m1 runs on %s, m2's base", got)
	}
	m.revertLive("m2", save2)
	check("restore m2", map[byte]bool{markA: true, markB: true, markC: false})
	sums[m2] = fileSum(t, m2)
	m.write(markC, 3)
	m.revertLive("m2", save2)
	check("restore m2 again", map[byte]bool{markA: true, markB: true, markC: false})
	if err := m.stopAndStart(); err != nil {
		t.Fatal(err)
	}
	check("after a stop and start", map[byte]bool{markA: true, markB: true, markC: false})
}

// Re-review R2-M3: a snapshot name with a dot (v1.2) is created, restored
// while a later snapshot exists, restored again and deleted like any
// other; the restore's overlay keeps the disk's name
// (vm-root.v1.2-r<time>), not a name cut at the dot.
func TestRevert_ADottedSnapshotName(t *testing.T) {
	m := newLibvirt10(t)
	m.write(markA, 1)
	m.snapshot("v1.2")
	m.write(markB, 2)
	m.snapshot("v2")
	m.revert("v1.2")
	got := filepath.Base(m.active())
	if !strings.HasPrefix(got, "vm-root.v1.2-r") {
		t.Fatalf("restoring v1.2 runs on %s, want vm-root.v1.2-r<time>", got)
	}
	m.revert("v1.2")
	if filepath.Base(m.active()) != got {
		t.Fatalf("the second restore runs on %s, want %s reused", filepath.Base(m.active()), got)
	}
	m.rm("v2")
	m.rm("v1.2")
	m.requireWhole(map[byte]bool{markA: true, markB: false})
}

// A litevirt domain's XML carries litevirt's namespaced metadata
// (litevirt-managed, litevirt-owner-epoch) and may carry qemu:commandline;
// the revert's repoint edits only the one disk's <source file=> and drops
// its <backingStore> chain, and leaves every other byte as it was.
func TestRepointRevertedDisk_KeepsNamespacedXML(t *testing.T) {
	in, err := os.ReadFile("testdata/revert_litevirt_domain.xml")
	if err != nil {
		t.Fatal(err)
	}
	out, err := repointRevertedDisk(string(in), "vda", "/var/lib/litevirt/disks/sl1-root.s1-r1700000000")
	if err != nil {
		t.Fatalf("repoint: %v", err)
	}
	if got := parseDomainDiskSources(out); got["vda"] != "/var/lib/litevirt/disks/sl1-root.s1-r1700000000" || got["sdb"] != "/var/lib/litevirt/cloudinit/sl1.iso" {
		t.Fatalf("disk sources %v", got)
	}
	if c := xmlBackingChains(out); len(c["vda"]) != 0 {
		t.Fatalf("vda keeps the chain %v", c["vda"])
	}
	// Outside vda's <source> and its <backingStore>, byte for byte.
	src := string(in)
	i := strings.Index(src, "<source file='/var/lib/litevirt/disks/sl1-root.s2'")
	j := strings.Index(src, "      <target dev='vda'")
	k := strings.Index(out, "      <target dev='vda'")
	if i < 0 || j < 0 || k < 0 || src[:i] != out[:i] || src[j:] != out[k:] {
		t.Fatalf("bytes outside vda's source and chain changed:\n%s", out)
	}
	for _, keep := range []string{`<litevirt-managed:managed xmlns:litevirt-managed="https://litevirt.dev/xmlns/managed/1" incarnation="3f1a"/>`,
		`<qemu:arg value='name=opt/litevirt/x,string=a&amp;b'/>`, "index='3'"} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q is gone", keep)
		}
	}
}

// Double-quoted attributes, as libvirt's own XML API may write them.
func TestRepointRevertedDisk_DoubleQuoted(t *testing.T) {
	in := `<domain xmlns:x="urn:x"><devices><disk type="file"><source file="/d/a.s2"/><backingStore type="file"><source file="/d/a.qcow2"/></backingStore><target dev="vda"/></disk></devices><x:y/></domain>`
	out, err := repointRevertedDisk(in, "vda", "/d/a.s1-r1")
	if err != nil {
		t.Fatal(err)
	}
	if want := `<domain xmlns:x="urn:x"><devices><disk type="file"><source file="/d/a.s1-r1"/><target dev="vda"/></disk></devices><x:y/></domain>`; out != want {
		t.Fatalf("got\n%s\nwant\n%s", out, want)
	}
}

// A memory snapshot restored on a stopped VM: the domain is shut off, so
// there is nothing to destroy, and the revert brings it back running at
// the snapshot's instant — for the newest snapshot and an older one. (It
// failed with "destroy domain before revert: domain is not running", on
// main too.)
func TestRevert_AMemorySnapshotOnAStoppedVM(t *testing.T) {
	for _, older := range []bool{false, true} {
		t.Run(map[bool]string{false: "newest", true: "older"}[older], func(t *testing.T) {
			m := newLibvirt10(t)
			m.write(markA, 1)
			save := m.memorySnapshot("m1")
			m.write(markB, 2)
			if older {
				m.memorySnapshot("m2")
				m.write(markC, 3)
			}
			if err := m.DomainDestroy(golibvirt.Domain{Name: "vm"}); err != nil {
				t.Fatal(err)
			}
			m.revertLive("m1", save)
			if m.state() != golibvirt.DomainRunning {
				t.Fatalf("after the revert the domain is in state %d, want running", m.state())
			}
			m.requireWhole(map[byte]bool{markA: true, markB: false, markC: false})
		})
	}
}

// The lab's round-3 loss (snapshot-lab.md): s1, s2, restore s1 twice, then
// restore s2 twice. libvirt rewrites s2's recorded base to s1's when the
// revert drops s1's metadata, so a base taken from s2's snapshot XML put
// s2's restore on root.qcow2 and B was gone. Every restore of s2 must read
// A and B, for disk and memory snapshots, running and stopped.
func TestRevert_TheLaterSnapshotAfterTheOlderOneTwice(t *testing.T) {
	for _, kind := range []string{"disk", "memory"} {
		for _, stopped := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stopped=%v", kind, stopped), func(t *testing.T) {
				m := newLibvirt10(t)
				saves := map[string]string{}
				take := func(n string) {
					if kind == "memory" {
						saves[n] = m.memorySnapshot(n)
					} else {
						m.snapshot(n)
					}
				}
				restore := func(n string) {
					if stopped && m.state() != golibvirt.DomainShutoff {
						if err := m.DomainDestroy(golibvirt.Domain{Name: "vm"}); err != nil {
							t.Fatal(err)
						}
					}
					if kind == "memory" {
						m.revertLive(n, saves[n])
					} else {
						m.revert(n)
					}
				}
				check := func(when string, a, b bool) {
					t.Helper()
					if got := m.has(markA, 1); got != a {
						t.Errorf("%s: A present=%v, want %v (qemu opens %s)", when, got, a, m.qemuSpec("vda"))
					}
					if got := m.has(markB, 2); got != b {
						t.Errorf("%s: B present=%v, want %v (qemu opens %s)", when, got, b, m.qemuSpec("vda"))
					}
				}
				m.write(markA, 1)
				take("s1")
				m.write(markB, 2)
				take("s2")
				s1 := filepath.Join(m.dir, "vm-root.s1")
				restore("s1")
				check("restore s1", true, false)
				restore("s1")
				check("restore s1 again", true, false)
				restore("s2")
				check("restore s2", true, true)
				if c, _ := m.dom.effective("vda"); len(c) < 2 || c[1] != s1 {
					t.Errorf("restoring s2 runs on %v, want a new overlay directly on %s", c, s1)
				}
				restore("s2")
				check("restore s2 again", true, true)
				m.rm("s1")
				m.rm("s2")
				m.requireWhole(map[byte]bool{markA: true, markB: true})
			})
		}
	}
}

// After a revert of s1 drops and redefines its metadata, libvirt has
// rewritten s2's recorded base to s1's; SnapshotDiskFiles still names the
// file s2's overlay backs on (root.s1), which a clone may use.
func TestSnapshotDiskFiles_NamesTheOverlaysRealBase(t *testing.T) {
	m := newLibvirt10(t)
	m.snapshot("s1")
	s1 := m.active()
	m.snapshot("s2")
	m.revert("s1")
	files, err := snapshotDiskFiles(m, "vm", "s2")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f == s1 {
			return
		}
	}
	t.Fatalf("SnapshotDiskFiles(s2) = %v, want it to name %s, the file s2's overlay backs on", files, s1)
}

// The lab (snapshot-lab.md, Round 3 row 2c): after a memory restore the
// domain came back without litevirt-managed metadata, from a saved image
// that does not carry it, until a background task stamped it ~10 s later.
// The revert carries litevirt's metadata from the domain it replaces into
// the restored domain and its definition, the moment they exist.
func TestRevert_AMemoryRestoreKeepsLitevirtMetadata(t *testing.T) {
	for _, older := range []bool{false, true} {
		for _, stopped := range []bool{false, true} {
			t.Run(fmt.Sprintf("older=%v/stopped=%v", older, stopped), func(t *testing.T) {
				m := newLibvirt10(t)
				m.saveWithoutManaged = true
				save := m.memorySnapshot("m1")
				if older {
					m.memorySnapshot("m2")
				}
				if stopped {
					if err := m.DomainDestroy(golibvirt.Domain{Name: "vm"}); err != nil {
						t.Fatal(err)
					}
				}
				var during string
				m.onRestore = func(x string) { during = x }
				m.revertLive("m1", save)
				x, err := m.DomainGetXMLDesc(golibvirt.Domain{Name: "vm"}, 0)
				if err != nil {
					t.Fatal(err)
				}
				for when, xml := range map[string]string{"restored domain": during, "definition": x} {
					if !strings.Contains(xml, `<litevirt-managed:managed xmlns:litevirt-managed="https://litevirt.dev/xmlns/managed/1" incarnation="1"/>`) ||
						!strings.Contains(xml, "litevirt-owner-epoch:owner-epoch") {
						t.Errorf("the %s lacks litevirt's metadata:\n%s", when, xml)
					}
				}
			})
		}
	}
}

// carryLitevirtMetadata adds only what is missing, into an existing
// <metadata> or a new one after <uuid>, and leaves other bytes alone.
func TestCarryLitevirtMetadata(t *testing.T) {
	from := `<domain><name>vm</name><uuid>u</uuid><metadata><litevirt-managed:managed xmlns:litevirt-managed="https://litevirt.dev/xmlns/managed/1" incarnation="7"/>` +
		`<other:x xmlns:other="urn:other"/><litevirt-owner-epoch:owner-epoch xmlns:litevirt-owner-epoch="https://litevirt.dev/xmlns/owner-epoch/1">3</litevirt-owner-epoch:owner-epoch></metadata></domain>`
	for _, tc := range []struct{ in, want string }{
		{`<domain><name>vm</name><uuid>u</uuid><devices/></domain>`,
			`<domain><name>vm</name><uuid>u</uuid><metadata><litevirt-managed:managed xmlns:litevirt-managed="https://litevirt.dev/xmlns/managed/1" incarnation="7"/><litevirt-owner-epoch:owner-epoch xmlns:litevirt-owner-epoch="https://litevirt.dev/xmlns/owner-epoch/1">3</litevirt-owner-epoch:owner-epoch></metadata><devices/></domain>`},
		{`<domain><name>vm</name><metadata><litevirt-owner-epoch:owner-epoch xmlns:litevirt-owner-epoch="https://litevirt.dev/xmlns/owner-epoch/1">3</litevirt-owner-epoch:owner-epoch></metadata></domain>`,
			`<domain><name>vm</name><metadata><litevirt-owner-epoch:owner-epoch xmlns:litevirt-owner-epoch="https://litevirt.dev/xmlns/owner-epoch/1">3</litevirt-owner-epoch:owner-epoch><litevirt-managed:managed xmlns:litevirt-managed="https://litevirt.dev/xmlns/managed/1" incarnation="7"/></metadata></domain>`},
		{from, from},
		// Re-review R4-M2: an element the saved image already carries is
		// replaced by the current one — the snapshot-time owner epoch (1)
		// gives way to today's (3) — and other namespaces are left alone.
		{`<domain><name>vm</name><metadata><other:x xmlns:other="urn:other"/><litevirt-owner-epoch:owner-epoch xmlns:litevirt-owner-epoch="https://litevirt.dev/xmlns/owner-epoch/1">1</litevirt-owner-epoch:owner-epoch></metadata></domain>`,
			`<domain><name>vm</name><metadata><other:x xmlns:other="urn:other"/><litevirt-owner-epoch:owner-epoch xmlns:litevirt-owner-epoch="https://litevirt.dev/xmlns/owner-epoch/1">3</litevirt-owner-epoch:owner-epoch><litevirt-managed:managed xmlns:litevirt-managed="https://litevirt.dev/xmlns/managed/1" incarnation="7"/></metadata></domain>`},
	} {
		got, err := carryLitevirtMetadata(tc.in, from)
		if err != nil || got != tc.want {
			t.Errorf("carry(%s)\n got %s (%v)\nwant %s", tc.in, got, err, tc.want)
		}
	}
}

// After a dotted snapshot (v1.2) libvirt would name the next overlay by
// cutting the live source at its last dot: vm-root.v1.s3, which no stem
// rule can tie back to the disk (snapshot-lab.md, Round 3 "4b"). The create
// names that overlay itself: vm-root.s3. Then everything is deleted and
// only the disk's own files were ever made.
func TestSnapshotCreate_AfterADottedSnapshotNamesTheOverlayByTheDisk(t *testing.T) {
	m := newLibvirt10(t)
	m.snapshot("v1.2")
	m.snapshot("s3")
	if got := filepath.Base(m.active()); got != "vm-root.s3" {
		t.Fatalf("s3's overlay is %s, want vm-root.s3", got)
	}
	m.snapshot("v2.0")
	m.snapshot("s4")
	if got := filepath.Base(m.active()); got != "vm-root.s4" {
		t.Fatalf("s4's overlay is %s, want vm-root.s4", got)
	}
	for _, n := range []string{"v1.2", "s3", "v2.0", "s4"} {
		m.rm(n)
	}
	m.requireWhole(nil)
}

// Re-review R4-M1: the base a restore puts the VM back on is read from the
// snapshot's overlay header; when that names a file that is gone, or a
// protocol (json:, nbd://) rather than a file, the restore fails before
// anything is torn down — the domain still defined and running on its
// disk, the snapshot still registered, the overlay untouched.
func TestRevert_ABadBaseFailsBeforeTeardown(t *testing.T) {
	for _, tc := range []string{"gone", "protocol"} {
		for _, memory := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/memory=%v", tc, memory), func(t *testing.T) {
				m := newLibvirt10(t)
				var save string
				if memory {
					save = m.memorySnapshot("s1")
				} else {
					m.snapshot("s1")
				}
				ov := m.active()
				switch tc {
				case "gone":
					missing := filepath.Join(m.dir, "missing-base.qcow2")
					run(t, "qemu-img", "rebase", "-q", "-u", "-f", "qcow2", "-F", "qcow2", "-b", missing, ov)
				case "protocol":
					run(t, "qemu-img", "rebase", "-q", "-u", "-f", "qcow2", "-F", "raw", "-b", "nbd://127.0.0.1:1/x", ov)
				}
				before := fileSum(t, ov)
				var err error
				if memory {
					err = revertToLiveSnapshot(m, "vm", "s1", save, nil, nil)
				} else {
					err = revertToSnapshot(m, "vm", "s1", nil)
				}
				if err == nil {
					t.Fatal("the restore went ahead over a bad base")
				}
				if m.dom == nil || m.state() != golibvirt.DomainRunning {
					t.Fatalf("the domain was torn down (state %d) before the base was judged: %v", m.state(), err)
				}
				if _, lerr := m.DomainSnapshotLookupByName(golibvirt.Domain{Name: "vm"}, "s1", 0); lerr != nil {
					t.Fatalf("the snapshot's metadata was dropped: %v", lerr)
				}
				if fileSum(t, ov) != before || m.active() != ov {
					t.Fatal("the overlay or the domain's disk changed")
				}
			})
		}
	}
}

// The owner epoch moves on after a memory snapshot is taken (a failover
// and back, a re-key); its restore must come back with today's epoch, not
// the saved image's, or the reconciler would read a superseded runtime.
func TestRevert_AMemoryRestoreCarriesTheCurrentOwnerEpoch(t *testing.T) {
	m := newLibvirt10(t)
	save := m.memorySnapshot("m1") // the image carries epoch 1
	m.mu.Lock()
	m.dom.metadata = strings.Replace(m.dom.metadata, ">1</litevirt-owner-epoch:owner-epoch>", ">4</litevirt-owner-epoch:owner-epoch>", 1)
	m.mu.Unlock()
	var during string
	m.onRestore = func(x string) { during = x }
	m.revertLive("m1", save)
	after, _ := m.DomainGetXMLDesc(golibvirt.Domain{Name: "vm"}, 0)
	for when, x := range map[string]string{"restored domain": during, "definition": after} {
		if !strings.Contains(x, ">4</litevirt-owner-epoch:owner-epoch>") || strings.Contains(x, ">1</litevirt-owner-epoch:owner-epoch>") {
			t.Errorf("the %s does not carry the current owner epoch 4:\n%s", when, x)
		}
	}
}
