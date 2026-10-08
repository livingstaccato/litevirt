package libvirt

import (
	"os"
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

func (m *libvirt10) rm(name string) {
	m.t.Helper()
	if err := deleteSnapshot(m, "vm", name); err != nil {
		m.t.Fatalf("delete %s: %v", name, err)
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
