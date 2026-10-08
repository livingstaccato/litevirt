package e2e

import (
	"encoding/xml"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Snapshot restore and delete against libvirt's own external-snapshot
// delete on the nested lab, one test per scenario of the reproduction that
// lost data (snapshot-repro.md, libvirt 10.0.0 / QEMU 8.2.2): 1, 1 in
// lab-recheck-5's order, the minimal case, 2a, 2b, 2c and 3. Markers are
// 64 KiB patterns at guest offsets 900M (A) and 901M (B), written through
// QEMU's block layer on a running VM and with qemu-io on a stopped one, and
// read back with qemu-io once the VM is stopped. Every test ends with the VM
// stopped, its markers checked, and started again: a start opens every
// layer of every disk. What is checked is read from the node — qemu-io,
// qemu-img and virsh — never from litevirt.
//
//	LITEVIRT_E2E=1 LV_BIN=/usr/local/bin/litevirt E2E_LAB_DIR=~/litevirt-lab \
//	  go test ./tests/e2e/ -run TestLab_Snapshot -v -timeout 90m

var snapMarkerAt = map[byte]string{0xaa: "900M", 0xbb: "901M"}

const (
	snapMarkA byte = 0xaa
	snapMarkB byte = 0xbb
)

// snapTestVM creates one small running VM on an up node.
func snapTestVM(l *lab, prefix string) (host, vm string) {
	l.t.Helper()
	h := labUpHosts(l, 1)[0]
	return h, l.createVMs(h, prefix, h)[h]
}

func (l *lab) mustLVf(host, what string, args ...string) {
	l.t.Helper()
	if out, err := l.lv(host, args...); err != nil {
		l.t.Fatalf("%s (lv %s): %v\n%s", what, strings.Join(args, " "), err, out)
	}
	l.mark("snap: %s", what)
}

// snapActiveDisk is the file the domain's vda is on, from virsh.
func snapActiveDisk(l *lab, host, vm string) string {
	l.t.Helper()
	out := l.mustSSH(host, 30*time.Second, "virsh -c qemu:///system domblklist "+shellQuote(vm))
	for _, ln := range strings.Split(out, "\n") {
		if f := strings.Fields(ln); len(f) == 2 && f[0] == "vda" {
			return f[1]
		}
	}
	l.t.Fatalf("%s on %s has no vda:\n%s", vm, host, out)
	return ""
}

func snapDomState(l *lab, host, vm string) string {
	out, _ := l.ssh(host, 20*time.Second, "virsh -c qemu:///system domstate "+shellQuote(vm))
	return strings.TrimSpace(out)
}

// snapWrite writes marker p into the VM's disk: through QEMU's block layer
// when the domain runs, with qemu-io on its active layer when it is shut off.
func snapWrite(l *lab, host, vm string, p byte) {
	l.t.Helper()
	io := fmt.Sprintf("write -P 0x%02x %s 64k", p, snapMarkerAt[p])
	var cmd string
	if snapDomState(l, host, vm) == "running" {
		cmd = "virsh -c qemu:///system qemu-monitor-command " + shellQuote(vm) + " --hmp " +
			shellQuote(`qemu-io -d /machine/peripheral/virtio-disk0/virtio-backend "`+io+`"`)
	} else {
		cmd = "qemu-io -f qcow2 -c " + shellQuote(io) + " " + shellQuote(snapActiveDisk(l, host, vm))
	}
	out := l.mustSSH(host, 60*time.Second, cmd)
	if strings.Contains(out, "error") || strings.Contains(out, "failed") {
		l.t.Fatalf("writing marker 0x%02x to %s: %s", p, vm, out)
	}
	l.mark("snap: %s marker 0x%02x written", vm, p)
}

// snapHas reads marker p from the stopped VM's disk with qemu-io.
func snapHas(l *lab, host, vm string, p byte) bool {
	l.t.Helper()
	out, err := l.ssh(host, 60*time.Second, "qemu-io -r -U -f qcow2 -c "+
		shellQuote(fmt.Sprintf("read -P 0x%02x %s 64k", p, snapMarkerAt[p]))+" "+shellQuote(snapActiveDisk(l, host, vm)))
	return err == nil && strings.Contains(out, "read 65536/65536") && !strings.Contains(out, "Pattern verification failed")
}

func snapStop(l *lab, host, vm string) {
	l.t.Helper()
	if snapDomState(l, host, vm) == "shut off" {
		return
	}
	l.mustLVf(host, "stop "+vm, "stop", vm, "--force")
	if !l.waitDomainState(host, vm, "shut off", 3*time.Minute) {
		l.t.Fatalf("%s did not stop", vm)
	}
}

// requireSnapVMWhole stops vm, checks its disk chain opens and which markers
// it reads, then starts it and waits for virsh to show it running.
func requireSnapVMWhole(l *lab, host, vm string, want map[byte]bool) {
	l.t.Helper()
	snapStop(l, host, vm)
	disk := snapActiveDisk(l, host, vm)
	if out, err := l.ssh(host, 60*time.Second, "qemu-img info -U --backing-chain "+shellQuote(disk)); err != nil {
		l.t.Fatalf("the chain of %s's disk %s on %s is broken: %v\n%s", vm, disk, host, err, out)
	}
	for p, present := range want {
		if got := snapHas(l, host, vm, p); got != present {
			l.t.Errorf("%s: marker 0x%02x present=%v, want %v", vm, p, got, present)
		}
	}
	if out, err := l.lv(host, "start", vm); err != nil {
		l.t.Fatalf("%s cannot be started: %v\n%s", vm, err, out)
	}
	if !l.waitDomainState(host, vm, "running", 3*time.Minute) {
		l.t.Fatalf("%s is not running after its start", vm)
	}
	l.mark("snap: %s whole, markers %v, started", vm, want)
}

func snapCreate(l *lab, host, vm, name string, memory bool) {
	l.t.Helper()
	args := []string{"snapshot", "create", vm, name}
	if memory {
		args = append(args, "--memory")
	}
	l.mustLVf(host, "create "+vm+" "+name, args...)
}

func snapRestore(l *lab, host, vm, name string) {
	l.t.Helper()
	l.mustLVf(host, "restore "+vm+" "+name, "snapshot", "restore", vm, name)
	if !l.waitDomainState(host, vm, "running", 3*time.Minute) {
		l.t.Fatalf("%s is not running after the restore of %s", vm, name)
	}
}

func snapRm(l *lab, host, vm, name string) {
	l.t.Helper()
	l.mustLVf(host, "rm "+vm+" "+name, "snapshot", "rm", vm, name)
}

// Scenario 1 (sr1): memory snapshots m1, A, m2, B, restore m2, rm m1, rm m2.
// libvirt refused rm m1 and, at rm m2, unlinked root.m1 (marker A).
func TestLab_SnapshotScenario1_RestoreLaterThenDeleteBoth(t *testing.T) {
	l := newLab(t)
	h, vm := snapTestVM(l, "snap1")
	snapCreate(l, h, vm, "m1", true)
	snapWrite(l, h, vm, snapMarkA)
	snapCreate(l, h, vm, "m2", true)
	snapWrite(l, h, vm, snapMarkB)
	snapRestore(l, h, vm, "m2")
	snapRm(l, h, vm, "m1")
	snapRm(l, h, vm, "m2")
	requireSnapVMWhole(l, h, vm, map[byte]bool{snapMarkA: true, snapMarkB: false})
}

// Scenario 1 in lab-recheck-5's order (sr6): m1, restore m1, m2, restore m2,
// rm m1, rm m2. libvirt unlinked the VM's root disk, then root.m1.
func TestLab_SnapshotScenario1ExactOrder(t *testing.T) {
	l := newLab(t)
	h, vm := snapTestVM(l, "snap1x")
	snapWrite(l, h, vm, snapMarkA)
	snapCreate(l, h, vm, "m1", true)
	snapRestore(l, h, vm, "m1")
	snapCreate(l, h, vm, "m2", true)
	snapRestore(l, h, vm, "m2")
	snapRm(l, h, vm, "m1")
	snapRm(l, h, vm, "m2")
	requireSnapVMWhole(l, h, vm, map[byte]bool{snapMarkA: true})
}

// The minimal case (sr7): one memory snapshot, B, restore, rm. libvirt
// unlinked the VM's root disk.
func TestLab_SnapshotMinimal_OneSnapshotRestoreDelete(t *testing.T) {
	l := newLab(t)
	h, vm := snapTestVM(l, "snapmin")
	snapWrite(l, h, vm, snapMarkA)
	snapCreate(l, h, vm, "m1", true)
	snapWrite(l, h, vm, snapMarkB)
	snapRestore(l, h, vm, "m1")
	snapRm(l, h, vm, "m1")
	requireSnapVMWhole(l, h, vm, map[byte]bool{snapMarkA: true, snapMarkB: false})
}

// Scenario 2a (sr2): scenario 1 with disk-only snapshots.
func TestLab_SnapshotScenario2a_DiskOnly(t *testing.T) {
	l := newLab(t)
	h, vm := snapTestVM(l, "snap2a")
	snapCreate(l, h, vm, "d1", false)
	snapWrite(l, h, vm, snapMarkA)
	snapCreate(l, h, vm, "d2", false)
	snapWrite(l, h, vm, snapMarkB)
	snapRestore(l, h, vm, "d2")
	snapRm(l, h, vm, "d1")
	snapRm(l, h, vm, "d2")
	requireSnapVMWhole(l, h, vm, map[byte]bool{snapMarkA: true, snapMarkB: false})
}

// Scenario 2b (sr3): the restored snapshot deleted first. libvirt unlinked
// root.m1 at rm m2.
func TestLab_SnapshotScenario2b_ReverseOrder(t *testing.T) {
	l := newLab(t)
	h, vm := snapTestVM(l, "snap2b")
	snapCreate(l, h, vm, "m1", true)
	snapWrite(l, h, vm, snapMarkA)
	snapCreate(l, h, vm, "m2", true)
	snapWrite(l, h, vm, snapMarkB)
	snapRestore(l, h, vm, "m2")
	snapRm(l, h, vm, "m2")
	snapRm(l, h, vm, "m1")
	requireSnapVMWhole(l, h, vm, map[byte]bool{snapMarkA: true, snapMarkB: false})
}

// Scenario 2c (sr4, sr9): snapshots of a stopped VM, markers written
// offline. The restore starts the VM; it is stopped again before the
// deletes, which libvirt then merges with QEMU started paused.
func TestLab_SnapshotScenario2c_StoppedVM(t *testing.T) {
	t.Run("two snapshots", func(t *testing.T) {
		l := newLab(t)
		h, vm := snapTestVM(l, "snap2c")
		snapStop(l, h, vm)
		snapCreate(l, h, vm, "s1", false)
		snapWrite(l, h, vm, snapMarkA)
		snapCreate(l, h, vm, "s2", false)
		snapWrite(l, h, vm, snapMarkB)
		snapRestore(l, h, vm, "s2")
		snapStop(l, h, vm)
		snapRm(l, h, vm, "s1")
		snapRm(l, h, vm, "s2")
		requireSnapVMWhole(l, h, vm, map[byte]bool{snapMarkA: true, snapMarkB: false})
	})
	t.Run("one snapshot", func(t *testing.T) {
		l := newLab(t)
		h, vm := snapTestVM(l, "snap2c1")
		snapStop(l, h, vm)
		snapWrite(l, h, vm, snapMarkA)
		snapCreate(l, h, vm, "d1", false)
		snapWrite(l, h, vm, snapMarkB)
		snapRestore(l, h, vm, "d1")
		snapStop(l, h, vm)
		snapRm(l, h, vm, "d1")
		requireSnapVMWhole(l, h, vm, map[byte]bool{snapMarkA: true, snapMarkB: false})
	})
}

// Scenario 3 (sr10c): a linked clone of the stopped source backs on the
// snapshot's overlay. libvirt merged the overlay away and the clone never
// started again. The delete and a restore (which resets that overlay) are
// refused, naming the clone, while it exists; the delete goes ahead once it
// is gone.
func TestLab_SnapshotScenario3_LinkedCloneOnTheSnapshot(t *testing.T) {
	l := newLab(t)
	h, src := snapTestVM(l, "snap3")
	snapStop(l, h, src)
	snapWrite(l, h, src, snapMarkA)
	snapCreate(l, h, src, "s1", false)
	clone := uniqueName("snap3c")
	l.onRestore(func() {
		if v := l.liveHost(); v != "" {
			l.lv(v, "rm", "--force", clone)
		}
	})
	l.mustLVf(h, "linked clone "+src+" → "+clone, "clone", src, clone, "--mode", "linked")
	if backing := l.mustSSH(h, 30*time.Second, "qemu-img info -U "+shellQuote(snapActiveDisk(l, h, clone))); !strings.Contains(backing, src+"-root.s1") {
		t.Fatalf("setup: the clone does not back on the snapshot's overlay:\n%s", backing)
	}
	out, err := l.lv(h, "snapshot", "rm", src, "s1")
	if err == nil {
		t.Fatalf("snapshot rm %s s1 went ahead while %s backs on its overlay:\n%s", src, clone, out)
	}
	if !strings.Contains(err.Error()+out, clone) {
		t.Errorf("the refusal does not name the clone %s: %v\n%s", clone, err, out)
	}
	l.mark("snap: rm %s s1 refused while %s backs on it", src, clone)
	// The restore resets the overlay the clone backs on (review C-1).
	if out, err := l.lv(h, "snapshot", "restore", src, "s1"); err == nil || !strings.Contains(err.Error()+out, clone) {
		t.Fatalf("snapshot restore %s s1 = %v, want refused naming %s while it backs on the overlay:\n%s", src, err, clone, out)
	}
	l.mark("snap: restore %s s1 refused while %s backs on it", src, clone)
	requireSnapVMWhole(l, h, clone, map[byte]bool{snapMarkA: true})
	snapStop(l, h, clone)
	l.mustLVf(h, "rm "+clone, "rm", "--force", clone)
	snapRm(l, h, src, "s1")
	requireSnapVMWhole(l, h, src, map[byte]bool{snapMarkA: true})
}

// snapXMLChain is the chain libvirt has for the domain's vda in its live
// XML: the source, then each <backingStore> under it. libvirt opens that
// chain as written, so it is what the guest reads.
func snapXMLChain(l *lab, host, vm string) []string {
	l.t.Helper()
	type bs struct {
		Source struct {
			File string `xml:"file,attr"`
		} `xml:"source"`
		BackingStore *bs `xml:"backingStore"`
	}
	var dom struct {
		Devices struct {
			Disks []struct {
				Source struct {
					File string `xml:"file,attr"`
				} `xml:"source"`
				Target struct {
					Dev string `xml:"dev,attr"`
				} `xml:"target"`
				BackingStore *bs `xml:"backingStore"`
			} `xml:"disk"`
		} `xml:"devices"`
	}
	out := l.mustSSH(host, 30*time.Second, "virsh -c qemu:///system dumpxml "+shellQuote(vm))
	if err := xml.Unmarshal([]byte(out), &dom); err != nil {
		l.t.Fatalf("%s's XML: %v", vm, err)
	}
	for _, d := range dom.Devices.Disks {
		if d.Target.Dev == "vda" {
			chain := []string{d.Source.File}
			for b := d.BackingStore; b != nil && b.Source.File != ""; b = b.BackingStore {
				chain = append(chain, b.Source.File)
			}
			return chain
		}
	}
	l.t.Fatalf("%s has no vda in its XML", vm)
	return nil
}

// snapHeaderChain is the chain of file read from the image headers with
// qemu-img --backing-chain.
func snapHeaderChain(l *lab, host, file string) []string {
	l.t.Helper()
	out := l.mustSSH(host, 60*time.Second, "qemu-img info -U --backing-chain "+shellQuote(file)+" | sed -n 's/^image: //p'")
	return strings.Fields(out)
}

// requireRestoredOnto checks, right after a restore of a snapshot taken of
// base, that the VM runs on a fresh overlay directly on base — in libvirt's
// live XML and in the image headers alike — and on no file in later.
func requireRestoredOnto(l *lab, host, vm, base string, later ...string) {
	l.t.Helper()
	x := snapXMLChain(l, host, vm)
	h := snapHeaderChain(l, host, x[0])
	if len(x) < 2 || x[1] != base || len(h) < 2 || h[1] != base {
		l.t.Fatalf("%s after the restore: libvirt opens %v and the headers say %v, want a new overlay directly on %s", vm, x, h, base)
	}
	for _, f := range later {
		for _, c := range append(x, h...) {
			if c == f {
				l.t.Fatalf("%s after the restore still uses %s, a later snapshot's file: libvirt %v, headers %v", vm, f, x, h)
			}
		}
	}
	l.mark("snap: %s restored onto %s (libvirt %v)", vm, base, x)
}

// Restoring an older snapshot while a later one exists (snapshot-lab.md,
// Round 1 row 5): the VM must read exactly the older snapshot's state, in
// the chain libvirt opens; the later snapshot must still restore its own;
// and both deletes then go through.
func TestLab_SnapshotRestoreOlderThenDeleteBoth(t *testing.T) {
	for _, memory := range []bool{false, true} {
		t.Run(map[bool]string{false: "disk", true: "memory"}[memory], func(t *testing.T) {
			l := newLab(t)
			h, vm := snapTestVM(l, "snapold")
			root := snapActiveDisk(l, h, vm)
			snapWrite(l, h, vm, snapMarkA)
			snapCreate(l, h, vm, "s1", memory)
			s1 := snapActiveDisk(l, h, vm)
			snapWrite(l, h, vm, snapMarkB)
			snapCreate(l, h, vm, "s2", memory)
			s2 := snapActiveDisk(l, h, vm)

			snapRestore(l, h, vm, "s1")
			requireRestoredOnto(l, h, vm, root, s1, s2)
			requireSnapVMWhole(l, h, vm, map[byte]bool{snapMarkA: true, snapMarkB: false})

			snapRestore(l, h, vm, "s2")
			requireRestoredOnto(l, h, vm, s1, s2)
			requireSnapVMWhole(l, h, vm, map[byte]bool{snapMarkA: true, snapMarkB: true})

			snapRestore(l, h, vm, "s1")
			snapRm(l, h, vm, "s2")
			snapRm(l, h, vm, "s1")
			if out := l.mustLV(h, "snapshot", "ls", vm); strings.Contains(out, "s1") || strings.Contains(out, "s2") {
				t.Fatalf("snapshots left after both deletes:\n%s", out)
			}
			requireSnapVMWhole(l, h, vm, map[byte]bool{snapMarkA: true, snapMarkB: false})
		})
	}
}
