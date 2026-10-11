package e2e

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// VM disk files are the guest's data: a disk litevirt makes is the owner's
// alone (0600), and qemu opens it as its owner because libvirt's DAC driver
// chowns it at start. That chown, and libvirt's own modes for the snapshot
// overlays and memory image it makes, exist only on a real host — the fleet
// fakes cannot say whether a VM with an owner-only disk starts. What is checked
// is read from the node (stat, virsh), never from litevirt.
//
//	LITEVIRT_E2E=1 LV_BIN=/usr/local/bin/litevirt E2E_LAB_DIR=~/litevirt-lab \
//	  go test ./tests/e2e/ -run TestLab_DiskModes -v -timeout 30m
//
// Lab checks L1, L2 (linked clone), L3, L4 and L7 (seed) of disk-modes-report.md.

// fileMode is path's permission bits, owner and group on host.
func fileMode(l *lab, host, path string) (perm int64, owner string) {
	l.t.Helper()
	out := strings.Fields(l.mustSSH(host, 20*time.Second, "stat -c '%a %U:%G' "+shellQuote(path)))
	if len(out) != 2 {
		l.t.Fatalf("stat %s on %s: %q", path, host, out)
	}
	p, err := strconv.ParseInt(out[0], 8, 32)
	if err != nil {
		l.t.Fatalf("stat %s on %s: %q", path, host, out)
	}
	return p, out[1]
}

// requireOwnerOnly fails when path on host has any group or other bit.
func requireOwnerOnly(l *lab, host, path, what string) {
	l.t.Helper()
	perm, owner := fileMode(l, host, path)
	l.mark("modes: %s %s %04o %s", what, path, perm, owner)
	if perm&0o077 != 0 {
		l.t.Errorf("%s %s on %s is %04o (%s): readable by other users", what, path, host, perm, owner)
	}
}

func TestLab_DiskModes_NewDisksOwnerOnly(t *testing.T) {
	l := newLab(t)
	host, vm := snapTestVM(l, "dm")

	// The test exists for the path where a NON-root qemu opens an owner-only
	// disk because libvirt chowned it. With qemu as root, or libvirt not
	// relabelling (dynamic_ownership = 0), every start below would pass
	// without proving that, so the test says so and stops.
	pid := strings.TrimSpace(l.mustSSH(host, 20*time.Second, "pgrep -f -- "+shellQuote("guest="+vm+",")+" | head -1"))
	if pid == "" {
		t.Fatalf("no qemu process for %s on %s", vm, host)
	}
	if user := strings.TrimSpace(l.mustSSH(host, 20*time.Second, "ps -o user= -p "+pid)); user == "root" {
		t.Skipf("qemu runs as root on %s: an owner-only disk opens whatever libvirt does, so this proves nothing; run it on a host with a non-root qemu", host)
	}
	// L1: a new VM's disk, while running (libvirt's owner) and stopped.
	disk := snapActiveDisk(l, host, vm)
	if _, owner := fileMode(l, host, disk); strings.HasPrefix(owner, "root:") {
		t.Skipf("the running disk %s on %s is root-owned: libvirt does not relabel (dynamic_ownership = 0), so a non-root qemu could not have opened it and this proves nothing", disk, host)
	}
	requireOwnerOnly(l, host, disk, "running disk")
	// L7: the VM's cloud-init seed (it carries the user-data), when it has one.
	if seed := "/var/lib/litevirt/cloudinit/" + vm + ".iso"; l.fileExists(host, seed) {
		requireOwnerOnly(l, host, seed, "cloud-init seed")
	}

	// L3: a disk-only and a memory snapshot; the VM keeps running, restores,
	// and the snapshots delete.
	snapCreate(l, host, vm, "dm1", false)
	requireOwnerOnly(l, host, snapActiveDisk(l, host, vm), "disk-only snapshot overlay")
	snapCreate(l, host, vm, "dm2", true)
	requireOwnerOnly(l, host, snapActiveDisk(l, host, vm), "memory snapshot overlay")
	// libvirt/xmlgen.go VMStatePath.
	requireOwnerOnly(l, host, "/var/lib/litevirt/vmstate/"+vm+"-dm2.save", "memory image")
	snapRestore(l, host, vm, "dm1")
	requireOwnerOnly(l, host, snapActiveDisk(l, host, vm), "reverted overlay")
	snapRm(l, host, vm, "dm2")
	snapRm(l, host, vm, "dm1")

	// Stopped: libvirt gives the top image back to its owner; the mode stays,
	// and a start opens it again.
	snapStop(l, host, vm)
	disk = snapActiveDisk(l, host, vm)
	requireOwnerOnly(l, host, disk, "stopped disk")
	if out, err := l.lv(host, "start", vm); err != nil {
		t.Fatalf("%s cannot be started again: %v\n%s", vm, err, out)
	}
	if !l.waitDomainState(host, vm, "running", 3*time.Minute) {
		t.Fatalf("%s is not running after its start", vm)
	}

	// L2: a linked clone — an overlay on the source's owner-only disk —
	// starts, and its overlay is owner-only. The source stays stopped while
	// the clone runs on its disk.
	snapStop(l, host, vm)
	clone := vm + "-lc"
	l.onRestore(func() {
		l.lv(host, "rm", "--force", clone)
		l.ssh(host, 30*time.Second, "rm -f /var/lib/litevirt/disks/"+shellQuote(clone)+"-*")
	})
	if out, err := l.lv(host, "clone", vm, clone, "--mode", "linked", "--start"); err != nil {
		t.Fatalf("linked clone of %s: %v\n%s", vm, err, out)
	}
	if !l.waitDomainState(host, clone, "running", 3*time.Minute) {
		t.Fatalf("the linked clone %s is not running", clone)
	}
	requireOwnerOnly(l, host, snapActiveDisk(l, host, clone), "linked clone overlay")
	if out, err := l.lv(host, "rm", "--force", clone); err != nil {
		t.Fatalf("remove the linked clone %s: %v\n%s", clone, err, out)
	}

	// L4: a cold migration writes the target's copy owner-only, and the VM
	// starts there.
	ups := labUpHosts(l, 2)
	target := ups[0]
	if target == host {
		target = ups[1]
	}
	snapStop(l, host, vm)
	if out, err := l.lv(host, "migrate", vm, target, "--cold"); err != nil {
		t.Fatalf("cold migrate %s to %s: %v\n%s", vm, target, err, out)
	}
	if out, err := l.lv(target, "start", vm); err != nil {
		t.Fatalf("%s cannot be started on %s: %v\n%s", vm, target, err, out)
	}
	if !l.waitDomainState(target, vm, "running", 3*time.Minute) {
		t.Fatalf("%s is not running on %s", vm, target)
	}
	requireOwnerOnly(l, target, snapActiveDisk(l, target, vm), "cold-migrated disk")
}
