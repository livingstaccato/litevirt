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
// Lab checks L1, L3, L4 of disk-modes-report.md.

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

	// L1: a new VM's disk, while running (libvirt's owner) and stopped.
	disk := snapActiveDisk(l, host, vm)
	requireOwnerOnly(l, host, disk, "running disk")
	if _, owner := fileMode(l, host, disk); strings.HasPrefix(owner, "root:") {
		l.mark("modes: the running disk is still root-owned (dynamic_ownership off, or qemu runs as root)")
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
