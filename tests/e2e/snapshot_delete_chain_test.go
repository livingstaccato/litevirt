package e2e

import (
	"strings"
	"testing"
	"time"
)

// Snapshot delete against the real qemu chain, on the nested lab
// (E2E_LAB_DIR; skipped without it, and the whole suite skips without
// LITEVIRT_E2E=1). lab-recheck-5 lines 81 and 82: with libvirt >= 9 the
// delete unlinked the base a VM's later layer backed on, and the overlay a
// linked clone backed on. What is checked is read from the node itself —
// qemu-img's view of each disk's chain and virsh's domain state — never from
// litevirt.
//
//	LITEVIRT_E2E=1 LV_BIN=/usr/local/bin/litevirt E2E_LAB_DIR=~/litevirt-lab \
//	  go test ./tests/e2e/ -run TestLab_SnapshotDelete -v -timeout 60m

// activeDisk is the file the domain's vda is on, read from virsh.
func activeDisk(l *lab, host, domain string) string {
	l.t.Helper()
	out := l.mustSSH(host, 30*time.Second, "virsh -c qemu:///system domblklist "+shellQuote(domain))
	for _, ln := range strings.Split(out, "\n") {
		if f := strings.Fields(ln); len(f) == 2 && f[0] == "vda" {
			return f[1]
		}
	}
	l.t.Fatalf("%s on %s has no vda:\n%s", domain, host, out)
	return ""
}

// requireChainWhole checks, on host, that every file of disk's backing chain
// is there to open.
func requireChainWhole(l *lab, host, disk, when string) {
	l.t.Helper()
	out, err := l.ssh(host, 60*time.Second, "qemu-img info -U --backing-chain "+shellQuote(disk))
	if err != nil {
		l.t.Fatalf("%s: the chain of %s on %s is broken: %v\n%s", when, disk, host, err, out)
	}
	l.mark("snapdel: %s: chain of %s whole", when, disk)
}

// requireRestarts stops and starts vm through litevirt and waits for virsh
// to show it running: a start opens every layer of every disk.
func requireRestarts(l *lab, host, vm string) {
	l.t.Helper()
	l.mustLV(host, "stop", vm)
	if !l.waitDomainState(host, vm, "shut off", 3*time.Minute) {
		l.t.Fatalf("%s did not stop", vm)
	}
	if out, err := l.lv(host, "start", vm); err != nil {
		l.t.Fatalf("%s cannot be started after its snapshots were deleted: %v\n%s", vm, err, out)
	}
	if !l.waitDomainState(host, vm, "running", 3*time.Minute) {
		l.t.Fatalf("%s is not running after its start", vm)
	}
}

// Two memory snapshots, a revert to the later one, then both deleted, in
// each order: the VM keeps its disk and starts.
func TestLab_SnapshotDeleteKeepsTheDiskChain(t *testing.T) {
	for _, order := range [][2]string{{"m1", "m2"}, {"m2", "m1"}} {
		t.Run(order[0]+"-then-"+order[1], func(t *testing.T) {
			l := newLab(t)
			h := labUpHosts(l, 1)[0]
			vm := l.createVMs(h, "snapdel", h)[h]
			for _, s := range []string{"m1", "m2"} {
				if out, err := l.lv(h, "snapshot", "create", vm, s, "--memory"); err != nil {
					t.Fatalf("snapshot create %s %s: %v\n%s", vm, s, err, out)
				}
			}
			if out, err := l.lv(h, "snapshot", "restore", vm, "m2"); err != nil {
				t.Fatalf("snapshot restore %s m2: %v\n%s", vm, err, out)
			}
			if !l.waitDomainState(h, vm, "running", 3*time.Minute) {
				t.Fatalf("%s is not running after the revert", vm)
			}
			for _, s := range order {
				if out, err := l.lv(h, "snapshot", "rm", vm, s); err != nil {
					t.Fatalf("snapshot rm %s %s: %v\n%s", vm, s, err, out)
				}
				requireChainWhole(l, h, activeDisk(l, h, vm), "after rm "+s)
			}
			requireRestarts(l, h, vm)
			requireChainWhole(l, h, activeDisk(l, h, vm), "after the restart")
		})
	}
}

// A linked clone of a VM that has a snapshot backs on the snapshot's
// overlay; deleting the snapshot keeps the clone's chain whole.
func TestLab_SnapshotDeleteKeepsALinkedClonesBacking(t *testing.T) {
	l := newLab(t)
	h := labUpHosts(l, 1)[0]
	src := l.createVMs(h, "snapdelsrc", h)[h]
	l.mustLV(h, "stop", src)
	if !l.waitDomainState(h, src, "shut off", 3*time.Minute) {
		t.Fatalf("%s did not stop", src)
	}
	if out, err := l.lv(h, "snapshot", "create", src, "s1"); err != nil {
		t.Fatalf("snapshot create %s s1: %v\n%s", src, err, out)
	}
	clone := uniqueName("snapdelclone")
	l.onRestore(func() {
		if v := l.liveHost(); v != "" {
			l.lv(v, "rm", "--force", clone)
		}
	})
	if out, err := l.lv(h, "clone", src, clone, "--mode", "linked"); err != nil {
		t.Fatalf("linked clone %s → %s: %v\n%s", src, clone, err, out)
	}
	if out, err := l.lv(h, "snapshot", "rm", src, "s1"); err != nil {
		t.Logf("snapshot rm %s s1 refused (allowed, the clone's backing is what matters): %v\n%s", src, err, out)
	}
	if out, err := l.lv(h, "start", clone); err != nil {
		t.Fatalf("the linked clone %s cannot start after its source's snapshot was deleted: %v\n%s", clone, err, out)
	}
	at := whereRunning(l, clone, 3*time.Minute)
	if at == "" {
		t.Fatalf("%s is not running on any node", clone)
	}
	requireChainWhole(l, at, activeDisk(l, at, clone), "clone after rm s1")
}
