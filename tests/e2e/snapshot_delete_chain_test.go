package e2e

import (
	"fmt"
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
	// No delete that worked is refused: the snapshot goes, its files stay.
	if out, err := l.lv(h, "snapshot", "rm", src, "s1"); err != nil {
		t.Fatalf("snapshot rm %s s1 was refused: %v\n%s", src, err, out)
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

// chainDepth is how many files make up disk's backing chain on host.
func chainDepth(l *lab, host, disk string) int {
	l.t.Helper()
	out := l.mustSSH(host, 60*time.Second, "qemu-img info -U --backing-chain "+shellQuote(disk))
	return strings.Count(out, "image: ")
}

// Review I-1: snapshot create/rm cycles — running and stopped, disk and
// memory — leave the chain as deep as they found it, and the VM still
// starts. Without the merge, a layer per cycle took the chain past the
// 16 a start accepts.
func TestLab_SnapshotCreateRmCyclesKeepTheChainDepth(t *testing.T) {
	l := newLab(t)
	h := labUpHosts(l, 1)[0]
	vm := l.createVMs(h, "snapcyc", h)[h]
	want := chainDepth(l, h, activeDisk(l, h, vm))
	cycle := func(name string, args ...string) {
		t.Helper()
		if out, err := l.lv(h, append([]string{"snapshot", "create", vm, name}, args...)...); err != nil {
			t.Fatalf("snapshot create %s %s: %v\n%s", vm, name, err, out)
		}
		if out, err := l.lv(h, "snapshot", "rm", vm, name); err != nil {
			t.Fatalf("snapshot rm %s %s: %v\n%s", vm, name, err, out)
		}
		if got := chainDepth(l, h, activeDisk(l, h, vm)); got != want {
			t.Fatalf("after %s the chain is %d deep, want %d", name, got, want)
		}
	}
	for i := 0; i < 20; i++ {
		cycle(fmt.Sprintf("run%d", i))
	}
	for i := 0; i < 3; i++ {
		cycle(fmt.Sprintf("mem%d", i), "--memory")
	}
	l.mustLV(h, "stop", vm)
	if !l.waitDomainState(h, vm, "shut off", 3*time.Minute) {
		t.Fatalf("%s did not stop", vm)
	}
	for i := 0; i < 20; i++ {
		cycle(fmt.Sprintf("off%d", i))
	}
	if out, err := l.lv(h, "start", vm); err != nil {
		t.Fatalf("%s cannot be started after the cycles: %v\n%s", vm, err, out)
	}
	if !l.waitDomainState(h, vm, "running", 3*time.Minute) {
		t.Fatalf("%s is not running after its start", vm)
	}
	requireChainWhole(l, h, activeDisk(l, h, vm), "after the cycles")
}

// manifestTS is the manifest timestamp `lv backup snapshot` printed.
func manifestTS(t *testing.T, out string) string {
	t.Helper()
	for _, ln := range strings.Split(out, "\n") {
		if i := strings.Index(ln, "manifest="); i >= 0 {
			if f := strings.Fields(ln[i+len("manifest="):]); len(f) > 0 {
				return f[0]
			}
		}
	}
	t.Fatalf("no manifest timestamp in:\n%s", out)
	return ""
}

// Review M-5: a stopped merge is `qemu-img commit`, which — unlike libvirt's
// block-commit — may not carry the persistent dirty bitmaps (backup
// checkpoints) of the merged layer into the base. Then the next incremental
// backup diffs against a stale bitmap and silently misses the blocks the
// merge brought down. Written from outside the guest, into the snapshot's
// overlay while the VM is off, merged by the snapshot delete, then backed up
// incrementally: the restored image must carry those bytes.
func TestLab_IncrementalBackupAfterAnOfflineMergeCarriesEveryChangedBlock(t *testing.T) {
	l := newLab(t)
	h := labUpHosts(l, 1)[0]
	vm := l.createVMs(h, "snapbk", h)[h]
	repo := "/var/tmp/" + uniqueName("e2e-bkrepo")
	restored := "/var/tmp/" + uniqueName("e2e-bkrestore") + ".img"
	l.onRestore(func() { l.ssh(h, 60*time.Second, "rm -rf "+shellQuote(repo)+" "+shellQuote(restored)) })
	l.mustLV(h, "backup", "repo", "init", repo)

	// 1. A full guest-content backup: it establishes the checkpoint (a
	// persistent dirty bitmap in the active layer) the next one diffs from.
	l.mustLV(h, "backup", "snapshot", vm, "--repo", repo)
	base := activeDisk(l, h, vm)
	depth := chainDepth(l, h, base)

	// 2. Off, a snapshot, and a pattern written into its overlay from
	// outside the guest, near the disk's end (past what a small guest uses).
	l.mustLV(h, "stop", vm)
	if !l.waitDomainState(h, vm, "shut off", 3*time.Minute) {
		t.Fatalf("%s did not stop", vm)
	}
	if out, err := l.lv(h, "snapshot", "create", vm, "bk1"); err != nil {
		t.Fatalf("snapshot create %s bk1: %v\n%s", vm, err, out)
	}
	top := activeDisk(l, h, vm)
	if top == base {
		t.Fatalf("the snapshot did not cut %s over to an overlay (still on %s)", vm, base)
	}
	size, err := l.qemuVirtualSize(h, top)
	if err != nil {
		t.Fatal(err)
	}
	off := size - 4<<20
	pattern := fmt.Sprintf("write -P 0xab %d 64k", off)
	l.mustSSH(h, 60*time.Second, "qemu-io -f qcow2 -c "+shellQuote(pattern)+" "+shellQuote(top))
	l.mark("snapbk: wrote 64k of 0xab at %d into %s", off, top)

	// 3. The offline merge.
	if out, err := l.lv(h, "snapshot", "rm", vm, "bk1"); err != nil {
		t.Fatalf("snapshot rm %s bk1: %v\n%s", vm, err, out)
	}
	if got := activeDisk(l, h, vm); got != base {
		t.Fatalf("after the merge %s is on %s, want %s — this test needs the offline merge", vm, got, base)
	}
	if got := chainDepth(l, h, base); got != depth {
		t.Fatalf("after the merge the chain is %d deep, want %d", got, depth)
	}

	// 4. Running again, an incremental backup.
	if out, err := l.lv(h, "start", vm); err != nil {
		t.Fatalf("start %s: %v\n%s", vm, err, out)
	}
	if !l.waitDomainState(h, vm, "running", 3*time.Minute) {
		t.Fatalf("%s is not running", vm)
	}
	out := l.mustLV(h, "backup", "snapshot", vm, "--repo", repo, "--incremental")
	l.saveEvidence("snapbk-incremental.txt", out)
	if !strings.Contains(out, "incremental guest-content backup") {
		t.Logf("the second backup was not a bitmap-driven incremental, so a stale bitmap cannot show here:\n%s", out)
	}
	ts := manifestTS(t, out)

	// 5. The restored image carries the merged bytes.
	l.mustLV(h, "backup", "restore-from", "--repo", repo, "--vm", vm, "--disk", "root", "--timestamp", ts, "--target-path", restored)
	read := fmt.Sprintf("read -P 0xab %d 64k", off)
	if got, err := l.ssh(h, 60*time.Second, "qemu-io -r -c "+shellQuote(read)+" "+shellQuote(restored)); err != nil ||
		strings.Contains(got, "Pattern verification failed") {
		t.Fatalf("the incremental backup after an offline merge misses the merged blocks (stale checkpoint bitmap): %v\n%s", err, got)
	}
}
