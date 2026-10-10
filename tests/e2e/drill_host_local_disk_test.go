package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Drill: a RUNNING VM with a host-local disk loses its host.
//
// The VM is restarted on another host on a disk rebuilt from its image, as
// restart-any always did. What this drill checks on real qemu, with virsh,
// stat and qemu-img on the nodes rather than litevirt's own view:
//
//  1. `lv inspect` names the real disk left on the failed host;
//  2. when the failed host is powered back on, it sets the real disk aside
//     (<path>.superseded-<time>) — the same file, by inode, not a copy;
//  3. it survives the retention rule at any age: the sweep and a bare
//     `--purge` run the same check (health.PurgeSupersededDisks), and a bare
//     purge ignores age, so a copy it keeps would be kept by the sweep at any
//     age too;
//  4. it is restorable: stop, cold-migrate back, `--restore`, start — and the
//     domain then runs on that same inode, while the disk it ran on since the
//     failover is kept beside it.
//
// Written for the lab; run by the controller (lab 2).
func TestDrill_HostLocalDiskSurvivesFailoverAndIsRestorable(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	q := l.hosts[0]
	victim := l.leastLoaded(q, l.except(q))
	vm := l.createVMs(q, "hld", victim)[victim]

	before, err := l.inspectVM(q, vm)
	if err != nil {
		t.Fatalf("inspect %s: %v", vm, err)
	}
	if len(before.Disks) == 0 || before.Disks[0].Path == "" {
		t.Fatalf("%s has no recorded disk: %+v", vm, before)
	}
	path := before.Disks[0].Path
	inode := strings.TrimSpace(l.mustSSH(victim, 20*time.Second, "stat -c %i "+shellQuote(path)))
	l.mark("hld: %s on %s, disk %s inode %s", vm, victim, path, inode)

	// 1. The failure: the VM comes back elsewhere, the real disk is named.
	l.powerOff(victim)
	var moved vmInfo
	deadline := time.Now().Add(recoverBy)
	for time.Now().Before(deadline) {
		if v, err := l.inspectVM(q, vm); err == nil && v.HostName != victim && v.HostName != "" {
			moved = v
			if l.waitDomainState(v.HostName, vm, "running", 30*time.Second) {
				break
			}
		}
		time.Sleep(10 * time.Second)
	}
	if moved.HostName == "" || moved.HostName == victim {
		t.Fatalf("%s was not restarted off %s within %v", vm, victim, recoverBy)
	}
	l.mark("hld: %s restarted on %s", vm, moved.HostName)
	if s := strandedDisks(t, l, q, vm); len(s) != 1 || s[0].Host != victim || s[0].Path != path {
		t.Errorf("inspect strandedDisks = %+v, want %s on %s", s, path, victim)
	}

	// 2. The host comes back and sets the real disk aside, same inode.
	if err := l.powerOn(victim); err != nil {
		t.Fatalf("power on %s: %v", victim, err)
	}
	l.waitAllActive(q, 6*time.Minute)
	var copyPath string
	deadline = time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) && copyPath == "" {
		out, _ := l.ssh(victim, 20*time.Second, "for f in "+shellQuote(path)+".superseded-*; do [ -e \"$f\" ] && echo \"$(stat -c %i \"$f\") $f\"; done")
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			if f := strings.Fields(line); len(f) == 2 && f[0] == inode {
				copyPath = f[1]
			}
		}
		if copyPath == "" {
			time.Sleep(10 * time.Second)
		}
	}
	if copyPath == "" {
		t.Fatalf("%s did not set the real disk (inode %s) aside next to %s", victim, inode, path)
	}
	if l.fileExists(victim, path) {
		t.Errorf("%s still has a file at %s after setting the real disk aside", victim, path)
	}
	if out, err := l.ssh(victim, 60*time.Second, "qemu-img check -U "+shellQuote(copyPath)); err != nil {
		t.Errorf("qemu-img check of the set-aside real disk %s: %v\n%s", copyPath, err, out)
	}
	if s := strandedDisks(t, l, q, vm); len(s) != 1 || s[0].Copy != copyPath {
		t.Errorf("inspect strandedDisks = %+v, want the copy %s", s, copyPath)
	}

	// 3. The retention rule keeps it whatever its age.
	if out, err := l.lv(q, "host", "superseded-disks", victim, "--purge"); err != nil {
		t.Fatalf("purge on %s: %v\n%s", victim, err, out)
	}
	if got := strings.TrimSpace(l.mustSSH(victim, 20*time.Second, "stat -c %i "+shellQuote(copyPath))); got != inode {
		t.Fatalf("after a purge the copy %s is %q, want inode %s: the only copy of the VM's data was removed", copyPath, got, inode)
	}

	// 4. Put it back.
	l.mustLV(q, "stop", vm)
	if out, err := l.lv(q, "migrate", vm, victim, "--cold"); err != nil {
		t.Fatalf("cold migrate %s to %s: %v\n%s", vm, victim, err, out)
	}
	out := l.mustLV(q, "host", "superseded-disks", victim, "--restore", copyPath)
	l.mark("hld: restore: %s", strings.TrimSpace(out))
	if got := strings.TrimSpace(l.mustSSH(victim, 20*time.Second, "stat -c %i "+shellQuote(path))); got != inode {
		t.Fatalf("after the restore %s is inode %q, want the real disk's %s", path, got, inode)
	}
	if l.fileExists(victim, copyPath) {
		t.Errorf("the restored copy is still at %s", copyPath)
	}
	kept := strings.TrimSpace(l.mustSSH(victim, 20*time.Second,
		"ls "+shellQuote(path)+".superseded-* 2>/dev/null | wc -l"))
	if kept == "0" {
		t.Errorf("the disk %s ran on since the failover was not kept beside the restored one", vm)
	}
	l.mustLV(q, "start", vm)
	if !l.waitDomainState(victim, vm, "running", 3*time.Minute) {
		t.Fatalf("%s did not start on %s on its restored disk (virsh)", vm, victim)
	}
	blk := l.mustSSH(victim, 20*time.Second, "virsh domblklist "+shellQuote(vm))
	if !strings.Contains(blk, path) {
		t.Errorf("virsh domblklist %s on %s does not show %s:\n%s", vm, victim, path, blk)
	}
	if got := strings.TrimSpace(l.mustSSH(victim, 20*time.Second, "stat -c %i "+shellQuote(path))); got != inode {
		t.Errorf("%s runs on inode %q, want the real disk's %s", vm, got, inode)
	}
}

type strandedDiskInfo struct {
	Host string `json:"host"`
	Disk string `json:"disk"`
	Path string `json:"path"`
	Copy string `json:"copy"`
}

// strandedDisks reads `lv inspect`'s strandedDisks for vm.
func strandedDisks(t *testing.T, l *lab, via, vm string) []strandedDiskInfo {
	t.Helper()
	out, err := l.lv(via, "inspect", vm)
	if err != nil {
		t.Fatalf("inspect %s: %v", vm, err)
	}
	var v struct {
		StrandedDisks []strandedDiskInfo `json:"strandedDisks"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("inspect %s: %v\n%s", vm, err, out)
	}
	return v.StrandedDisks
}
