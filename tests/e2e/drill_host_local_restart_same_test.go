package e2e

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Drill: a RUNNING restart-same VM with a host-local disk loses its host.
//
// restart-same with a host-local disk waits for its host: a restart anywhere
// else would run it on a disk rebuilt blank from its image
// (docs/migration-failover.md, the failure policy table). What this drill
// checks on real qemu, with virsh, stat, qemu-img and the replicas themselves
// rather than litevirt's own view of the VM:
//
//  1. while the host is powered off, the failover coordinator decides to hold
//     the VM (a failover.skip audit row "held on <host>") and, for a minute
//     past that decision, no other host defines its domain and every replica
//     still places its row on the dead host;
//  2. when the host is powered back on, it starts the VM there itself, on its
//     real disks: the same files (inode) the VM ran on before, and the data
//     disk, which the guest never writes, is identical (qemu-img compare) to a
//     copy taken on the host before the power cut.
//
// The restart-any counterpart is TestDrill_HostLocalDiskSurvivesFailoverAndIsRestorable.
func TestDrill_RestartSameHostLocalVMWaitsForItsHost(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	q := l.hosts[0]
	victim := l.leastLoaded(q, l.except(q))
	stack := uniqueName("hrs")
	vm := stack + "-1"
	yaml := fmt.Sprintf("name: %s\nvms:\n  %s:\n    image: %s\n    cpu: 1\n    memory: %s\n    disks:\n      root:\n        size: \"1G\"\n      data:\n        size: \"64M\"\n    placement:\n      host: %s\n    migrate:\n      on-host-failure: restart-same\n",
		stack, vm, drillImage(), drillMemory(), victim)
	file := "/tmp/" + stack + ".yaml"
	l.mustSSH(q, 30*time.Second, "echo "+base64.StdEncoding.EncodeToString([]byte(yaml))+" | base64 -d > "+file)
	l.onRestore(func() { l.deleteVMs(stack, map[string]string{victim: vm}) })
	if out, err := l.lv(q, "compose", "up", "-f", file, "-y"); err != nil {
		t.Fatalf("compose up %s: %v\n%s", stack, err, out)
	}
	if !l.waitDomainState(victim, vm, "running", 4*time.Minute) {
		t.Fatalf("%s never ran on %s (virsh)", vm, victim)
	}

	diskPath := func(disk string) string {
		rows := l.mustSQL(q, "SELECT path FROM vm_disks WHERE vm_name = '"+vm+"' AND disk_name = '"+disk+"' AND deleted_at IS NULL")
		if len(rows) != 1 || rows[0][0] == "" {
			t.Fatalf("%s disk of %s: rows %v", disk, vm, rows)
		}
		return rows[0][0]
	}
	root, data := diskPath("root"), diskPath("data")
	inode := func(path string) string {
		return strings.TrimSpace(l.mustSSH(victim, 20*time.Second, "stat -c %i "+shellQuote(path)))
	}

	// A marker on the data disk, written while the VM is stopped (qemu holds
	// the image locked while it runs), so a disk rebuilt from nothing cannot
	// match it. The guest never mounts the disk, so it stays as written.
	l.mustLV(q, "stop", vm)
	if !l.waitDomainState(victim, vm, "shut off", 3*time.Minute) {
		t.Fatalf("%s did not stop (virsh)", vm)
	}
	l.mustSSH(victim, 60*time.Second, "qemu-io -f qcow2 -c 'write -P 0x5a 0 4M' "+shellQuote(data))
	l.mustLV(q, "start", vm)
	if !l.waitDomainState(victim, vm, "running", 3*time.Minute) {
		t.Fatalf("%s did not start again on %s (virsh)", vm, victim)
	}
	ref := "/var/tmp/" + vm + "-data.ref"
	l.mustSSH(victim, 60*time.Second, "cp --reflink=never "+shellQuote(data)+" "+shellQuote(ref)+" && sync")
	l.onRestore(func() { l.ssh(victim, 20*time.Second, "rm -f "+shellQuote(ref)) })
	rootIno, dataIno := inode(root), inode(data)
	l.mark("hrs: %s running on %s, root %s (inode %s), data %s (inode %s)", vm, victim, root, rootIno, data, dataIno)

	// 1. The host goes away; the VM is held, not started anywhere.
	since := l.nodeNow(q)
	l.powerOff(victim)
	var others []string
	for _, h := range l.hosts {
		if h != victim {
			others = append(others, h)
		}
	}
	notElsewhere := func() {
		t.Helper()
		for _, h := range others {
			out, err := l.ssh(h, 20*time.Second, "virsh -c qemu:///system list --all --name")
			if err != nil {
				continue // a host that does not answer defines nothing we can see
			}
			for _, d := range strings.Fields(out) {
				if d == vm {
					st, _ := l.ssh(h, 20*time.Second, "virsh -c qemu:///system domstate "+shellQuote(vm))
					t.Fatalf("the held VM %s is defined on %s (state %q) while %s is down: restart-same started it elsewhere", vm, h, strings.TrimSpace(st), victim)
				}
			}
		}
		for _, h := range others {
			rows, err := l.sql(h, "SELECT host_name FROM vms WHERE name = '"+vm+"' AND deleted_at IS NULL")
			if err != nil {
				continue
			}
			if len(rows) != 1 || rows[0][0] != victim {
				t.Fatalf("%s's replica places %s on %v while %s is down; want it held on %s", h, vm, rows, victim, victim)
			}
		}
	}
	held := ""
	deadline := time.Now().Add(recoverBy)
	for time.Now().Before(deadline) && held == "" {
		notElsewhere()
		rows, err := l.sql(q, "SELECT detail FROM audit_log WHERE action = 'failover.skip' AND target = '"+vm+"' AND timestamp >= '"+since+"' AND detail LIKE 'held on "+victim+"%'")
		if err == nil && len(rows) > 0 {
			held = rows[0][0]
			break
		}
		time.Sleep(5 * time.Second)
	}
	if held == "" {
		t.Fatalf("no failover.skip \"held on %s\" row for %s within %v of the power cut: the coordinator never decided to hold it", victim, vm, recoverBy)
	}
	l.mark("hrs: held: %s", held)
	for until := time.Now().Add(time.Minute); time.Now().Before(until); time.Sleep(5 * time.Second) {
		notElsewhere()
	}

	// 2. The host comes back and starts the VM on its real disks.
	if err := l.powerOn(victim); err != nil {
		t.Fatalf("power on %s: %v", victim, err)
	}
	l.waitAllActive(q, 6*time.Minute)
	if !l.waitDomainState(victim, vm, "running", 5*time.Minute) {
		st, _ := l.ssh(victim, 20*time.Second, "virsh -c qemu:///system domstate --reason "+shellQuote(vm))
		t.Fatalf("%s did not start on %s once it was back (virsh: %q)", vm, victim, strings.TrimSpace(st))
	}
	notElsewhere()
	blk := l.mustSSH(victim, 20*time.Second, "virsh -c qemu:///system domblklist "+shellQuote(vm))
	for _, p := range []string{root, data} {
		if !strings.Contains(blk, p) {
			t.Errorf("virsh domblklist %s on %s does not show %s:\n%s", vm, victim, p, blk)
		}
	}
	if got := inode(root); got != rootIno {
		t.Errorf("%s runs on root inode %s, want the real disk's %s", vm, got, rootIno)
	}
	if got := inode(data); got != dataIno {
		t.Errorf("%s runs on data inode %s, want the real disk's %s", vm, got, dataIno)
	}
	if out, err := l.ssh(victim, 2*time.Minute, "qemu-img compare -U "+shellQuote(ref)+" "+shellQuote(data)); err != nil {
		t.Errorf("the data disk %s %s runs on is not the one it had before the power cut: %v\n%s", vm, data, err, out)
	} else {
		l.mark("hrs: %s back on %s, data disk identical to the reference: %s", vm, victim, strings.TrimSpace(out))
	}
}
