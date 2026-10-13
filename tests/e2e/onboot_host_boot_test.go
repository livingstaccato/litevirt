package e2e

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Lab 2 F-4: an onboot VM its operator stopped starts when its host boots,
// and only then. Checked on real qemu with virsh, not litevirt's own view:
//
//  1. a plain daemon restart (the same kernel boot) leaves the stopped VM
//     shut off, past the daemon's warm-up and several reconcile passes;
//  2. a host boot starts it: the daemon's record of the boot onboot last ran
//     in is made stale first, exactly as a reboot's new kernel boot ID makes
//     it (a real power cycle would also have the failover coordinator act on
//     the host), and the boot-time attempt meets the gate's warm-up refusal
//     as on a real boot;
//  3. once started, the record names this boot.
func TestLab_OnbootStartsAnOperatorStoppedVMOnlyAtHostBoot(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	q := l.hosts[0]
	victim := l.leastLoaded(q, l.except(q))
	stack := uniqueName("obh")
	vm := stack + "-1"
	yaml := fmt.Sprintf("name: %s\nvms:\n  %s:\n    image: %s\n    cpu: 1\n    memory: %s\n    onboot: true\n    placement:\n      host: %s\n",
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
	l.mustLV(q, "stop", vm)
	if !l.waitDomainState(victim, vm, "shut off", 3*time.Minute) {
		t.Fatalf("%s did not stop (virsh)", vm)
	}

	// 1. A plain daemon restart: the stop stands.
	if err := l.restartDaemon(victim); err != nil {
		t.Fatal(err)
	}
	time.Sleep(90 * time.Second)
	if st := strings.TrimSpace(l.mustSSH(victim, 20*time.Second, "virsh -c qemu:///system domstate "+shellQuote(vm))); st != "shut off" {
		t.Fatalf("a daemon restart started %s, which its operator stopped (virsh: %q)", vm, st)
	}
	l.mark("onboot: %s still shut off 90 s after a plain daemon restart on %s", vm, victim)

	// 2. A host boot: the recorded boot is not this kernel's.
	const record = "/var/lib/litevirt/onboot-boot-id"
	l.mustSSH(victim, 2*time.Minute, "systemctl stop litevirt && echo 00000000-0000-0000-0000-000000000000 > "+record+" && systemctl start litevirt")
	l.mark("onboot: emulated host boot on %s", victim)
	if err := l.waitDaemon(victim, 3*time.Minute); err != nil {
		t.Fatal(err)
	}
	if !l.waitDomainState(victim, vm, "running", 5*time.Minute) {
		st, _ := l.ssh(victim, 20*time.Second, "virsh -c qemu:///system domstate --reason "+shellQuote(vm))
		t.Fatalf("a host boot did not start onboot %s, which its operator had stopped (virsh: %q)", vm, strings.TrimSpace(st))
	}

	// 3. The boot is recorded once its start is made.
	deadline := time.Now().Add(time.Minute)
	for {
		got := l.mustSSH(victim, 20*time.Second, "cat "+record+"; echo; cat /proc/sys/kernel/random/boot_id")
		f := strings.Fields(got)
		if len(f) == 2 && f[0] == f[1] {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the boot onboot ran in is not recorded on %s: %q", victim, got)
		}
		time.Sleep(5 * time.Second)
	}
}
