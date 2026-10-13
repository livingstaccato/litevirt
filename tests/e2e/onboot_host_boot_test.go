package e2e

import (
	"encoding/base64"
	"encoding/json"
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
//  3. once started, the record names this boot and owes nothing;
//  4. stopped again by its operator, a daemon restart leaves it stopped.
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

	// 2. A host boot: the recorded boot is not this kernel's. The record is in
	// the node's configured data_dir.
	dataDir := strings.TrimSpace(l.mustSSH(victim, 20*time.Second,
		`d=$(sed -n 's/^data_dir:[[:space:]]*//p' /etc/litevirt/config.yaml | tr -d '"'"'"'"' | head -1); echo "${d:-/var/lib/litevirt}"`))
	record := dataDir + "/onboot-boot-id"
	stale := `{"boot_id":"00000000-0000-4000-8000-000000000000"}`
	l.mustSSH(victim, 2*time.Minute, "systemctl stop litevirt && echo "+shellQuote(stale)+" > "+shellQuote(record)+" && systemctl start litevirt")
	l.mark("onboot: emulated host boot on %s", victim)
	if err := l.waitDaemon(victim, 3*time.Minute); err != nil {
		t.Fatal(err)
	}
	if !l.waitDomainState(victim, vm, "running", 5*time.Minute) {
		st, _ := l.ssh(victim, 20*time.Second, "virsh -c qemu:///system domstate --reason "+shellQuote(vm))
		t.Fatalf("a host boot did not start onboot %s, which its operator had stopped (virsh: %q)", vm, strings.TrimSpace(st))
	}

	// 3. The record names this boot and owes nothing once the start is made.
	boot := strings.TrimSpace(l.mustSSH(victim, 20*time.Second, "cat /proc/sys/kernel/random/boot_id"))
	deadline := time.Now().Add(time.Minute)
	for {
		raw := l.mustSSH(victim, 20*time.Second, "cat "+shellQuote(record))
		var rec struct {
			BootID string            `json:"boot_id"`
			Owed   []json.RawMessage `json:"owed"`
		}
		if json.Unmarshal([]byte(raw), &rec) == nil && rec.BootID == boot && len(rec.Owed) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the onboot record on %s does not name this boot (%s) owing nothing: %q", victim, boot, raw)
		}
		time.Sleep(5 * time.Second)
	}

	// 4. Stopped again, then a plain daemon restart: the stop stands.
	l.mustLV(q, "stop", vm)
	if !l.waitDomainState(victim, vm, "shut off", 3*time.Minute) {
		t.Fatalf("%s did not stop (virsh)", vm)
	}
	if err := l.restartDaemon(victim); err != nil {
		t.Fatal(err)
	}
	time.Sleep(90 * time.Second)
	if st := strings.TrimSpace(l.mustSSH(victim, 20*time.Second, "virsh -c qemu:///system domstate "+shellQuote(vm))); st != "shut off" {
		t.Fatalf("a daemon restart after the boot's start started %s again over its operator's stop (virsh: %q)", vm, st)
	}
}
