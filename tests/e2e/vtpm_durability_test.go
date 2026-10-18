package e2e

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Drill: a guest's TPM NV write survives a hard power cut of its host moments
// later.
//
// swtpm writes a vTPM's state as a temp file renamed over the old one, with no
// fsync, so without vtpm_state_sync the write and the rename wait for the next
// journal commit and the power cut loses them (lab 3, 2026-10-18: 5 of 5
// writes lost to a cut 0.06 s after the write, 2 of 5 to one 3 s after it).
//
//	E2E_VTPM_IMAGE        a cloud image whose cloud-init can install tpm2-tools (default ubuntu-ga)
//	E2E_VTPM_MEMORY       its memory (default 768)
//	E2E_VTPM_EXPECT_LOSS  1 for the control run on a build without vtpm_state_sync:
//	                      the write must then be lost
//
// What it checks, on real swtpm and the host's own disk:
//
//  1. the VM's swtpm state directory and file carry the sync attribute;
//  2. periodic writeback is off on the host (vm.dirty_writeback_centisecs=0,
//     after a sync), so only a synchronous write can put the TPM write on disk;
//  3. a value written to a TPM NV index in the guest reaches the host's swtpm
//     state file, and the host is powered off at once (within 1 s);
//  4. once the host is back, the state file on disk still holds the value, and
//     the guest, started again there, reads it back from its TPM.
func TestDrill_VTPMStateSurvivesHostPowerCut(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)
	expectLoss := envOr("E2E_VTPM_EXPECT_LOSS", "") == "1"

	q := l.hosts[0]
	victim := l.leastLoaded(q, l.except(q))
	stack := uniqueName("vtd")
	vm := stack + "-1"
	const guestUser, guestPassword = "ubuntu", "vtd-e2e-pw"
	yaml := fmt.Sprintf(`name: %[1]s
networks:
  vtd:
    type: bridge
    interface: e2evtdbr
    subnet: 10.211.0.0/24
    dhcp: true
vms:
  %[2]s:
    image: %[3]s
    firmware: bios
    machine: q35
    onboot: true
    cpu: 1
    memory: %[4]s
    disks:
      root:
        size: 8G
    network: [{name: vtd}]
    placement:
      host: %[5]s
    migrate:
      on-host-failure: restart-same
    cloud-init:
      userdata: |
        #cloud-config
        ssh_pwauth: true
        packages: [tpm2-tools]
        chpasswd:
          expire: false
          users:
            - {name: %[6]s, password: %[7]s, type: text}
`, stack, vm, envOr("E2E_VTPM_IMAGE", "ubuntu-ga"), envOr("E2E_VTPM_MEMORY", "768"), victim, guestUser, guestPassword)
	file := "/tmp/" + stack + ".yaml"
	l.putFile(q, file, yaml)
	l.onRestore(func() { l.deleteVMs(stack, map[string]string{victim: vm}) })
	if out, err := l.lv(q, "compose", "up", "-f", file, "-y"); err != nil {
		t.Fatalf("compose up %s: %v\n%s", stack, err, out)
	}
	if !l.waitDomainState(victim, vm, "running", 4*time.Minute) {
		t.Fatalf("%s never ran on %s (virsh)", vm, victim)
	}
	guest := func(cmd string) (string, bool, error) {
		return l.guestRunAs(victim, l.guestIP(victim, vm, 5*time.Minute), guestUser, guestPassword, cmd)
	}
	waitGuest := func(cmd, want string) {
		t.Helper()
		var last string
		for deadline := time.Now().Add(10 * time.Minute); time.Now().Before(deadline); time.Sleep(10 * time.Second) {
			out, ok, err := guest(cmd)
			if err == nil && ok && strings.Contains(out, want) {
				return
			}
			last = fmt.Sprintf("ok=%v err=%v out=%q", ok, err, out)
		}
		t.Fatalf("%s: %q never printed %q: %s", vm, cmd, want, last)
	}
	// cloud-init installs tpm2-tools; its own writes are flushed before the
	// cut, so the guest comes back with its SSH host keys.
	waitGuest("cloud-init status --wait >/dev/null; command -v tpm2_nvwrite && sudo sync", "tpm2_nvwrite")

	// A vTPM is attached to a stopped VM (compose has no tpm field).
	l.mustLV(q, "stop", vm)
	if !l.waitDomainState(victim, vm, "shut off", 3*time.Minute) {
		t.Fatalf("%s never stopped", vm)
	}
	l.mustLV(q, "update", vm, "--tpm", "--force")
	l.mustLV(q, "start", vm)
	if !l.waitDomainState(victim, vm, "running", 4*time.Minute) {
		t.Fatalf("%s never ran with a vTPM", vm)
	}
	waitGuest("ls /dev/tpmrm0", "/dev/tpmrm0")

	uuid := strings.TrimSpace(l.mustSSH(victim, 30*time.Second, "virsh -c qemu:///system domuuid "+shellQuote(vm)))
	state := "/var/lib/libvirt/swtpm/" + uuid + "/tpm2/tpm2-00.permall"
	const index = "0x1500016"
	nvwrite := func(v string) {
		t.Helper()
		if out, ok, err := guest(fmt.Sprintf("printf '%%-32s' %s | sudo tpm2_nvwrite %s -C o -i -", v, index)); err != nil || !ok {
			t.Fatalf("tpm2_nvwrite in %s: ok=%v err=%v %s", vm, ok, err, out)
		}
	}
	if out, ok, err := guest("sudo tpm2_nvdefine " + index + ` -C o -s 32 -a "ownerread|ownerwrite|authread|authwrite"`); err != nil || !ok {
		t.Fatalf("tpm2_nvdefine in %s: ok=%v err=%v %s", vm, ok, err, out)
	}
	before := "lvvtd-before-" + strconv.FormatInt(time.Now().UnixNano()%1e9, 36)
	nvwrite(before)

	// 1. The state tree carries the sync attribute (none on the control build).
	attrs := l.mustSSH(victim, 20*time.Second, "lsattr -d /var/lib/libvirt/swtpm "+shellQuote("/var/lib/libvirt/swtpm/"+uuid+"/tpm2")+" "+shellQuote(state))
	mount := strings.TrimSpace(l.mustSSH(victim, 20*time.Second, "findmnt -no SOURCE,FSTYPE,OPTIONS -T "+shellQuote(state)))
	l.mark("vtd: %s's swtpm state on %s (%s):\n%s", vm, victim, mount, attrs)
	for _, line := range strings.Split(strings.TrimSpace(attrs), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			t.Fatalf("lsattr: %q", line)
		}
		if hasSync := strings.Contains(f[0], "S"); hasSync == expectLoss {
			t.Fatalf("%s: sync attribute %v, want %v (expect loss %v)", f[1], hasSync, !expectLoss, expectLoss)
		}
	}

	// 2. Only a synchronous write can persist it: periodic writeback off,
	// after syncs that clean what came before.
	orig := strings.TrimSpace(l.mustSSH(victim, 20*time.Second, "cat /proc/sys/vm/dirty_writeback_centisecs"))
	if _, err := strconv.Atoi(orig); err != nil {
		t.Fatalf("vm.dirty_writeback_centisecs on %s: %q", victim, orig)
	}
	l.onRestore(func() { l.ssh(victim, 20*time.Second, "sysctl -qw vm.dirty_writeback_centisecs="+orig) })
	if out, ok, err := guest("sudo sync"); err != nil || !ok {
		t.Fatalf("sync in %s: ok=%v err=%v %s", vm, ok, err, out)
	}
	l.mustSSH(victim, 2*time.Minute, "sync && sysctl -qw vm.dirty_writeback_centisecs=0 && sync")

	// 3. The write, and the power cut straight after.
	marker := "lvvtd-" + strconv.FormatInt(time.Now().UnixNano()%1e12, 36)
	nvwrite(marker)
	written := l.mark("vtd: %s wrote %s=%s", vm, index, marker)
	cut := l.powerOff(victim)
	gap := cut.Sub(written)
	l.mark("vtd: %s powered off %v after the write", victim, gap.Round(time.Millisecond))
	if gap > time.Second {
		t.Fatalf("the power cut came %v after the write; it must come within 1 s to prove anything", gap)
	}

	// 4. Back on: the state file on disk holds it, and the TPM hands it back.
	if err := l.powerOn(victim); err != nil {
		t.Fatalf("power on %s: %v", victim, err)
	}
	after := strings.TrimSpace(l.mustSSH(victim, 20*time.Second, "grep -a -c -F "+shellQuote(marker)+" "+shellQuote(state)+"; true"))
	onDisk := after != "" && after != "0"
	l.saveEvidence("vtd-state-after-cut.txt", fmt.Sprintf("vm %s uuid %s expect-loss %v\nstate %s\nmount: %s\nattrs:\n%s\nwrite→cut %v\nmarker on disk after power-on: %s\n",
		vm, uuid, expectLoss, state, mount, attrs, gap, after))
	if !l.waitDomainState(victim, vm, "running", 6*time.Minute) {
		t.Fatalf("%s did not start on %s once it was back", vm, victim)
	}
	var got string
	for deadline := time.Now().Add(10 * time.Minute); time.Now().Before(deadline); time.Sleep(10 * time.Second) {
		out, ok, err := guest("sudo tpm2_nvread " + index + " -C o -s 32 | tr -d '\\000'")
		if err == nil && ok {
			got = strings.TrimSpace(out)
			break
		}
	}
	l.mark("vtd: %s after a power cut %v after the write: on disk %v, TPM reads %q (expect loss %v)", vm, gap.Round(time.Millisecond), onDisk, got, expectLoss)
	switch {
	case got == "":
		t.Fatalf("could not read %s from %s's TPM after the power cut", index, vm)
	case expectLoss && (onDisk || got == marker):
		t.Fatalf("control run: the write survived (on disk %v, TPM reads %q)", onDisk, got)
	case expectLoss && got != before:
		t.Fatalf("control run: the TPM reads %q, want the value before, %q", got, before)
	case !expectLoss && !onDisk:
		t.Fatalf("the TPM write made %v before the power cut is not in %s on %s's disk", gap.Round(time.Millisecond), state, victim)
	case !expectLoss && got != marker:
		t.Fatalf("after the power cut %s's TPM reads %q, want %q", vm, got, marker)
	}
}
