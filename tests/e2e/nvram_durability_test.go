package e2e

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/health"
	lvirt "github.com/litevirt/litevirt/internal/libvirt"
)

// Drills: a guest's UEFI variable write survives a hard power cut of its host
// a few seconds later.
//
// qemu writes the UEFI vars file with no flush and libvirt has no cache mode
// for <nvram>, so without the daemon's flusher (libvirt.NvramFlusher) the
// write waits in the host page cache for writeback (30 s by default) and the
// power cut loses it (lab 2, 2026-10-18: a write 9 s before the cut was gone).
//
//	E2E_UEFI_IMAGE        a UEFI-bootable cloud image with efivarfs (default ubuntu-ga)
//	E2E_UEFI_MEMORY       its memory (default 768)
//	E2E_NVRAM_CUT_AFTER   delay between the write and the power cut (default 3s, 2s to 5s)
//	E2E_NVRAM_EXPECT_LOSS 1 for the control run on a build without the flusher:
//	                      the write must then be lost
//
// What they check, on real qemu and the host's own disk:
//
//  1. periodic writeback is off on the host (vm.dirty_writeback_centisecs=0,
//     after a sync), so only an fsync can put the write on disk before the
//     cut;
//  2. a variable written in the guest through efivarfs reaches the host's
//     vars file (read on the host before the cut);
//  3. the host is powered off E2E_NVRAM_CUT_AFTER after the write;
//  4. once the host is back, its vars file on disk still holds the value, and
//     the guest, started again there, reads it back from its firmware.
//
// One drill covers a plain UEFI VM, whose vars file is libvirt's
// (/var/lib/libvirt/qemu/nvram); the other a Secure Boot + vTPM VM, whose
// vars file is litevirt's (<data_dir>/nvram). Both are created plain with
// onboot, so the VM starts again on its host once it is back; the second is
// then stopped, given Secure Boot and a vTPM with lv update, and started.
func TestDrill_UEFIVariableSurvivesHostPowerCut(t *testing.T) {
	uefiVariablePowerCutDrill(t, false)
}

func TestDrill_UEFIVariableSurvivesHostPowerCut_SecureBootVTPM(t *testing.T) {
	uefiVariablePowerCutDrill(t, true)
}

func uefiVariablePowerCutDrill(t *testing.T, secureBoot bool) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	cutAfter := 3 * time.Second
	if v := envOr("E2E_NVRAM_CUT_AFTER", ""); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 2*time.Second || d > 5*time.Second {
			t.Fatalf("E2E_NVRAM_CUT_AFTER=%q: want a duration from 2s to 5s", v)
		}
		cutAfter = d
	}
	expectLoss := envOr("E2E_NVRAM_EXPECT_LOSS", "") == "1"

	q := l.hosts[0]
	victim := l.leastLoaded(q, l.except(q))
	stack := uniqueName("nvd")
	vm := stack + "-1"
	const guestUser, guestPassword = "ubuntu", "nvd-e2e-pw"
	yaml := fmt.Sprintf(`name: %[1]s
networks:
  nvd:
    type: bridge
    interface: e2envdbr
    subnet: 10.208.0.0/24
    dhcp: true
vms:
  %[2]s:
    image: %[3]s
    firmware: uefi
    onboot: true
    machine: q35
    cpu: 1
    memory: %[4]s
    disks:
      root:
        size: 8G
    network: [{name: nvd}]
    placement:
      host: %[5]s
    migrate:
      on-host-failure: restart-same
    cloud-init:
      userdata: |
        #cloud-config
        ssh_pwauth: true
        chpasswd:
          expire: false
          users:
            - {name: %[6]s, password: %[7]s, type: text}
`, stack, vm, envOr("E2E_UEFI_IMAGE", "ubuntu-ga"), envOr("E2E_UEFI_MEMORY", "768"), victim, guestUser, guestPassword)
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
	waitGuest := func() {
		t.Helper()
		var last error
		for deadline := time.Now().Add(10 * time.Minute); time.Now().Before(deadline); time.Sleep(10 * time.Second) {
			out, ok, err := guest("test -d /sys/firmware/efi/efivars && echo EFI")
			if err == nil && ok && strings.Contains(out, "EFI") {
				return
			}
			if err == nil && !ok {
				t.Fatalf("%s did not boot under UEFI (no efivarfs): %s", vm, out)
			}
			last = err
		}
		t.Fatalf("%s never accepted a login: %v", vm, last)
	}
	waitGuest()
	if secureBoot {
		l.mustLV(q, "stop", vm)
		if !l.waitDomainState(victim, vm, "shut off", 3*time.Minute) {
			t.Fatalf("%s never stopped on %s (virsh)", vm, victim)
		}
		l.mustLV(q, "update", vm, "--secure-boot", "--tpm", "--force")
		// A build without fix/update-firmware-nvram-dir leaves the vars
		// file's directory unmade on a host where no Secure Boot VM was ever
		// created, and the start then fails. Make it as the daemon does, and
		// say so: this drill measures the flush, not that fix.
		sbXML := l.mustSSH(victim, 30*time.Second, "virsh -c qemu:///system dumpxml --inactive "+shellQuote(vm))
		if p := lvirt.NvramPathFromXML(sbXML); p != "" {
			dir := shellQuote(filepath.Dir(p))
			if out, _ := l.ssh(victim, 20*time.Second, "test -d "+dir+" && echo present || { install -d -m 0711 "+dir+" && echo made; }"); strings.TrimSpace(out) == "made" {
				l.mark("nvd: lv update left no %s on %s; made it 0711 (a build without fix/update-firmware-nvram-dir)", filepath.Dir(p), victim)
			}
		}
		l.mustLV(q, "start", vm)
		if !l.waitDomainState(victim, vm, "running", 4*time.Minute) {
			t.Fatalf("%s never ran on %s with Secure Boot and a vTPM (virsh)", vm, victim)
		}
		waitGuest()
	}

	xml := l.mustSSH(victim, 30*time.Second, "virsh -c qemu:///system dumpxml "+shellQuote(vm))
	vars := lvirt.NvramPathFromXML(xml)
	if vars == "" {
		t.Fatalf("%s's domain names no <nvram> file:\n%s", vm, xml)
	}
	inLibvirtDir := strings.HasPrefix(vars, health.LibvirtNvramDir+"/")
	if secureBoot == inLibvirtDir {
		t.Fatalf("%s's vars file is %s: want it under <data_dir>/nvram for Secure Boot + vTPM, under %s otherwise", vm, vars, health.LibvirtNvramDir)
	}

	// 1. Only an fsync can persist the write: periodic writeback off, after
	// a sync that cleans what boot dirtied. The power cut resets the sysctl;
	// restore puts it back if the drill fails before that. The guest syncs
	// first: cloud-init does not fsync the SSH host keys it writes at first
	// boot, so a cut seconds after it leaves them empty and sshd never
	// answers again. That sync comes before the measured write.
	if out, ok, err := guest("sudo sync"); err != nil || !ok {
		t.Fatalf("sync in %s: ok=%v err=%v %s", vm, ok, err, out)
	}
	orig := strings.TrimSpace(l.mustSSH(victim, 20*time.Second, "cat /proc/sys/vm/dirty_writeback_centisecs"))
	if _, err := strconv.Atoi(orig); err != nil {
		t.Fatalf("vm.dirty_writeback_centisecs on %s: %q", victim, orig)
	}
	l.onRestore(func() { l.ssh(victim, 20*time.Second, "sysctl -qw vm.dirty_writeback_centisecs="+orig) })
	l.mustSSH(victim, 2*time.Minute, "sync && sysctl -qw vm.dirty_writeback_centisecs=0 && sync")

	// 2. The variable: non-volatile, boot-service and runtime access (0x07).
	marker := "lvnvd-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	efivar := "/sys/firmware/efi/efivars/LvNvramDurability-7a1c3d2e-0000-4d2e-9a1b-6e7672616d31"
	read := "sudo cat " + efivar + " | tail -c +5"
	if out, ok, err := guest(fmt.Sprintf(`sudo sh -c "printf '\007\000\000\000%s' > %s" && %s`, marker, efivar, read)); err != nil || !ok || strings.TrimSpace(out) != marker {
		t.Fatalf("write the UEFI variable in %s: ok=%v err=%v out=%q", vm, ok, err, out)
	}
	written := l.mark("nvd: %s wrote %s=%s", vm, efivar, marker)

	grepVars := "grep -a -c -F " + shellQuote(marker) + " " + shellQuote(vars)
	if out, _ := l.ssh(victim, 20*time.Second, grepVars); strings.TrimSpace(out) == "0" || strings.TrimSpace(out) == "" {
		t.Fatalf("the value never reached %s on %s: grep says %q", vars, victim, out)
	}
	stat := l.mustSSH(victim, 20*time.Second, "stat -c '%y %s' "+shellQuote(vars))
	// The guarantee rests on the filesystem the vars file is on: record it.
	mount := strings.TrimSpace(l.mustSSH(victim, 20*time.Second, "findmnt -no SOURCE,FSTYPE,OPTIONS -T "+shellQuote(vars)))

	// 3. The power cut.
	if wait := cutAfter - time.Since(written) - time.Second; wait > 0 {
		time.Sleep(wait)
	}
	meminfo, _ := l.ssh(victim, 10*time.Second, "grep -E '^(Dirty|Writeback):' /proc/meminfo; cat /proc/sys/vm/dirty_writeback_centisecs")
	if wait := cutAfter - time.Since(written); wait > 0 {
		time.Sleep(wait)
	}
	cut := l.powerOff(victim)
	gap := cut.Sub(written)
	l.mark("nvd: %s powered off %v after the write (vars %s: %s; on %s)", victim, gap.Round(time.Millisecond), vars, strings.TrimSpace(stat), mount)
	if gap > 5*time.Second {
		t.Fatalf("the power cut came %v after the write; it must come within 5 s to prove anything", gap)
	}

	// 4. Back on: the file on disk holds it, and the firmware hands it back.
	if err := l.powerOn(victim); err != nil {
		t.Fatalf("power on %s: %v", victim, err)
	}
	after := l.mustSSH(victim, 20*time.Second, "stat -c '%y %s' "+shellQuote(vars)+"; "+grepVars+" || true")
	l.saveEvidence("nvd-vars-after-cut.txt", fmt.Sprintf("vm %s secure-boot+tpm %v expect-loss %v\nvars %s\nmount: %s\nbefore cut: %s\nmeminfo before cut:\n%s\nafter power-on: %s\nwrite→cut %v\n",
		vm, secureBoot, expectLoss, vars, mount, stat, meminfo, after, gap))
	lines := strings.Split(strings.TrimSpace(after), "\n")
	onDisk := strings.TrimSpace(lines[len(lines)-1]) != "0"
	switch {
	case expectLoss && onDisk:
		t.Fatalf("control run: the UEFI variable is in %s on %s's disk although no flusher ran; the drill cannot tell a fix from luck (stat/grep: %q)", vars, victim, after)
	case !expectLoss && !onDisk:
		t.Fatalf("the UEFI variable written %v before the power cut is not in %s on %s's disk: the write was lost (stat/grep: %q)", gap.Round(time.Millisecond), vars, victim, after)
	}
	l.waitAllActive(q, 6*time.Minute)
	if !l.waitDomainState(victim, vm, "running", 5*time.Minute) {
		st, _ := l.ssh(victim, 20*time.Second, "virsh -c qemu:///system domstate --reason "+shellQuote(vm))
		t.Fatalf("%s did not start on %s once it was back (virsh: %q)", vm, victim, strings.TrimSpace(st))
	}
	waitGuest()
	out, ok, err := guest(read)
	got := strings.TrimSpace(out)
	switch {
	case err != nil:
		t.Fatalf("read %s in %s after the power cut: %v", efivar, vm, err)
	case expectLoss && ok && got == marker:
		t.Fatalf("control run: %s still reads %s as %q after the power cut", vm, efivar, got)
	case !expectLoss && (!ok || got != marker):
		t.Fatalf("after the power cut %s reads %s as %q (ok=%v), want %q", vm, efivar, got, ok, marker)
	}
	l.mark("nvd: %s after a power cut %v after the write: on disk %v, guest reads %q (expect loss %v)", vm, gap.Round(time.Millisecond), onDisk, got, expectLoss)
}
