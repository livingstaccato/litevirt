package e2e

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	lvirt "github.com/litevirt/litevirt/internal/libvirt"
)

// Drill: a guest's UEFI variable write survives a hard power cut of its host
// a few seconds later.
//
// qemu writes the UEFI vars file with no flush and libvirt has no cache mode
// for <nvram>, so without the daemon's flusher (libvirt.NvramFlusher) the
// write waits in the host page cache for writeback (30 s by default) and the
// power cut loses it (lab 2, 2026-10-18: a write 9 s before the cut was gone).
//
//	E2E_UEFI_IMAGE      a UEFI-bootable cloud image with efivarfs (default ubuntu-ga)
//	E2E_UEFI_MEMORY     its memory (default 768)
//	E2E_NVRAM_CUT_AFTER delay between the write and the power cut (default 3s)
//
// What it checks, on real qemu and the host's own disk:
//
//  1. a variable written in the guest through efivarfs reaches the host's
//     vars file (read on the host before the cut);
//  2. the host is powered off E2E_NVRAM_CUT_AFTER (default 3 s, at most 5 s)
//     after the write;
//  3. once the host is back, its vars file on disk still holds the value, and
//     the guest, started again there, reads it back from its firmware.
func TestDrill_UEFIVariableSurvivesHostPowerCut(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	cutAfter := 3 * time.Second
	if v := envOr("E2E_NVRAM_CUT_AFTER", ""); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 || d > 5*time.Second {
			t.Fatalf("E2E_NVRAM_CUT_AFTER=%q: want a duration from 0 to 5s", v)
		}
		cutAfter = d
	}

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

	xml := l.mustSSH(victim, 30*time.Second, "virsh -c qemu:///system dumpxml "+shellQuote(vm))
	vars := lvirt.NvramPathFromXML(xml)
	if vars == "" {
		t.Fatalf("%s's domain names no <nvram> file:\n%s", vm, xml)
	}

	// The variable: non-volatile, boot-service and runtime access (0x07).
	marker := "lvnvd-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	efivar := "/sys/firmware/efi/efivars/LvNvramDurability-7a1c3d2e-0000-4d2e-9a1b-6e7672616d31"
	read := "sudo cat " + efivar + " | tail -c +5"
	if out, ok, err := guest(fmt.Sprintf(`sudo sh -c "printf '\007\000\000\000%s' > %s" && %s`, marker, efivar, read)); err != nil || !ok || strings.TrimSpace(out) != marker {
		t.Fatalf("write the UEFI variable in %s: ok=%v err=%v out=%q", vm, ok, err, out)
	}
	written := l.mark("nvd: %s wrote %s=%s", vm, efivar, marker)

	grepVars := "grep -a -c -F " + shellQuote(marker) + " " + shellQuote(vars)
	// 1. It reached the host (from its page cache, at least).
	if out, _ := l.ssh(victim, 20*time.Second, grepVars); strings.TrimSpace(out) == "0" || strings.TrimSpace(out) == "" {
		t.Fatalf("the value never reached %s on %s: grep says %q", vars, victim, out)
	}
	stat := l.mustSSH(victim, 20*time.Second, "stat -c '%y %s' "+shellQuote(vars))

	// 2. The power cut.
	if wait := cutAfter - time.Since(written); wait > 0 {
		time.Sleep(wait)
	}
	cut := l.powerOff(victim)
	gap := cut.Sub(written)
	l.mark("nvd: %s powered off %v after the write (vars %s: %s)", victim, gap.Round(time.Millisecond), vars, strings.TrimSpace(stat))
	if gap > 5*time.Second {
		t.Fatalf("the power cut came %v after the write; it must come within 5 s to prove anything", gap)
	}

	// 3. Back on: the file on disk holds it, and the firmware hands it back.
	if err := l.powerOn(victim); err != nil {
		t.Fatalf("power on %s: %v", victim, err)
	}
	after := l.mustSSH(victim, 20*time.Second, "stat -c '%y %s' "+shellQuote(vars)+"; "+grepVars+" || true")
	l.saveEvidence("nvd-vars-after-cut.txt", fmt.Sprintf("vars %s\nbefore cut: %s\nafter power-on: %s\nwrite→cut %v\n", vars, stat, after, gap))
	lines := strings.Split(strings.TrimSpace(after), "\n")
	if n := strings.TrimSpace(lines[len(lines)-1]); n == "0" {
		t.Fatalf("the UEFI variable written %v before the power cut is not in %s on %s's disk: the write was lost (stat/grep: %q)", gap.Round(time.Millisecond), vars, victim, after)
	}
	l.waitAllActive(q, 6*time.Minute)
	if !l.waitDomainState(victim, vm, "running", 5*time.Minute) {
		st, _ := l.ssh(victim, 20*time.Second, "virsh -c qemu:///system domstate --reason "+shellQuote(vm))
		t.Fatalf("%s did not start on %s once it was back (virsh: %q)", vm, victim, strings.TrimSpace(st))
	}
	waitGuest()
	if out, ok, err := guest(read); err != nil || !ok || strings.TrimSpace(out) != marker {
		t.Fatalf("after the power cut %s reads %s as %q (ok=%v err=%v), want %q", vm, efivar, strings.TrimSpace(out), ok, err, marker)
	}
	l.mark("nvd: %s reads %s back after a power cut %v after the write", vm, marker, gap.Round(time.Millisecond))
}
