package e2e

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A running VM's installer ISO across live migrations, a drain and a memory
// snapshot's revert, on the nested lab (E2E_LAB_DIR; skipped without it, and
// the whole suite skips without LITEVIRT_E2E=1).
//
// Every node holds EVERY node's file x-<node>.iso (an optical image), and
// /srv/lv-e2e-iso/x.iso links to the node's own — as virtio-win.iso links to a
// versioned file that differs between hosts while a fleet updates. A move that
// handed the target the source's file would open an existing, wrong file
// there, and that is what is checked: after each step, what the node's qemu
// holds open is read from the node itself — virsh's live and persistent
// definitions, and /proc/<qemu pid>/fd — never from litevirt.
//
// Each leg runs or skips by name, saying why, so a green run never stands for
// a leg it did not exercise:
//
//	live-tunnelled      lv migrate (memory only): needs the VM's disk on
//	                    shared storage, else skipped
//	live-with-storage   lv migrate --with-storage
//	drain-live          lv host drain moving it live: a VM with a host-local
//	                    disk is moved cold instead, and the leg is skipped
//	                    after checking the cold landing
//	memory-revert       lv snapshot create --memory, the link re-pointed,
//	                    lv snapshot restore: the revert opens the file the link
//	                    names now, and the VNC password survives
//
//	LITEVIRT_E2E=1 LV_BIN=/usr/local/bin/litevirt E2E_LAB_DIR=~/litevirt-lab \
//	  go test ./tests/e2e/ -run TestLab_ISO -v -timeout 60m

const isoLinkDir = "/srv/lv-e2e-iso"

func isoFileOf(host string) string { return isoLinkDir + "/x-" + host + ".iso" }

// prepareISOLinks writes, on every up node, every node's optical image and the
// link x.iso to the node's own.
func prepareISOLinks(l *lab, up []string) {
	l.t.Helper()
	for _, h := range up {
		var cmd strings.Builder
		fmt.Fprintf(&cmd, "mkdir -p %s", isoLinkDir)
		for _, o := range l.hosts {
			f := shellQuote(isoFileOf(o))
			fmt.Fprintf(&cmd, " && truncate -s 1M %[1]s && printf '\\001CD001\\001' | dd of=%[1]s bs=1 seek=32768 conv=notrunc status=none", f)
		}
		fmt.Fprintf(&cmd, " && ln -sfn %s %s/x.iso", shellQuote(isoFileOf(h)), isoLinkDir)
		l.mustSSH(h, 60*time.Second, cmd.String())
	}
	l.t.Cleanup(func() {
		for _, h := range l.upHosts() {
			l.ssh(h, 30*time.Second, "rm -rf "+isoLinkDir)
		}
	})
}

// isoVM deploys a small VM pinned to host whose installer ISO is the link.
func isoVM(l *lab, via, host string) string {
	l.t.Helper()
	stack := uniqueName("isomv")
	name := stack + "-1"
	yaml := fmt.Sprintf("name: %s\nvms:\n  %s:\n    image: %s\n    cpu: 1\n    memory: %s\n    iso: %s/x.iso\n    placement:\n      host: %s\n",
		stack, name, drillImage(), drillMemory(), isoLinkDir, host)
	file := "/tmp/" + stack + ".yaml"
	l.mustSSH(via, 30*time.Second, "echo "+base64.StdEncoding.EncodeToString([]byte(yaml))+" | base64 -d > "+file)
	l.t.Cleanup(func() { l.deleteVMs(stack, map[string]string{host: name}) })
	if out, err := l.lv(via, "compose", "up", "-f", file, "-y"); err != nil {
		l.t.Fatalf("compose up %s: %v\n%s", stack, err, out)
	}
	if !l.waitDomainState(host, name, "running", 4*time.Minute) {
		l.t.Fatalf("test VM %s never ran on %s (virsh)", name, host)
	}
	return name
}

// whereRunning is the up node whose virsh shows domain running.
func whereRunning(l *lab, domain string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, h := range l.upHosts() {
			out, _ := l.ssh(h, 20*time.Second, "virsh -c qemu:///system domstate "+shellQuote(domain)+" 2>/dev/null")
			if strings.TrimSpace(out) == "running" {
				return h
			}
		}
		time.Sleep(3 * time.Second)
	}
	return ""
}

// requireISOOpened checks, on host, that the running domain's CD-ROM, its
// persistent definition's CD-ROM and the file qemu holds open are want, and
// that no other node's file is open.
func requireISOOpened(l *lab, host, domain, want string) {
	l.t.Helper()
	live := l.mustSSH(host, 30*time.Second, "virsh -c qemu:///system domblklist --details "+shellQuote(domain))
	if !strings.Contains(live, want) {
		l.t.Fatalf("%s on %s: the running domain's disks are\n%s\nwant the CD-ROM %s", domain, host, live, want)
	}
	persist := l.mustSSH(host, 30*time.Second, "virsh -c qemu:///system dumpxml --inactive "+shellQuote(domain))
	if !strings.Contains(persist, want) {
		l.t.Fatalf("%s on %s: the persistent definition does not carry %s", domain, host, want)
	}
	fds := l.mustSSH(host, 30*time.Second, fmt.Sprintf(
		"pid=$(cat /run/libvirt/qemu/%s.pid) && ls -l /proc/$pid/fd | grep %s || true", shellQuote(domain), isoLinkDir))
	if !strings.Contains(fds, want) {
		l.t.Fatalf("%s on %s: qemu holds open\n%s\nwant %s", domain, host, fds, want)
	}
	for _, h := range l.hosts {
		if f := isoFileOf(h); f != want && strings.Contains(fds, f) {
			l.t.Fatalf("%s on %s: qemu holds %s open (the wrong file):\n%s", domain, host, f, fds)
		}
	}
	l.mark("iso: %s on %s opened %s (live, persistent, /proc fd)", domain, host, want)
}

func labUpHosts(l *lab, n int) []string {
	l.t.Helper()
	up := l.upHosts()
	if len(up) < n {
		l.t.Skipf("need %d up lab nodes, have %v", n, up)
	}
	return up
}

func TestLab_ISOLiveMovesOpenTheTargetsFile(t *testing.T) {
	l := newLab(t)
	up := labUpHosts(l, 2)
	src, dst := up[0], up[1]
	prepareISOLinks(l, up)
	vm := isoVM(l, src, src)
	requireISOOpened(l, src, vm, isoFileOf(src))
	at := src

	t.Run("live-tunnelled", func(t *testing.T) {
		out, err := l.lv(src, "migrate", vm, dst)
		if err != nil && strings.Contains(out+err.Error(), "with-storage") {
			t.Skipf("%s's disk is host-local; the tunnelled (memory-only) leg needs the VM on a shared pool: %s", vm, strings.TrimSpace(out))
		}
		if err != nil {
			t.Fatalf("live migrate %s → %s: %v\n%s", vm, dst, err, out)
		}
		if !l.waitDomainState(dst, vm, "running", 4*time.Minute) {
			t.Fatalf("%s is not running on %s after the live move", vm, dst)
		}
		at = dst
		requireISOOpened(l, dst, vm, isoFileOf(dst))
	})

	t.Run("live-with-storage", func(t *testing.T) {
		to := dst
		if at == dst {
			to = src
		}
		if out, err := l.lv(at, "migrate", vm, to, "--with-storage"); err != nil {
			t.Fatalf("live migrate --with-storage %s → %s: %v\n%s", vm, to, err, out)
		}
		if !l.waitDomainState(to, vm, "running", 6*time.Minute) {
			t.Fatalf("%s is not running on %s after the storage move", vm, to)
		}
		at = to
		requireISOOpened(l, to, vm, isoFileOf(to))
	})
}

func TestLab_ISODrainOpensTheTargetsFile(t *testing.T) {
	l := newLab(t)
	up := labUpHosts(l, 2)
	via, src := up[0], up[len(up)-1]
	prepareISOLinks(l, up)
	vm := isoVM(l, via, src)
	requireISOOpened(l, src, vm, isoFileOf(src))

	t.Cleanup(func() { l.lv(via, "host", "undrain", src) })
	out, err := l.lv(via, "host", "drain", src)
	if err != nil && !strings.Contains(out, "drain incomplete") {
		t.Fatalf("drain %s: %v\n%s", src, err, out)
	}
	var line string
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, vm) {
			line = ln
		}
	}
	to := whereRunning(l, vm, 6*time.Minute)
	if to == "" || to == src {
		t.Fatalf("%s did not move off %s (running on %q); drain said %q", vm, src, to, line)
	}
	requireISOOpened(l, to, vm, isoFileOf(to))
	t.Run("drain-live", func(t *testing.T) {
		switch {
		case strings.Contains(line, "[MIGRATE_LIVE]"):
			l.mark("iso: the drain moved %s live: %s", vm, line)
		case strings.Contains(line, "[MIGRATE_COLD]"):
			t.Skipf("the drain moved %s cold (a host-local disk), so the live drain was not exercised; the cold landing was checked: %s", vm, line)
		default:
			t.Fatalf("the drain's line for %s names no strategy: %q", vm, line)
		}
	})
}

func TestLab_ISOMemoryRevertOpensTheJudgedFile(t *testing.T) {
	l := newLab(t)
	up := labUpHosts(l, 2)
	h, other := up[0], up[1]
	prepareISOLinks(l, up)
	vm := isoVM(l, h, h)
	requireISOOpened(l, h, vm, isoFileOf(h))

	t.Run("memory-revert", func(t *testing.T) {
		// A VNC password the saved image must carry back.
		const pw = "e2e-iso-pw"
		l.mustSSH(h, 30*time.Second, fmt.Sprintf(
			"virsh -c qemu:///system dumpxml --security-info %[1]s | sed -n '/<graphics type=.vnc./,/<\\/graphics>/p' | sed -e 's#<graphics #<graphics passwd=\"%[2]s\" #' -e 's#passwd=\"[^\"]*\" passwd=#passwd=#' > /tmp/%[1]s-gfx.xml && virsh -c qemu:///system update-device %[1]s /tmp/%[1]s-gfx.xml --live",
			shellQuote(vm), pw))
		if out, err := l.lv(h, "snapshot", "create", vm, "iso-mem", "--memory"); err != nil {
			t.Fatalf("memory snapshot of %s: %v\n%s", vm, err, out)
		}
		// The link now names another file on this node: the revert must open
		// that one (judged now), not the one the image was saved with.
		l.mustSSH(h, 30*time.Second, fmt.Sprintf("ln -sfn %s %s/x.iso", shellQuote(isoFileOf(other)), isoLinkDir))
		if out, err := l.lv(h, "snapshot", "restore", vm, "iso-mem"); err != nil {
			t.Fatalf("revert %s to its memory snapshot: %v\n%s", vm, err, out)
		}
		if !l.waitDomainState(h, vm, "running", 3*time.Minute) {
			t.Fatalf("%s is not running after the revert", vm)
		}
		requireISOOpened(l, h, vm, isoFileOf(other))
		sec := l.mustSSH(h, 30*time.Second, "virsh -c qemu:///system dumpxml --security-info "+shellQuote(vm))
		if !strings.Contains(sec, `passwd='`+pw+`'`) && !strings.Contains(sec, `passwd="`+pw+`"`) {
			t.Fatalf("the reverted domain lost its VNC password:\n%s", sec)
		}
	})
}
