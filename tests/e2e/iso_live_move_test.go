package e2e

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A running VM's installer ISO across a live migration and a drain, on the
// nested lab (E2E_LAB_DIR; skipped without it, and the whole suite skips
// without LITEVIRT_E2E=1).
//
// Every node gets /srv/lv-e2e-iso/x.iso as a link to a file whose name is the
// node's own (x-node-N.iso), as virtio-win.iso links to a versioned file that
// differs between hosts while a fleet updates. After each move, what the
// target's qemu holds open is read from the node itself — virsh's live and
// persistent definitions, and /proc/<qemu pid>/fd — never from litevirt.
//
//	LITEVIRT_E2E=1 LV_BIN=/usr/local/bin/litevirt E2E_LAB_DIR=~/litevirt-lab \
//	  go test ./tests/e2e/ -run TestLab_ISO -v -timeout 40m

const isoLinkDir = "/srv/lv-e2e-iso"

func isoFileOn(host string) string { return isoLinkDir + "/x-" + host + ".iso" }

// prepareISOLinks writes, on every node, an optical image under the node's own
// name and the link x.iso to it.
func prepareISOLinks(l *lab) {
	l.t.Helper()
	for _, h := range l.hosts {
		if !l.isUp(h) {
			continue
		}
		f := isoFileOn(h)
		l.mustSSH(h, 30*time.Second, fmt.Sprintf(
			"mkdir -p %[1]s && truncate -s 1M %[2]s && printf '\\001CD001\\001' | dd of=%[2]s bs=1 seek=32768 conv=notrunc status=none && ln -sfn %[2]s %[1]s/x.iso",
			isoLinkDir, shellQuote(f)))
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

// whereRunning is the node whose virsh shows domain running.
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

// requireISOOpenedOn checks, on host, that the running domain's CD-ROM, its
// persistent definition's CD-ROM and the file qemu holds open are the node's
// own file, and that no other node's file is open.
func requireISOOpenedOn(l *lab, host, domain string) {
	l.t.Helper()
	want := isoFileOn(host)
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
		if h != host && strings.Contains(fds, isoFileOn(h)) {
			l.t.Fatalf("%s on %s: qemu holds %s's file open:\n%s", domain, host, h, fds)
		}
	}
	l.mark("iso: %s on %s opened %s (live, persistent, /proc fd)", domain, host, want)
}

// A live migration, tunnelled and with storage, lands on the target's file.
func TestLab_ISOLiveMoveOpensTheTargetsFile(t *testing.T) {
	l := newLab(t)
	src, dst := l.hosts[0], l.hosts[1]
	prepareISOLinks(l)
	vm := isoVM(l, src, src)
	requireISOOpenedOn(l, src, vm)

	// Tunnelled (memory only) where the VM's disk is on shared storage; a
	// host-local disk needs the storage copy, which the second leg covers.
	if out, err := l.lv(src, "migrate", vm, dst); err != nil {
		if !strings.Contains(out+err.Error(), "with-storage") {
			t.Fatalf("live migrate %s → %s: %v\n%s", vm, dst, err, out)
		}
		l.mark("iso: %s has a host-local disk, so the tunnelled leg is not available here; moving it with storage", vm)
		if out, err := l.lv(src, "migrate", vm, dst, "--with-storage"); err != nil {
			t.Fatalf("live migrate --with-storage %s → %s: %v\n%s", vm, dst, err, out)
		}
	}
	if !l.waitDomainState(dst, vm, "running", 4*time.Minute) {
		t.Fatalf("%s is not running on %s after the live move", vm, dst)
	}
	requireISOOpenedOn(l, dst, vm)

	if out, err := l.lv(src, "migrate", vm, src, "--with-storage"); err != nil {
		t.Fatalf("live migrate --with-storage %s → %s: %v\n%s", vm, src, err, out)
	}
	if !l.waitDomainState(src, vm, "running", 6*time.Minute) {
		t.Fatalf("%s is not running on %s after the storage move", vm, src)
	}
	requireISOOpenedOn(l, src, vm)
}

// A drain moves the running VM live, onto whichever node it picks, and that
// node's own file is what its qemu opens.
func TestLab_ISODrainOpensTheTargetsFile(t *testing.T) {
	l := newLab(t)
	src := l.hosts[len(l.hosts)-1]
	prepareISOLinks(l)
	vm := isoVM(l, l.hosts[0], src)
	requireISOOpenedOn(l, src, vm)

	t.Cleanup(func() { l.lv(l.hosts[0], "host", "undrain", src) })
	if out, err := l.lv(l.hosts[0], "host", "drain", src); err != nil && !strings.Contains(out, "drain incomplete") {
		t.Fatalf("drain %s: %v\n%s", src, err, out)
	}
	to := whereRunning(l, vm, 6*time.Minute)
	if to == "" || to == src {
		t.Fatalf("%s did not move off %s (running on %q)", vm, src, to)
	}
	requireISOOpenedOn(l, to, vm)
}
