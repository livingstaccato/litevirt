package e2e

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// NIC hot-detach against a real libvirt domain — the regression guard for the
// fix in "fix(libvirt): build NIC detach XML from the domain, not from the MAC
// alone".
//
// The bug: DetachNIC had only a MAC to work from, so it marshalled
// `<interface type="bridge">` with an EMPTY `<source>`. libvirt matches an
// interface by MAC BEFORE validating the device element, so the malformed source
// went unexamined while the MAC was present — and surfaced as
//
//	XML error: Missing required attribute 'bridge' in element 'source'
//
// the moment it wasn't, which says nothing about the real problem.
//
// The pre-existing TestVM_AttachDetachNIC cannot catch this class: it detaches
// only `if len(macs) >= 2` — so a run that fails to parse two MACs skips the
// detach entirely and still passes — and it never checks that the interface
// actually went away. This asserts against `virsh domiflist`, i.e. the domain
// itself, so "litevirt returned success" is not accepted as evidence.

// domIfaceMACs returns the MACs libvirt currently reports on a domain.
func domIfaceMACs(t *testing.T, domain string) []string {
	t.Helper()
	out, err := exec.Command("virsh", "-c", "qemu:///system", "domiflist", domain).CombinedOutput()
	if err != nil {
		t.Fatalf("virsh domiflist %s: %v\n%s", domain, err, out)
	}
	var macs []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		// Interface Type Source Model MAC — the MAC is the last column.
		if len(f) >= 5 && strings.Count(f[len(f)-1], ":") == 5 {
			macs = append(macs, strings.ToLower(f[len(f)-1]))
		}
	}
	return macs
}

func containsMAC(macs []string, mac string) bool {
	for _, m := range macs {
		if strings.EqualFold(m, mac) {
			return true
		}
	}
	return false
}

// waitGuestActive waits until libvirt can see the guest on the network (ARP),
// i.e. the kernel is up and driving devices.
//
// This must happen BEFORE the attach, not just before the detach. A NIC
// hot-plugged into a guest whose PCI subsystem has not initialised is never
// enumerated, so the guest cannot eject it later either — the detach then fails
// forever for a reason that has nothing to do with detach. Proceeds anyway on
// timeout and lets the detach retry loop decide, rather than skipping on a
// signal that is only a proxy for readiness.
func waitGuestActive(t *testing.T, domain string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("virsh", "-c", "qemu:///system", "domifaddr", domain, "--source", "arp").CombinedOutput()
		if err == nil && strings.Count(string(out), ".") >= 3 {
			return
		}
		time.Sleep(10 * time.Second)
	}
	t.Logf("guest %s not visible on the network after %s; continuing anyway", domain, timeout)
}

// virtioDriversOK reports whether vm (on host) has at least one virtio device of
// the given kind ("virtio-blk", "virtio-net") and a guest driver has taken up
// every one of them: DRIVER_OK in the device status, which the guest sets once
// its driver has bound and initialised the device. It asks QEMU directly
// (x-query-virtio / x-query-virtio-status, QEMU >= 7.2) on the VM's host, so it
// is a fact about the guest, not litevirt's report of one.
//
// It needs no NIC and no guest agent, which is what a VM from `lv run` has
// neither of: its root disk being driven is the "guest has booted" signal, and
// a hot-added NIC being driven is the "guest has enumerated the device it will
// be asked to eject" signal.
//
// An error means the question could not be asked (no shell on the host, no
// virsh, an older QEMU), never "not ready".
func virtioDriversOK(host, vm, kind string) (bool, error) {
	qmp := func(cmd string) (json.RawMessage, error) {
		out, err := nodeOut(host, "virsh -c qemu:///system qemu-monitor-command "+shellQuote(vm)+" "+shellQuote(cmd))
		if err != nil {
			return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(out))
		}
		var reply struct {
			Return json.RawMessage `json:"return"`
		}
		if err := json.Unmarshal([]byte(out), &reply); err != nil || reply.Return == nil {
			return nil, fmt.Errorf("unexpected QMP reply to %s: %.200s", cmd, out)
		}
		return reply.Return, nil
	}
	raw, err := qmp(`{"execute":"x-query-virtio"}`)
	if err != nil {
		return false, err
	}
	var devs []struct {
		Path string `json:"path"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &devs); err != nil {
		return false, fmt.Errorf("x-query-virtio: %v", err)
	}
	found := false
	for _, d := range devs {
		if d.Name != kind {
			continue
		}
		found = true
		st, err := qmp(`{"execute":"x-query-virtio-status","arguments":{"path":"` + d.Path + `"}}`)
		if err != nil {
			return false, err
		}
		if !strings.Contains(string(st), `"driver-ok"`) {
			return false, nil
		}
	}
	return found, nil
}

// waitVirtioDriversOK waits until virtioDriversOK holds and reports whether it
// could tell. It returns false at once, with the reason logged, when the host
// cannot be asked: the caller's CLI-level assertions then carry the test alone.
// A guest that never takes the device up within timeout fails the test.
func waitVirtioDriversOK(t *testing.T, host, vm, kind string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ok, err := virtioDriversOK(host, vm, kind)
		if err != nil {
			t.Logf("cannot read the guest's %s driver state on %s (%v); continuing without the guest wait", kind, host, err)
			return false
		}
		if ok {
			return true
		}
		if time.Now().After(deadline) {
			t.Fatalf("no guest driver took up %s's %s device(s) within %v", vm, kind, timeout)
		}
		time.Sleep(3 * time.Second)
	}
}

// nicCopies reports whether mac is in vm's live domain and in its persistent
// definition, read with virsh on host.
func nicCopies(host, vm, mac string) (live, config bool, err error) {
	q := shellQuote(vm)
	out, err := nodeOut(host, "V='virsh -c qemu:///system'; echo '##live'; $V dumpxml "+q+"; echo '##config'; $V dumpxml --inactive "+q)
	if err != nil {
		return false, false, fmt.Errorf("%v: %.200s", err, out)
	}
	liveXML, configXML, ok := strings.Cut(out, "##config")
	if !ok {
		return false, false, fmt.Errorf("unexpected dumpxml output: %.200s", out)
	}
	has := func(x string) bool { return strings.Contains(strings.ToLower(x), "address='"+strings.ToLower(mac)+"'") }
	return has(liveXML), has(configXML), nil
}

// TestVM_DetachNIC_ActuallyRemovesItFromTheDomain attaches a NIC, confirms
// libvirt sees it, detaches it, and confirms libvirt no longer does.
func TestVM_DetachNIC_ActuallyRemovesItFromTheDomain(t *testing.T) {
	requireImage(t)
	if !virshAvailable() {
		t.Skip("needs virsh on this node to inspect the domain; run the suite on a cluster node")
	}
	netName := uniqueName("n")
	vmName := uniqueName("vm")
	host := hostWithCapacity(t, 1, 1024)
	if host != localHost {
		t.Skipf("VM would land on %s but virsh only reaches %s", host, localHost)
	}
	cleanup(t, func() {
		lvErr(t, "rm", vmName, "--force")
		lvErr(t, "network", "rm", netName, "--force")
	})

	lv(t, "network", "create", netName, "--type", "bridge",
		"--subnet", "172.33.0.0/24", "--dhcp")
	lv(t, "run", "--name", vmName, "--image", testImage,
		"--cpu", "1", "--memory", "1024", "--disk", "5G",
		"--host", host)
	waitVM(t, vmName, "RUNNING", 2*time.Minute)
	waitGuestActive(t, vmName, 4*time.Minute)

	before := domIfaceMACs(t, vmName)

	// ── attach ─────────────────────────────────────────────────────────────
	lv(t, "attach-nic", vmName, netName)

	var added string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		for _, m := range domIfaceMACs(t, vmName) {
			if !containsMAC(before, m) {
				added = m
				break
			}
		}
		if added != "" {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if added == "" {
		t.Fatalf("no new interface appeared on the domain after attach-nic (libvirt still reports %v) — nothing to detach, so the rest of this test would prove nothing",
			before)
	}

	// ── detach ─────────────────────────────────────────────────────────────
	// PCI hot-unplug is COOPERATIVE: libvirt asks the guest to eject the device
	// over ACPI, and a guest that has not yet enumerated a just-hot-added device
	// never answers — the request is DROPPED, not queued, so waiting alone never
	// clears it. DetachNIC now polls AND periodically re-requests the unplug
	// (hotplug_unplug_wait.go), which is what makes it converge.
	//
	// This used to SKIP when the guest never acknowledged, because before that fix
	// it genuinely never did — the same VM here failed to detach across a full
	// five-minute retry window. It now succeeds under those same conditions, so
	// the skip is gone: a detach that does not complete is a failure.
	//
	// The outer retry is kept as margin on top of the detach's own 30s wait; it
	// should normally succeed on the first attempt.
	//
	// The regression is checked on EVERY attempt, not just the last: the old code
	// sent malformed detach XML, which libvirt rejected with a complaint about a
	// missing 'bridge' attribute. That error must never appear, whatever the guest
	// is doing.
	var lastOut string
	var lastErr error
	detached := false
	deadline = time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		out, err := lvErr(t, "detach-nic", vmName, added)
		lastOut, lastErr = out, err
		if strings.Contains(strings.ToLower(out), "missing required attribute") {
			t.Fatalf("detach-nic sent malformed XML libvirt rejected — this is the regression: %v\n%s", err, out)
		}
		if err == nil {
			detached = true
			break
		}
		time.Sleep(15 * time.Second)
	}
	if !detached {
		t.Fatalf("detach never completed within the window — the unplug wait re-requests the eject, so a cooperative guest must eventually release the device (last: %v\n%s)",
			lastErr, lastOut)
	}

	// Succeeded — libvirt must no longer report it.
	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if !containsMAC(domIfaceMACs(t, vmName), added) {
			return // gone from the domain — the detach really happened
		}
		time.Sleep(2 * time.Second)
	}
	t.Errorf("detach-nic reported success but libvirt still reports MAC %s on %s — litevirt claimed the hypervisor did something it did not (domiflist: %v)",
		added, vmName, domIfaceMACs(t, vmName))
}

// TestVM_DetachNIC_AbsentMACIsRefusedNotMisreported: detaching a MAC the domain
// does not have must fail on its own terms. The old code reached libvirt with a
// malformed device element, so this surfaced as an XML validation error about a
// missing 'bridge' attribute — an error about litevirt's own request, which sent
// operators looking for a network misconfiguration that did not exist.
func TestVM_DetachNIC_AbsentMACIsRefusedNotMisreported(t *testing.T) {
	requireImage(t)
	if !virshAvailable() {
		t.Skip("needs virsh on this node to inspect the domain; run the suite on a cluster node")
	}
	vmName := uniqueName("vm")
	host := hostWithCapacity(t, 1, 1024)
	if host != localHost {
		t.Skipf("VM would land on %s but virsh only reaches %s", host, localHost)
	}
	cleanup(t, func() { lvErr(t, "rm", vmName, "--force") })

	lv(t, "run", "--name", vmName, "--image", testImage,
		"--cpu", "1", "--memory", "1024", "--disk", "5G",
		"--host", host)
	waitVM(t, vmName, "RUNNING", 2*time.Minute)

	const absent = "52:54:00:de:ad:be"
	if containsMAC(domIfaceMACs(t, vmName), absent) {
		t.Skipf("%s unexpectedly present on the domain", absent)
	}

	out, err := lvErr(t, "detach-nic", vmName, absent)
	if err == nil {
		t.Fatalf("detaching an absent MAC reported success:\n%s", out)
	}
	msg := strings.ToLower(out + err.Error())
	if strings.Contains(msg, "missing required attribute") {
		t.Errorf("the refusal is libvirt rejecting OUR malformed detach XML, not a statement about the MAC — this is the regression: %v\n%s", err, out)
	}
	// The VM must be undisturbed by a refused detach.
	if got := lv(t, "inspect", vmName); !strings.Contains(got, "RUNNING") {
		t.Errorf("VM is not RUNNING after a refused detach-nic:\n%s", got)
	}
}
