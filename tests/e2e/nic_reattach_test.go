package e2e

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// `lv update --nic-mtu N=` on a NIC detached and attached again (lab 2,
// dombld P2). A NIC ordinal is never reused, so A, attached again under its
// MAC, takes a new ordinal and moves to the end of the VM's NIC list: the
// list is B, A, and NIC 1 is A. tests/fleet proves the bookkeeping against
// libvirtfake; this reads the definition libvirt holds on the owner.

var ifaceBlockRE = regexp.MustCompile(`(?s)<interface\b.*?</interface>`)

// ifaceBlock is the <interface> element of x whose MAC is mac, "" when none.
func ifaceBlock(x, mac string) string {
	for _, b := range ifaceBlockRE.FindAllString(x, -1) {
		if strings.Contains(strings.ToLower(b), "'"+strings.ToLower(mac)+"'") {
			return b
		}
	}
	return ""
}

func TestVM_NICMTUOnANICAttachedAgain(t *testing.T) {
	requireImage(t)
	host := hostWithCapacity(t, 1, 1024)
	jumbo, plain := shortNetName("rj"), shortNetName("rp")
	jumboNet := fmt.Sprintf("10.236.%d.0/24", os.Getpid()%200)
	plainNet := fmt.Sprintf("10.237.%d.0/24", os.Getpid()%200)
	vm := uniqueName("ra")
	macA := fmt.Sprintf("52:54:00:7a:%02x:0a", os.Getpid()%256)
	macB := fmt.Sprintf("52:54:00:7a:%02x:0b", os.Getpid()%256)
	cleanup(t, func() {
		lvErr(t, "rm", vm, "--force")
		lvErr(t, "network", "rm", jumbo, "--force")
		lvErr(t, "network", "rm", plain, "--force")
		delTestLink(t, jumbo)
		delTestLink(t, plain)
	})
	lv(t, "network", "create", jumbo, "--type", "bridge", "--subnet", jumboNet, "--dhcp")
	lv(t, "network", "create", plain, "--type", "bridge", "--subnet", plainNet, "--dhcp")
	if failed := waitOnHosts(hostNames, bridgePresent(jumbo)+" && "+bridgePresent(plain), netRmPass); len(failed) > 0 {
		t.Fatalf("bridges %s / %s missing after %s on: %v", jumbo, plain, netRmPass, failed)
	}
	if _, failed := onHosts(hostNames, "ip link set "+jumbo+" mtu 9000"); len(failed) > 0 {
		t.Skipf("cannot raise %s to MTU 9000 on every host (the lab's underlay?): %v", jumbo, failed)
	}

	// A VM made with no NIC, stopped: the NICs are attached to its
	// definition, which needs no guest to acknowledge a hot-plug.
	lv(t, "run", "--name", vm, "--image", testImage, "--cpu", "1", "--memory", "1024", "--disk", "5G", "--host", host)
	waitVM(t, vm, "RUNNING", 3*time.Minute)
	lv(t, "stop", vm, "--force")
	waitVM(t, vm, "STOPPED", 2*time.Minute)
	lv(t, "attach-nic", vm, plain, "--mac", macB)
	lv(t, "attach-nic", vm, jumbo, "--mac", macA)
	lv(t, "detach-nic", vm, macA)
	lv(t, "attach-nic", vm, jumbo, "--mac", macA)

	// The NIC list, as `lv inspect` shows it under spec.network: B, then A.
	insp := lv(t, "inspect", vm)
	if ib, ia := strings.Index(strings.ToLower(insp), macB), strings.Index(strings.ToLower(insp), macA); ib < 0 || ia < 0 || ib > ia {
		t.Fatalf("lv inspect does not list B before A:\n%s", insp)
	}

	out, err := lvErr(t, "update", vm, "--nic-mtu", "1=9000")
	if err != nil {
		if strings.Contains(out, "cluster upgrade must finish") {
			t.Skipf("nic_mtu is not open on this cluster yet: %s", out)
		}
		t.Fatalf("lv update --nic-mtu 1=9000 (A): %v\n%s", err, out)
	}
	x, err := nodeOut(host, "virsh -c qemu:///system dumpxml --inactive "+vm)
	if err != nil {
		t.Fatalf("virsh dumpxml --inactive %s on %s: %v\n%s", vm, host, err, x)
	}
	a, b := ifaceBlock(x, macA), ifaceBlock(x, macB)
	if a == "" || b == "" {
		t.Fatalf("the definition on %s lacks A or B:\n%s", host, x)
	}
	if !strings.Contains(a, "<mtu size='9000'/>") {
		t.Errorf("A (NIC 1) has no <mtu size='9000'/>:\n%s", a)
	}
	if strings.Contains(b, "<mtu") {
		t.Errorf("B (NIC 0) took an MTU:\n%s", b)
	}

	// NIC 0 is B, on the 1500 bridge: refused naming that bridge.
	out, err = lvErr(t, "update", vm, "--nic-mtu", "0=9000")
	if err == nil || !strings.Contains(out, "does not match bridge "+plain) {
		t.Errorf("lv update --nic-mtu 0=9000 (B on %s): err=%v, want a refusal naming %s:\n%s", plain, err, plain, out)
	}

	lv(t, "start", vm)
	waitVM(t, vm, "RUNNING", 3*time.Minute)
	live, err := nodeOut(host, "virsh -c qemu:///system dumpxml "+vm)
	if err != nil || !strings.Contains(ifaceBlock(live, macA), "<mtu size='9000'/>") || strings.Contains(ifaceBlock(live, macB), "<mtu") {
		t.Errorf("the running domain on %s does not carry A's MTU only (err %v):\n%s", host, err, live)
	}
}
