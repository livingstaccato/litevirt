package e2e

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Per-NIC MTU against real bridges (spec §3.6). tests/fleet's bridge MTU is a
// number in libvirtfake; this reads the bridge, the tap and the guest on the
// host, and sends a jumbo frame that may not be fragmented.

func nicMTUCompose(stack, vm, host, netName, mtu string) string {
	return fmt.Sprintf(`name: %s
networks:
  %s:
    external: true
vms:
  %s:
    image: %s
    cpu: 1
    memory: 1024
    guest-agent: true
    disks: {root: 8G}
    network:
      - name: %s
        mtu: %s
    placement: {host: %s}
    cloud-init:
      userdata: |
        #cloud-config
        package_update: true
        packages: [qemu-guest-agent]
        runcmd:
          - systemctl enable --now qemu-guest-agent
`, stack, netName, vm, testImage, netName, mtu, host)
}

// bridgeMTU reads bridge's MTU on host.
func bridgeMTU(t *testing.T, host, bridge string) string {
	t.Helper()
	out, err := nodeOut(host, "cat /sys/class/net/"+bridge+"/mtu")
	if err != nil {
		t.Fatalf("read the MTU of %s on %s: %v\n%s", bridge, host, err, out)
	}
	return strings.TrimSpace(out)
}

// domainXMLOn is vm's live definition on host, read with virsh there.
func domainXMLOn(t *testing.T, host, vm string) string {
	t.Helper()
	out, err := nodeOut(host, "virsh -c qemu:///system dumpxml "+vm)
	if err != nil {
		t.Fatalf("virsh dumpxml %s on %s: %v\n%s", vm, host, err, out)
	}
	return out
}

func TestVM_NICMTU(t *testing.T) {
	requireImage(t)
	host := hostWithCapacity(t, 1, 1024)
	jumbo, plain := shortNetName("mj"), shortNetName("mp")
	jumboNet := fmt.Sprintf("10.238.%d.0/24", os.Getpid()%200)
	plainNet := fmt.Sprintf("10.239.%d.0/24", os.Getpid()%200)
	stack, refused := uniqueName("mtu"), uniqueName("mtux")
	vm, vmx := uniqueName("mt"), uniqueName("mtx")
	cleanup(t, func() {
		composeDown(t, stack)
		composeDown(t, refused)
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
	// litevirt never sets a bridge's MTU: the operator does, on every host.
	if _, failed := onHosts(hostNames, "ip link set "+jumbo+" mtu 9000"); len(failed) > 0 {
		t.Skipf("cannot raise %s to MTU 9000 on every host (the lab's underlay?): %v", jumbo, failed)
	}

	// (1) `mtu: bridge` on the 9000 bridge: the domain, the tap and the guest
	// are at 9000, and a 9000-byte frame crosses unfragmented.
	if out, err := lvErr(t, "compose", "up", "-f", writeComposeFile(t, stack, nicMTUCompose(stack, vm, host, jumbo, "bridge")), "-y"); err != nil {
		if strings.Contains(out, "cluster upgrade must finish") {
			t.Skipf("nic_mtu is not open on this cluster yet (the release token has not latched): %s", out)
		}
		t.Fatalf("compose up: %v\n%s", err, out)
	}
	waitVM(t, vm, "RUNNING", 3*time.Minute)
	if x := domainXMLOn(t, host, vm); !strings.Contains(x, "<mtu size='9000'/>") {
		t.Errorf("the domain has no <mtu size='9000'/>:\n%s", x)
	}
	tapOut, err := nodeOut(host, "tap=$(virsh -c qemu:///system domiflist "+vm+" | awk 'NR>2 && NF>=5 {print $1; exit}'); cat /sys/class/net/$tap/mtu")
	if err != nil || strings.TrimSpace(tapOut) != "9000" {
		t.Errorf("the guest's tap MTU on %s = %q (%v), want 9000", host, strings.TrimSpace(tapOut), err)
	}
	if got := bridgeMTU(t, host, jumbo); got != "9000" {
		t.Errorf("bridge %s is at %s after the guest joined it, want 9000", jumbo, got)
	}

	// (2) An explicit 1400 on the 1500 bridge is refused, and the bridge is not
	// pulled down to it (review I-6): still 1500 on every host.
	before := bridgeMTU(t, host, plain)
	out, err := lvErr(t, "compose", "up", "-f", writeComposeFile(t, refused, nicMTUCompose(refused, vmx, host, plain, "1400")), "-y")
	want := fmt.Sprintf("NIC 0 MTU 1400 does not match bridge %s MTU %s on host %s", plain, before, host)
	if err == nil || !strings.Contains(out, want) {
		t.Errorf("compose up with mtu 1400 on a %s bridge: err=%v, want a refusal containing %q:\n%s", before, err, want, out)
	}
	for _, h := range hostNames {
		if got := bridgeMTU(t, h, plain); got != before {
			t.Errorf("bridge %s on %s is %s after the refused 1400, want %s", plain, h, got, before)
		}
	}

	// (3) The guest sees 9000 and a 9000-byte frame (8972 + 28 bytes of
	// headers) reaches the host's bridge address with fragmenting forbidden.
	gw, err := nodeOut(host, "ip -4 -o addr show "+jumbo+" | awk '{print $4; exit}' | cut -d/ -f1")
	gw = strings.TrimSpace(gw)
	if err != nil || gw == "" {
		t.Fatalf("no address on bridge %s on %s: %v", jumbo, host, err)
	}
	if _, err := execRetry(t, vm, "true"); err != nil {
		t.Skipf("guest agent never connected on %s (no internet / image lacks qemu-guest-agent); the host-side checks above passed", vm)
	}
	link, err := execRetry(t, vm, "sh", "-c", "ip -o link | grep -v ' lo:'")
	if err != nil || !strings.Contains(link, "mtu 9000") {
		t.Errorf("the guest's NIC is not at 9000: %v\n%s", err, link)
	}
	if out, err := execRetry(t, vm, "ping", "-M", "do", "-s", "8972", "-c", "3", "-W", "2", gw); err != nil {
		t.Errorf("ping -M do -s 8972 %s from the guest: %v\n%s", gw, err, out)
	}

	// (4) A migration to a host whose bridge differs is refused before
	// anything moves; to a matching one it lands with the MTU. Runs last: the
	// VM then lives on another host.
	if len(hostNames) < 2 {
		return
	}
	target := hostNames[0]
	if target == host {
		target = hostNames[1]
	}
	if out, err := nodeOut(target, "ip link set "+jumbo+" mtu 1500"); err != nil {
		t.Fatalf("lower %s on %s: %v\n%s", jumbo, target, err, out)
	}
	out, err = lvErr(t, "migrate", vm, target, "--with-storage")
	want = fmt.Sprintf("NIC 0 MTU 9000 does not match bridge %s MTU 1500 on host %s", jumbo, target)
	if err == nil || !strings.Contains(out, want) {
		t.Errorf("migrate to a 1500 bridge: err=%v, want a refusal containing %q:\n%s", err, want, out)
	}
	if !strings.Contains(lv(t, "inspect", vm), host) {
		t.Errorf("the refused migration moved %s off %s", vm, host)
	}
	if out, err := nodeOut(target, "ip link set "+jumbo+" mtu 9000"); err != nil {
		t.Fatalf("raise %s on %s: %v\n%s", jumbo, target, err, out)
	}
	if out, err := lvErr(t, "migrate", vm, target, "--with-storage"); err != nil {
		t.Fatalf("migrate to a matching bridge: %v\n%s", err, out)
	}
	waitVM(t, vm, "RUNNING", 3*time.Minute)
	if x := domainXMLOn(t, target, vm); !strings.Contains(x, "<mtu size='9000'/>") {
		t.Errorf("the guest landed on %s without its MTU:\n%s", target, x)
	}
}
