//go:build linux

package libvirt

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The access-tap kernel test runs configureAccessBridgeVLAN against a real
// VLAN-filtering Linux bridge in a private user and network namespace
// (unshare -rn): no root, nothing on the host touched. It is opted into with
// the firewall kernel tests' switch, LITEVIRT_NFT_NETNS=1, so a run that
// proves those proves this; LITEVIRT_NFT_REQUIRE=1 turns a skip into a failure.
const (
	vlanNetnsOptIn = "LITEVIRT_NFT_NETNS"
	vlanRequire    = "LITEVIRT_NFT_REQUIRE"
	vlanNetnsChild = "LITEVIRT_VLAN_NETNS_CHILD"
)

func TestKernel_AccessTapVLAN(t *testing.T) {
	if os.Getenv(vlanNetnsChild) == "1" {
		t.Skip("parent only")
	}
	if os.Getenv(vlanNetnsOptIn) != "1" {
		if os.Getenv(vlanRequire) == "1" {
			t.Fatalf("%s=1 needs %s=1", vlanRequire, vlanNetnsOptIn)
		}
		t.Skipf("set %s=1 to run the access-tap kernel test in a private namespace", vlanNetnsOptIn)
	}
	for _, bin := range []string{"unshare", "ip", "bridge"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Fatalf("%s=1 but %s is not on PATH", vlanNetnsOptIn, bin)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "unshare", "-rn", os.Args[0], "-test.run", "^TestKernelChild_AccessTap", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), vlanNetnsChild+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("namespace run:\n%s", out)
	if err != nil {
		t.Fatalf("kernel test failed in the namespace: %v", err)
	}
	if !strings.Contains(string(out), "--- PASS: TestKernelChild_AccessTapCarriesOnlyItsVLAN") {
		t.Fatal("TestKernelChild_AccessTapCarriesOnlyItsVLAN did not pass in the namespace")
	}
}

// A port of a VLAN-filtering bridge starts with VLAN 1 as pvid, untagged.
// After configureAccessBridgeVLAN it carries VLAN 30 alone, as pvid, untagged
// — so no VLAN-1 frame reaches it, and none it sends untagged joins VLAN 1 —
// and a second pass changes nothing.
func TestKernelChild_AccessTapCarriesOnlyItsVLAN(t *testing.T) {
	if os.Getenv(vlanNetnsChild) != "1" {
		t.Skip("runs only inside the namespace TestKernel_AccessTapVLAN makes")
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
		return string(out)
	}
	run("ip", "link", "add", "br0", "type", "bridge", "vlan_filtering", "1")
	run("ip", "link", "add", "v0", "type", "veth", "peer", "name", "v0p")
	run("ip", "link", "set", "v0", "master", "br0")
	if got := parseTapVLANEntries(run("bridge", "vlan", "show", "dev", "v0")); len(got) != 1 || got[0] != (tapVLAN{1, true, true}) {
		t.Fatalf("a new port: %+v, want VLAN 1 pvid untagged (the bridge's default_pvid)", got)
	}
	for pass := 1; pass <= 2; pass++ {
		if err := configureAccessBridgeVLAN("v0", 30); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		show := run("bridge", "vlan", "show", "dev", "v0")
		if got := parseTapVLANEntries(show); len(got) != 1 || got[0] != (tapVLAN{30, true, true}) {
			t.Fatalf("pass %d: the access port carries %+v (%q), want VLAN 30 alone, pvid, untagged", pass, got, show)
		}
	}
}
