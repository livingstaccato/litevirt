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
	// A mount namespace too, so the child can mount a sysfs of its own
	// network namespace (TapMasterVLANFiltering reads it).
	cmd := exec.CommandContext(ctx, "unshare", "-rnm", os.Args[0], "-test.run", "^TestKernelChild_(AccessTap|TapMaster)", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), vlanNetnsChild+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("namespace run:\n%s", out)
	if err != nil {
		t.Fatalf("kernel test failed in the namespace: %v", err)
	}
	for _, child := range []string{"TestKernelChild_AccessTapCarriesOnlyItsVLAN", "TestKernelChild_TapMasterIsReadFromTheKernel"} {
		if !strings.Contains(string(out), "--- PASS: "+child) {
			t.Errorf("%s did not pass in the namespace", child)
		}
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

// TapMasterVLANFiltering reads the bridge a tap is really enslaved to, and its
// vlan_filtering, from the kernel: a tap on a filtering bridge and one on a
// non-filtering bridge are told apart, and a tap with no master is an error.
func TestKernelChild_TapMasterIsReadFromTheKernel(t *testing.T) {
	if os.Getenv(vlanNetnsChild) != "1" {
		t.Skip("runs only inside the namespace TestKernel_AccessTapVLAN makes")
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
	}
	run("mount", "-t", "sysfs", "sysfs", "/sys")
	run("ip", "link", "add", "brf", "type", "bridge", "vlan_filtering", "1")
	run("ip", "link", "add", "bru", "type", "bridge", "vlan_filtering", "0")
	for _, p := range [][2]string{{"tf", "brf"}, {"tu", "bru"}, {"tn", ""}} {
		run("ip", "link", "add", p[0], "type", "veth", "peer", "name", p[0]+"p")
		if p[1] != "" {
			run("ip", "link", "set", p[0], "master", p[1])
		}
	}
	if m, on, err := tapMasterVLANFiltering("tf"); err != nil || m != "brf" || !on {
		t.Errorf("tap on brf: %q %v %v, want brf filtering", m, on, err)
	}
	if m, on, err := tapMasterVLANFiltering("tu"); err != nil || m != "bru" || on {
		t.Errorf("tap on bru: %q %v %v, want bru not filtering", m, on, err)
	}
	if _, _, err := tapMasterVLANFiltering("tn"); err == nil {
		t.Error("a tap with no master: no error")
	}
}
