package cloudinit

import (
	"context"
	"strings"
	"testing"
)

// entry is the V2 entry of a NIC the document names.
func namedEntry(name, mac string) string {
	return "  " + name + ":\n    match:\n      macaddress: \"" + mac + "\"\n    set-name: " + name + "\n"
}

// Review I-1: a NIC's guest name never changes once a seed gave it one. With
// cloud-init re-applying the seed on every boot, a rebuild that renamed by
// position renamed NICs nobody touched (detach the middle one of three and
// the third became eth1). Names come from the seed being replaced: a kept
// NIC keeps its set-name.
//
// Mutation: ignore the prior seed's names — C is written eth1.
func TestSeedNetworkConfig_DetachMiddleKeepsTheOthersNames(t *testing.T) {
	db, spec := hotplugSeedDB(t) // A(stnet, 10.5.0.50) ord0, B(dnet) ord1
	ctx := context.Background()
	hotAttachRows(t, db, true, "isonet", "52:54:00:00:0c:0c", 2)
	before, err := SeedNetworkConfig(ctx, db, "hp", spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(before, namedEntry("eth2", "52:54:00:00:0c:0c")) {
		t.Fatalf("setup: C is not eth2:\n%s", before)
	}
	hotDetachRows(t, db, true, "52:54:00:00:0b:0b")
	got, err := SeedNetworkConfig(ctx, db, "hp", spec, PriorFrom(before))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "macaddress: \"52:54:00:00:0a:0a\"\n    set-name: eth0\n") ||
		!strings.Contains(got, namedEntry("eth2", "52:54:00:00:0c:0c")) {
		t.Errorf("after the detach of the middle NIC, want A eth0 and C eth2:\n%s", got)
	}
	if strings.Contains(got, "52:54:00:00:0b:0b") {
		t.Errorf("the detached NIC is still there:\n%s", got)
	}
}

// Review I-1: a one-NIC VM's seed has no network-config, so cloud-init's
// fallback named its NIC by the kernel's name (enp1s0). Its first hot attach
// must not rename it: it is written matched by MAC alone, with no set-name,
// and the attached NIC takes the lowest eth<n> not held — counting the
// unnamed NIC as holding eth0, which a guest booted with net.ifnames=0 calls
// it.
//
// Mutation: give the kept NIC a set-name — red; start the new NIC at eth0 —
// red; name the kept NIC by an entry key the guest has no device for, with no
// MAC match — red.
func TestSeedNetworkConfig_FirstAttachToAOneNICVMRenamesNothing(t *testing.T) {
	db, spec := hotplugSeedDB(t)
	ctx := context.Background()
	hotDetachRows(t, db, true, "52:54:00:00:0a:0a") // leaves B alone: one DHCP NIC
	one, err := SeedNetworkConfig(ctx, db, "hp", spec, nil)
	if err != nil || one != "" {
		t.Fatalf("setup: a one-DHCP-NIC VM has no network-config: %q, %v", one, err)
	}
	hotAttachRows(t, db, true, "dnet", "52:54:00:00:0c:0c", 2)
	got, err := SeedNetworkConfig(ctx, db, "hp", spec, PriorFrom(one, "52:54:00:00:0c:0c"))
	if err != nil {
		t.Fatal(err)
	}
	b := "macaddress: \"52:54:00:00:0b:0b\"\n"
	i := strings.Index(got, b)
	if i < 0 {
		t.Fatalf("B is not in the document:\n%s", got)
	}
	bEntry := got[i:]
	if j := strings.Index(bEntry, "\n  "); j > 0 && !strings.HasPrefix(bEntry[j:], "\n    ") {
		bEntry = bEntry[:j]
	}
	if next := strings.Index(bEntry[len(b):], "macaddress:"); next >= 0 {
		bEntry = bEntry[:len(b)+next]
	}
	if strings.Contains(bEntry, "set-name") {
		t.Errorf("the one NIC the VM had is renamed:\n%s", got)
	}
	if !strings.Contains(got, namedEntry("eth1", "52:54:00:00:0c:0c")) {
		t.Errorf("the attached NIC is not eth1:\n%s", got)
	}
	if !strings.Contains(got, "dhcp4: true") || strings.Count(got, "macaddress:") != 2 {
		t.Errorf("want both NICs on DHCP:\n%s", got)
	}
}

// Review I-1: an attach whose NIC shares an ordinal with a kept NIC (an
// earlier build's attach) renames nothing, and the new NIC's name does not
// depend on how the MACs sort: the kept NICs keep their names and the new one
// takes the lowest eth<n> free.
//
// Mutation: ignore the prior names — whichever MAC sorts first takes eth1.
func TestSeedNetworkConfig_SharedOrdinalAttachIsDeterministic(t *testing.T) {
	for _, newMAC := range []string{"52:54:00:00:00:01", "52:54:00:00:ff:ff"} { // sorts before / after B
		db, spec := hotplugSeedDB(t)
		ctx := context.Background()
		before, err := SeedNetworkConfig(ctx, db, "hp", spec, nil) // A eth0, B eth1
		if err != nil {
			t.Fatal(err)
		}
		hotAttachRows(t, db, true, "dnet", newMAC, 1) // shares B's ordinal
		got, err := SeedNetworkConfig(ctx, db, "hp", spec, PriorFrom(before, newMAC))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(got, "macaddress: \"52:54:00:00:0a:0a\"\n    set-name: eth0\n") ||
			!strings.Contains(got, namedEntry("eth1", "52:54:00:00:0b:0b")) ||
			!strings.Contains(got, namedEntry("eth2", newMAC)) {
			t.Errorf("new NIC %s: want A eth0, B eth1, new eth2:\n%s", newMAC, got)
		}
	}
}

// PriorFrom reads the names a seed's network-config gives, V1 and V2, and an
// entry with no set-name as a NIC matched by MAC alone.
func TestPriorFrom(t *testing.T) {
	v1 := BuildV1([]StaticIface{{MAC: "52:54:00:00:00:01", Address: "10.0.0.2/24"}, {MAC: "52:54:00:00:00:02", Address: "10.0.1.2/24"}})
	p := PriorFrom(v1)
	if p.Names["52:54:00:00:00:01"] != "eth0" || p.Names["52:54:00:00:00:02"] != "eth1" {
		t.Errorf("V1: %+v", p.Names)
	}
	v2 := "version: 2\nethernets:\n  eth3:\n    match:\n      macaddress: \"52:54:00:00:00:0A\"\n    set-name: eth3\n" +
		"  nic5254000000b:\n    match:\n      macaddress: \"52:54:00:00:00:0b\"\n    dhcp4: true\n"
	p = PriorFrom(v2, "52:54:00:00:00:0C")
	if n, ok := p.Names["52:54:00:00:00:0a"]; !ok || n != "eth3" {
		t.Errorf("V2 named: %q %v", n, ok)
	}
	if n, ok := p.Names["52:54:00:00:00:0b"]; !ok || n != "" {
		t.Errorf("V2 unnamed: %q %v", n, ok)
	}
	if !p.Added["52:54:00:00:00:0c"] {
		t.Errorf("added MAC not recorded, folded: %+v", p.Added)
	}
	if p := PriorFrom(""); p == nil || len(p.Names) != 0 {
		t.Errorf("no network-config: %+v", p)
	}
}

// A version 1 entry always names its device, so a NIC matched by MAC alone
// takes a version 2 document even where every NIC is static.
//
// Mutation: choose V1 for an all-static set regardless — red.
func TestGuestNetworkConfig_AnUnnamedNICTakesV2(t *testing.T) {
	doc := GuestNetworkConfig([]GuestNIC{
		{Ordinal: 0, MAC: "52:54:00:00:00:01", Unnamed: true, Static: &StaticIface{MAC: "52:54:00:00:00:01", Address: "10.0.0.2/24"}},
		{Ordinal: 1, MAC: "52:54:00:00:00:02", Name: "eth1", Static: &StaticIface{MAC: "52:54:00:00:00:02", Name: "eth1", Address: "10.0.1.2/24"}},
	})
	if !strings.HasPrefix(doc, "version: 2\n") || strings.Contains(doc, "set-name: eth0") ||
		!strings.Contains(doc, "  nic525400000001:\n    match:\n      macaddress: \"52:54:00:00:00:01\"\n    addresses:\n") {
		t.Errorf("an unnamed static NIC:\n%s", doc)
	}
}

// Re-review m-N4: an attached NIC's name never takes the kernel name of a NIC
// the seed leaves unnamed. A guest booted with net.ifnames=0 numbers every NIC
// eth0..eth(N-1); so eth0..eth(N-1), N the NICs that were there before the
// attach, are held, whatever the prior seed named.
//
// Mutation: hold only eth0..eth(u-1), u the unnamed NICs — Z takes eth1, the
// kernel name of the unnamed Y.
func TestSeedNetworkConfig_AttachedNameSkipsUnnamedKernelNames(t *testing.T) {
	db, spec := hotplugSeedDB(t) // A(stnet) ord0, B(dnet) ord1
	ctx := context.Background()
	// The prior seed names A eth0 and does not list B (an earlier build's
	// attach): B stays unnamed.
	prior := "version: 2\nethernets:\n  eth0:\n    match:\n      macaddress: \"52:54:00:00:0a:0a\"\n    set-name: eth0\n    dhcp4: true\n"
	hotAttachRows(t, db, true, "isonet", "52:54:00:00:0c:0c", 2)
	got, err := SeedNetworkConfig(ctx, db, "hp", spec, PriorFrom(prior, "52:54:00:00:0c:0c"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, namedEntry("eth2", "52:54:00:00:0c:0c")) {
		t.Errorf("want Z eth2 (eth1 is the unnamed B's kernel name):\n%s", got)
	}
}
