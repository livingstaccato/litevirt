package libvirt

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A /proc/net/arp as the kernel prints it. Flags 0x2 is ATF_COM (a complete,
// usable entry); 0x0 is an entry being resolved or one that FAILED. A failed
// entry that was once valid keeps its hardware address, so it names a MAC
// that no longer answers at that IP — after a guest moves to a new DHCP lease
// its old address can sit here with its MAC for minutes.
const arpFixture = `IP address       HW type     Flags       HW address            Mask     Device
172.16.60.23     0x1         0x0         52:54:00:aa:bb:01     *        br0
172.16.60.9      0x1         0x0         00:00:00:00:00:00     *        br0
172.16.60.8      0x1         0x2         00:00:00:00:00:00     *        br0
172.16.60.41     0x1         0x2         52:54:00:aa:bb:01     *        br0
172.16.60.50     0x1         0x6         52:54:00:aa:bb:02     *        br0
172.16.60.77     0x1         0x0         52:54:00:aa:bb:03     *        br0
`

func withARPTable(t *testing.T, content string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "arp")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	old := arpTablePath
	arpTablePath = p
	t.Cleanup(func() { arpTablePath = old })
}

func TestGetIPFromARP_OnlyCompleteEntriesCount(t *testing.T) {
	withARPTable(t, arpFixture)
	cases := []struct {
		mac, want, why string
	}{
		{"52:54:00:aa:bb:01", "172.16.60.41", "the failed entry for the old address comes first and must be skipped"},
		{"52:54:00:AA:BB:01", "172.16.60.41", "MACs compare case-insensitively"},
		{"52:54:00:aa:bb:02", "172.16.60.50", "a permanent entry (ATF_PERM|ATF_COM) is complete"},
		{"52:54:00:aa:bb:03", "", "a MAC whose only entry failed is not answering anywhere"},
		{"00:00:00:00:00:00", "", "a zero hardware address is never a match, whatever the flags say"},
		{"52:54:00:ff:ff:ff", "", "an absent MAC"},
	}
	for _, c := range cases {
		if got := GetIPFromARP(c.mac); got != c.want {
			t.Errorf("GetIPFromARP(%s) = %q, want %q: %s", c.mac, got, c.want, c.why)
		}
	}
}

func withLeaseDir(t *testing.T, leases string) {
	t.Helper()
	dir := t.TempDir()
	if leases != "" {
		if err := os.WriteFile(filepath.Join(dir, "br0.leases"), []byte(leases), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := dhcpLeaseDir
	dhcpLeaseDir = dir
	t.Cleanup(func() { dhcpLeaseDir = old })
}

// The guest rebooted onto a new lease. Its old address is still in the ARP
// cache as a STALE entry — complete (ATF_COM), and on a small table never
// garbage-collected until it is next used — while dnsmasq's lease file holds
// the one current answer for the MAC. The lease wins: ARP first would hand
// every discovery path, the recording ones included, the old address.
func TestDiscoverIPForMAC_LeaseWinsOverAStaleARPEntry(t *testing.T) {
	withARPTable(t, `IP address       HW type     Flags       HW address            Mask     Device
172.16.60.23     0x1         0x2         52:54:00:aa:bb:01     *        br0
`)
	withLeaseDir(t, "4102444800 52:54:00:aa:bb:01 172.16.60.41 web *\n")
	if got := DiscoverIPForMAC("52:54:00:aa:bb:01"); got != "172.16.60.41" {
		t.Fatalf("DiscoverIPForMAC = %q, want the lease's 172.16.60.41 over the stale ARP entry", got)
	}
}

// With no lease (a static address, an external DHCP server) a complete ARP
// entry answers, and a failed one does not.
func TestDiscoverIPForMAC_FallsBackToCompleteARP(t *testing.T) {
	withARPTable(t, arpFixture)
	withLeaseDir(t, "")
	if got := DiscoverIPForMAC("52:54:00:aa:bb:01"); got != "172.16.60.41" {
		t.Errorf("DiscoverIPForMAC with no lease = %q, want the complete ARP entry 172.16.60.41", got)
	}
	if got := DiscoverIPForMAC("52:54:00:aa:bb:03"); got != "" {
		t.Errorf("DiscoverIPForMAC = %q for a MAC with only a failed ARP entry and no lease, want \"\"", got)
	}
}

func TestGetIPFromARP_MissingTable(t *testing.T) {
	old := arpTablePath
	arpTablePath = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { arpTablePath = old })
	if got := GetIPFromARP("52:54:00:aa:bb:01"); got != "" {
		t.Errorf("GetIPFromARP with no table = %q, want \"\"", got)
	}
}

func writeLeaseFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func withLeaseClock(t *testing.T, now int64) {
	t.Helper()
	old := leaseNow
	leaseNow = func() time.Time { return time.Unix(now, 0) }
	t.Cleanup(func() { leaseNow = old })
}

// A network was deprovisioned and its lease file stayed behind; the guest now
// holds a lease on another bridge. The expired lease in the leftover file
// sorts first in glob order and must not win.
func TestGetIPFromDHCPLeases_SkipsExpiredAndPrefersNewest(t *testing.T) {
	dir := t.TempDir()
	withLeaseClock(t, 2_000_000_000)
	writeLeaseFile(t, dir, "litevirt-br-a.leases", "1999999000 52:54:00:aa:bb:01 10.0.1.5 web *\n")
	if got := GetIPFromDHCPLeases(dir, "52:54:00:aa:bb:01"); got != "" {
		t.Fatalf("GetIPFromDHCPLeases = %q with only an expired lease, want \"\" (the ARP fallback answers)", got)
	}
	writeLeaseFile(t, dir, "litevirt-br-b.leases", "2000003600 52:54:00:aa:bb:01 10.0.2.5 web *\n")
	if got := GetIPFromDHCPLeases(dir, "52:54:00:aa:bb:01"); got != "10.0.2.5" {
		t.Fatalf("GetIPFromDHCPLeases = %q, want the current lease 10.0.2.5 over the expired 10.0.1.5", got)
	}

	// Several live leases for one MAC: the one dnsmasq granted most recently
	// (latest expiry) is the current answer, whichever file globs first.
	writeLeaseFile(t, dir, "litevirt-br-c.leases", "2000007200 52:54:00:aa:bb:01 10.0.3.5 web *\n")
	writeLeaseFile(t, dir, "litevirt-br-0.leases", "2000001800 52:54:00:aa:bb:01 10.0.4.5 web *\n")
	if got := GetIPFromDHCPLeases(dir, "52:54:00:aa:bb:01"); got != "10.0.3.5" {
		t.Fatalf("GetIPFromDHCPLeases = %q, want 10.0.3.5, the lease with the latest expiry", got)
	}

	// Expiry 0 is dnsmasq's infinite lease: never expired, and newer than any
	// dated one.
	writeLeaseFile(t, dir, "litevirt-br-d.leases", "0 52:54:00:aa:bb:01 10.0.5.5 web *\n")
	if got := GetIPFromDHCPLeases(dir, "52:54:00:aa:bb:01"); got != "10.0.5.5" {
		t.Fatalf("GetIPFromDHCPLeases = %q, want the infinite lease 10.0.5.5", got)
	}
}

// Where the NIC's bridge is known, only that bridge's dnsmasq can be leasing
// it an address: a lease for the same MAC in another bridge's file is not it.
func TestDiscoverIPForMACOnBridge_IgnoresOtherBridges(t *testing.T) {
	withARPTable(t, "IP address       HW type     Flags       HW address            Mask     Device\n")
	withLeaseClock(t, 2_000_000_000)
	withLeaseDir(t, "")
	writeLeaseFile(t, dhcpLeaseDir, "litevirt-br-a.leases", "2000007200 52:54:00:aa:bb:01 10.0.1.5 web *\n")
	writeLeaseFile(t, dhcpLeaseDir, "litevirt-br-b.leases", "2000003600 52:54:00:aa:bb:01 10.0.2.5 web *\n")
	if got := DiscoverIPForMACOnBridge("52:54:00:aa:bb:01", "br-b"); got != "10.0.2.5" {
		t.Fatalf("DiscoverIPForMACOnBridge(br-b) = %q, want br-b's lease 10.0.2.5", got)
	}
	if got := DiscoverIPForMACOnBridge("52:54:00:aa:bb:01", "br-c"); got != "" {
		t.Fatalf("DiscoverIPForMACOnBridge(br-c) = %q, want \"\": br-c has no lease for the MAC", got)
	}
	if got := DiscoverIPForMACOnBridge("52:54:00:aa:bb:01", ""); got != "10.0.1.5" {
		t.Fatalf("DiscoverIPForMACOnBridge with no bridge = %q, want the newest lease anywhere (10.0.1.5)", got)
	}
}
