package network

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netutil"
	"github.com/litevirt/litevirt/internal/network/fdbfake"
)

// multiHomedLab models a lab node (lab1-vxlan-dhcp.md): the default route and
// its source address are the qemu user-mode NAT, 10.0.2.15 on ens3 and the
// same on every node, while the cluster network is net1 with this node's
// advertise address.
func multiHomedLab(t *testing.T) {
	t.Helper()
	setHostAddrs(t, localAddrs{
		"127.0.0.1":  "lo",
		"10.0.2.15":  "ens3",
		"10.77.0.11": "net1",
	})
}

// setHostAddrs models this host's addresses (address → interface). lo and
// dummy* interfaces cannot carry a tunnel; every other one can.
func setHostAddrs(t *testing.T, addrs localAddrs) {
	t.Helper()
	prev, prevCarries := hostAddrs, deviceCarries
	hostAddrs = func() (localAddrs, error) { return addrs, nil }
	deviceCarries = func(dev string) bool { return dev != "lo" && !strings.HasPrefix(dev, "dummy") }
	t.Cleanup(func() { hostAddrs, deviceCarries = prev, prevCarries })
}

// fakeExec records every command and answers each through reply (nil means
// success with no output).
func fakeExec(t *testing.T, reply func(cmd string) ([]byte, error)) *[]string {
	t.Helper()
	var calls []string
	execCommand = func(name string, args ...string) ([]byte, error) {
		cmd := strings.Join(append([]string{name}, args...), " ")
		calls = append(calls, cmd)
		if reply != nil {
			return reply(cmd)
		}
		return nil, nil
	}
	t.Cleanup(func() { execCommand = defaultExec })
	return &calls
}

func vtepTestDB(t *testing.T) *corrosion.Client {
	t.Helper()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return db
}

func defaultRouteVia(dev string) func(cmd string) ([]byte, error) {
	return func(cmd string) ([]byte, error) {
		if cmd == "ip route show default" {
			return []byte("default via 10.0.2.2 dev " + dev + " proto dhcp metric 100\n"), nil
		}
		return nil, nil
	}
}

var vxdDef = compose.NetworkDef{Type: "vxlan", Interface: "vxdnet", VNI: 5177}

// TestResolveVTEP_HostAddressOnItsInterface: once switched, the tunnel's local
// address is the host address and its underlay the interface holding it —
// net1 — not the default-route interface ens3, whose NAT address every lab
// node shares.
func TestResolveVTEP_HostAddressOnItsInterface(t *testing.T) {
	multiHomedLab(t)
	fakeExec(t, defaultRouteVia("ens3"))
	local, dev, err := ResolveVTEP("vxd_vxdnet", vxdDef, "10.77.0.11", true)
	if err != nil || local != "10.77.0.11" || dev != "net1" {
		t.Fatalf("ResolveVTEP = %q, %q, %v; want 10.77.0.11 on net1", local, dev, err)
	}
}

// TestResolveVTEP_BeforeTheSwitch: before the latch the endpoint is the one
// every earlier build used — the default-route source address, over the
// named underlay or the default-route interface.
func TestResolveVTEP_BeforeTheSwitch(t *testing.T) {
	multiHomedLab(t)
	fakeExec(t, defaultRouteVia("ens3"))
	local, dev, err := ResolveVTEP("vxd_vxdnet", vxdDef, "10.77.0.11", false)
	if err != nil || local != netutil.HostAddress("") || dev != "ens3" {
		t.Fatalf("ResolveVTEP = %q, %q, %v; want %s on ens3", local, dev, err, netutil.HostAddress(""))
	}
	named := vxdDef
	named.Underlay = "eth0"
	if _, dev, _ := ResolveVTEP("vxd_vxdnet", named, "10.77.0.11", false); dev != "eth0" {
		t.Fatalf("named underlay before the switch: dev %q, want eth0", dev)
	}
}

// TestResolveVTEP_NamedUnderlayWins: a network that names its underlay runs
// the tunnel from an address that device holds — the host address when it is
// one of them, else the device's own — and a device with no IPv4 address is
// refused, naming the network and the device.
func TestResolveVTEP_NamedUnderlayWins(t *testing.T) {
	setHostAddrs(t, localAddrs{
		"127.0.0.1":   "lo",
		"192.168.1.5": "eth0",
		"fe80::1":     "eth0",
		"10.77.0.11":  "net1",
		"fe80::2":     "eth9",
	})
	fakeExec(t, defaultRouteVia("eth0"))
	for _, tc := range []struct{ underlay, local string }{
		{"eth0", "192.168.1.5"}, // the host address is on net1: eth0's own
		{"net1", "10.77.0.11"},  // the host address is on it
	} {
		def := vxdDef
		def.Underlay = tc.underlay
		local, dev, err := ResolveVTEP("vxd_vxdnet", def, "10.77.0.11", true)
		if err != nil || local != tc.local || dev != tc.underlay {
			t.Errorf("underlay %s: ResolveVTEP = %q, %q, %v; want %s on %s", tc.underlay, local, dev, err, tc.local, tc.underlay)
		}
	}
	def := vxdDef
	def.Underlay = "eth9"
	_, _, err := ResolveVTEP("vxd_vxdnet", def, "10.77.0.11", true)
	var r *VTEPRefusal
	if !errors.As(err, &r) || r.Network != "vxd_vxdnet" || r.Device != "eth9" {
		t.Fatalf("underlay with no IPv4 address: %v, want a VTEPRefusal naming vxd_vxdnet and eth9", err)
	}
}

// TestResolveVTEP_LoopbackOrDummyHolder: a routed-to-the-host fabric puts the
// host /32 on lo or a dummy device. That device cannot carry the tunnel; the
// default-route interface does, from the same address.
func TestResolveVTEP_LoopbackOrDummyHolder(t *testing.T) {
	fakeExec(t, defaultRouteVia("eth0"))
	for _, holder := range []string{"lo", "dummy0"} {
		setHostAddrs(t, localAddrs{
			"127.0.0.1":    "lo",
			"10.1.1.1":     holder,
			"192.168.0.10": "eth0",
		})
		local, dev, err := ResolveVTEP("vxd_vxdnet", vxdDef, "10.1.1.1", true)
		if err != nil || local != "10.1.1.1" || dev != "eth0" {
			t.Errorf("/32 on %s: ResolveVTEP = %q, %q, %v; want 10.1.1.1 on eth0", holder, local, dev, err)
		}
	}
}

// TestResolveVTEP_RefusesAnAddressItCannotUse: no host address (never
// wired), or one no interface holds (a 1:1-NAT'd advertise address), is
// refused — never a tunnel from an address the host cannot send from.
func TestResolveVTEP_RefusesAnAddressItCannotUse(t *testing.T) {
	multiHomedLab(t)
	fakeExec(t, defaultRouteVia("ens3"))
	for _, tc := range []struct{ addr, reason string }{
		{"", "not known"},
		{"203.0.113.9", "no interface holds"},
	} {
		var r *VTEPRefusal
		if _, _, err := ResolveVTEP("vxd_vxdnet", vxdDef, tc.addr, true); !errors.As(err, &r) ||
			r.Network != "vxd_vxdnet" || !strings.Contains(r.Reason, tc.reason) {
			t.Errorf("host address %q: %v, want a VTEPRefusal saying %q", tc.addr, err, tc.reason)
		}
	}
}

// TestProvision_VXLAN_RefusesWithoutALocalAddress: Provision does not guess
// a tunnel address; a caller that resolved none is refused before any device
// is touched.
func TestProvision_VXLAN_RefusesWithoutALocalAddress(t *testing.T) {
	calls := fakeExec(t, nil)
	if _, err := Provision(context.Background(), vtepTestDB(t), "vxd_vxdnet", vxdDef, "", "node-1"); err == nil {
		t.Fatal("Provision set up a vxlan network with no local address")
	}
	if len(*calls) != 0 {
		t.Fatalf("commands ran: %v", *calls)
	}
}

// TestProvision_VXLAN_DoesNotReviveADeletedNetworksVTEP: a provisioning pass
// that meets the network's tombstone does not upsert its VTEP row, which
// would clear deleted_at and bring the row back under a deleted network.
func TestProvision_VXLAN_DoesNotReviveADeletedNetworksVTEP(t *testing.T) {
	multiHomedLab(t)
	fakeExec(t, nil)
	ctx := context.Background()
	db := vtepTestDB(t)
	if err := corrosion.UpsertNetwork(ctx, db, corrosion.NetworkRecord{Name: "vxd_vxdnet", Type: "vxlan", Config: "{}"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteNetwork(ctx, db, "vxd_vxdnet"); err != nil {
		t.Fatal(err)
	}
	def := vxdDef
	def.Underlay = "net1"
	if _, err := Provision(ctx, db, "vxd_vxdnet", def, "10.77.0.11", "node-1"); err == nil ||
		!strings.Contains(err.Error(), "was deleted") {
		t.Fatalf("Provision of a deleted network: %v, want the deleted-network refusal", err)
	}
	if v, _ := GetVTEPs(ctx, db, "vxd_vxdnet"); len(v) != 0 {
		t.Fatalf("live VTEP rows for a deleted network: %+v", v)
	}
}

// TestFDBEntries_RefuseThisHostsAddress: a flood or unicast entry whose
// destination is an address of this host is never installed — the kernel
// loops such a frame straight back into the vxlan device.
func TestFDBEntries_RefuseThisHostsAddress(t *testing.T) {
	multiHomedLab(t)
	calls := fakeExec(t, nil)

	for _, self := range []string{"10.0.2.15", "10.77.0.11", "127.0.0.1"} {
		if err := FloodEntry(5177, self); err != nil {
			t.Errorf("FloodEntry(%s): %v", self, err)
		}
		if err := AddFDBEntry(5177, "52:54:00:44:37:23", self); err != nil {
			t.Errorf("AddFDBEntry(%s): %v", self, err)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("entries pointing at this host were installed:\n%s", strings.Join(*calls, "\n"))
	}

	if err := FloodEntry(5177, "10.77.0.14"); err != nil {
		t.Fatalf("FloodEntry(peer): %v", err)
	}
	if err := AddFDBEntry(5177, "52:54:00:53:c8:b3", "10.77.0.14"); err != nil {
		t.Fatalf("AddFDBEntry(peer): %v", err)
	}
	want := []string{
		"bridge fdb append 00:00:00:00:00:00 dev vxlan5177 dst 10.77.0.14",
		"bridge fdb add 52:54:00:53:c8:b3 dev vxlan5177 dst 10.77.0.14",
	}
	if !slices.Equal(*calls, want) {
		t.Fatalf("peer entries: got\n%s\nwant\n%s", strings.Join(*calls, "\n"), strings.Join(want, "\n"))
	}
}

// labFDB is node-1's vxlan5177 forwarding table from the lab (01-state.txt),
// plus a flood entry for an address no host has any more and one for a live
// host whose VTEP row has not replicated here yet.
const labFDB = `00:00:00:00:00:00 dst 10.0.2.15 self permanent
00:00:00:00:00:00 dst 192.168.5.4 self permanent
00:00:00:00:00:00 dst 10.77.0.13 self permanent
00:00:00:00:00:00 dst 10.77.0.12 self permanent
52:54:00:44:37:23 dst 10.0.2.15 self permanent
52:54:00:44:37:23 master br-vni5177
`

func fdbReply(cmd string) ([]byte, error) {
	if cmd == "bridge fdb show dev vxlan5177" {
		return []byte(labFDB), nil
	}
	return nil, nil
}

// fdbChanges splits a pass's commands into its installs ("add <mac> ..." for
// a unicast entry, "append 00:00:00:00:00:00 ..." for a flood destination)
// and its removals ("<mac> dev ... dst ...").
func fdbChanges(calls []string) (adds, dels []string) {
	for _, c := range calls {
		switch {
		case strings.HasPrefix(c, "bridge fdb add "), strings.HasPrefix(c, "bridge fdb append "):
			adds = append(adds, strings.TrimPrefix(c, "bridge fdb "))
		case strings.HasPrefix(c, "bridge fdb del "):
			dels = append(dels, strings.TrimPrefix(c, "bridge fdb del "))
		}
	}
	slices.Sort(adds)
	slices.Sort(dels)
	return adds, dels
}

// TestSyncFloodEntries_SkipsSelfAndPrunesStale: the upgrade path. A peer still
// on the old build registers the shared NAT address; that row is skipped, not
// flooded to. The self-pointing flood and unicast entries the old build left
// are removed, as is a flood entry for an address no host has. A live host's
// registered address is kept though no VTEP row names it yet.
func TestSyncFloodEntries_SkipsSelfAndPrunesStale(t *testing.T) {
	multiHomedLab(t)
	calls := fakeExec(t, fdbReply)
	ctx := context.Background()
	db := vtepTestDB(t)
	for _, v := range []struct{ host, ip string }{
		{"node-1", "10.77.0.11"}, // this host
		{"node-2", "10.77.0.12"},
		{"node-4", "10.0.2.15"}, // a peer on the old build
	} {
		if err := UpsertVTEP(ctx, db, "vxd_vxdnet", v.host, v.ip, 5177); err != nil {
			t.Fatalf("UpsertVTEP: %v", err)
		}
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "node-3", Address: "10.77.0.13", State: "active"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	// A host registered without advertise_address on the NAT'd lab: its
	// address is the shared 10.0.2.15, so it is a live host's address and
	// this host's own at once. Its own-address entries still go.
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "node-5", Address: "10.0.2.15", State: "active"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	if err := SyncFloodEntries(ctx, db, "vxd_vxdnet", "node-1", 5177); err != nil {
		t.Fatalf("SyncFloodEntries: %v", err)
	}
	adds, dels := fdbChanges(*calls)
	if want := []string{"append 00:00:00:00:00:00 dev vxlan5177 dst 10.77.0.12"}; !slices.Equal(adds, want) {
		t.Errorf("added %q, want %q", adds, want)
	}
	wantDels := []string{
		"00:00:00:00:00:00 dev vxlan5177 dst 10.0.2.15",
		"00:00:00:00:00:00 dev vxlan5177 dst 192.168.5.4",
		"52:54:00:44:37:23 dev vxlan5177 dst 10.0.2.15",
	}
	if !slices.Equal(dels, wantDels) {
		t.Errorf("removed %q, want %q", dels, wantDels)
	}
}

// TestSyncPeerVTEP_ReplacesThePeersOldAddress: a peer that sends its new VTEP
// before its row has replicated here gets the new address, and its old one —
// still in the row — is neither re-added nor kept.
func TestSyncPeerVTEP_ReplacesThePeersOldAddress(t *testing.T) {
	multiHomedLab(t)
	calls := fakeExec(t, func(cmd string) ([]byte, error) {
		if cmd == "bridge fdb show dev vxlan5177" {
			return []byte("00:00:00:00:00:00 dst 192.168.5.4 self permanent\n"), nil
		}
		return nil, nil
	})
	ctx := context.Background()
	db := vtepTestDB(t)
	if err := UpsertVTEP(ctx, db, "vxd_vxdnet", "node-4", "192.168.5.4", 5177); err != nil {
		t.Fatalf("UpsertVTEP: %v", err)
	}

	if err := SyncPeerVTEP(ctx, db, "vxd_vxdnet", "node-1", 5177, "node-4", "10.77.0.14"); err != nil {
		t.Fatalf("SyncPeerVTEP: %v", err)
	}
	adds, dels := fdbChanges(*calls)
	if want := []string{"append 00:00:00:00:00:00 dev vxlan5177 dst 10.77.0.14"}; !slices.Equal(adds, want) {
		t.Errorf("added %q, want %q", adds, want)
	}
	if want := []string{"00:00:00:00:00:00 dev vxlan5177 dst 192.168.5.4"}; !slices.Equal(dels, want) {
		t.Errorf("removed %q, want %q", dels, want)
	}
}

const labVXLANLink = `12: vxlan5177: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue master br-vni5177 state UNKNOWN mode DEFAULT group default qlen 1000\    link/ether 5e:43:7e:b2:df:28 brd ff:ff:ff:ff:ff:ff promiscuity 1 minmtu 68 maxmtu 65535 \    vxlan id 5177 local 10.0.2.15 dev ens3 srcport 0 0 dstport 4789 nolearning ttl auto ageing 300 udpcsum noudp6zerocsumtx noudp6zerocsumrx \    bridge_slave state forwarding priority 32 cost 100 hairpin off`

// TestEnsureVXLAN_RecreatesADriftedDevice: an existing vxlan device made with
// the old local address and underlay is replaced, so a host heals on upgrade.
// Only the vxlan port goes — the bridge, and the guests' taps on it, stay —
// and the new port is put back on the bridge.
func TestEnsureVXLAN_RecreatesADriftedDevice(t *testing.T) {
	multiHomedLab(t)
	adds := 0
	calls := fakeExec(t, func(cmd string) ([]byte, error) {
		switch {
		case strings.HasPrefix(cmd, "ip link add vxlan5177 "):
			adds++
			if adds == 1 {
				return []byte("RTNETLINK answers: File exists\n"), errors.New("exit status 2")
			}
		case cmd == "ip link add br-vni5177 type bridge":
			return []byte("RTNETLINK answers: File exists\n"), errors.New("exit status 2")
		case cmd == "ip -d -o link show vxlan5177":
			return []byte(labVXLANLink), nil
		}
		return nil, nil
	})

	if _, err := EnsureVXLAN(5177, "net1", "10.77.0.11"); err != nil {
		t.Fatalf("EnsureVXLAN: %v", err)
	}
	add := "ip link add vxlan5177 type vxlan id 5177 dstport 4789 local 10.77.0.11 dev net1 nolearning"
	del := "ip link del vxlan5177"
	iDel, iAdd2 := slices.Index(*calls, del), -1
	for i, c := range *calls {
		if c == add && i > iDel {
			iAdd2 = i
		}
	}
	if iDel < 0 || iAdd2 < 0 {
		t.Fatalf("the drifted device was not deleted and re-added:\n%s", strings.Join(*calls, "\n"))
	}
	if slices.Contains(*calls, "ip link del br-vni5177") {
		t.Fatal("the bridge was deleted; its guests' taps would go with it")
	}
	if i := slices.Index(*calls, "ip link set vxlan5177 master br-vni5177"); i < iAdd2 {
		t.Fatalf("the new vxlan port is not put back on the bridge after it is re-added:\n%s", strings.Join(*calls, "\n"))
	}
}

// TestEnsureVXLAN_KeepsAMatchingDevice: a device already on this host's
// address and underlay is left in place.
func TestEnsureVXLAN_KeepsAMatchingDevice(t *testing.T) {
	calls := fakeExec(t, func(cmd string) ([]byte, error) {
		switch {
		case strings.HasPrefix(cmd, "ip link add "):
			return []byte("RTNETLINK answers: File exists\n"), errors.New("exit status 2")
		case cmd == "ip -d -o link show vxlan5177":
			return []byte(strings.ReplaceAll(strings.ReplaceAll(labVXLANLink,
				"local 10.0.2.15", "local 10.77.0.11"), "dev ens3", "dev net1")), nil
		}
		return nil, nil
	})
	if _, err := EnsureVXLAN(5177, "net1", "10.77.0.11"); err != nil {
		t.Fatalf("EnsureVXLAN: %v", err)
	}
	if slices.Contains(*calls, "ip link del vxlan5177") {
		t.Fatalf("a device already on this host's address was recreated:\n%s", strings.Join(*calls, "\n"))
	}
}

// TestEnsureVXLAN_DoesNotRecreateIntoAnUnheldAddress: a drifted device is
// kept when the new local address is not one this host holds; the kernel
// could not send from it.
func TestEnsureVXLAN_DoesNotRecreateIntoAnUnheldAddress(t *testing.T) {
	multiHomedLab(t)
	calls := fakeExec(t, func(cmd string) ([]byte, error) {
		switch {
		case strings.HasPrefix(cmd, "ip link add "):
			return []byte("RTNETLINK answers: File exists\n"), errors.New("exit status 2")
		case cmd == "ip -d -o link show vxlan5177":
			return []byte(labVXLANLink), nil
		}
		return nil, nil
	})
	if _, err := EnsureVXLAN(5177, "net1", "203.0.113.9"); err == nil {
		t.Fatal("EnsureVXLAN accepted a local address this host does not hold")
	}
	if slices.Contains(*calls, "ip link del vxlan5177") {
		t.Fatal("the working device was deleted for an address this host cannot send from")
	}
}

// seedNIC records a live VM NIC (vm_interfaces) or container NIC on network.
func seedNIC(t *testing.T, db *corrosion.Client, host, owner, mac string, container bool) {
	t.Helper()
	ctx := context.Background()
	if container {
		if err := db.Execute(ctx, `INSERT INTO container_interfaces (host_name, ct_name, network_name, ordinal, mac, updated_at)
			VALUES (?, ?, 'vxd_vxdnet', 0, ?, '2026-10-15T00:00:00Z')`, host, owner, mac); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: owner, HostName: host, State: "running", Spec: "{}"},
		[]corrosion.InterfaceRecord{{VMName: owner, NetworkName: "vxd_vxdnet", Ordinal: 0, MAC: mac}}, nil); err != nil {
		t.Fatal(err)
	}
}

// TestSyncFloodEntries_UnicastFollowsTheNICs: every live NIC on the network
// on another host gets a unicast entry at that host's VTEP — so a recreated
// device, which starts with none, gets them all back — an entry still at a
// peer's old VTEP is repointed, and one at an address that is no VTEP is
// removed. A local NIC gets none; an unknown MAC at a current VTEP is kept.
func TestSyncFloodEntries_UnicastFollowsTheNICs(t *testing.T) {
	multiHomedLab(t)
	ctx := context.Background()
	db := vtepTestDB(t)
	for _, v := range []struct{ host, ip string }{
		{"node-1", "10.77.0.11"}, {"node-2", "10.77.0.12"}, {"node-4", "10.77.0.14"},
	} {
		if err := UpsertVTEP(ctx, db, "vxd_vxdnet", v.host, v.ip, 5177); err != nil {
			t.Fatal(err)
		}
	}
	seedNIC(t, db, "node-2", "vxd2", "52:54:00:00:00:02", false)
	seedNIC(t, db, "node-4", "ct4", "52:54:00:00:00:04", true)
	seedNIC(t, db, "node-1", "vxd1", "52:54:00:00:00:01", false) // local

	// A recreated device: no entries at all.
	calls := fakeExec(t, nil)
	if err := SyncFloodEntries(ctx, db, "vxd_vxdnet", "node-1", 5177); err != nil {
		t.Fatal(err)
	}
	adds, dels := fdbChanges(*calls)
	want := []string{
		"add 52:54:00:00:00:02 dev vxlan5177 dst 10.77.0.12",
		"add 52:54:00:00:00:04 dev vxlan5177 dst 10.77.0.14",
		"append 00:00:00:00:00:00 dev vxlan5177 dst 10.77.0.12",
		"append 00:00:00:00:00:00 dev vxlan5177 dst 10.77.0.14",
	}
	if !slices.Equal(adds, want) || len(dels) != 0 {
		t.Fatalf("on an empty device: added %q removed %q, want added %q", adds, dels, want)
	}

	// node-2's VTEP moved; this host still points vxd2's MAC at the old one.
	calls = fakeExec(t, func(cmd string) ([]byte, error) {
		if cmd == "bridge fdb show dev vxlan5177" {
			return []byte(`00:00:00:00:00:00 dst 10.77.0.12 self permanent
00:00:00:00:00:00 dst 10.77.0.14 self permanent
52:54:00:00:00:02 dst 10.77.0.99 self permanent
52:54:00:00:00:04 dst 10.77.0.14 self permanent
52:54:00:00:00:77 dst 10.77.0.14 self permanent
52:54:00:00:00:88 dst 198.51.100.7 self permanent
`), nil
		}
		return nil, nil
	})
	if err := SyncFloodEntries(ctx, db, "vxd_vxdnet", "node-1", 5177); err != nil {
		t.Fatal(err)
	}
	adds, dels = fdbChanges(*calls)
	wantAdds := []string{
		"add 52:54:00:00:00:02 dev vxlan5177 dst 10.77.0.12",
		"append 00:00:00:00:00:00 dev vxlan5177 dst 10.77.0.12",
		"append 00:00:00:00:00:00 dev vxlan5177 dst 10.77.0.14",
	}
	wantDels := []string{
		"52:54:00:00:00:02 dev vxlan5177 dst 10.77.0.99",
		"52:54:00:00:00:88 dev vxlan5177 dst 198.51.100.7",
	}
	if !slices.Equal(adds, wantAdds) || !slices.Equal(dels, wantDels) {
		t.Fatalf("repoint: added %q removed %q, want added %q removed %q", adds, dels, wantAdds, wantDels)
	}
}

// TestRefusedEntry_LoggedOncePerAddress: a peer that keeps pushing an address
// of this host's is refused on every attempt but logged once per address,
// at Warn, not once per pass.
func TestRefusedEntry_LoggedOncePerAddress(t *testing.T) {
	multiHomedLab(t)
	fakeExec(t, nil)
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	for i := 0; i < 3; i++ {
		_ = FloodEntry(9177, "10.0.2.15")
	}
	_ = FloodEntry(9177, "10.77.0.11")
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("logged %d lines for 4 refusals of 2 addresses, want 2:\n%s", len(lines), buf.String())
	}
	for _, l := range lines {
		if !strings.Contains(l, "level=WARN") {
			t.Errorf("refusal logged as %q, want WARN", l)
		}
	}
}

// TestSyncFloodEntries_FloodListHoldsEveryPeer runs the sync against a model
// of the kernel's table (fdbfake): one flood entry per device, with a list of
// destinations, where a second `add` of the all-zeros MAC is refused with
// "File exists". Every peer ends up on the list — the lab's node-1 held only
// .13 and never gained .14 — and removing a peer that moved deletes only its
// own destination.
func TestSyncFloodEntries_FloodListHoldsEveryPeer(t *testing.T) {
	multiHomedLab(t)
	k := fdbfake.New()
	k.Set("vxlan5177", floodMAC, "10.77.0.13") // what an earlier build left
	prev := execCommand
	execCommand = k.Exec
	t.Cleanup(func() { execCommand = prev })
	ctx := context.Background()
	db := vtepTestDB(t)
	for _, v := range []struct{ host, ip string }{
		{"node-1", "10.77.0.11"}, {"node-2", "10.77.0.12"}, {"node-3", "10.77.0.13"}, {"node-4", "10.77.0.14"},
	} {
		if err := UpsertVTEP(ctx, db, "vxd_vxdnet", v.host, v.ip, 5177); err != nil {
			t.Fatal(err)
		}
	}

	if err := SyncFloodEntries(ctx, db, "vxd_vxdnet", "node-1", 5177); err != nil {
		t.Fatal(err)
	}
	want := []string{"10.77.0.12", "10.77.0.13", "10.77.0.14"}
	if got := k.Dsts("vxlan5177", floodMAC); !slices.Equal(got, want) {
		t.Fatalf("flood list %v, want every peer %v", got, want)
	}

	// node-4's VTEP moves: its old destination goes, the others stay.
	if err := UpsertVTEP(ctx, db, "vxd_vxdnet", "node-4", "10.77.0.24", 5177); err != nil {
		t.Fatal(err)
	}
	if err := SyncFloodEntries(ctx, db, "vxd_vxdnet", "node-1", 5177); err != nil {
		t.Fatal(err)
	}
	want = []string{"10.77.0.12", "10.77.0.13", "10.77.0.24"}
	if got := k.Dsts("vxlan5177", floodMAC); !slices.Equal(got, want) {
		t.Fatalf("flood list after node-4 moved %v, want %v", got, want)
	}
}
