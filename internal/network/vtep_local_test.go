package network

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// multiHomedLab models a lab node (lab1-vxlan-dhcp.md): the default route and
// its source address are the qemu user-mode NAT, 10.0.2.15 on ens3 and the
// same on every node, while the cluster network is net1 with this node's
// advertise address.
func multiHomedLab(t *testing.T) {
	t.Helper()
	prev := hostAddrs
	hostAddrs = func() (map[string]string, error) {
		return map[string]string{
			"127.0.0.1":  "lo",
			"10.0.2.15":  "ens3",
			"10.77.0.11": "net1",
		}, nil
	}
	t.Cleanup(func() { hostAddrs = prev })
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

// TestProvision_VXLAN_UnderlayHoldsTheHostAddress: with no underlay set, the
// tunnel runs over the interface that holds this host's address — net1 — and
// not over the default-route interface. On the lab the default route's
// interface (ens3) carries the NAT address every node shares.
func TestProvision_VXLAN_UnderlayHoldsTheHostAddress(t *testing.T) {
	multiHomedLab(t)
	calls := fakeExec(t, func(cmd string) ([]byte, error) {
		if cmd == "ip route show default" {
			return []byte("default via 10.0.2.2 dev ens3 proto dhcp src 10.0.2.15 metric 100\n"), nil
		}
		return nil, nil
	})

	def := compose.NetworkDef{Type: "vxlan", Interface: "vxdnet", VNI: 5177}
	if _, err := Provision(context.Background(), vtepTestDB(t), "vxd_vxdnet", def, "10.77.0.11", "node-1"); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	want := "ip link add vxlan5177 type vxlan id 5177 dstport 4789 local 10.77.0.11 dev net1 nolearning"
	if !slices.Contains(*calls, want) {
		t.Fatalf("no %q among the commands:\n%s", want, strings.Join(*calls, "\n"))
	}
}

// TestUnderlayFor_FallsBackToTheDefaultRoute: an address no interface holds
// (or a loopback one) leaves the default-route interface as the underlay.
func TestUnderlayFor_FallsBackToTheDefaultRoute(t *testing.T) {
	multiHomedLab(t)
	fakeExec(t, func(cmd string) ([]byte, error) {
		return []byte("default via 10.0.2.2 dev ens3\n"), nil
	})
	for _, ip := range []string{"203.0.113.9", "127.0.0.1"} {
		if got := underlayFor(ip); got != "ens3" {
			t.Errorf("underlayFor(%s) = %q, want the default-route interface ens3", ip, got)
		}
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
		"bridge fdb add 00:00:00:00:00:00 dev vxlan5177 dst 10.77.0.14",
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

func fdbChanges(calls []string) (adds, dels []string) {
	for _, c := range calls {
		switch {
		case strings.HasPrefix(c, "bridge fdb add "):
			adds = append(adds, strings.TrimPrefix(c, "bridge fdb add "))
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

	if err := SyncFloodEntries(ctx, db, "vxd_vxdnet", "node-1", 5177); err != nil {
		t.Fatalf("SyncFloodEntries: %v", err)
	}
	adds, dels := fdbChanges(*calls)
	if want := []string{"00:00:00:00:00:00 dev vxlan5177 dst 10.77.0.12"}; !slices.Equal(adds, want) {
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
	if want := []string{"00:00:00:00:00:00 dev vxlan5177 dst 10.77.0.14"}; !slices.Equal(adds, want) {
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
