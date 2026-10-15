package network

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The bridge MAC of a network is a function of its name alone — every host
// derives the same one, so the value is pinned — and is a locally
// administered unicast address, so it can never be a vendor's or a multicast
// address. Different networks get different MACs.
//
// Mutations: add anything host-specific to the hash input — the pinned value
// goes red; prefix 0x08 (not locally administered) — red.
func TestNetworkBridgeMAC(t *testing.T) {
	a := NetworkBridgeMAC("st_lan")
	if a.String() != "0a:23:4e:9c:eb:85" {
		t.Fatalf("NetworkBridgeMAC(st_lan) = %s, want 0a:23:4e:9c:eb:85 on every host", a)
	}
	if len(a) != 6 {
		t.Fatalf("MAC %s is %d bytes", a, len(a))
	}
	if a[0]&0x02 == 0 || a[0]&0x01 != 0 {
		t.Errorf("MAC %s is not a locally administered unicast address", a)
	}
	if c := NetworkBridgeMAC("st_wan"); c.String() == a.String() {
		t.Errorf("two networks share the bridge MAC %s", a)
	}
}

// ensureBridgeMAC sets the MAC only when the bridge has another one (sysfs
// prints it in lower case; any case matches), and reports whether it did.
//
// Mutation: drop the equality check — the second call sets it again and
// reports a change.
func TestEnsureBridgeMAC_ReconcilesOnlyADifferentMAC(t *testing.T) {
	sys := t.TempDir()
	origSys := sysClassNet
	sysClassNet = sys
	var cmds []string
	execCommand = func(name string, args ...string) ([]byte, error) {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	t.Cleanup(func() { sysClassNet = origSys; execCommand = defaultExec })
	mac := NetworkBridgeMAC("n1")
	writeAddr := func(addr string) {
		if err := os.MkdirAll(filepath.Join(sys, "br1"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sys, "br1", "address"), []byte(addr+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	writeAddr("fe:54:00:11:22:33")
	changed, err := ensureBridgeMAC("br1", mac)
	if err != nil || !changed {
		t.Fatalf("ensureBridgeMAC on a bridge with another MAC = %v, %v; want changed", changed, err)
	}
	if want := "ip link set dev br1 address " + mac.String(); len(cmds) != 1 || cmds[0] != want {
		t.Errorf("commands %q, want [%s]", cmds, want)
	}

	cmds = nil
	writeAddr(strings.ToUpper(mac.String()))
	changed, err = ensureBridgeMAC("br1", mac)
	if err != nil || changed || len(cmds) != 0 {
		t.Errorf("ensureBridgeMAC on a bridge that has the MAC = %v, %v, commands %q; want no change", changed, err, cmds)
	}

	if _, err := ensureBridgeMAC("absent", mac); err == nil {
		t.Error("ensureBridgeMAC on a bridge whose MAC cannot be read reported no error")
	}
}

// Provision gives a bridge litevirt creates for a network, and an isolated
// network's bridge, the network's MAC; it leaves a bridge it did not create
// (an operator's, found already there) and a VLAN bridge alone.
//
// Mutations: drop the bridgeRecorded check — the operator's bridge gets a MAC;
// drop the VLAN check — the VLAN bridge gets one; drop the call from the
// isolated case — the isolated bridge keeps its MAC.
func TestProvision_BridgeGetsTheNetworkMAC(t *testing.T) {
	sys := t.TempDir()
	origSys, origSysfs, origDir := sysClassNet, sysfsNet, createdBridgeDir
	sysClassNet, sysfsNet = sys, sys
	createdBridgeDir = filepath.Join(t.TempDir(), "bridges")
	t.Cleanup(func() {
		sysClassNet, sysfsNet, createdBridgeDir = origSys, origSysfs, origDir
		execCommand = defaultExec
	})
	var cmds []string
	ifindex := 20
	exists := map[string]bool{}
	execCommand = func(name string, args ...string) ([]byte, error) {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		if name == "ip" && len(args) >= 3 && args[0] == "link" && args[1] == "add" {
			dev := args[2]
			if exists[dev] {
				return []byte("RTNETLINK answers: File exists"), errors.New("exit status 2")
			}
			ifindex++
			writeSysBridge(t, sys, dev, ifindex)
			if err := os.WriteFile(filepath.Join(sys, dev, "address"), []byte("fe:54:00:aa:bb:cc\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return nil, nil
	}
	db := corrosion.NewTestClientT(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	setMAC := func(dev string) string {
		for _, c := range cmds {
			if strings.HasPrefix(c, "ip link set dev "+dev+" address ") {
				return strings.TrimPrefix(c, "ip link set dev "+dev+" address ")
			}
		}
		return ""
	}

	cmds = nil
	if _, err := Provision(ctx, db, "st_lan", compose.NetworkDef{Type: "bridge", Interface: "lvmac1"}, "", "h1"); err != nil {
		t.Fatalf("Provision lvmac1: %v", err)
	}
	if got, want := setMAC("lvmac1"), NetworkBridgeMAC("st_lan").String(); got != want {
		t.Errorf("litevirt's bridge lvmac1 got MAC %q, want the network's %s", got, want)
	}

	// An operator's bridge: `ip link add` finds it there, so no record.
	exists["lvmac2"] = true
	writeSysBridge(t, sys, "lvmac2", 90)
	if err := os.WriteFile(filepath.Join(sys, "lvmac2", "address"), []byte("fe:54:00:aa:bb:cd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmds = nil
	if _, err := Provision(ctx, db, "st_op", compose.NetworkDef{Type: "bridge", Interface: "lvmac2"}, "", "h1"); err != nil {
		t.Fatalf("Provision lvmac2: %v", err)
	}
	if got := setMAC("lvmac2"); got != "" {
		t.Errorf("the operator's bridge lvmac2 was given MAC %s", got)
	}

	cmds = nil
	if _, err := Provision(ctx, db, "st_vlan", compose.NetworkDef{Type: "bridge", Interface: "lvmac3", VLAN: 30, Underlay: "eth0"}, "", "h1"); err != nil {
		t.Fatalf("Provision lvmac3: %v", err)
	}
	if got := setMAC("lvmac3"); got != "" {
		t.Errorf("the VLAN bridge lvmac3 was given MAC %s", got)
	}

	cmds = nil
	if _, err := Provision(ctx, db, "st_iso", compose.NetworkDef{Type: "isolated"}, "", "h1"); err != nil {
		t.Fatalf("Provision isolated: %v", err)
	}
	if got, want := setMAC(IsolatedBridgeName("st_iso")), NetworkBridgeMAC("st_iso").String(); got != want {
		t.Errorf("isolated bridge got MAC %q, want %s", got, want)
	}
}
