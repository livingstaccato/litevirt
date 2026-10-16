package corrosion

import (
	"context"
	"strings"
	"testing"
)

// UpdateVMInterfaceIP lands only on the live row of the NIC it is for. The
// legacy vm_interfaces table is keyed by (vm, network) and a detach after the
// hardware_v2 latch tombstones only vm_nics, so an unfiltered UPDATE on the
// legacy row revives a detached NIC (scenario A) or bumps an old tombstone over
// a NIC re-attached under the same MAC (scenario B). Both are asserted through
// the overlay every reader uses (MergedVMNICs) and again after one pass of the
// hardware bridge (BridgeVMNICs), which is what makes either outcome permanent.

const (
	ipNICX = "52:54:00:aa:00:01"
	ipNICY = "52:54:00:aa:00:02"
)

func mergedByMAC(t *testing.T, c *Client, vm string) map[string]NICRecord {
	t.Helper()
	nics, err := MergedVMNICs(context.Background(), c, vm)
	if err != nil {
		t.Fatalf("MergedVMNICs: %v", err)
	}
	out := make(map[string]NICRecord, len(nics))
	for _, n := range nics {
		out[strings.ToLower(n.MAC)] = n
	}
	return out
}

func mustBridge(t *testing.T, c *Client, vm string) {
	t.Helper()
	if err := BridgeVMNICs(context.Background(), c, vm); err != nil {
		t.Fatalf("BridgeVMNICs: %v", err)
	}
}

// createdNIC writes a NIC the way a create, or a pre-latch attach, does: both
// tables, same MAC.
func createdNIC(t *testing.T, c *Client, vm, network, mac string, ordinal int) {
	t.Helper()
	ctx := context.Background()
	if err := InsertInterface(ctx, c, InterfaceRecord{VMName: vm, NetworkName: network, Ordinal: ordinal, MAC: mac}); err != nil {
		t.Fatalf("InsertInterface: %v", err)
	}
	if err := UpsertNIC(ctx, c, NICRecord{VMName: vm, ID: DeterministicNICID(vm, mac), NetworkName: network, MAC: mac, Ordinal: ordinal}); err != nil {
		t.Fatalf("UpsertNIC: %v", err)
	}
}

func ifaceIPVM(t *testing.T) *Client {
	t.Helper()
	c := testClient(t)
	if err := InsertVM(context.Background(), c, VMRecord{Name: "web", HostName: "h1", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	return c
}

// Scenario A: a detach after the latch leaves the legacy row live. An IP write
// for that network, by network alone (SetVMIP) or by the detached NIC's MAC (a
// stale lease), must not bring the NIC back, before or after the bridge.
func TestUpdateVMInterfaceIP_DoesNotReviveADetachedNIC(t *testing.T) {
	for _, mac := range []string{"", ipNICX} {
		t.Run("mac="+mac, func(t *testing.T) {
			c := ifaceIPVM(t)
			ctx := context.Background()
			createdNIC(t, c, "web", "lan", ipNICX, 0)
			// Post-latch detach: vm_nics only.
			if err := TombstoneNIC(ctx, c, "web", DeterministicNICID("web", ipNICX)); err != nil {
				t.Fatal(err)
			}
			if _, live := mergedByMAC(t, c, "web")[ipNICX]; live {
				t.Fatal("fixture: the detached NIC is still live")
			}

			written, err := UpdateVMInterfaceIP(ctx, c, "web", "lan", mac, "10.0.0.7")
			if err != nil {
				t.Fatalf("UpdateVMInterfaceIP: %v", err)
			}
			if written {
				t.Error("UpdateVMInterfaceIP reported a write with no live NIC on the network")
			}
			if n, live := mergedByMAC(t, c, "web")[ipNICX]; live {
				t.Fatalf("the detached NIC is live again after an IP write: %+v", n)
			}
			mustBridge(t, c, "web")
			if n, live := mergedByMAC(t, c, "web")[ipNICX]; live {
				t.Fatalf("the detached NIC is live again after the bridge: %+v", n)
			}
		})
	}
}

// Scenario A with a replacement NIC: the address lands on the live NIC Y, and
// the detached NIC X, whose legacy row still names the network, stays gone.
func TestUpdateVMInterfaceIP_LandsOnTheLiveNICNotTheDetachedLegacyRow(t *testing.T) {
	for _, mac := range []string{"", ipNICY} {
		t.Run("mac="+mac, func(t *testing.T) {
			c := ifaceIPVM(t)
			ctx := context.Background()
			createdNIC(t, c, "web", "lan", ipNICX, 0)
			if err := TombstoneNIC(ctx, c, "web", DeterministicNICID("web", ipNICX)); err != nil {
				t.Fatal(err)
			}
			// Post-latch attach of Y on the same network: vm_nics only, with a
			// model the legacy table cannot carry.
			if err := UpsertNIC(ctx, c, NICRecord{VMName: "web", ID: DeterministicNICID("web", ipNICY), NetworkName: "lan", Model: "e1000", MAC: ipNICY, Ordinal: 1}); err != nil {
				t.Fatal(err)
			}

			written, err := UpdateVMInterfaceIP(ctx, c, "web", "lan", mac, "10.0.0.8")
			if err != nil || !written {
				t.Fatalf("UpdateVMInterfaceIP: written=%v err=%v", written, err)
			}
			for _, pass := range []string{"after the write", "after the bridge"} {
				got := mergedByMAC(t, c, "web")
				if n, live := got[ipNICX]; live {
					t.Errorf("%s: the detached NIC X is live again: %+v", pass, n)
				}
				y, live := got[ipNICY]
				if !live || y.IP != "10.0.0.8" || y.Model != "e1000" {
					t.Errorf("%s: NIC Y = %+v (live %v), want live, ip 10.0.0.8, model e1000", pass, y, live)
				}
				mustBridge(t, c, "web")
			}
		})
	}
}

// Scenario B: a pre-latch detach tombstoned both rows, and the NIC came back
// under the same MAC after the latch (vm_nics only). An IP write must not bump
// the legacy tombstone over the live row, which would hide the NIC and let the
// bridge tombstone it.
func TestUpdateVMInterfaceIP_DoesNotBumpATombstoneOverAReattachedNIC(t *testing.T) {
	for _, mac := range []string{"", ipNICX} {
		t.Run("mac="+mac, func(t *testing.T) {
			c := ifaceIPVM(t)
			ctx := context.Background()
			createdNIC(t, c, "web", "lan", ipNICX, 0)
			// Pre-latch detach: both tables.
			if err := TombstoneNIC(ctx, c, "web", DeterministicNICID("web", ipNICX)); err != nil {
				t.Fatal(err)
			}
			if err := SoftDeleteInterfaceByMAC(ctx, c, "web", ipNICX); err != nil {
				t.Fatal(err)
			}
			// Post-latch re-attach under the same MAC: vm_nics only.
			if err := UpsertNIC(ctx, c, NICRecord{VMName: "web", ID: DeterministicNICID("web", ipNICX), NetworkName: "lan", MAC: ipNICX, Ordinal: 0}); err != nil {
				t.Fatal(err)
			}
			legacyBefore := legacyRow(t, c, "web", "lan")

			written, err := UpdateVMInterfaceIP(ctx, c, "web", "lan", mac, "10.0.0.9")
			if err != nil || !written {
				t.Fatalf("UpdateVMInterfaceIP: written=%v err=%v", written, err)
			}
			if after := legacyRow(t, c, "web", "lan"); after != legacyBefore {
				t.Errorf("the legacy tombstone was written: before %+v, after %+v", legacyBefore, after)
			}
			for _, pass := range []string{"after the write", "after the bridge"} {
				x, live := mergedByMAC(t, c, "web")[ipNICX]
				if !live || x.IP != "10.0.0.9" {
					t.Errorf("%s: re-attached NIC X = %+v (live %v), want live with ip 10.0.0.9", pass, x, live)
				}
				mustBridge(t, c, "web")
			}
		})
	}
}

// A legacy row newer than its vm_nics counterpart (an older peer's write) is
// the NIC's current state. The IP lands on it, and the older vm_nics row is not
// rewritten over it: that would replace the legacy row's newer fields.
func TestUpdateVMInterfaceIP_NewerLegacyRowKeepsItsFields(t *testing.T) {
	c := ifaceIPVM(t)
	ctx := context.Background()
	createdNIC(t, c, "web", "lan", ipNICX, 0)
	// An older peer binds a security group on the legacy row only.
	if err := SetInterfaceSecurityGroups(ctx, c, "web", "lan", []string{"web-sg"}); err != nil {
		t.Fatal(err)
	}
	written, err := UpdateVMInterfaceIP(ctx, c, "web", "lan", ipNICX, "10.0.0.10")
	if err != nil || !written {
		t.Fatalf("UpdateVMInterfaceIP: written=%v err=%v", written, err)
	}
	for _, pass := range []string{"after the write", "after the bridge"} {
		x, live := mergedByMAC(t, c, "web")[ipNICX]
		if !live || x.IP != "10.0.0.10" || !strings.Contains(x.SecurityGroups, "web-sg") {
			t.Errorf("%s: NIC X = %+v (live %v), want live, ip 10.0.0.10, group web-sg", pass, x, live)
		}
		mustBridge(t, c, "web")
	}
	ifaces, err := GetVMInterfaces(ctx, c, "web")
	if err != nil || len(ifaces) != 1 || ifaces[0].IP != "10.0.0.10" {
		t.Errorf("legacy view = %+v (%v), want the address on the legacy row too", ifaces, err)
	}
}

// A NIC both tables carry, with vm_nics the newer row: both are written, the
// legacy row for a peer that reads only vm_interfaces, and vm_nics last so it
// stays the winner and the bridge does not copy the legacy row (with its
// synthesized model) over it.
func TestUpdateVMInterfaceIP_WritesBothTablesForADualWrittenNIC(t *testing.T) {
	c := ifaceIPVM(t)
	ctx := context.Background()
	if err := InsertInterface(ctx, c, InterfaceRecord{VMName: "web", NetworkName: "lan", MAC: ipNICX}); err != nil {
		t.Fatal(err)
	}
	if err := UpsertNIC(ctx, c, NICRecord{VMName: "web", ID: DeterministicNICID("web", ipNICX), NetworkName: "lan", Model: "e1000", MAC: ipNICX}); err != nil {
		t.Fatal(err)
	}
	written, err := UpdateVMInterfaceIP(ctx, c, "web", "lan", "", "10.0.0.11")
	if err != nil || !written {
		t.Fatalf("UpdateVMInterfaceIP: written=%v err=%v", written, err)
	}
	ifaces, err := GetVMInterfaces(ctx, c, "web")
	if err != nil || len(ifaces) != 1 || ifaces[0].IP != "10.0.0.11" {
		t.Errorf("legacy view = %+v (%v), want ip 10.0.0.11", ifaces, err)
	}
	for _, pass := range []string{"after the write", "after the bridge"} {
		x, live := mergedByMAC(t, c, "web")[ipNICX]
		if !live || x.IP != "10.0.0.11" || x.Model != "e1000" {
			t.Errorf("%s: NIC X = %+v (live %v), want live, ip 10.0.0.11, model e1000", pass, x, live)
		}
		mustBridge(t, c, "web")
	}
}

// Two live NICs on one network: a write naming one MAC lands on that NIC only.
// By network alone it lands where the unfiltered UPDATE did, on the NIC the
// legacy row names.
func TestUpdateVMInterfaceIP_TwoNICsOnOneNetwork(t *testing.T) {
	c := ifaceIPVM(t)
	ctx := context.Background()
	createdNIC(t, c, "web", "lan", ipNICX, 0)
	if err := UpsertNIC(ctx, c, NICRecord{VMName: "web", ID: DeterministicNICID("web", ipNICY), NetworkName: "lan", MAC: ipNICY, Ordinal: 1}); err != nil {
		t.Fatal(err)
	}
	if written, err := UpdateVMInterfaceIP(ctx, c, "web", "lan", ipNICY, "10.0.0.12"); err != nil || !written {
		t.Fatalf("UpdateVMInterfaceIP(Y): written=%v err=%v", written, err)
	}
	got := mergedByMAC(t, c, "web")
	if got[ipNICY].IP != "10.0.0.12" || got[ipNICX].IP != "" {
		t.Errorf("after a write for Y: X=%+v Y=%+v, want only Y addressed", got[ipNICX], got[ipNICY])
	}
	if written, err := UpdateVMInterfaceIP(ctx, c, "web", "lan", "", "10.0.0.13"); err != nil || !written {
		t.Fatalf("UpdateVMInterfaceIP(network): written=%v err=%v", written, err)
	}
	got = mergedByMAC(t, c, "web")
	if got[ipNICX].IP != "10.0.0.13" || got[ipNICY].IP != "10.0.0.12" {
		t.Errorf("after a write by network: X=%+v Y=%+v, want X (the legacy row's NIC) at 10.0.0.13", got[ipNICX], got[ipNICY])
	}
}

type legacySnapshot struct{ ip, updatedAt, deletedAt string }

func legacyRow(t *testing.T, c *Client, vm, network string) legacySnapshot {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT COALESCE(ip, '') AS ip, updated_at, COALESCE(deleted_at, '') AS deleted_at
		 FROM vm_interfaces WHERE vm_name = ? AND network_name = ?`, vm, network)
	if err != nil || len(rows) != 1 {
		t.Fatalf("legacy row (%s, %s): %d rows, %v", vm, network, len(rows), err)
	}
	return legacySnapshot{rows[0].String("ip"), rows[0].String("updated_at"), rows[0].String("deleted_at")}
}
