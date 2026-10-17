package corrosion

import (
	"context"
	"testing"
)

// A legacy vm_interfaces row has no model column. When a write bumps it past
// the NIC's live vm_nics row (an IP write: SetVMIP, NetBox discovery), the
// NIC's model is still the vm_nics row's: the merge reports it, and the
// hardware bridge that copies the newer legacy row into vm_nics keeps it.
// A tombstoned vm_nics row is not consulted: a NIC attached again under the
// MAC is another NIC.
//
// Mutations: copy the synthesized model in BridgeVMNICs again — "bridge"
// goes red; take the legacy winner's model in nicRowWinners — "merge" goes
// red; consult a tombstoned vm_nics row too — "tombstoned" goes red.
func TestNICModel_SurvivesANewerLegacyRow(t *testing.T) {
	const mac = "52:54:00:aa:cc:01"
	setup := func(t *testing.T, tombstone bool) *Client {
		t.Helper()
		c := testClient(t)
		ctx := context.Background()
		if err := UpsertNIC(ctx, c, NICRecord{VMName: "vm1", ID: DeterministicNICID("vm1", mac),
			NetworkName: "lan", Model: "e1000", MAC: mac, Ordinal: 0}); err != nil {
			t.Fatal(err)
		}
		if tombstone {
			if err := TombstoneNIC(ctx, c, "vm1", DeterministicNICID("vm1", mac)); err != nil {
				t.Fatal(err)
			}
		}
		if err := InsertInterface(ctx, c, InterfaceRecord{VMName: "vm1", NetworkName: "lan", Ordinal: 0, MAC: mac, IP: "10.0.0.5"}); err != nil {
			t.Fatal(err)
		}
		return c
	}
	model := func(t *testing.T, c *Client) string {
		t.Helper()
		nics, err := MergedVMNICs(context.Background(), c, "vm1")
		if err != nil || len(nics) != 1 {
			t.Fatalf("MergedVMNICs: %+v, %v", nics, err)
		}
		return nics[0].Model
	}

	t.Run("merge", func(t *testing.T) {
		if got := model(t, setup(t, false)); got != "e1000" {
			t.Fatalf("merged model %q, want the vm_nics row's e1000", got)
		}
	})
	t.Run("bridge", func(t *testing.T) {
		c := setup(t, false)
		ctx := context.Background()
		if err := BridgeVMNICs(ctx, c, "vm1"); err != nil {
			t.Fatal(err)
		}
		rows, err := VMNICRowModels(ctx, c, "vm1")
		if err != nil {
			t.Fatal(err)
		}
		if rows[mac] != "e1000" {
			t.Fatalf("after the bridge the vm_nics model is %q, want e1000", rows[mac])
		}
	})
	t.Run("tombstoned", func(t *testing.T) {
		if got := model(t, setup(t, true)); got != "virtio" {
			t.Fatalf("merged model %q, want the legacy row's virtio (the vm_nics row is a detached NIC's)", got)
		}
	})
}
