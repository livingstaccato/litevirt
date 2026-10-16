package health

import (
	"context"
	"encoding/xml"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A failover or onboot render takes each NIC's model from the spec NIC with
// its MAC, else its vm_nics row. A NIC whose newer vm_interfaces row wins the
// merge reads as virtio there (that table has no model column); the
// reconciler rendered it as virtio, and an e1000 guest came up with no
// network on the host it failed over to.
//
// Mutation: render the merged row's model alone — both NICs go red.
func TestDomainXMLFor_NICModelSurvivesALegacyWinningRow(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	r, _, _ := sharedDiskReconciler(t, db)
	const specMAC, hotMAC = "52:54:00:aa:bb:01", "52:54:00:aa:bb:02"
	vm := corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running", CPUActual: 1, MemActual: 512}
	if err := corrosion.InsertVM(ctx, db, vm, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// The hot-plugged NIC: vm_nics, then the legacy row, which is newer.
	if err := corrosion.UpsertNIC(ctx, db, corrosion.NICRecord{VMName: "vm1", ID: corrosion.DeterministicNICID("vm1", hotMAC),
		NetworkName: "br1", Model: "rtl8139", MAC: hotMAC, Ordinal: 1}); err != nil {
		t.Fatalf("UpsertNIC: %v", err)
	}
	for _, i := range []corrosion.InterfaceRecord{
		{VMName: "vm1", NetworkName: "br0", Ordinal: 0, MAC: specMAC},
		{VMName: "vm1", NetworkName: "br1", Ordinal: 1, MAC: hotMAC},
	} {
		if err := corrosion.InsertInterface(ctx, db, i); err != nil {
			t.Fatalf("InsertInterface: %v", err)
		}
	}
	spec := &pb.VMSpec{Name: "vm1", Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{{Name: "br0", Model: "e1000", Mac: specMAC}}}
	x, _, failure := r.domainXMLFor(ctx, vm, spec, nil)
	if failure != "" {
		t.Fatalf("domainXMLFor: %s", failure)
	}
	var d struct {
		Interfaces []struct {
			MAC struct {
				Address string `xml:"address,attr"`
			} `xml:"mac"`
			Model struct {
				Type string `xml:"type,attr"`
			} `xml:"model"`
		} `xml:"devices>interface"`
	}
	if err := xml.Unmarshal([]byte(x), &d); err != nil {
		t.Fatalf("parse: %v\n%s", err, x)
	}
	got := map[string]string{}
	for _, i := range d.Interfaces {
		got[strings.ToLower(i.MAC.Address)] = i.Model.Type
	}
	for mac, want := range map[string]string{specMAC: "e1000", hotMAC: "rtl8139"} {
		if got[mac] != want {
			t.Errorf("NIC %s: model %q, want %q (all %v)", mac, got[mac], want, got)
		}
	}
}

// A failover render of a NIC detached and attached again under the same MAC
// takes the attach's model (its vm_nics row), not the old NIC's spec entry:
// the detach recorded on the VM's operations says the entry is stale. In
// both directions; with no detach on record the spec entry still decides.
//
// Mutation: ignore the recorded detach in compose.NICModels — both
// re-attached cases go red.
func TestDomainXMLFor_AReattachedMACTakesItsNewModel(t *testing.T) {
	const mac = "52:54:00:aa:bb:07"
	for _, tc := range []struct {
		name, spec, row, want string
		detached              bool
	}{
		{"e1000 -> virtio", "e1000", "virtio", "virtio", true},
		{"virtio -> e1000", "virtio", "e1000", "e1000", true},
		{"no detach: the spec decides", "e1000", "virtio", "e1000", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			ctx := context.Background()
			r, _, _ := sharedDiskReconciler(t, db)
			vm := corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running", CPUActual: 1, MemActual: 512}
			if err := corrosion.InsertVMWithHardware(ctx, db, vm,
				[]corrosion.InterfaceRecord{{VMName: "vm1", NetworkName: "br0", Ordinal: 0, MAC: mac}}, nil,
				[]corrosion.NICRecord{{VMName: "vm1", ID: corrosion.DeterministicNICID("vm1", mac),
					NetworkName: "br0", Model: tc.row, MAC: mac, Ordinal: 0}}, nil, false); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			if tc.detached {
				if err := corrosion.InsertOperation(ctx, db, corrosion.OperationRecord{ID: "op-detach",
					Method: "DetachDevice", ResourceKind: "vm", ResourceID: "vm1",
					OperationKind: string(corrosion.OpDeviceDetach),
					RequestHash:   corrosion.NICDetachRequestHash("vm1", mac)}); err != nil {
					t.Fatalf("InsertOperation: %v", err)
				}
			}
			spec := &pb.VMSpec{Name: "vm1", Cpu: 1, MemoryMib: 512,
				Network: []*pb.NetworkAttachment{{Name: "br0", Model: tc.spec, Mac: mac}}}
			x, _, failure := r.domainXMLFor(ctx, vm, spec, nil)
			if failure != "" {
				t.Fatalf("domainXMLFor: %s", failure)
			}
			if !strings.Contains(x, `<model type="`+tc.want+`">`) && !strings.Contains(x, `<model type="`+tc.want+`"/>`) &&
				!strings.Contains(x, `<model type="`+tc.want+`"></model>`) {
				t.Fatalf("want model %s:\n%s", tc.want, x)
			}
		})
	}
}

// A failover render of a NIC swapped under its MAC from a virtio NIC with an
// MTU to an e1000 one: the attach rewrote the spec entry
// (compose.RewriteSpecNICForAttach), so the domain is defined with e1000 and
// no MTU instead of being refused as non-retryable.
//
// Mutation: drop the MTU rewrite in RewriteSpecNICForAttach — the render
// fails ("an MTU needs the virtio model").
func TestDomainXMLFor_ASwappedNICDefinesWithoutTheOldMTU(t *testing.T) {
	const mac = "52:54:00:aa:bb:31"
	db := testReconcilerDB(t)
	ctx := context.Background()
	r, fake, _ := sharedDiskReconciler(t, db)
	fake.SetBridgeMTU("br0", 9000)
	vm := corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running", CPUActual: 1, MemActual: 512}
	if err := corrosion.InsertVMWithHardware(ctx, db, vm,
		[]corrosion.InterfaceRecord{{VMName: "vm1", NetworkName: "br0", Ordinal: 0, MAC: mac}}, nil,
		[]corrosion.NICRecord{{VMName: "vm1", ID: corrosion.DeterministicNICID("vm1", mac),
			NetworkName: "br0", Model: "e1000", MAC: mac, Ordinal: 0}}, nil, false); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	spec := &pb.VMSpec{Name: "vm1", Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{{Name: "br0", Model: "virtio", Mac: mac, Mtu: 9000, Queues: 4}}}
	compose.RewriteSpecNICForAttach(spec, mac, "e1000")
	x, _, failure := r.domainXMLFor(ctx, vm, spec, nil)
	if failure != "" {
		t.Fatalf("domainXMLFor: %s", failure)
	}
	if !strings.Contains(x, `"e1000"`) || strings.Contains(x, "<mtu") {
		t.Fatalf("want an e1000 NIC with no MTU:\n%s", x)
	}
}
