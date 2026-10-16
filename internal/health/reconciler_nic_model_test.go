package health

import (
	"context"
	"encoding/xml"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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
