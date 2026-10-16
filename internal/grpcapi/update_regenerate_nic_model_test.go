package grpcapi

import (
	"encoding/xml"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// nicModelsByMAC reads each <interface>'s model from a domain definition,
// keyed by its lower-cased MAC.
func nicModelsByMAC(t *testing.T, domXML string) map[string]string {
	t.Helper()
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
	if err := xml.Unmarshal([]byte(domXML), &d); err != nil {
		t.Fatalf("parse domain XML: %v\n%s", err, domXML)
	}
	out := map[string]string{}
	for _, i := range d.Interfaces {
		out[strings.ToLower(i.MAC.Address)] = i.Model.Type
	}
	return out
}

// UpdateVM's regenerate rendered every NIC as virtio, so an e1000 guest
// (a Windows or appliance image without virtio drivers) came back from an
// `lv update` with no working network. The model is the one CreateVM
// recorded: the spec's NIC, or for a NIC hot-plugged after the create (in the
// NIC rows only) its vm_nics row.
//
// Mutation: hardcode "virtio" again in UpdateVM's network loop — all three
// NICs go red; take the row's model alone — the legacy-row NIC goes red.
func TestUpdateVM_RegenerateKeepsTheNICModel(t *testing.T) {
	const (
		macSpec   = "52:54:00:00:00:01" // in the spec and both NIC tables
		macLegacy = "52:54:00:00:00:02" // in the spec and vm_interfaces only
		macHot    = "52:54:00:00:00:03" // hot-plugged: vm_nics only
	)
	s := reconfigServer(t)
	ctx := adminCtx()
	spec := &pb.VMSpec{Name: "nicm", Cpu: 2, MemoryMib: 2048, Machine: "pc",
		Network: []*pb.NetworkAttachment{
			{Name: "lan", Model: "e1000", Mac: macSpec},
			{Name: "lan2", Model: "e1000e", Mac: macLegacy},
		}}
	vm := corrosion.VMRecord{Name: "nicm", HostName: "test-host", State: "stopped",
		CPUActual: 2, MemActual: 2048, Spec: seedSpecJSON(t, spec)}
	ifaces := []corrosion.InterfaceRecord{
		{VMName: "nicm", NetworkName: "lan", Ordinal: 0, MAC: macSpec},
		{VMName: "nicm", NetworkName: "lan2", Ordinal: 1, MAC: macLegacy},
	}
	nics := []corrosion.NICRecord{
		{VMName: "nicm", ID: corrosion.DeterministicNICID("nicm", macSpec), NetworkName: "lan", Model: "e1000", MAC: macSpec, Ordinal: 0},
		{VMName: "nicm", ID: corrosion.DeterministicNICID("nicm", macHot), NetworkName: "lan3", Model: "rtl8139", MAC: macHot, Ordinal: 2},
	}
	if err := corrosion.InsertVMWithHardware(ctx, s.db, vm, ifaces, nil, nics, nil, false); err != nil {
		t.Fatalf("insert VM: %v", err)
	}

	// A machine change is never patched in place.
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "nicm", Machine: "q35"}); err != nil {
		t.Fatalf("UpdateVM: %v", err)
	}
	domXML, err := s.virt.DumpXMLInactive("nicm")
	if err != nil {
		t.Fatalf("DumpXMLInactive: %v", err)
	}
	got := nicModelsByMAC(t, domXML)
	for mac, want := range map[string]string{macSpec: "e1000", macLegacy: "e1000e", macHot: "rtl8139"} {
		if got[mac] != want {
			t.Errorf("NIC %s rendered with model %q, want %q (all: %v)", mac, got[mac], want, got)
		}
	}
}
