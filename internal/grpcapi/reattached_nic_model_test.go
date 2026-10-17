package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A NIC detached and attached again under the same MAC (a driver swap that
// keeps the MAC's DHCP lease) is a new NIC: the attach records its model in
// the vm_nics row only, and the create's spec entry for the MAC still names
// the old one. Every regenerate renders the attached model, in both
// directions; the detach on record is what says the spec entry is stale.
//
// Mutation: ignore the recorded detach in compose.NICModels — every case goes
// red with the old model.
func TestRegenerate_AReattachedMACTakesItsNewModel(t *testing.T) {
	const mac = "52:54:00:aa:00:07"
	for _, tc := range []struct{ from, to string }{{"e1000", "virtio"}, {"virtio", "e1000"}} {
		for _, path := range []string{"UpdateVM", "reconcile"} {
			t.Run(tc.from+"->"+tc.to+"/"+path, func(t *testing.T) {
				s := hotplugDiskServer(t)
				enableHardwareV2(t, s)
				ctx := adminCtx()
				spec := &pb.VMSpec{Name: "swap", Cpu: 1, MemoryMib: 512, Machine: "pc",
					Network: []*pb.NetworkAttachment{{Name: "lan", Model: tc.from, Mac: mac}}}
				vm := corrosion.VMRecord{Name: "swap", HostName: "test-host", State: "stopped",
					CPUActual: 1, MemActual: 512, Spec: seedSpecJSON(t, spec)}
				if err := corrosion.InsertVMWithHardware(ctx, s.db, vm,
					[]corrosion.InterfaceRecord{{VMName: "swap", NetworkName: "lan", Ordinal: 0, MAC: mac}}, nil,
					[]corrosion.NICRecord{{VMName: "swap", ID: corrosion.DeterministicNICID("swap", mac),
						NetworkName: "lan", Model: tc.from, MAC: mac, Ordinal: 0}}, nil, false); err != nil {
					t.Fatalf("insert VM: %v", err)
				}

				if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "swap", NicMac: mac}); err != nil {
					t.Fatalf("detach: %v", err)
				}
				if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "swap",
					Nic: &pb.NetworkAttachment{Name: "lan", Model: tc.to, Mac: mac}}); err != nil {
					t.Fatalf("attach: %v", err)
				}

				if path == "UpdateVM" {
					if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "swap", Machine: "q35"}); err != nil {
						t.Fatalf("UpdateVM: %v", err)
					}
				} else {
					// No definition: the reconcile regenerates rather than patches.
					_ = s.virt.UndefineDomain("swap", false)
					if err := s.reconcileDomainDefinition(ctx, mustGetVM(t, s, "swap"), nil); err != nil {
						t.Fatalf("reconcileDomainDefinition: %v", err)
					}
				}
				domXML, err := s.virt.DumpXMLInactive("swap")
				if err != nil {
					t.Fatalf("DumpXMLInactive: %v", err)
				}
				if got := nicModelsByMAC(t, domXML)[mac]; got != tc.to {
					t.Fatalf("the re-attached NIC renders %q, want %q:\n%s", got, tc.to, domXML)
				}
			})
		}
	}
}
