package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A NIC swapped under the same MAC (detach, then attach with another model)
// is described by the spec from the attach on: the entry for the MAC takes
// the new model and drops tuning the model cannot take. Otherwise a virtio
// NIC's MTU stayed on the e1000 NIC that replaced it, and every later define
// — the stopped attach itself, UpdateVM, a reconcile, a failover — was
// refused ("an MTU needs the virtio model"). An `lv update --nic-mtu` is then
// judged against the NIC's real model: accepted on the virtio NIC that
// replaced an e1000, refused on the e1000 that replaced a virtio.
//
// Mutation: begin the attach with the stored spec unchanged — the
// virtio->e1000 attach fails, and the e1000->virtio MTU update is refused.
func TestNICSwap_SpecFollowsTheAttachedModel(t *testing.T) {
	const mac = "52:54:00:aa:00:31"
	for _, tc := range []struct {
		from, to string
		mtu      int32
	}{{"virtio", "e1000", 9000}, {"e1000", "virtio", 0}} {
		t.Run(tc.from+"->"+tc.to, func(t *testing.T) {
			s := hotplugDiskServer(t)
			enableHardwareV2(t, s)
			s.SetReleaseFeatureGate(newMTUGate(t, true))
			fake := s.virt.(*libvirtfake.Fake)
			fake.SetBridgeMTU("lan", 9000)
			ctx := adminCtx()
			spec := &pb.VMSpec{Name: "sw", Cpu: 1, MemoryMib: 512, Machine: "pc",
				Network: []*pb.NetworkAttachment{{Name: "lan", Model: tc.from, Mac: mac, Mtu: tc.mtu}}}
			vm := corrosion.VMRecord{Name: "sw", HostName: "test-host", State: "stopped",
				CPUActual: 1, MemActual: 512, Spec: seedSpecJSON(t, spec)}
			if err := corrosion.InsertVMWithHardware(ctx, s.db, vm,
				[]corrosion.InterfaceRecord{{VMName: "sw", NetworkName: "lan", Ordinal: 0, MAC: mac}}, nil,
				[]corrosion.NICRecord{{VMName: "sw", ID: corrosion.DeterministicNICID("sw", mac),
					NetworkName: "lan", Model: tc.from, MAC: mac, Ordinal: 0}}, nil, false); err != nil {
				t.Fatalf("insert VM: %v", err)
			}

			if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "sw", NicMac: mac}); err != nil {
				t.Fatalf("detach: %v", err)
			}
			if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "sw",
				Nic: &pb.NetworkAttachment{Name: "lan", Model: tc.to, Mac: mac}}); err != nil {
				t.Fatalf("attach %s under the MAC: %v", tc.to, err)
			}
			entry := loadStoredSpec(t, s, "sw").Network[0]
			if entry.GetModel() != tc.to || (tc.to != "virtio" && entry.GetMtu() != 0) {
				t.Fatalf("the spec entry after the attach is %+v, want model %s with no MTU it cannot take", entry, tc.to)
			}

			check := func(step string) {
				t.Helper()
				x, err := s.virt.DumpXMLInactive("sw")
				if err != nil {
					t.Fatalf("%s: DumpXMLInactive: %v", step, err)
				}
				if got := nicModelsByMAC(t, x)[mac]; got != tc.to {
					t.Fatalf("%s: the NIC renders %q, want %q:\n%s", step, got, tc.to, x)
				}
				if tc.to != "virtio" && strings.Contains(x, "<mtu") {
					t.Fatalf("%s: an %s NIC was given an MTU:\n%s", step, tc.to, x)
				}
			}
			if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "sw", Machine: "q35"}); err != nil {
				t.Fatalf("UpdateVM: %v", err)
			}
			check("UpdateVM")
			_ = s.virt.UndefineDomain("sw", false)
			if err := s.reconcileDomainDefinition(ctx, mustGetVM(t, s, "sw"), nil); err != nil {
				t.Fatalf("reconcileDomainDefinition: %v", err)
			}
			check("reconcile")

			_, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "sw", NicMtu: []*pb.NICMTUUpdate{{Ordinal: 0, Mtu: 9000}}})
			if tc.to == "virtio" {
				if err != nil {
					t.Fatalf("an MTU on the virtio NIC that replaced an e1000 was refused: %v", err)
				}
				if got := loadStoredSpec(t, s, "sw").Network[0].GetMtu(); got != 9000 {
					t.Fatalf("stored MTU %d, want 9000", got)
				}
			} else if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "this NIC is "+tc.to) {
				t.Fatalf("an MTU on the %s NIC that replaced a virtio: err %v, want InvalidArgument naming %s", tc.to, err, tc.to)
			}
		})
	}
}
