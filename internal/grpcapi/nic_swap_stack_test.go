package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/network"
)

// A NIC of a stack VM swapped under the same MAC (detach, then attach as
// e1000) leaves the stored spec as the compose file wrote it. The compose
// plan diffs the file against that spec, and a NIC model difference is a
// network-topology change: had the attach rewritten the entry, the next
// `lv compose up` of the unchanged file would plan a recreate, which replaces
// the VM's disks. The domain is still defined with the attached model, and
// the old NIC's MTU and queues are left off at render (an e1000 cannot take
// them), so the attach's own define, UpdateVM and a reconcile all succeed.
// An `lv update --nic-mtu` on that NIC is refused as e1000.
//
// Mutations: rewrite the spec on a stack VM too — the plan goes red
// (recreate); keep the old NIC's MTU at render — UpdateVM is refused
// ("an MTU needs the virtio model").
func TestNICSwap_AStackVMKeepsItsComposeSpec(t *testing.T) {
	const mac = "52:54:00:aa:00:41"
	f, err := compose.ParseBytes([]byte(`name: web
networks:
  lan: {}
vms:
  app:
    image: img
    cpu: 2
    memory: 512
    network:
      - name: lan
        model: virtio
        mac: "` + mac + `"
        mtu: 9000
        queues: 4
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	def := f.VMs["app"]
	desired, err := compose.BuildVMSpec("app", "app", &def, f)
	if err != nil {
		t.Fatalf("BuildVMSpec: %v", err)
	}
	netName := desired.Network[0].Name

	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	s.SetReleaseFeatureGate(newMTUGate(t, true))
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetBridgeMTU(network.FlatBridgeName(netName), 9000)
	ctx := adminCtx()
	vm := corrosion.VMRecord{Name: "app", StackName: "web", HostName: "test-host", State: "stopped",
		CPUActual: 2, MemActual: 512, Spec: seedSpecJSON(t, desired)}
	if err := corrosion.InsertVMWithHardware(ctx, s.db, vm,
		[]corrosion.InterfaceRecord{{VMName: "app", NetworkName: netName, Ordinal: 0, MAC: mac}}, nil,
		[]corrosion.NICRecord{{VMName: "app", ID: corrosion.DeterministicNICID("app", mac),
			NetworkName: netName, Model: "virtio", MAC: mac, Ordinal: 0}}, nil, false); err != nil {
		t.Fatalf("insert VM: %v", err)
	}

	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "app", NicMac: mac}); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "app",
		Nic: &pb.NetworkAttachment{Name: netName, Model: "e1000", Mac: mac}}); err != nil {
		t.Fatalf("attach e1000 under the MAC: %v", err)
	}

	stored := loadStoredSpec(t, s, "app")
	plan, err := compose.Build(f, []compose.CurrentVM{{Name: "app", State: "stopped", HostName: "test-host", Spec: stored}})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	for _, op := range plan.Ops {
		if op.VMName == "app" && (op.Kind != compose.OpNoChange || len(op.Change.RecreateReasons) != 0) {
			t.Fatalf("the unchanged compose file plans %s for the VM (%s), want no change; stored NIC %+v",
				op.Kind, op.Detail, stored.Network[0])
		}
	}

	check := func(step string) {
		t.Helper()
		x, err := s.virt.DumpXMLInactive("app")
		if err != nil {
			t.Fatalf("%s: DumpXMLInactive: %v", step, err)
		}
		if got := nicModelsByMAC(t, x)[mac]; got != "e1000" {
			t.Fatalf("%s: the NIC renders %q, want e1000:\n%s", step, got, x)
		}
		if strings.Contains(x, "<mtu") || strings.Contains(x, "queues=") {
			t.Fatalf("%s: the e1000 NIC was given the old NIC's tuning:\n%s", step, x)
		}
	}
	check("attach")
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "app", Machine: "pc"}); err != nil {
		t.Fatalf("UpdateVM: %v", err)
	}
	check("UpdateVM")
	_ = s.virt.UndefineDomain("app", false)
	if err := s.reconcileDomainDefinition(ctx, mustGetVM(t, s, "app"), nil); err != nil {
		t.Fatalf("reconcileDomainDefinition: %v", err)
	}
	check("reconcile")

	_, err = s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "app", NicMtu: []*pb.NICMTUUpdate{{Ordinal: 0, Mtu: 9000}}})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "this NIC is e1000") {
		t.Fatalf("an MTU on the stack VM's e1000 NIC: err %v, want InvalidArgument naming e1000", err)
	}
}
