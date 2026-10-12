package grpcapi

import (
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// fullNIC is a NIC with every field of NetworkAttachment set, so a projection
// that rebuilds the attachment from the NIC rows alone loses something.
func fullNIC() *pb.NetworkAttachment {
	return &pb.NetworkAttachment{
		Name: "lan0", Model: "virtio", Ip: "10.0.0.5", Gateway: "10.0.0.1",
		Mac: "52:54:00:aa:bb:cc", Trunk: []int32{10, 20},
		Ipv6: "fd00::5", Ipv6Gateway: "fd00::1",
		SecurityGroups: []string{"web", "ssh"},
		Queues:         4, RateMbSec: 4,
		SpoofGuard: "off", AllowedAddresses: []string{"10.0.0.9/32"},
		AllowDhcpServer: true, AllowRouterAdvertisement: true, AllowVlanTags: true,
	}
}

func insertVMWithNIC(t *testing.T, s *Server, name string, spec *pb.VMSpec, nic *pb.NetworkAttachment) {
	t.Helper()
	ctx := adminCtx()
	blob, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: name, HostName: "other-host", State: "running", Spec: string(blob),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.InsertInterface(ctx, s.db, corrosion.InterfaceRecord{
		VMName: name, NetworkName: nic.Name, Ordinal: 0, MAC: nic.Mac, IP: nic.Ip,
	}); err != nil {
		t.Fatalf("InsertInterface: %v", err)
	}
}

// F4: InspectVM rebuilt Spec.Network with name/model/MAC only, so rate, queues,
// security groups, trunk, IPv6 and the guard fields vanished from `lv inspect`
// and the UI.
func TestInspectVM_CarriesEveryStoredNICField(t *testing.T) {
	s := testServer(t)
	nic := fullNIC()
	insertVMWithNIC(t, s, "nic-full", &pb.VMSpec{Network: []*pb.NetworkAttachment{nic}}, nic)

	resp, err := s.InspectVM(adminCtx(), &pb.InspectVMRequest{Name: "nic-full"})
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	if len(resp.GetSpec().GetNetwork()) != 1 {
		t.Fatalf("Spec.Network = %d NICs, want 1", len(resp.GetSpec().GetNetwork()))
	}
	got := resp.Spec.Network[0]
	if !proto.Equal(got, nic) {
		t.Errorf("inspected NIC lost stored fields:\n got  %v\n want %v", got, nic)
	}
}

// `lv compose diff` classifies the file against the inspected spec; an
// unchanged file must not report a NIC change (the lab saw nic_rate_0 0→4).
func TestInspectVM_UnchangedComposeFileReportsNoNICChange(t *testing.T) {
	s := testServer(t)
	nic := fullNIC()
	spec := &pb.VMSpec{Network: []*pb.NetworkAttachment{nic}}
	insertVMWithNIC(t, s, "nic-diff", spec, nic)

	resp, err := s.InspectVM(adminCtx(), &pb.InspectVMRequest{Name: "nic-diff"})
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	plan := compose.Classify(proto.Clone(spec).(*pb.VMSpec), resp.Spec, nil)
	if plan.Max() != compose.ActionNoChange {
		t.Errorf("unchanged file plans %v, want no change: %s", plan.Max(), plan.Reasons())
	}
}

// A NIC hot-attached after create has no stored-spec entry; it must still be
// listed (name/model/MAC), and a stored entry must not be applied to it.
func TestInspectVM_HotAttachedNICHasNoSpecFields(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	nic := fullNIC()
	insertVMWithNIC(t, s, "nic-hot", &pb.VMSpec{Network: []*pb.NetworkAttachment{nic}}, nic)
	if err := corrosion.InsertInterface(ctx, s.db, corrosion.InterfaceRecord{
		VMName: "nic-hot", NetworkName: "lan1", Ordinal: 1, MAC: "52:54:00:dd:ee:ff",
	}); err != nil {
		t.Fatalf("InsertInterface: %v", err)
	}
	resp, err := s.InspectVM(ctx, &pb.InspectVMRequest{Name: "nic-hot"})
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	if len(resp.Spec.Network) != 2 {
		t.Fatalf("Spec.Network = %d, want 2", len(resp.Spec.Network))
	}
	hot := resp.Spec.Network[1]
	if hot.Name != "lan1" || hot.RateMbSec != 0 || hot.Queues != 0 || len(hot.Trunk) != 0 || hot.SpoofGuard != "" {
		t.Errorf("hot-attached NIC picked up spec fields: %v", hot)
	}
}
