package grpcapi

import (
	"context"
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
	if len(nic.SecurityGroups) > 0 {
		if err := corrosion.SetInterfaceSecurityGroups(ctx, s.db, name, nic.Name, nic.SecurityGroups); err != nil {
			t.Fatalf("SetInterfaceSecurityGroups: %v", err)
		}
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

// I1: the guard the firewall enforces is the nic_guards row, which SetNICGuard
// changes without touching the spec. Inspect shows the live row, not the guard
// the NIC was created with.
func TestInspectVM_ShowsTheLiveNICGuardNotTheCreateTimeOne(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	nic := &pb.NetworkAttachment{Name: "lan", Mac: "52:54:00:00:00:01", Ip: "10.0.0.5", SpoofGuard: "on"}
	blob, _ := json.Marshal(&pb.VMSpec{Network: []*pb.NetworkAttachment{nic}})
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "web", HostName: s.hostName, Spec: string(blob), State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "web", NetworkName: "lan", MAC: nic.Mac, IP: nic.Ip}}, nil); err != nil {
		t.Fatal(err)
	}
	admin := adminCtxWithEngine(t, s)
	if _, err := s.SetNICGuard(admin, &pb.SetNICGuardRequest{VmName: "web", NetworkName: "lan", Mode: "off",
		AllowedAddresses: []string{"10.0.0.250"}, AllowDhcpServer: true}); err != nil {
		t.Fatalf("SetNICGuard: %v", err)
	}
	resp, err := s.InspectVM(admin, &pb.InspectVMRequest{Name: "web"})
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	got := resp.Spec.Network[0]
	if got.SpoofGuard != "off" || len(got.AllowedAddresses) != 1 || got.AllowedAddresses[0] != "10.0.0.250" || !got.AllowDhcpServer {
		t.Errorf("inspect shows the create-time guard, not the live one: %v", got)
	}
}

// I2: unbinding every group is a binding of none; the stale spec groups must
// not come back.
func TestInspectVM_AnEmptiedSecurityGroupBindingShowsNoGroups(t *testing.T) {
	s := testServer(t)
	nic := fullNIC()
	insertVMWithNIC(t, s, "sg-empty", &pb.VMSpec{Network: []*pb.NetworkAttachment{nic}}, nic)
	if err := corrosion.SetInterfaceSecurityGroups(adminCtx(), s.db, "sg-empty", "lan0", nil); err != nil {
		t.Fatal(err)
	}
	resp, err := s.InspectVM(adminCtx(), &pb.InspectVMRequest{Name: "sg-empty"})
	if err != nil {
		t.Fatal(err)
	}
	if sgs := resp.Spec.Network[0].SecurityGroups; len(sgs) != 0 {
		t.Errorf("security groups = %v after an empty binding, want none", sgs)
	}
}

// m2: a row binding that differs from the spec wins.
func TestInspectVM_TheRowSecurityGroupBindingWinsOverTheSpec(t *testing.T) {
	s := testServer(t)
	nic := fullNIC()
	insertVMWithNIC(t, s, "sg-row", &pb.VMSpec{Network: []*pb.NetworkAttachment{nic}}, nic)
	if err := corrosion.SetInterfaceSecurityGroups(adminCtx(), s.db, "sg-row", "lan0", []string{"db"}); err != nil {
		t.Fatal(err)
	}
	resp, _ := s.InspectVM(adminCtx(), &pb.InspectVMRequest{Name: "sg-row"})
	if sgs := resp.Spec.Network[0].SecurityGroups; len(sgs) != 1 || sgs[0] != "db" {
		t.Errorf("security groups = %v, want [db]", sgs)
	}
}

// m1: a legacy spec with no MACs matches by ordinal; a NIC attached after the
// original was detached does not inherit the detached NIC's settings.
func TestInspectVM_LegacyMACLessSpecMatchesByOrdinal(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	spec := &pb.VMSpec{Network: []*pb.NetworkAttachment{
		{Name: "lan0", RateMbSec: 4}, {Name: "lan1", RateMbSec: 9},
	}}
	blob, _ := json.Marshal(spec)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "legacy", HostName: "other-host", State: "running", Spec: string(blob)}, nil, nil); err != nil {
		t.Fatal(err)
	}
	for i, mac := range []string{"52:54:00:00:00:a1", "52:54:00:00:00:a2"} {
		if err := corrosion.InsertInterface(ctx, s.db, corrosion.InterfaceRecord{VMName: "legacy", NetworkName: []string{"lan0", "lan1"}[i], Ordinal: i, MAC: mac}); err != nil {
			t.Fatal(err)
		}
	}
	resp, _ := s.InspectVM(ctx, &pb.InspectVMRequest{Name: "legacy"})
	if len(resp.Spec.Network) != 2 || resp.Spec.Network[0].RateMbSec != 4 || resp.Spec.Network[1].RateMbSec != 9 {
		t.Fatalf("MAC-less entries not matched by ordinal: %v", resp.Spec.Network)
	}
	// Detach the lan0 NIC and attach a different one on lan0 at the next
	// ordinal: it has no spec entry, and must not take the detached NIC's.
	if err := corrosion.SoftDeleteInterfaceByMAC(ctx, s.db, "legacy", "52:54:00:00:00:a1"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertInterface(ctx, s.db, corrosion.InterfaceRecord{VMName: "legacy", NetworkName: "lan0", Ordinal: 2, MAC: "52:54:00:00:00:a3"}); err != nil {
		t.Fatal(err)
	}
	resp, _ = s.InspectVM(ctx, &pb.InspectVMRequest{Name: "legacy"})
	for _, n := range resp.Spec.Network {
		switch n.Mac {
		case "52:54:00:00:00:a3":
			if n.RateMbSec != 0 {
				t.Errorf("a re-attached NIC inherited the detached NIC's rate: %v", n)
			}
		case "52:54:00:00:00:a2":
			if n.RateMbSec != 9 {
				t.Errorf("the surviving NIC lost its entry: %v", n)
			}
		}
	}
}
