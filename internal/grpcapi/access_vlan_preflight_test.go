package grpcapi

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/network"
)

// refusingPreflight is a NIC preflight that records what it is asked and
// refuses every access-port NIC, as network.RunPreFlight does on a bridge
// with vlan_filtering off.
type refusingPreflight struct {
	mu     sync.Mutex
	asked  []network.PreFlightCheck
	refuse bool
}

func (p *refusingPreflight) run(checks []network.PreFlightCheck) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.asked = append(p.asked, checks...)
	for _, c := range checks {
		if p.refuse && c.AccessVLAN != 0 {
			return errors.New(`bridge "` + c.Bridge + `" does not filter VLANs`)
		}
	}
	return nil
}

func (p *refusingPreflight) accessAsked() []network.PreFlightCheck {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []network.PreFlightCheck
	for _, c := range p.asked {
		if c.AccessVLAN != 0 {
			out = append(out, c)
		}
	}
	return out
}

// A create whose access-port NIC (trunk: with one VLAN) is on a bridge that
// does not filter VLANs is refused before its domain is defined, with no VM
// row left; a trunk NIC (two or more VLANs) is not judged, and passes.
//
// Mutation: drop the nicPreflight call from CreateVM's NIC loop — red (the
// create succeeds and defines the domain).
func TestCreateVM_AccessVLANOnANonFilteringBridgeIsRefused(t *testing.T) {
	s, fake := provableCreateServer(t)
	s.SetBridgeEnsure(func(string) error { return nil })
	pf := &refusingPreflight{refuse: true}
	s.SetNetPreflight(pf.run)

	req := disklessCreateRequest("acc")
	req.Spec.Network[0].Trunk = []int32{30}
	_, err := s.CreateVM(adminCtx(), req)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "does not filter VLANs") {
		t.Fatalf("CreateVM with an access VLAN on a non-filtering bridge: %v, want FailedPrecondition naming the bridge", err)
	}
	if got := pf.accessAsked(); len(got) != 1 || got[0].Bridge != "lo" || got[0].AccessVLAN != 30 {
		t.Fatalf("preflight asked %+v, want lo on VLAN 30", got)
	}
	for _, e := range fake.EventLog() {
		if e.Op == "define" && e.Domain == "acc" {
			t.Fatalf("the refused create defined its domain: %+v", e)
		}
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "acc"); vm != nil {
		t.Fatalf("the refused create left a VM row: %+v", vm)
	}

	// A trunk is not an access port: not refused.
	req = disklessCreateRequest("trk")
	req.Spec.Network[0].Trunk = []int32{100, 101}
	if _, err := s.CreateVM(adminCtx(), req); err != nil {
		t.Fatalf("CreateVM with a trunk NIC: %v", err)
	}
}

// Every start path checks an access-port NIC's bridge on the host that starts
// it (PrepareHardwareForStart): a stopped VM whose bridge here does not filter
// VLANs is refused and its domain stays down; once it does, the VM starts.
//
// Mutation: drop accessVLANStartPreflight from PrepareHardwareForStart — red.
func TestStartVM_AccessVLANOnANonFilteringBridgeIsRefused(t *testing.T) {
	s := hotplugDiskServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "vm1", "test-host", "stopped", seedSpecJSON(t, &pb.VMSpec{
		Name: "vm1", Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{
			{Name: "accnet", Mac: "52:54:00:aa:00:01", Trunk: []int32{30}},
			{Name: "trknet", Mac: "52:54:00:aa:00:02", Trunk: []int32{100, 101}},
		},
	}))
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetState("vm1", libvirtfake.StateDefined)
	pf := &refusingPreflight{refuse: true}
	s.SetNetPreflight(pf.run)

	_, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "does not filter VLANs") {
		t.Fatalf("StartVM: %v, want FailedPrecondition naming the bridge", err)
	}
	if st, _ := fake.DomainState("vm1"); st == "running" {
		t.Fatal("the refused start started the domain")
	}
	if got := pf.accessAsked(); len(got) != 1 || got[0].Bridge != network.FlatBridgeName("accnet") || got[0].AccessVLAN != 30 {
		t.Fatalf("preflight asked %+v, want only the access NIC's bridge on VLAN 30", got)
	}

	pf.refuse = false
	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("StartVM once the bridge filters VLANs: %v", err)
	}
	if st, _ := fake.DomainState("vm1"); st != "running" {
		t.Fatalf("domain state %q, want running", st)
	}
}
