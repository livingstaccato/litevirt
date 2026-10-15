package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// migrantVM is VM "mv" with three NICs: an explicit 9000, none, and a
// `bridge` one; its live definition carries what each rendered here.
func migrantVM(t *testing.T) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s := reconfigServer(t)
	s.dataDir = t.TempDir()
	fake := s.virt.(*libvirtfake.Fake)
	spec := &pb.VMSpec{Name: "mv", Cpu: 1, MemoryMib: 512, Network: []*pb.NetworkAttachment{
		{Name: "lan", Mac: "52:54:00:00:20:01", Mtu: 9000},
		{Name: "mgmt", Mac: "52:54:00:00:20:02"},
		{Name: "jumbo", Mac: "52:54:00:00:20:03", Mtu: compose.NICMTUBridge},
	}}
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "mv", HostName: s.hostName, State: "running",
		CPUActual: 1, MemActual: 512, Spec: seedSpecJSON(t, spec)},
		[]corrosion.InterfaceRecord{
			{VMName: "mv", NetworkName: "lan", MAC: "52:54:00:00:20:01", Ordinal: 0},
			{VMName: "mv", NetworkName: "mgmt", MAC: "52:54:00:00:20:02", Ordinal: 1},
			{VMName: "mv", NetworkName: "jumbo", MAC: "52:54:00:00:20:03", Ordinal: 2},
		}, nil); err != nil {
		t.Fatal(err)
	}
	fake.SetState("mv", libvirtfake.StateRunning)
	fake.SetActiveXML("mv", `<domain type='kvm'><name>mv</name><devices>
<interface type='bridge'><mac address='52:54:00:00:20:01'/><source bridge='lan'/><model type='virtio'/><mtu size='9000'/></interface>
<interface type='bridge'><mac address='52:54:00:00:20:02'/><source bridge='mgmt'/><model type='virtio'/></interface>
<interface type='bridge'><mac address='52:54:00:00:20:03'/><source bridge='jumbo'/><model type='virtio'/><mtu size='9000'/></interface>
</devices></domain>`)
	return s, fake
}

// The source sends, for each NIC that carries an MTU, the value its live
// definition RESOLVED (a `bridge` NIC included, at what its bridge had here),
// with the NIC's network and ordinal. A VM whose spec sets no MTU sends none.
//
// Mutation: send the stored spec's value instead of the live definition's —
// the bridge NIC goes out as 1 and the test goes red.
func TestNICMTUExpectations_FromTheLiveDefinition(t *testing.T) {
	s, _ := migrantVM(t)
	got, err := s.nicMTUExpectations(adminCtx(), "mv")
	if err != nil {
		t.Fatal(err)
	}
	want := []*pb.NICMTUExpectation{{Network: "lan", Mtu: 9000, Ordinal: 0}, {Network: "jumbo", Mtu: 9000, Ordinal: 2}}
	if len(got) != len(want) {
		t.Fatalf("expectations = %v, want %v", got, want)
	}
	for i := range want {
		if !proto.Equal(got[i], want[i]) {
			t.Errorf("expectation %d = %v, want %v", i, got[i], want[i])
		}
	}
	plain := reconfigServer(t)
	insertTestVMWithSpec(t, adminCtx(), plain.db, "p", plain.hostName, "running", seedSpecJSON(t, &pb.VMSpec{Name: "p",
		Network: []*pb.NetworkAttachment{{Name: "lan"}}}))
	if got, err := plain.nicMTUExpectations(adminCtx(), "p"); err != nil || len(got) != 0 {
		t.Errorf("a VM with no MTU: %v, %v; want nothing sent", got, err)
	}
}

// The target answers nic_mtu_problem for each NIC whose resolved MTU its
// bridge does not equal — a `bridge` NIC resolved at 9000 against a 1500
// target included — in the create's words, and creates nothing; an empty
// field is never a problem.
//
// Mutations: drop the call from EnsureDisks — the mismatch case goes red;
// accept a smaller target bridge — red.
func TestEnsureDisks_NICMTUProblem(t *testing.T) {
	s, fake := migrantVM(t)
	fake.SetBridgeMTU("lan", 9000)
	fake.SetBridgeMTU("jumbo", 1500)
	stub := s.dataDir + "/disks/mv/root.qcow2"
	resp, err := s.EnsureDisks(adminCtx(), &pb.EnsureDisksRequest{VmName: "mv",
		Disks:  []*pb.DiskStub{{Path: stub}},
		NicMtu: []*pb.NICMTUExpectation{{Network: "lan", Mtu: 9000, Ordinal: 0}, {Network: "jumbo", Mtu: 9000, Ordinal: 2}}})
	if err != nil {
		t.Fatalf("EnsureDisks: %v", err)
	}
	want := "NIC 2 MTU 9000 does not match bridge jumbo MTU 1500 on host test-host (a guest MTU must equal its bridge's)"
	if p := resp.GetNicMtuProblem(); p != want {
		t.Errorf("nic_mtu_problem = %q, want %q", p, want)
	}
	if len(resp.GetCreatedPaths()) != 0 {
		t.Errorf("a refused target created %v", resp.GetCreatedPaths())
	}
	fake.SetBridgeMTU("jumbo", 9000)
	if resp, err := s.EnsureDisks(adminCtx(), &pb.EnsureDisksRequest{VmName: "mv",
		NicMtu: []*pb.NICMTUExpectation{{Network: "jumbo", Mtu: 9000, Ordinal: 2}}}); err != nil || resp.GetNicMtuProblem() != "" {
		t.Errorf("matched: %v, %v", resp.GetNicMtuProblem(), err)
	}
	if resp, err := s.EnsureDisks(adminCtx(), &pb.EnsureDisksRequest{VmName: "mv"}); err != nil || resp.GetNicMtuProblem() != "" {
		t.Errorf("no expectations: %v, %v", resp.GetNicMtuProblem(), err)
	}
}

// The source turns a target's answer into a refusal, before anything moves;
// an empty answer (an older target, or no problem) refuses nothing.
func TestNICMTURefusal(t *testing.T) {
	err := nicMTURefusal("mv", "node-b", "NIC 0 MTU 9000 does not match bridge lan MTU 1500 on host node-b (a guest MTU must equal its bridge's)")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), `"mv"`) || !strings.Contains(err.Error(), "bridge lan MTU 1500 on host node-b") {
		t.Errorf("refusal = %v", err)
	}
	if err := nicMTURefusal("mv", "node-b", ""); err != nil {
		t.Errorf("no problem: %v", err)
	}
}
