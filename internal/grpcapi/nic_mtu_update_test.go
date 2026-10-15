package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

const (
	mtuMAC0 = "52:54:00:00:10:01"
	mtuMAC1 = "52:54:00:00:10:02" // hot-plugged: in vm_interfaces, not in the spec
)

// mtuVM is a VM "m" whose spec lists one NIC (lan) and whose host also has a
// hot-plugged second one (lan2), both bridges at 9000.
func mtuVM(t *testing.T, state string, gate *mtuGate) (*Server, *libvirtfake.Fake, context.Context) {
	t.Helper()
	s := reconfigServer(t)
	s.SetReleaseFeatureGate(gate)
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetBridgeMTU("lan", 9000)
	fake.SetBridgeMTU("lan2", 9000)
	ctx := adminCtx()
	spec := &pb.VMSpec{Name: "m", Cpu: 2, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{{Name: "lan", Model: "virtio", Mac: mtuMAC0}}}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "m", HostName: s.hostName, State: state,
		CPUActual: 2, MemActual: 512, Spec: seedSpecJSON(t, spec)},
		[]corrosion.InterfaceRecord{
			{VMName: "m", NetworkName: "lan", MAC: mtuMAC0, Ordinal: 0},
			{VMName: "m", NetworkName: "lan2", MAC: mtuMAC1, Ordinal: 1},
		}, nil); err != nil {
		t.Fatal(err)
	}
	x, err := lv.GenerateDomainXML(lv.VMConfig{Name: "m", CPU: 2, MemoryMiB: 512, Networks: []lv.NetworkConfig{
		{Bridge: "lan", Model: "virtio", MAC: mtuMAC0}, {Bridge: "lan2", Model: "virtio", MAC: mtuMAC1}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(x); err != nil {
		t.Fatal(err)
	}
	if state == "running" {
		fake.SetState("m", libvirtfake.StateRunning)
	}
	return s, fake, ctx
}

func mtuReq(updates ...*pb.NICMTUUpdate) *pb.UpdateVMRequest {
	return &pb.UpdateVMRequest{Name: "m", NicMtu: updates}
}

// interfaceMTU is the <mtu size> of the NIC with mac in x, 0 when it has none.
func interfaceMTU(t *testing.T, x, mac string) int {
	t.Helper()
	for _, n := range lv.InterfaceMTUs(x) {
		if strings.EqualFold(n.MAC, mac) {
			return n.MTU
		}
	}
	return 0
}

// `lv update --nic-mtu` stores the MTU in the spec and renders it into the
// definition: a redefine-class change, applied to a stopped VM. A NIC the
// stored spec does not list (hot-plugged) gets its entry, made from its
// interface record, and 0 removes an MTU again.
//
// Mutations: drop the spec write of the MTU — the stored checks go red; skip
// making the entry for an unlisted NIC — the hot-plugged case goes red.
func TestUpdateVM_NICMTU(t *testing.T) {
	s, fake, ctx := mtuVM(t, "stopped", newMTUGate(t, true))
	if !requestsHardwareTuning(mtuReq(&pb.NICMTUUpdate{Ordinal: 0, Mtu: 9000})) {
		t.Error("an MTU update does not count as a redefine")
	}
	if _, err := s.UpdateVM(ctx, mtuReq(&pb.NICMTUUpdate{Ordinal: 0, Mtu: 9000}, &pb.NICMTUUpdate{Ordinal: 1, Mtu: compose.NICMTUBridge})); err != nil {
		t.Fatalf("UpdateVM: %v", err)
	}
	spec := loadStoredSpec(t, s, "m")
	if len(spec.Network) != 2 || spec.Network[0].GetMtu() != 9000 || spec.Network[1].GetMtu() != compose.NICMTUBridge {
		t.Fatalf("stored network = %+v, want 9000 on NIC 0 and bridge on the hot-plugged NIC 1", spec.Network)
	}
	if n := spec.Network[1]; n.GetName() != "lan2" || n.GetMac() != mtuMAC1 {
		t.Errorf("the hot-plugged NIC's new entry = %+v, want lan2 / %s from its NIC record", n, mtuMAC1)
	}
	x, _ := fake.DumpXMLInactive("m")
	if interfaceMTU(t, x, mtuMAC0) != 9000 || interfaceMTU(t, x, mtuMAC1) != 9000 {
		t.Errorf("the definition does not carry both MTUs:\n%s", x)
	}
	if _, err := s.UpdateVM(ctx, mtuReq(&pb.NICMTUUpdate{Ordinal: 0, Mtu: 0})); err != nil {
		t.Fatalf("UpdateVM 0=0: %v", err)
	}
	if got := loadStoredSpec(t, s, "m").Network[0].GetMtu(); got != 0 {
		t.Errorf("0=0 left mtu %d", got)
	}
	if x, _ := fake.DumpXMLInactive("m"); interfaceMTU(t, x, mtuMAC0) != 0 {
		t.Errorf("0=0 left the <mtu> in the definition:\n%s", x)
	}
}

// A running VM is refused without --restart-if-needed, before anything is
// stopped; an MTU its bridge does not equal is refused before the stop even
// with it; and before the latch the update is refused naming nic_mtu, with
// nothing written.
//
// Mutations: drop the up-front bridge check — the mismatch case stops the VM
// and goes red; drop the entry-node refusal and the owner grant — the
// unlatched case goes red.
func TestUpdateVM_NICMTURefusals(t *testing.T) {
	s, fake, ctx := mtuVM(t, "running", newMTUGate(t, true))
	_, err := s.UpdateVM(ctx, mtuReq(&pb.NICMTUUpdate{Ordinal: 0, Mtu: 9000}))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "--restart-if-needed") {
		t.Errorf("running VM without --restart-if-needed: %v", err)
	}
	yes := true
	req := mtuReq(&pb.NICMTUUpdate{Ordinal: 0, Mtu: 1500})
	req.AllowRestart = &yes
	_, err = s.UpdateVM(ctx, req)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "NIC 0 MTU 1500 does not match bridge lan MTU 9000 on host test-host") {
		t.Errorf("mismatched MTU with --restart-if-needed: %v", err)
	}
	if st, _ := fake.RawState("m"); st != libvirtfake.StateRunning {
		t.Errorf("a refused update left the VM %v, want it still running", st)
	}
	for _, bad := range []*pb.NICMTUUpdate{{Ordinal: 0, Mtu: 70000}, {Ordinal: 5, Mtu: 9000}} {
		if _, err := s.UpdateVM(ctx, mtuReq(bad)); err == nil {
			t.Errorf("update %+v accepted", bad)
		}
	}

	un, _, uctx := mtuVM(t, "stopped", newMTUGate(t, false))
	_, err = un.UpdateVM(uctx, mtuReq(&pb.NICMTUUpdate{Ordinal: 0, Mtu: 9000}))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), string(capabilities.FeatureNICMTU)) {
		t.Errorf("before the latch: %v", err)
	}
	if got := loadStoredSpec(t, un, "m").Network[0].GetMtu(); got != 0 {
		t.Errorf("a refused update stored mtu %d", got)
	}
	// Removing an MTU sets nothing: it is not refused before the latch.
	if _, err := un.UpdateVM(uctx, mtuReq(&pb.NICMTUUpdate{Ordinal: 0, Mtu: 0})); err != nil {
		t.Errorf("0=0 before the latch: %v", err)
	}
}
