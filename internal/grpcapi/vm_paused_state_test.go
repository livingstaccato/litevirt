package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestListVMs_APausedDomainIsPausedNotStopped: a VM the partition pauser
// suspended (docs/design/partition-pause.md §3.2) is active with its RAM kept,
// and resumes where it was. libvirt's coarse state reports it "stopped", the
// same string as shut off, so `lv ls` on that host showed it VM_STOPPED — and
// the list's drift heal for "running in the DB, stopped in libvirt" wrote
// "stopped" into its replicated row. Both read the reason now: a paused domain
// is VM_PAUSED, and its row is left alone.
//
// Mutations, each red: drop the paused-reason read — VM_STOPPED and a
// "stopped" row; map "paused" to VM_STOPPED in vmStateToPB — the state check.
func TestListVMs_APausedDomainIsPausedNotStopped(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	fake := libvirtfake.New()
	s.virt = fake
	for _, n := range []string{"vm-paused"} {
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: n, HostName: s.hostName, State: "running",
			Spec: `{"name":"` + n + `"}`}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	fake.SetState("vm-paused", libvirtfake.StateRunning)
	fake.SetPaused("vm-paused")

	resp, err := s.ListVMs(ctx, &pb.ListVMsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]pb.VMState{}
	for _, vm := range resp.GetVms() {
		got[vm.GetName()] = vm.GetState()
	}
	if got["vm-paused"] != pb.VMState_VM_PAUSED {
		t.Errorf("lv ls shows the paused vm-paused as %s, want VM_PAUSED", got["vm-paused"])
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "vm-paused"); vm == nil || vm.State != "running" {
		t.Errorf("listing rewrote the paused VM's replicated state: %+v", vm)
	}

	insp, err := s.InspectVM(ctx, &pb.InspectVMRequest{Name: "vm-paused"})
	if err != nil {
		t.Fatal(err)
	}
	if insp.GetState() != pb.VMState_VM_PAUSED {
		t.Errorf("lv inspect shows the paused vm-paused as %s, want VM_PAUSED", insp.GetState())
	}
}
