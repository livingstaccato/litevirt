package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ConfirmPartitionResume answers from the voter's OWN replica: the caller's
// host state and the workload's row (host, epoch, incarnation). It is what lets
// a healed host with a stale replica learn that its workload moved, with
// recovery claims off (the default) or after an undrain.
//
// Mutations: report the caller's state from the request instead of the
// replica (always "active") — the fenced case goes red; omit the row's host —
// the moved case goes red; skip the peer check — the unauthenticated call
// passes and goes red.
func TestConfirmPartitionResume_AnswersFromTheVotersReplica(t *testing.T) {
	s := testServer(t)
	ctx := peerCtxFor(t, s, "node-a")
	db := s.db
	bg := context.Background()
	if err := corrosion.InsertVM(bg, db, corrosion.VMRecord{Name: "vm-ha", HostName: "node-a",
		Spec: `{"on_host_failure":"restart-any"}`, State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	vm, _ := corrosion.GetVM(bg, db, "vm-ha")
	inc := corrosion.IncarnationOf(vm.CreatedAt)
	req := &pb.ConfirmPartitionResumeRequest{Workloads: []*pb.PausedWorkload{{Kind: corrosion.ClaimKindVM,
		Name: "vm-ha", OwnerEpoch: vm.OwnerEpoch, Incarnation: inc}}}

	resp, err := s.ConfirmPartitionResume(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetCallerState() != "active" || len(resp.GetViews()) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	v := resp.GetViews()[0]
	if !v.GetLive() || v.GetHostName() != "node-a" || v.GetIncarnation() != inc || v.GetAcceptedDest() != "" {
		t.Fatalf("view = %+v, want node-a's live row of incarnation %s", v, inc)
	}

	// The majority fenced node-a and moved the VM.
	if err := corrosion.UpdateHostState(bg, db, "node-a", "fenced"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateVMHost(bg, db, "vm-ha", "node-b", "running"); err != nil {
		t.Fatal(err)
	}
	resp, err = s.ConfirmPartitionResume(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetCallerState() != "fenced" {
		t.Fatalf("caller state = %q, want fenced", resp.GetCallerState())
	}
	if h := resp.GetViews()[0].GetHostName(); h != "node-b" {
		t.Fatalf("row host = %q, want node-b", h)
	}

	if _, err := s.ConfirmPartitionResume(adminCtx(), req); err == nil {
		t.Fatal("a caller without a host certificate was answered")
	}
}
