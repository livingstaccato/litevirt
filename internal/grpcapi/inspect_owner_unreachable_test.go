package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// hangingInspectPeer is an owner that accepted the connection and never
// answers: what a peer cut off by a partition looks like to grpc.NewClient,
// which dials lazily.
type hangingInspectPeer struct{ pb.LiteVirtClient }

func (hangingInspectPeer) InspectVM(ctx context.Context, _ *pb.InspectVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	<-ctx.Done()
	return nil, status.FromContextError(ctx.Err()).Err()
}

// refusingInspectPeer is an owner that answers with an error of its own.
type refusingInspectPeer struct{ pb.LiteVirtClient }

func (refusingInspectPeer) InspectVM(context.Context, *pb.InspectVMRequest, ...grpc.CallOption) (*pb.VM, error) {
	return nil, status.Error(codes.PermissionDenied, "owner refused")
}

// Drill 1 on both labs: `lv inspect` of a VM whose host is cut off, run on the
// majority, hung until the CLI's deadline (dial i/o timeout), because the
// forward to the owner never failed fast and the local fallback was never
// reached. It now answers from this node's replica, within the forward's
// bound, and says so in a response header.
//
// Mutation: forward without a bound (the caller's context only) — the call
// takes the caller's whole deadline and fails with DeadlineExceeded.
func TestInspectVM_OwnerUnreachableAnswersFromTheReplica(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	insertTestVMR2(t, ctx, s.db, "cut-vm", "node-1", "stopped")
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return hangingInspectPeer{}, func() {}, nil
	}
	old := inspectForwardTimeout
	inspectForwardTimeout = 200 * time.Millisecond
	t.Cleanup(func() { inspectForwardTimeout = old })

	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st := &trailerStream{}
	start := time.Now()
	vm, err := s.InspectVM(grpc.NewContextWithServerTransportStream(cctx, st), &pb.InspectVMRequest{Name: "cut-vm"})
	if err != nil {
		t.Fatalf("InspectVM with its owner unreachable: %v (after %s)", err, time.Since(start).Round(time.Millisecond))
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("InspectVM took %s; the forward to an unreachable owner must be bounded", d.Round(time.Millisecond))
	}
	if vm.Name != "cut-vm" || vm.HostName != "node-1" || vm.State != pb.VMState_VM_STOPPED {
		t.Errorf("answer = %s on %s (%v), want this node's record: cut-vm on node-1, stopped", vm.Name, vm.HostName, vm.State)
	}
	note := strings.Join(st.hdr.Get(InspectStaleHeader), " ")
	if !strings.Contains(note, "node-1") {
		t.Errorf("header %s = %q, want a note naming the unreachable owner node-1", InspectStaleHeader, note)
	}
}

// An owner that answers with an error is not unreachable: its answer stands.
func TestInspectVM_OwnerErrorIsReturned(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	insertTestVMR2(t, ctx, s.db, "owned-vm", "node-1", "running")
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return refusingInspectPeer{}, func() {}, nil
	}
	if _, err := s.InspectVM(ctx, &pb.InspectVMRequest{Name: "owned-vm"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("InspectVM = %v, want the owner's PermissionDenied", err)
	}
}
