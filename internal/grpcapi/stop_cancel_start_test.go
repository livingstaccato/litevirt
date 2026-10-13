package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// heldVMNoDomain is heldVM with no domain defined, as a start deferred
// before its define (storage that does not answer) leaves it.
func heldVMNoDomain(t *testing.T, s *Server, state string) string {
	t.Helper()
	copyPath := heldVM(t, s, state)
	if err := s.virt.(*libvirtfake.Fake).UndefineDomain("vm1", false); err != nil {
		t.Fatal(err)
	}
	return copyPath
}

func noStoppedEvent(t *testing.T, s *Server, what string) {
	t.Helper()
	evs, _ := corrosion.ListVMEvents(context.Background(), s.db, "vm1", 50, "")
	for _, e := range evs {
		if e.Type == "vm.stopped" {
			t.Fatalf("%s: a refused stop recorded %+v", what, e)
		}
	}
}

// Lab 2 F-1: a stop of a pending or starting VM whose domain does not exist
// (the real dead-NFS deferral) answered Internal "Domain not found". Without
// --force it is now the FailedPrecondition of a VM being started, and says
// --force cancels the start. Nothing is changed.
//
// Mutations: domain-not-found not read as "not running" — Internal: red. The
// --force hint dropped — red.
func TestStopVM_AStartWithNoDomainRefusesAPlainStopNamingForce(t *testing.T) {
	for _, state := range []string{"pending", "starting"} {
		s := hotplugDiskServer(t)
		copyPath := heldVMNoDomain(t, s, state)
		_, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "vm1"})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "being started") ||
			!strings.Contains(err.Error(), "lv stop --force vm1") {
			t.Fatalf("%s: stop = %v, want FailedPrecondition saying it is being started and that --force cancels it", state, err)
		}
		heldUntouched(t, s, state, copyPath)
		noStoppedEvent(t, s, state)
	}
}

// The ruling on F-1, "cancel a stuck start": with --force, a stop of a
// pending or starting VM with no domain cancels the start. The row is
// stopped/operator-stop (so no start path starts it), the vm.stopped event
// says the start was cancelled, and the copy a failover set aside for it
// stays held (review M6): it cannot be removed by name.
//
// Mutations: the cancel not recorded (RecordStartCancelled skipped) — the copy
// is no longer held: red. The event not saying the start was cancelled — red.
// --force ignored — FailedPrecondition: red.
func TestStopVM_ForceCancelsAStartWithNoDomainAndKeepsTheHold(t *testing.T) {
	for _, state := range []string{"pending", "starting"} {
		s := hotplugDiskServer(t)
		copyPath := heldVMNoDomain(t, s, state)
		if _, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "vm1", Force: true}); err != nil {
			t.Fatalf("%s: forced stop of a start with no domain: %v", state, err)
		}
		vm, err := corrosion.GetVM(context.Background(), s.db, "vm1")
		if err != nil || vm == nil || vm.State != "stopped" || vm.StateDetail != "operator-stop" {
			t.Fatalf("%s: row %+v (%v), want stopped/operator-stop", state, vm, err)
		}
		if d := stoppedEventDetail(t, s, "vm1"); !strings.Contains(d, "start cancelled") {
			t.Fatalf("%s: the vm.stopped event %q does not say the start was cancelled", state, d)
		}
		copies, err := health.ListSupersededDisks(context.Background(), s.db, s.dataDir)
		if err != nil || len(copies) != 1 || copies[0].Path != copyPath || copies[0].Held == "" {
			t.Fatalf("%s: copies %+v (%v), want %s still held", state, copies, err, copyPath)
		}
		if _, err := health.RemoveSupersededDisks(context.Background(), s.db, s.dataDir, []string{copyPath}); err == nil {
			t.Fatalf("%s: the copy of a cancelled start was removed by name", state)
		}
		// The start lease is released: a later start is not locked out.
		holder := health.OperatorStartLockHolder(s.hostName)
		if by, err := health.TryVMStartLease(context.Background(), s.db, holder, "vm1", time.Now()); err != nil || by != holder {
			t.Fatalf("%s: start lease after the cancel held by %q (%v)", state, by, err)
		}
		health.ReleaseVMStartLease(context.Background(), s.db, holder, "vm1")
	}
}

// A cancel is refused, changing nothing, while a start is in flight (another
// holder has the VM's start lease) and for a failover's proof-gated start.
//
// Mutations: the lease not taken — the stop succeeds under a start in
// flight: red. The proof-gated start cancelled — red.
func TestStopVM_ForceDoesNotCancelAStartInFlightOrAFailoversStart(t *testing.T) {
	s := hotplugDiskServer(t)
	copyPath := heldVMNoDomain(t, s, "starting")
	if by, err := health.TryVMStartLease(context.Background(), s.db, s.hostName, "vm1", time.Now()); err != nil || by != s.hostName {
		t.Fatalf("setup lease: %q %v", by, err)
	}
	_, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "vm1", Force: true})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "in flight") {
		t.Fatalf("forced stop under a start in flight = %v, want FailedPrecondition", err)
	}
	heldUntouched(t, s, "starting", copyPath)
	noStoppedEvent(t, s, "start in flight")

	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm2", HostName: "other-host", State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.WriteVMRescheduleProof(ctx, s.db, corrosion.ActionProof{
		ID: "p-1", Action: corrosion.ActionReschedule, TargetKind: "vm", TargetName: "vm2", DestHost: s.hostName,
		Coordinator: "coord-1", LeaseHolder: "coord-1", QuorumLive: 3, QuorumNeeded: 2,
	}, "vm2", s.hostName); err != nil {
		t.Fatal(err)
	}
	_, err = s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "vm2", Force: true})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "p-1") {
		t.Fatalf("forced stop of a proof-gated start = %v, want FailedPrecondition naming the action", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "vm2"); vm == nil || vm.State != "pending" || vm.PendingActionID != "p-1" {
		t.Fatalf("a refused cancel changed the row: %+v", vm)
	}
}
