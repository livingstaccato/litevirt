package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
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
		// A pending row is a transfer onto this host, and the record says so
		// (review I-1); the starting one is not (no probe says it is).
		if ev, err := health.StartCancelledOf(context.Background(), s.db, "vm1", s.hostName); err != nil || ev == nil || ev.Transfer != (state == "pending") {
			t.Fatalf("%s: record %+v (%v), want transfer=%v", state, ev, err, state == "pending")
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

// Review I-1: after a forced stop cancelled a start with no domain, `lv start`
// starts the VM again. Its domain was never defined, so the start re-arms the
// row to "starting" and the reconciler's start defines and starts it, as the
// cancelled start would have. The copies stay held until the VM runs, and
// vm_start_cancelled clears once it does.
//
// Mutation: no re-arm (StartVM starts the undefined domain) — Internal
// "domain not found": red.
func TestStartVM_AStartCancelledEarlierIsMadeAgain(t *testing.T) {
	s := hotplugDiskServer(t)
	ctx := context.Background()
	copyPath := heldVMNoDomain(t, s, "starting")
	if err := qcow2.Create(filepath.Join(s.dataDir, "disks", "vm1-root.qcow2"), 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	s.virt.(*libvirtfake.Fake).FailShutdownDomain, s.virt.(*libvirtfake.Fake).FailDestroyDomain = nil, nil
	if _, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "vm1", Force: true}); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("start of a VM whose start was cancelled: %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "vm1"); vm == nil || vm.State != "starting" {
		t.Fatalf("row %+v, want re-armed to starting", vm)
	}
	if copies, err := health.ListSupersededDisks(ctx, s.db, s.dataDir); err != nil || len(copies) != 1 || copies[0].Path != copyPath || copies[0].Held == "" {
		t.Fatalf("copies %+v (%v), want still held while the start is made", copies, err)
	}

	r := health.NewReconciler(s.hostName, s.dataDir, s.db, s.virt.(*libvirtfake.Fake))
	r.ReconcileOnce(ctx)
	if vm, _ := corrosion.GetVM(ctx, s.db, "vm1"); vm == nil || vm.State != "running" {
		t.Fatalf("row %+v after a reconcile pass, want running", vm)
	}
	if active, err := s.virt.DomainIsActive("vm1"); err != nil || !active {
		t.Fatalf("domain active=%v (%v), want running", active, err)
	}
	r.ReconcileOnce(ctx)
	if ev, err := health.StartCancelledOf(ctx, s.db, "vm1", s.hostName); err != nil || ev != nil {
		t.Fatalf("vm_start_cancelled %+v (%v) still open once the VM runs", ev, err)
	}
}

// Re-review m-1: a start of a cancelled start re-arms the row and returns,
// so its capacity reservation is released before the reconciler starts the
// VM. A "starting" row now counts against its host
// (corrosion.SumVMResourcesByHost, as placement counts it), so a concurrent
// start cannot be admitted against the same memory meanwhile.
//
// Mutation: "starting" not counted — the second start is admitted: red.
func TestStartVM_ARearmedStartHoldsItsCapacity(t *testing.T) {
	s := testServerR2(t)
	fake := libvirtfake.New()
	s.virt = fake
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "test-host", Address: "10.0.0.9", State: "active", CPUTotal: 8, MemTotal: 4096,
	}); err != nil {
		t.Fatal(err)
	}
	// Allocatable 4096-1024 = 3072. vm1 (2048) and vm2 (1024), each with its
	// qemu overhead, do not both fit.
	for _, v := range []struct {
		name string
		mem  int
	}{{"vm1", 2048}, {"vm2", 1024}} {
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
			Name: v.name, HostName: "test-host", State: "stopped", StateDetail: "operator-stop", CPUActual: 1, MemActual: v.mem,
			Spec: seedSpecJSON(t, &pb.VMSpec{Name: v.name, Cpu: 1, MemoryMib: int32(v.mem)}),
		}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := fake.DefineDomain(`<domain type='kvm'><name>vm2</name><devices></devices></domain>`); err != nil {
		t.Fatal(err)
	}
	if _, err := health.RecordStartCancelled(ctx, s.db, "test-host", "vm1", "starting", false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("re-armed start of vm1: %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "vm1"); vm == nil || vm.State != "starting" {
		t.Fatalf("vm1 %+v, want re-armed to starting", vm)
	}
	if _, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "vm2"}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("start of vm2 against memory vm1's start holds = %v, want ResourceExhausted", err)
	}
}

