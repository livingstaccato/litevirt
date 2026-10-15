package grpcapi

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A successful coordinated grow of a VM whose owner epoch is NOT zero — every VM
// a real create makes starts at epoch 1 — must leave no nonterminal host
// reservation behind. The reservation's header is the one BeginVMOperation
// keeps (INSERT OR IGNORE), and CompleteVMOperation writes `completed` at the
// VM's epoch; aggregation reduces by (id, header epoch), so a header written at
// epoch 0 never sees its terminal step and counts against the host forever.
func TestResizeVMLive_GrowAtNonZeroOwnerEpochReleasesHostReservation(t *testing.T) {
	s := coordResizeServer(t)
	ctx := adminCtx()
	seedRunningVM(t, s, "ep", &pb.VMSpec{Name: "ep", Cpu: 2, MaxCpu: 8, MemoryMib: 2048, MinMemoryMib: 1024, MaxMemoryMib: 8192}, 2, 2048)
	if err := s.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 1 WHERE name = 'ep'`); err != nil {
		t.Fatalf("set owner epoch: %v", err)
	}

	if err := s.resizeVMLive(ctx, "ep", &pb.VMSpec{Cpu: 2, MemoryMib: 2560}, "k-ep"); err != nil {
		t.Fatalf("coordinated grow: %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "ep"); vm == nil || vm.ActiveOperationID != "" {
		t.Fatalf("resize did not complete: %+v", vm)
	}
	cpu, mem, err := corrosion.HostReserved(ctx, s.db, "test-host")
	if err != nil {
		t.Fatalf("HostReserved: %v", err)
	}
	if cpu != 0 || mem != 0 {
		t.Fatalf("after a completed resize the host still holds %d vCPU/%d MiB in nonterminal reservations, want 0/0 — "+
			"the resize's reservation outlived its operation", cpu, mem)
	}
	// The header is the workload operation's, written as one: at the VM's
	// epoch, carrying the request hash and idempotency key an idempotent
	// retry is checked against.
	rows, err := s.db.Query(ctx, `SELECT vm_owner_epoch, request_hash, idempotency_key FROM operations
		WHERE resource_id = 'ep' AND method = 'ResizeVMLive' AND deleted_at IS NULL`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("resize header: rows=%d err=%v, want exactly one", len(rows), err)
	}
	if got := rows[0].Int64("vm_owner_epoch"); got != 1 {
		t.Errorf("resize header vm_owner_epoch = %d, want the VM's epoch 1", got)
	}
	if got, want := rows[0].String("request_hash"), resizeRequestHash("ep", 2, 2560); got != want {
		t.Errorf("resize header request_hash = %q, want %q", got, want)
	}
	if got := rows[0].String("idempotency_key"); got != "k-ep" {
		t.Errorf("resize header idempotency_key = %q, want %q", got, "k-ep")
	}
}

// While a grow at a non-zero owner epoch is in flight, its reservation must
// hold — including when the project has an admission authority, where
// aggregation counts a reservation only through the authority facts on its
// `reserved` step at (operation, header epoch). A header moved to the VM's
// epoch with the facts left at epoch 0 holds nothing while the resize runs.
// Recovery then completes the operation at the VM's epoch, which frees it.
func TestResizeVMLive_InFlightGrowAtNonZeroOwnerEpochHoldsUnderProjectAuthority(t *testing.T) {
	s := coordResizeServer(t)
	s.SetProjectAuthorityEnforce(true)
	s.SetGate(fakeServerGate{enforcedTok: map[string]bool{
		capabilities.LiveResizeV1:        true,
		capabilities.OperationProtocolV1: true,
		capabilities.ProjectAuthorityV1:  true,
	}})
	ctx := adminCtx()
	if applied, err := corrosion.ClaimInitialProjectAuthority(ctx, s.db, "_default", "test-host"); err != nil || !applied {
		t.Fatalf("ClaimInitialProjectAuthority: applied=%v err=%v", applied, err)
	}
	seedRunningVM(t, s, "pa", &pb.VMSpec{Name: "pa", Cpu: 2, MaxCpu: 8, MemoryMib: 2048, MinMemoryMib: 1024, MaxMemoryMib: 8192}, 2, 2048)
	if err := s.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 1 WHERE name = 'pa'`); err != nil {
		t.Fatalf("set owner epoch: %v", err)
	}

	f := s.virt.(*libvirtfake.Fake)
	f.FailSetMemory = func(string, int) error { return errors.New("inject balloon failure") }
	if err := s.resizeVMLive(ctx, "pa", &pb.VMSpec{Cpu: 2, MemoryMib: 3072}, "k-pa"); err == nil {
		t.Fatal("expected the memory apply to fail and leave the operation recoverable")
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "pa"); vm == nil || vm.ActiveOperationID == "" {
		t.Fatalf("the resize is not in flight: %+v", vm)
	}
	cpu, mem, err := corrosion.HostReserved(ctx, s.db, "test-host")
	if err != nil {
		t.Fatalf("HostReserved: %v", err)
	}
	if cpu != 0 || mem != 1024 {
		t.Fatalf("an in-flight +1024 MiB grow holds %d vCPU/%d MiB on its host, want 0/1024 — "+
			"the reservation is not attributable to the project's authority at the operation's epoch", cpu, mem)
	}

	f.FailSetMemory = nil
	s.RecoverResourceOperations(ctx)
	if vm, _ := corrosion.GetVM(ctx, s.db, "pa"); vm == nil || vm.ActiveOperationID != "" {
		t.Fatalf("recovery did not complete the resize: %+v", vm)
	}
	if cpu, mem, err = corrosion.HostReserved(ctx, s.db, "test-host"); err != nil || cpu != 0 || mem != 0 {
		t.Fatalf("after recovery completed the resize the host holds %d vCPU/%d MiB (err %v), want 0/0", cpu, mem, err)
	}
}

// A grow refused by its host-capacity verify releases its reservation at the
// operation's epoch. A release written at any other epoch leaves the refused
// claim nonterminal, and it counts against the host forever.
func TestResizeVMLive_RefusedGrowAtNonZeroOwnerEpochReleasesItsReservation(t *testing.T) {
	s := coordResizeServer(t)
	ctx := adminCtx()
	// 4200 MiB: after the default reserve and the VM's 2048 MiB plus overhead,
	// about 1000 MiB is free — far short of the +6144 MiB grow below.
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "test-host", CPUTotal: 64, MemTotal: 4200, State: "HOST_ACTIVE",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	seedRunningVM(t, s, "rf", &pb.VMSpec{Name: "rf", Cpu: 2, MaxCpu: 8, MemoryMib: 2048, MinMemoryMib: 1024, MaxMemoryMib: 8192}, 2, 2048)
	if err := s.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 1 WHERE name = 'rf'`); err != nil {
		t.Fatalf("set owner epoch: %v", err)
	}

	err := s.resizeVMLive(ctx, "rf", &pb.VMSpec{Cpu: 2, MemoryMib: 8192}, "k-rf")
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("a grow that does not fit the host: got %v, want ResourceExhausted", err)
	}
	cpu, mem, err := corrosion.HostReserved(ctx, s.db, "test-host")
	if err != nil {
		t.Fatalf("HostReserved: %v", err)
	}
	if cpu != 0 || mem != 0 {
		t.Fatalf("after a refused grow the host still holds %d vCPU/%d MiB in nonterminal reservations, want 0/0 — "+
			"the refusal's release did not terminate the reservation", cpu, mem)
	}
}
