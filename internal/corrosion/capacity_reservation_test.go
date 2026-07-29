package corrosion

import (
	"context"
	"testing"
)

func TestCapacityReservationAuthorityClaimCountsBeforeExecutorImport(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	if _, err := ClaimInitialProjectAuthority(ctx, c, "p", "authority"); err != nil {
		t.Fatal(err)
	}
	reservation, err := (ReservationVector{
		Project: "p", ProjectCPU: 2, ProjectMemMiB: 2048,
		TargetHost: "executor", TargetCPU: 2, TargetMemMiB: 2048,
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	op := OperationRecord{
		ID: "op", Method: "CreateVM", Project: "p", ResourceKind: "vm",
		ResourceID: "vm1", OperationKind: string(OpWorkloadCreate),
		RequestHash: "hash", ReservationJSON: reservation,
		DesiredRef: "vm1", VMOwnerEpoch: 1,
	}
	if _, _, err := ClaimCapacityReservation(ctx, c, op, ReservationFacts{
		Project: "p", AuthorityEpoch: 1, AuthorityHost: "authority",
	}); err != nil {
		t.Fatal(err)
	}
	cpu, mem, err := ProjectReserved(ctx, c, "p")
	if err != nil {
		t.Fatal(err)
	}
	if cpu != 2 || mem != 2048 {
		t.Fatalf("pre-import reservation = %d/%d, want 2/2048", cpu, mem)
	}

	if err := AppendOperationStep(ctx, c, OperationStepRecord{
		OperationID: "op", OwnerEpoch: 1, StepName: OpStepDesiredPersisted,
	}); err != nil {
		t.Fatal(err)
	}
	cpu, mem, err = ProjectReserved(ctx, c, "p")
	if err != nil {
		t.Fatal(err)
	}
	if cpu != 0 || mem != 0 {
		t.Fatalf("orphaned post-import reservation = %d/%d, want 0/0", cpu, mem)
	}
}
