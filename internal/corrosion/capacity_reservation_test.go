package corrosion

import (
	"context"
	"strings"
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

func TestInitialForwardedReservationWithWrongAuthorityFailsClosed(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	for _, host := range []HostRecord{
		{Name: "executor", Address: "10.0.0.1", State: "active"},
		{Name: "authority", Address: "10.0.0.2", State: "active"},
	} {
		if err := InsertHost(ctx, c, host); err != nil {
			t.Fatal(err)
		}
	}
	selected, err := DeterministicInitialProjectAuthority("p", []HostRecord{
		{Name: "executor", State: "active"}, {Name: "authority", State: "active"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wrong := "executor"
	if selected == wrong {
		wrong = "authority"
	}
	reservation, err := (ReservationVector{
		Project: "p", ProjectCPU: 2, ProjectMemMiB: 2048,
		TargetHost: "executor", TargetCPU: 2, TargetMemMiB: 2048,
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ImportCapacityReservation(ctx, c, OperationRecord{
		ID: "wrong-authority", Method: "CreateVM", Project: "p",
		ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpWorkloadCreate), RequestHash: "hash",
		ReservationJSON: reservation, DesiredRef: "vm1", VMOwnerEpoch: 1,
	}, ReservationFacts{
		Project: "p", AuthorityEpoch: 1, AuthorityHost: wrong,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := HostReserved(ctx, c, "executor"); err == nil ||
		!strings.Contains(err.Error(), "does not match deterministic holder") {
		t.Fatalf("HostReserved error = %v, want deterministic-holder failure", err)
	}
}
