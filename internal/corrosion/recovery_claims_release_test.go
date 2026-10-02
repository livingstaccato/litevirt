package corrosion

import (
	"errors"
	"testing"
)

// AbandonForeignProofInFlight is the operator's release of a legacy-held claim
// (`lv cluster claim-release`, docs/design/recovery-claims.md §10 item 37). It
// overrides exactly one of AbandonForeignProof's refusals — a proof THIS node
// claimed and left in progress — once the caller has confirmed that nothing
// here runs it. Every other refusal stands, and once it is recorded no runner
// can take the proof again, not even this node resuming its own claim.
//
// Mutations: accept a proof another executor holds — the release abandons a
// proof it cannot speak for; drop the start-checkpoint check from the
// in-flight arm — a promote that may already have started is abandoned; skip
// the incarnation check (proofForeignToTx) on the in-flight arm — this
// incarnation's own pending decision is abandoned.
func TestAbandonForeignProofInFlight(t *testing.T) {
	c, ctx := foreignFixture(t)
	host := c.hostName

	// A's reschedule, claimed here and left in progress; A deleted, B
	// re-created, not pending on it.
	insertBareVM(t, c, "vm-f", host)
	mintVMProof(t, c, "v-stuck", "vm-f", "0")
	if err := ClaimActionProof(ctx, c, "v-stuck", host); err != nil {
		t.Fatal(err)
	}
	if err := DeleteVM(ctx, c, "vm-f"); err != nil {
		t.Fatal(err)
	}
	insertBareVM(t, c, "vm-f", host)
	b := liveVM(t, c, "vm-f")
	keyB := scoped(ClaimKindVM, "vm-f", IncarnationOf(b.CreatedAt), 0)

	if err := c.AbandonForeignProof(ctx, "v-stuck", keyB, "t"); !errors.Is(err, ErrProofNotForeign) {
		t.Fatalf("the bridge's exclusion abandoned a proof in flight here: %v", err)
	}
	if err := c.AbandonForeignProofInFlight(ctx, "v-stuck", keyB, "t"); err != nil {
		t.Fatalf("the release did not abandon the proof left in flight here: %v", err)
	}
	if ok, _ := c.ProofAbandoned(ctx, "v-stuck"); !ok {
		t.Fatal("the release was not recorded")
	}
	// No second runner: not another host, and not this one resuming.
	if err := ClaimActionProofFenced(ctx, c, "v-stuck", host, nil); !errors.Is(err, ErrProofAbandoned) {
		t.Fatalf("this node re-claimed a released proof: %v", err)
	}
	// The plain exclusion now re-signs it: the bridge's next ask excludes it.
	if err := c.AbandonForeignProof(ctx, "v-stuck", keyB, "t"); err != nil {
		t.Fatalf("the bridge's exclusion of a released proof: %v", err)
	}

	// Held by another executor: this node cannot speak for it.
	p := ActionProof{ID: "v-elsewhere", Action: ActionReschedule, TargetKind: ClaimKindVM, TargetName: "vm-f",
		DestHost: host, Coordinator: "coord", OwnerEpoch: "0"}
	if err := WriteActionProof(ctx, c, p); err != nil {
		t.Fatal(err)
	}
	if err := ClaimActionProof(ctx, c, p.ID, "some-other-host"); err != nil {
		t.Fatal(err)
	}
	if err := c.AbandonForeignProofInFlight(ctx, p.ID, keyB, "t"); !errors.Is(err, ErrProofNotForeign) {
		t.Fatalf("a proof another executor holds: %v, want ErrProofNotForeign", err)
	}

	// A promote that recorded its start checkpoint may already be running.
	pr := ActionProof{ID: "p-started", Action: ActionPromote, TargetKind: ClaimKindVM, TargetName: "vm-f",
		DestHost: host, Coordinator: "coord", OwnerEpoch: "0"}
	if err := WriteActionProof(ctx, c, pr); err != nil {
		t.Fatal(err)
	}
	if err := ClaimActionProof(ctx, c, pr.ID, host); err != nil {
		t.Fatal(err)
	}
	if err := AppendProofStepUnlessAbandoned(ctx, c, pr.ID, "start_attempted"); err != nil {
		t.Fatal(err)
	}
	if err := c.AbandonForeignProofInFlight(ctx, pr.ID, keyB, "t"); !errors.Is(err, ErrProofNotForeign) {
		t.Fatalf("a promote past its start checkpoint: %v, want ErrProofNotForeign", err)
	}

	// B's own decision, claimed here: B is pending on it, so it is not foreign.
	mintVMProof(t, c, "v-b", "vm-f", "0")
	if err := ClaimActionProof(ctx, c, "v-b", host); err != nil {
		t.Fatal(err)
	}
	if err := c.AbandonForeignProofInFlight(ctx, "v-b", keyB, "t"); !errors.Is(err, ErrProofNotForeign) {
		t.Fatalf("this incarnation's own in-flight decision: %v, want ErrProofNotForeign", err)
	}
}
