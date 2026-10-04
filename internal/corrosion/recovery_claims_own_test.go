package corrosion

import (
	"testing"
)

// ProofIsPendingDecisionOf tells the legacy-key bridge, from this replica
// alone, that a legacy value it could not exclude is the incarnation's OWN
// pending decision — so ha.claim.legacy_held is not raised for a destination
// that is merely slow to say so (docs/design/recovery-claims.md §10 item 37).
//
// Mutations: drop the incarnation comparison — another incarnation's key
// reads B's pending decision as its own; drop the epoch comparison — a key at
// another epoch does too; drop the spent check — a failed proof the row still
// points at is called pending; drop the token comparison for a container —
// any relocation is called the row's own.
func TestProofIsPendingDecisionOf(t *testing.T) {
	c, ctx := foreignFixture(t)
	host := c.hostName

	// A: pending on v-a; deleted; B re-created, pending on v-b.
	insertBareVM(t, c, "vm-o", host)
	mintVMProof(t, c, "v-a", "vm-o", "0")
	if err := DeleteVM(ctx, c, "vm-o"); err != nil {
		t.Fatal(err)
	}
	insertBareVM(t, c, "vm-o", host)
	b := liveVM(t, c, "vm-o")
	mintVMProof(t, c, "v-b", "vm-o", "0")
	keyB := scoped(ClaimKindVM, "vm-o", IncarnationOf(b.CreatedAt), 0)

	for _, tc := range []struct {
		what  string
		key   ClaimKey
		proof string
		want  bool
	}{
		{"B's own pending decision", keyB, "v-b", true},
		{"A's decision, which B is not pending on", keyB, "v-a", false},
		{"another incarnation's key", scoped(ClaimKindVM, "vm-o", "some-other-incarnation", 0), "v-b", false},
		{"another owner epoch", scoped(ClaimKindVM, "vm-o", IncarnationOf(b.CreatedAt), 1), "v-b", false},
		{"a proof this replica does not hold", keyB, "never-seen", false},
		{"a legacy key", keyB.Legacy(), "v-b", false},
	} {
		got, err := ProofIsPendingDecisionOf(ctx, c, tc.key, tc.proof)
		if err != nil {
			t.Fatalf("%s: %v", tc.what, err)
		}
		if got != tc.want {
			t.Errorf("%s: ProofIsPendingDecisionOf = %v, want %v", tc.what, got, tc.want)
		}
	}

	// Spent while the row still points at it: never runs again, so it is no
	// pending decision of anyone's.
	if err := c.Execute(ctx, `UPDATE runtime_action_proofs SET status = 'failed' WHERE id = 'v-b'`); err != nil {
		t.Fatal(err)
	}
	if got, err := ProofIsPendingDecisionOf(ctx, c, keyB, "v-b"); err != nil || got {
		t.Errorf("a failed proof the row still points at: %v %v, want false", got, err)
	}

	// A container relocation is the row's own while the row carries its token.
	if err := UpsertContainer(ctx, c, ContainerRecord{HostName: host, Name: "ct-o", State: "pending", Image: "alpine",
		RelocateToken: "tok-b"}); err != nil {
		t.Fatal(err)
	}
	ct, _ := GetContainer(ctx, c, host, "ct-o")
	keyC := scoped(ClaimKindContainer, "ct-o", IncarnationOf(ct.CreatedAt), 0)
	for _, p := range []ActionProof{
		{ID: "reloc-b", Action: ActionRelocate, TargetKind: ClaimKindContainer, TargetName: "ct-o", DestHost: host,
			Coordinator: "coord", RelocationToken: "tok-b", OwnerEpoch: "0"},
		{ID: "reloc-a", Action: ActionRelocate, TargetKind: ClaimKindContainer, TargetName: "ct-o", DestHost: host,
			Coordinator: "coord", RelocationToken: "tok-a", OwnerEpoch: "0"},
	} {
		if err := WriteActionProof(ctx, c, p); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := ProofIsPendingDecisionOf(ctx, c, keyC, "reloc-b"); err != nil || !got {
		t.Errorf("the relocation the row carries: %v %v, want true", got, err)
	}
	if got, err := ProofIsPendingDecisionOf(ctx, c, keyC, "reloc-a"); err != nil || got {
		t.Errorf("a relocation the row does not carry: %v %v, want false", got, err)
	}
}
