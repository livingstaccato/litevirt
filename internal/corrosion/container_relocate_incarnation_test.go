package corrosion

import (
	"context"
	"strings"
	"testing"
)

// A relocation moves one incarnation of a container; it does not make a new
// one (docs/design/recovery-claims.md §10 item 37). A recovery claim is keyed
// by the row's created_at, and the relocation is executed by its target
// against the row the relocation wrote.

// TestRelocateContainerWithToken_KeepsTheIncarnation: the target row keeps the
// source's created_at on both relocation shapes.
//
// Mutation: stamp the target afresh (the pre-review `rec.CreatedAt = ""` and
// nowRFC3339 on the guarded shape) — both cases fail.
func TestRelocateContainerWithToken_KeepsTheIncarnation(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name      string
		lifecycle bool
	}{{"pre-epoch upsert", false}, {"guarded insert", true}} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestDB(t)
			seedRelocatableContainer(t, c, "host-a", "web", tc.lifecycle)
			src, err := GetContainer(ctx, c, "host-a", "web")
			if err != nil || src == nil || src.CreatedAt == "" {
				t.Fatalf("source: %v %+v", err, src)
			}
			if err := RelocateContainerWithToken(ctx, c, "host-a", "web", "host-b", "tok"); err != nil {
				t.Fatal(err)
			}
			dst, err := GetContainer(ctx, c, "host-b", "web")
			if err != nil || dst == nil {
				t.Fatalf("target: %v %+v", err, dst)
			}
			if dst.CreatedAt != src.CreatedAt {
				t.Fatalf("the relocated row is incarnation %q, the source was %q", dst.CreatedAt, src.CreatedAt)
			}
		})
	}
}

// TestVerifyClaimCertificate_ARelocatedContainerIsBoundByItsToken: a scoped
// certificate for a container relocation verifies against the row the
// relocation wrote — the one carrying its token — even where that row's
// created_at is not the source's (the pre-epoch upsert keeps a stale target
// tombstone's created_at). A row carrying another token, of another
// incarnation, does not.
//
// Mutation: drop the relocation-token arm of certificateIncarnationIsLive —
// the relocation refuses at its destination and wedges.
func TestVerifyClaimCertificate_ARelocatedContainerIsBoundByItsToken(t *testing.T) {
	ctx := context.Background()
	f := newCertFixture(t)
	dest := f.voters[2]
	proof := ActionProof{ID: "reloc-1", Action: ActionRelocate, TargetKind: ClaimKindContainer, TargetName: "ct-1",
		DestHost: dest.name, Coordinator: "a", RelocationToken: "tok-1", OwnerEpoch: "0"}
	value := ClaimValue{Proof: &proof, SourceHost: "ghost"}
	key := ClaimKey{TargetKind: ClaimKindContainer, TargetName: "ct-1", Incarnation: "2026-10-01T12:00:00.000000001Z"}
	b := testBallot(4, "b")
	cert := ClaimCertificate{Key: key, ConfigGeneration: 1, Ballot: b, ValueDigest: value.MustDigest(), SourceHost: "ghost"}
	for _, v := range f.voters[:2] {
		res, err := v.c.ClaimAccept(ctx, key, b, value, 1, v.signer, unreachable)
		if err != nil || !res.Accepted {
			t.Fatalf("%s: %+v %v", v.name, res, err)
		}
		cert.Accepts = append(cert.Accepts, *res.Accept)
	}
	enc, err := cert.Encode()
	if err != nil {
		t.Fatal(err)
	}
	proof.ClaimCertificate = enc

	// The relocated row, with a created_at that is not the certificate's.
	row := func(token string) {
		t.Helper()
		if err := UpsertContainer(ctx, dest.c, ContainerRecord{HostName: dest.name, Name: "ct-1", State: "pending",
			Image: "alpine", StateDetail: ContainerRelocateRecreateDetail, RelocateToken: token,
			CreatedAt: "2026-09-01T00:00:00Z"}); err != nil {
			t.Fatal(err)
		}
	}
	row("tok-other")
	if _, err := VerifyClaimCertificate(ctx, dest.c, f.verifier, proof); err == nil ||
		!strings.Contains(err.Error(), "the live row here is incarnation") {
		t.Fatalf("a row of another incarnation with another token verified: %v", err)
	}
	row("tok-1")
	if _, err := VerifyClaimCertificate(ctx, dest.c, f.verifier, proof); err != nil {
		t.Fatalf("the row this relocation wrote refused its certificate: %v", err)
	}
}
