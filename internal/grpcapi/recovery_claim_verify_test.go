package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// carriedPromote is a promote proof for vm "db-v" destined for s, at owner
// epoch 0, as the coordinator would carry it.
func carriedPromote(s *Server, id string) *pb.RuntimeActionProof {
	return &pb.RuntimeActionProof{Id: id, Action: corrosion.ActionPromote, TargetKind: "vm", TargetName: "db-v",
		DestHost: s.hostName, Coordinator: s.hostName, OwnerEpoch: "0"}
}

// certify decides a claim for p on s (which is the whole voter generation)
// and stamps the certificate on it.
func certify(t *testing.T, s *Server, p *pb.RuntimeActionProof, source string) {
	t.Helper()
	proof := proofFromPB(p)
	key, err := corrosion.ClaimKeyForProof(proof, 0)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.DecideRecoveryClaim(context.Background(), key, corrosion.ClaimValue{Proof: &proof, SourceHost: source}, 1)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	enc, err := out.Certificate.Encode()
	if err != nil {
		t.Fatal(err)
	}
	p.ClaimCertificate = enc
}

// TestClaimCarriedProof_RequiresAVerifiedCertificate: the carried-proof
// executor (promote, restore-relocation) verifies the certificate on the
// persisted proof before it claims it, and refuses with
// recovery_claim_unproven otherwise (§3.10).
//
// Mutation: drop the verifyRecoveryClaim call in claimCarriedProofOwned — the
// uncertified promote is claimed.
func TestClaimCarriedProof_RequiresAVerifiedCertificate(t *testing.T) {
	ctx := context.Background()
	s := claimingServer(t)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "db-v", HostName: "dead-host", State: "running", Spec: `{}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	var reasons []string
	s.SetGateRefusedObserver(func(_, r string) { reasons = append(reasons, r) })

	bare := carriedPromote(s, "p-bare")
	_, err := s.claimCarriedProof(ctx, bare, corrosion.ActionPromote, "vm", "db-v")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "recovery_claim_unproven") {
		t.Fatalf("an uncertified promote was not refused as unproven: %v", err)
	}
	if pr, _, _ := corrosion.GetActionProof(ctx, s.db, "p-bare"); pr.Status != corrosion.ProofPrepared {
		t.Fatalf("the refused proof was consumed: status %q", pr.Status)
	}
	if len(reasons) == 0 || reasons[0] != "recovery_claim_unproven" {
		t.Errorf("the refusal was not counted as recovery_claim_unproven: %v", reasons)
	}

	good := carriedPromote(s, "p-good")
	certify(t, s, good, "dead-host")
	if _, err := s.claimCarriedProof(ctx, good, corrosion.ActionPromote, "vm", "db-v"); err != nil {
		t.Fatalf("a certified promote was refused: %v", err)
	}
}

// TestVerifyRecoveryClaim_OwnerMoveIsExempt: a relocate its live owner drives
// — a container cold migration — is not a recovery and needs no certificate;
// a failover relocate does, and so does every reschedule and promote,
// whatever the caller says (§2, §9 Q7).
//
// Mutation: honour ownerMove for every action in verifyRecoveryClaim — the
// uncertified promote passes.
func TestVerifyRecoveryClaim_OwnerMoveIsExempt(t *testing.T) {
	ctx := context.Background()
	s := claimingServer(t)
	reloc := corrosion.ActionProof{ID: "r1", Action: corrosion.ActionRelocate, TargetKind: "container",
		TargetName: "ct", DestHost: s.hostName, Coordinator: "src", OwnerEpoch: "0"}
	if _, err := s.verifyRecoveryClaim(ctx, reloc, true); err != nil {
		t.Errorf("an owner-driven relocate was refused: %v", err)
	}
	if _, err := s.verifyRecoveryClaim(ctx, reloc, false); err == nil {
		t.Error("an uncertified failover relocate verified")
	}
	promote := corrosion.ActionProof{ID: "p1", Action: corrosion.ActionPromote, TargetKind: "vm",
		TargetName: "v", DestHost: s.hostName, Coordinator: "src", OwnerEpoch: "0"}
	if _, err := s.verifyRecoveryClaim(ctx, promote, true); err == nil {
		t.Error("an uncertified promote verified because the caller called it an owner move")
	}
	lb := corrosion.ActionProof{ID: "l1", Action: corrosion.ActionLBApply, TargetKind: "lb", TargetName: "x"}
	if _, err := s.verifyRecoveryClaim(ctx, lb, false); err != nil {
		t.Errorf("an LB apply needed a certificate: %v", err)
	}
}

// TestOwnerDrivenRelocation: only a migrate marker backed by the source's own
// peer certificate, from the proof's coordinator, for a container the replica
// records on that source, marks a restore as an owner move. A failover
// restore-relocation — driven by a survivor — never qualifies.
//
// Mutation: drop the recorded-owner check — a peer migrating a container it
// does not own is exempted.
func TestOwnerDrivenRelocation(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	for _, h := range []string{"src", "survivor"} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h, Address: "127.0.0.1", State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{HostName: "src", Name: "ct", State: "running", Image: "alpine:3"}); err != nil {
		t.Fatal(err)
	}
	marker := func(cn, src string) context.Context {
		return metadata.NewIncomingContext(mtlsCtx(cn), metadata.Pairs(migrateFromMDKey, src))
	}
	proof := func(coord string) *pb.RuntimeActionProof {
		return &pb.RuntimeActionProof{Action: corrosion.ActionRelocate, TargetKind: "container", TargetName: "ct", Coordinator: coord}
	}
	if !s.ownerDrivenRelocation(marker("src", "src"), proof("src"), "ct") {
		t.Error("the owner's own migrate was not recognised")
	}
	if s.ownerDrivenRelocation(mtlsCtx("survivor"), proof("survivor"), "ct") {
		t.Error("a failover restore-relocation was taken for an owner move")
	}
	if s.ownerDrivenRelocation(marker("survivor", "survivor"), proof("survivor"), "ct") {
		t.Error("a peer that does not own the container exempted its own relocate")
	}
	if s.ownerDrivenRelocation(marker("src", "src"), proof("survivor"), "ct") {
		t.Error("a proof minted by someone else rode the owner's migrate marker")
	}
}
