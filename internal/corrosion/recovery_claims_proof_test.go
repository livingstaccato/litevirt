package corrosion

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// certFor is an unsigned certificate that certifies p with source src at
// voter generation gen — enough for everything below, none of which checks a
// signature (that is VerifyClaimCertificate's job).
func certFor(t *testing.T, p ActionProof, src string, gen, attempt int64) string {
	t.Helper()
	key, err := ClaimKeyForProof(p, attempt)
	if err != nil {
		t.Fatal(err)
	}
	q := p
	q.ClaimCertificate = ""
	digest := ClaimValue{Proof: &q, SourceHost: src}.MustDigest()
	enc, err := ClaimCertificate{Key: key, ConfigGeneration: gen, Ballot: Ballot{Round: 1, Coordinator: "a"},
		ValueDigest: digest, SourceHost: src}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func claimProof(id string) ActionProof {
	return ActionProof{ID: id, Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1",
		DestHost: "b", Coordinator: "a", OwnerEpoch: "3"}
}

func lastMutationSQL(t *testing.T, c *Client) string {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT stmts FROM mutation_log ORDER BY seq DESC LIMIT 1`)
	if err != nil || len(rows) == 0 {
		t.Fatalf("read mutation_log: %v (%d rows)", err, len(rows))
	}
	return rows[0].String("stmts")
}

// TestProofClaimCertificate_EmittedOnlyOnceLatched: the claim_certificate
// column's shapes are new in v60, and a previous-release peer that meets one
// stalls its stream, so a proof carrying a certificate is refused — retryably
// — until recovery_claim_v1 has latched, and a proof without one keeps going
// out in the shape every peer already decodes.
//
// Mutations: drop the certificate half of proofStampEmittable — the
// certificate is written with the gate closed; emit the claim shape
// unconditionally in WriteActionProof — the certificate-less proof carries the
// new column.
func TestProofClaimCertificate_EmittedOnlyOnceLatched(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	p := claimProof("p-closed")
	p.ClaimCertificate = certFor(t, p, "v", 1, 0)
	if err := WriteActionProof(ctx, c, p); !errors.Is(err, ErrClaimCertificateNotEmittable) {
		t.Fatalf("a certified proof was written before the latch: %v", err)
	}
	if _, ok, _ := GetActionProof(ctx, c, p.ID); ok {
		t.Fatal("the refused proof has a row")
	}
	plain := claimProof("p-plain")
	if err := WriteActionProof(ctx, c, plain); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(lastMutationSQL(t, c), "claim_certificate") {
		t.Fatal("a proof without a certificate went out in the v60 shape before the latch")
	}

	c.SetRecoveryClaimGate(func() bool { return true })
	if err := WriteActionProof(ctx, c, p); err != nil {
		t.Fatalf("a certified proof after the latch: %v", err)
	}
	got, ok, err := GetActionProof(ctx, c, p.ID)
	if err != nil || !ok || got.ClaimCertificate != p.ClaimCertificate {
		t.Fatalf("the certificate did not persist: ok=%v err=%v cert=%q", ok, err, got.ClaimCertificate)
	}
}

// TestWriteActionProofValidated_CertificateIsEvidence: a row may gain a
// certificate and may have it replaced by a re-certification of the same value
// at a later generation; a certificate for any other value is refused before
// anything is written, and one at a lower generation changes nothing (§3.9).
//
// Mutations: accept a lower generation in ClaimCertificateReplaces — the older
// certificate replaces the newer; skip CertificateAuthorizesProof in
// WriteActionProofValidated — the certificate for another destination is
// stored.
func TestWriteActionProofValidated_CertificateIsEvidence(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	c.SetRecoveryClaimGate(func() bool { return true })
	p := claimProof("p-ev")
	if err := WriteActionProofValidated(ctx, c, p); err != nil {
		t.Fatal(err)
	}
	certAt := func(gen int64) ActionProof {
		q := p
		q.ClaimCertificate = certFor(t, p, "v", gen, 0)
		return q
	}
	cert := func() string {
		got, _, err := GetActionProof(ctx, c, p.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.ClaimCertificate
	}

	if err := WriteActionProofValidated(ctx, c, certAt(2)); err != nil {
		t.Fatalf("gaining a certificate: %v", err)
	}
	if cert() != certAt(2).ClaimCertificate {
		t.Fatal("the row did not gain the certificate")
	}
	if err := WriteActionProofValidated(ctx, c, certAt(1)); err != nil {
		t.Fatalf("an older certificate should change nothing, not fail: %v", err)
	}
	if cert() != certAt(2).ClaimCertificate {
		t.Fatal("a certificate at a lower generation replaced a newer one")
	}
	if err := WriteActionProofValidated(ctx, c, certAt(3)); err != nil || cert() != certAt(3).ClaimCertificate {
		t.Fatalf("a re-certification at a later generation was not recorded: %v", err)
	}

	other := p
	other.DestHost = "c"
	forged := p
	forged.ClaimCertificate = certFor(t, other, "v", 4, 0)
	if err := WriteActionProofValidated(ctx, c, forged); !errors.Is(err, ErrProofDiverges) {
		t.Fatalf("a certificate for another destination was accepted: %v", err)
	}
	if cert() != certAt(3).ClaimCertificate {
		t.Fatal("the forged certificate reached the row")
	}

	// And on a SEED — no row yet — where nothing but the precheck stands
	// between the presented certificate and every peer's copy of the row.
	fresh := claimProof("p-ev-seed")
	otherFresh := fresh
	otherFresh.DestHost = "c"
	fresh.ClaimCertificate = certFor(t, otherFresh, "v", 1, 0)
	if err := WriteActionProofValidated(ctx, c, fresh); !errors.Is(err, ErrProofDiverges) {
		t.Fatalf("a seed carrying a certificate for another destination was accepted: %v", err)
	}
	if _, ok, _ := GetActionProof(ctx, c, fresh.ID); ok {
		t.Fatal("the seed with a forged certificate was written")
	}
}

// TestSensitiveAE_ClaimCertificateSurvivesTheMerge: whichever copy of a proof
// wins the lifecycle merge, the surviving row carries the certificate — a
// terminal copy without one must not strip it from a copy that has one.
//
// Mutation: drop the certificate fold in proofMergeKeepLocalRow — the merged
// row has no certificate.
func TestSensitiveAE_ClaimCertificateSurvivesTheMerge(t *testing.T) {
	ctx := context.Background()
	dst := mustTestClient(t)
	src := mustTestClient(t)
	src.SetRecoveryClaimGate(func() bool { return true })
	p := claimProof("p-merge")
	if err := WriteActionProof(ctx, dst, p); err != nil {
		t.Fatal(err)
	}
	if err := ClaimActionProof(ctx, dst, p.ID, "b"); err != nil {
		t.Fatal(err)
	}
	q := p
	q.ClaimCertificate = certFor(t, p, "v", 1, 0)
	if err := WriteActionProof(ctx, src, q); err != nil {
		t.Fatal(err)
	}
	// dst's in_progress copy outranks src's prepared one, so dst's row wins.
	dst.MergeSensitiveStateBytesLWW(src.DumpSensitiveStateBytes())
	got, ok, err := GetActionProof(ctx, dst, p.ID)
	if err != nil || !ok {
		t.Fatalf("proof missing: %v", err)
	}
	if got.Status != ProofInProgress {
		t.Fatalf("the higher-rank local status must survive, got %q", got.Status)
	}
	if got.ClaimCertificate != q.ClaimCertificate {
		t.Fatalf("the merged row lost the certificate: %q", got.ClaimCertificate)
	}
}
