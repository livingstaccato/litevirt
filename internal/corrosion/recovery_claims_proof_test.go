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

// TestVerifyClaimCertificate_AtTheDestination is §3.10 as a destination runs
// it: against the proof it is about to claim and ITS OWN adopted voter set.
//
// Mutations: skip CertificateAuthorizesProof in VerifyClaimCertificate — the
// proof for another destination verifies; skip the adopted-generation check —
// the node that adopted nothing verifies; skip ReplacedByForcedGeneration —
// the certificate from a replaced generation verifies; verify against a quorum
// of 1 — the single accept verifies.
func TestVerifyClaimCertificate_AtTheDestination(t *testing.T) {
	ctx := context.Background()
	f := newCertFixture(t)
	dest := f.voters[2] // adopted generation 1, did not sign
	enc, err := f.cert.Encode()
	if err != nil {
		t.Fatal(err)
	}
	proof := *f.value.Proof
	proof.ClaimCertificate = enc
	// The value's source is part of the digest; a proof carries the binding
	// fields and the certificate carries the source.
	if _, err := VerifyClaimCertificate(ctx, dest.c, f.verifier, proof); err != nil {
		t.Fatalf("a genuine certificate for this exact proof was refused: %v", err)
	}

	refused := func(t *testing.T, c *Client, p ActionProof, contains string) {
		t.Helper()
		_, err := VerifyClaimCertificate(ctx, c, f.verifier, p)
		if err == nil || !strings.Contains(err.Error(), contains) {
			t.Fatalf("want a refusal mentioning %q, got %v", contains, err)
		}
	}
	t.Run("no certificate", func(t *testing.T) {
		p := proof
		p.ClaimCertificate = ""
		refused(t, dest.c, p, "no recovery-claim certificate")
	})
	t.Run("another destination", func(t *testing.T) {
		p := proof
		p.DestHost = "c"
		refused(t, dest.c, p, "digests to")
	})
	t.Run("another epoch", func(t *testing.T) {
		p := proof
		p.OwnerEpoch = "4"
		refused(t, dest.c, p, "decides")
	})
	t.Run("generation not adopted here", func(t *testing.T) {
		fresh := newClaimTestVoter(t, f.ca, "d")
		refused(t, fresh.c, proof, "has not adopted")
	})
	t.Run("too few accepts", func(t *testing.T) {
		c := f.cert
		c.Accepts = c.Accepts[:1]
		one, _ := c.Encode()
		p := proof
		p.ClaimCertificate = one
		refused(t, dest.c, p, "needs 2")
	})
	t.Run("a generation a forced one replaced", func(t *testing.T) {
		v := newClaimTestVoter(t, f.ca, "c")
		adoptHandBuilt(t, 1, membersOf(f.voters...), v)
		forced := VoterConfigValue{Generation: 2, Members: membersOf(f.voters[0]), Change: "force:b,c",
			CreatedBy: "t", CreatedAt: "t"}
		if err := WriteVoterConfig(ctx, v.c, forced, ClaimCertificate{}); err != nil {
			t.Fatal(err)
		}
		if err := RecordVoterAdoption(ctx, v.c, 2); err != nil {
			t.Fatal(err)
		}
		refused(t, v.c, proof, "forced generation 2 replaced")
	})
}

// TestSensitiveAE_ReMaterializedProofCopiesConverge: a coordinator that loses
// a claim re-materializes the winner's proof with its own created_at and
// without the winner's evidence fields; the winner's lifecycle UPDATEs then
// stamp both copies with one updated_at. The two copies are one proof, and
// anti-entropy must settle them on one row — keeping local on the exact tie
// left the replicas' digests apart forever.
//
// Mutation: drop the equal-binding tie-break in proofMergeKeepLocalRow — the
// two rows stay different after merging both ways.
func TestSensitiveAE_ReMaterializedProofCopiesConverge(t *testing.T) {
	ctx := context.Background()
	winner, loser := mustTestClient(t), mustTestClient(t)
	for _, c := range []*Client{winner, loser} {
		c.SetRecoveryClaimGate(func() bool { return true })
	}
	p := claimProof("p-copy")
	full := p
	full.LeaseHolder, full.QuorumLive, full.QuorumNeeded = "a", 2, 2
	full.ClaimCertificate = certFor(t, p, "v", 1, 0)
	bare := p
	bare.ClaimCertificate = certFor(t, p, "v", 1, 0)
	if err := WriteActionProof(ctx, winner, full); err != nil {
		t.Fatal(err)
	}
	if err := WriteActionProof(ctx, loser, bare); err != nil {
		t.Fatal(err)
	}
	// The same lifecycle UPDATE, applied verbatim on both, as WAL relay does.
	for _, c := range []*Client{winner, loser} {
		if err := c.Execute(ctx, `UPDATE runtime_action_proofs SET status = 'completed', executor_host = 'b',
			completed_at = 'T', updated_at = '2026-01-01T00:00:00Z' WHERE id = ?`, p.ID); err != nil {
			t.Fatal(err)
		}
	}
	winner.MergeSensitiveStateBytesLWW(loser.DumpSensitiveStateBytes())
	loser.MergeSensitiveStateBytesLWW(winner.DumpSensitiveStateBytes())
	row := func(c *Client) string {
		rows, err := c.Query(ctx, `SELECT * FROM runtime_action_proofs WHERE id = ?`, p.ID)
		if err != nil || len(rows) != 1 {
			t.Fatalf("read proof: %v", err)
		}
		return proofRowEncoding(rows[0].Values)
	}
	if w, l := row(winner), row(loser); w != l {
		t.Fatalf("two copies of one proof did not converge:\n  winner %q\n  loser  %q", w, l)
	}
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
// A certificate replaces one the row holds only if it verifies here, which
// the unsigned ones below do not (TestClaimCertificate_ReplacedOnlyByOneThatVerifies
// covers replacement).
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
	if err := WriteActionProofValidated(ctx, c, certAt(3)); err != nil || cert() != certAt(2).ClaimCertificate {
		t.Fatalf("an unverified certificate at a later generation replaced the row's: %v", err)
	}

	other := p
	other.DestHost = "c"
	forged := p
	forged.ClaimCertificate = certFor(t, other, "v", 4, 0)
	if err := WriteActionProofValidated(ctx, c, forged); !errors.Is(err, ErrProofDiverges) {
		t.Fatalf("a certificate for another destination was accepted: %v", err)
	}
	if cert() != certAt(2).ClaimCertificate {
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

// TestClaimCertificate_ReplacedOnlyByOneThatVerifies: a certificate on a
// proof row is replaced only by one that verifies HERE — signatures and a
// majority of a generation this node has adopted, not replaced by a forced
// one. An unsigned certificate claiming generation 999 for the same value
// must neither overwrite a genuine one on the write path nor win the merge,
// or one peer could make every destination refuse the recovery forever. A
// genuine one replaces a copy that does not verify, whichever node holds
// which, so the replicas converge; a genuine re-certification at a later
// adopted generation still replaces an earlier one.
//
// Mutations: judge nothing in ClaimCertificateReplaces (the old
// later-generation rule) — the forged certificate replaces the genuine one;
// drop the verified-first fallback in betterClaimCertificate — the forged
// copy's greater encoding wins the merge on one side.
func TestClaimCertificate_ReplacedOnlyByOneThatVerifies(t *testing.T) {
	ctx := context.Background()
	f := newCertFixture(t)
	a, b := f.voters[0].c, f.voters[1].c
	for _, c := range []*Client{a, b} {
		c.SetRecoveryClaimGate(func() bool { return true })
		c.SetClaimCertificateVerifier(func() *ClaimVerifier { return f.verifier })
	}
	genuine, err := f.cert.Encode()
	if err != nil {
		t.Fatal(err)
	}
	fc := f.cert
	fc.ConfigGeneration = 999
	fc.Accepts = nil
	forged, err := fc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	proof := *f.value.Proof
	good, bad := proof, proof
	good.ClaimCertificate, bad.ClaimCertificate = genuine, forged
	certOn := func(c *Client) string {
		got, ok, err := GetActionProof(ctx, c, proof.ID)
		if err != nil || !ok {
			t.Fatalf("read proof: ok=%v %v", ok, err)
		}
		return got.ClaimCertificate
	}

	// The write path.
	if err := WriteActionProof(ctx, a, good); err != nil {
		t.Fatal(err)
	}
	if err := SetProofClaimCertificate(ctx, a, bad); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("an unverified certificate at generation 999 was not refused: %v", err)
	}
	if certOn(a) != genuine {
		t.Fatal("the forged certificate replaced the genuine one on the write path")
	}

	// The merge, both ways: b holds the forged copy.
	if err := WriteActionProof(ctx, b, bad); err != nil {
		t.Fatal(err)
	}
	a.MergeSensitiveStateBytesLWW(b.DumpSensitiveStateBytes())
	b.MergeSensitiveStateBytesLWW(a.DumpSensitiveStateBytes())
	if certOn(a) != genuine || certOn(b) != genuine {
		t.Fatalf("the replicas did not converge on the genuine certificate:\n  a %q\n  b %q", certOn(a), certOn(b))
	}

	// A forged certificate for the same proof that names another source has
	// another digest, so neither copy replaces the other; the merge must still
	// keep the one that verifies, not the greater encoding. The forgery's
	// ballot is picked so its encoding IS the greater.
	other := f.value
	other.SourceHost = "elsewhere"
	var forged2 string
	for round := uint64(3); round < 100 && forged2 <= genuine; round++ {
		f2 := ClaimCertificate{Key: f.key, ConfigGeneration: 1, Ballot: testBallot(round, "z"),
			ValueDigest: other.MustDigest(), SourceHost: "elsewhere"}
		if forged2, err = f2.Encode(); err != nil {
			t.Fatal(err)
		}
	}
	if forged2 <= genuine {
		t.Fatal("could not build a forgery whose encoding sorts above the genuine certificate")
	}
	c3 := f.voters[2].c
	c3.SetRecoveryClaimGate(func() bool { return true })
	c3.SetClaimCertificateVerifier(func() *ClaimVerifier { return f.verifier })
	bad2 := proof
	bad2.ClaimCertificate = forged2
	if err := WriteActionProof(ctx, c3, bad2); err != nil {
		t.Fatal(err)
	}
	a.MergeSensitiveStateBytesLWW(c3.DumpSensitiveStateBytes())
	c3.MergeSensitiveStateBytesLWW(a.DumpSensitiveStateBytes())
	if certOn(a) != genuine || certOn(c3) != genuine {
		t.Fatalf("a forgery naming another source won the merge:\n  a %q\n  c %q", certOn(a), certOn(c3))
	}

	// A genuine re-certification at a later adopted generation still replaces.
	adoptHandBuilt(t, 2, membersOf(f.voters...), f.voters...)
	b3 := testBallot(3, "b")
	c2 := ClaimCertificate{Key: f.key, ConfigGeneration: 2, Ballot: b3, ValueDigest: f.value.MustDigest(), SourceHost: "ghost"}
	for _, v := range f.voters[:2] {
		res, err := v.c.ClaimAccept(ctx, f.key, b3, f.value, 2, v.signer, unreachable)
		if err != nil || !res.Accepted {
			t.Fatalf("%s accept at generation 2: %+v %v", v.name, res, err)
		}
		c2.Accepts = append(c2.Accepts, *res.Accept)
	}
	recert, err := c2.Encode()
	if err != nil {
		t.Fatal(err)
	}
	re := proof
	re.ClaimCertificate = recert
	if err := SetProofClaimCertificate(ctx, a, re); err != nil || certOn(a) != recert {
		t.Fatalf("a genuine re-certification at generation 2 did not replace generation 1: %v", err)
	}
}
