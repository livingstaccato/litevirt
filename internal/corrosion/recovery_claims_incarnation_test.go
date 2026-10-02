package corrosion

import (
	"context"
	"strings"
	"testing"
)

// Incarnation-scoped claim keys (docs/design/recovery-claims.md §10 item 37):
// a workload deleted and re-created under one name starts again at the same
// owner epoch, so a key without the incarnation let the new workload meet the
// previous one's decision.

func scopedKey(inc string) ClaimKey {
	k := workloadKey()
	k.Incarnation = inc
	return k
}

// TestClaimVoter_IncarnationsHaveSeparateHistories: what a voter accepted for
// one incarnation is not reported as accepted for another, and an
// incarnation-scoped promise reports the legacy key's state separately.
//
// Mutation: route an incarnation-scoped key to local_recovery_claims in
// loadClaimRowTx / saveClaimRowTx — the second incarnation's promise reports
// the first's value as accepted.
func TestClaimVoter_IncarnationsHaveSeparateHistories(t *testing.T) {
	ctx := context.Background()
	_, a, _, _ := threeVoters(t)
	old := workloadValue("p-old", "b", "ghost")
	if res, err := a.c.ClaimAccept(ctx, scopedKey("inc-1"), testBallot(5, "x"), old, 1, a.signer, unreachable); err != nil || !res.Accepted {
		t.Fatalf("accept for the first incarnation: %+v %v", res, err)
	}
	res, err := a.c.ClaimPrepare(ctx, scopedKey("inc-2"), testBallot(1, "y"), 1)
	if err != nil || !res.Promised {
		t.Fatalf("a fresh incarnation's prepare was refused: %+v %v", res, err)
	}
	if !res.State.Accepted.IsZero() || res.State.Value != nil {
		t.Fatalf("the second incarnation's promise reports the first's value: %+v", res.State)
	}
	if res.Legacy != nil {
		t.Fatalf("nothing was accepted at the legacy key, but the promise reports %+v", res.Legacy)
	}
	if st, found, _ := a.c.ClaimState(ctx, workloadKey()); found {
		t.Fatalf("an incarnation-scoped accept wrote the legacy key: %+v", st)
	}

	// Something accepted at the legacy key is reported beside the scoped
	// state, never as it. (Attempt 2: attempt 0's legacy key is sealed by
	// now.)
	legacyKey := workloadKey()
	legacyKey.Attempt = 2
	legacy := workloadValue("p-legacy", "c", "ghost")
	if res, err := a.c.ClaimAccept(ctx, legacyKey, testBallot(2, "x"), legacy, 1, a.signer, unreachable); err != nil || !res.Accepted {
		t.Fatalf("legacy accept before any scoped step at its key: %+v %v", res, err)
	}
	k3 := scopedKey("inc-3")
	k3.Attempt = 2
	res, _ = a.c.ClaimPrepare(ctx, k3, testBallot(1, "y"), 1)
	if !res.Promised || res.State.Value != nil {
		t.Fatalf("scoped promise: %+v", res)
	}
	if res.Legacy == nil || res.Legacy.ValueDigest != legacy.MustDigest() || !res.Legacy.Accepted.Equal(testBallot(2, "x")) {
		t.Fatalf("the scoped promise did not report the legacy key's accepted value: %+v", res.Legacy)
	}
}

// TestClaimVoter_ScopedPromiseSealsTheLegacyKey: once a voter has answered a
// key at its incarnation-scoped form, it refuses the legacy form — its promise
// reported the legacy state as final.
//
// Mutation: drop the legacyKeySealedTx check in ClaimPrepare and ClaimAccept —
// the legacy Prepare and Accept are taken after the seal.
func TestClaimVoter_ScopedPromiseSealsTheLegacyKey(t *testing.T) {
	ctx := context.Background()
	_, a, _, _ := threeVoters(t)
	if res, _ := a.c.ClaimPrepare(ctx, workloadKey(), testBallot(1, "x"), 1); !res.Promised {
		t.Fatalf("the legacy key is open before any scoped step: %+v", res)
	}
	if res, _ := a.c.ClaimPrepare(ctx, scopedKey("inc-1"), testBallot(1, "y"), 1); !res.Promised {
		t.Fatalf("scoped prepare: %+v", res)
	}
	res, err := a.c.ClaimPrepare(ctx, workloadKey(), testBallot(9, "x"), 1)
	if err != nil || res.Promised || res.Refusal != RefusalLegacyKeySealed {
		t.Fatalf("a legacy prepare after the seal = %+v %v, want %s", res, err, RefusalLegacyKeySealed)
	}
	acc, err := a.c.ClaimAccept(ctx, workloadKey(), testBallot(9, "x"), workloadValue("p", "b", "ghost"), 1, a.signer, unreachable)
	if err != nil || acc.Accepted || acc.Refusal != RefusalLegacyKeySealed {
		t.Fatalf("a legacy accept after the seal = %+v %v, want %s", acc, err, RefusalLegacyKeySealed)
	}
	// Another attempt's legacy key is not sealed by this one.
	other := workloadKey()
	other.Attempt = 1
	if res, _ := a.c.ClaimPrepare(ctx, other, testBallot(1, "x"), 1); !res.Promised {
		t.Fatalf("the seal reached another attempt: %+v", res)
	}
}

// TestClaimVoter_ALegacyHeldValueIsCrossCheckedNotProbed: a value this voter
// accepted at the legacy key, re-proposed at the scoped key by the bridge, is
// not probed again (§3.15) — but its source is still checked against this
// voter's own row of THIS incarnation, which a previous incarnation's value
// fails.
//
// Mutations: return errClaimNeedsOwnerCheck for a legacy-held value — the
// reachable owner refuses it; skip the cross-check for it — the previous
// incarnation's value is accepted.
func TestClaimVoter_ALegacyHeldValueIsCrossCheckedNotProbed(t *testing.T) {
	ctx := context.Background()
	_, a, _, _ := threeVoters(t)
	// A previous incarnation's decision at attempt 1, accepted at the legacy
	// key while that incarnation (owned by old-owner) was the only one.
	prev := workloadValue("p-prev", "c", "old-owner")
	legacy := workloadKey()
	legacy.Attempt = 1
	if res, _ := a.c.ClaimAccept(ctx, legacy, testBallot(1, "x"), prev, 1, a.signer, unreachable); !res.Accepted {
		t.Fatalf("legacy accept at attempt 1: %+v", res)
	}
	// This incarnation, owned by ghost.
	if err := InsertVM(ctx, a.c, VMRecord{Name: "vm-1", HostName: "ghost", Spec: `{}`, State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.c.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 3 WHERE name = 'vm-1'`); err != nil {
		t.Fatal(err)
	}
	vm, err := GetVM(ctx, a.c, "vm-1")
	if err != nil || vm == nil || vm.CreatedAt == "" {
		t.Fatalf("read vm-1: %v %+v", err, vm)
	}
	reached := func(context.Context, string) (bool, string) { return true, "answered" }

	same := workloadValue("p-same", "b", "ghost")
	if res, _ := a.c.ClaimAccept(ctx, workloadKey(), testBallot(1, "x"), same, 1, a.signer, unreachable); !res.Accepted {
		t.Fatalf("legacy accept: %+v", res)
	}
	res, err := a.c.ClaimAccept(ctx, scopedKey(vm.CreatedAt), testBallot(2, "x"), same, 1, a.signer, reached)
	if err != nil || !res.Accepted {
		t.Fatalf("a value accepted at the legacy key was re-probed at the scoped key: %+v %v", res, err)
	}

	// A previous incarnation's value names that incarnation's owner.
	k := scopedKey(vm.CreatedAt)
	k.Attempt = 1
	res, _ = a.c.ClaimAccept(ctx, k, testBallot(2, "x"), prev, 1, a.signer, unreachable)
	if res.Accepted || res.Refusal != RefusalSourceMismatch {
		t.Fatalf("a previous incarnation's value was accepted for this one: %+v", res)
	}
}

// TestClaimVoter_ARowOfAnotherIncarnationSaysNothing: the source cross-check
// reads only this incarnation's row. A voter whose row is a re-created
// workload does not refuse a claim for the incarnation the key names on it,
// and does not wait for it: the destination binds the incarnation.
func TestClaimVoter_ARowOfAnotherIncarnationSaysNothing(t *testing.T) {
	ctx := context.Background()
	_, a, _, _ := threeVoters(t)
	if err := InsertVM(ctx, a.c, VMRecord{Name: "vm-1", HostName: "someone-else", Spec: `{}`, State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.c.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 3 WHERE name = 'vm-1'`); err != nil {
		t.Fatal(err)
	}
	vm, _ := GetVM(ctx, a.c, "vm-1")
	v := workloadValue("p1", "b", "ghost")
	if res, _ := a.c.ClaimAccept(ctx, scopedKey(vm.CreatedAt), testBallot(1, "x"), v, 1, a.signer, unreachable); res.Accepted ||
		res.Refusal != RefusalSourceMismatch {
		t.Fatalf("this incarnation's settled row names someone-else; want a source mismatch, got %+v", res)
	}
	if res, _ := a.c.ClaimAccept(ctx, scopedKey("an-earlier-incarnation"), testBallot(1, "x"), v, 1, a.signer, unreachable); !res.Accepted {
		t.Fatalf("a row of another incarnation refused the claim: %+v", res)
	}
}

// TestClaimAccept_ScopedSignatureIsItsOwn: an accept signed at an
// incarnation-scoped key verifies only for that key — not for the legacy key,
// not for another incarnation — and a legacy accept does not verify for any
// incarnation.
//
// Mutation: sign the v1 payload for a scoped key (drop the incarnation from
// acceptPayload) — the accept verifies for another incarnation.
func TestClaimAccept_ScopedSignatureIsItsOwn(t *testing.T) {
	ctx := context.Background()
	f := newCertFixture(t)
	scoped := scopedKey("inc-1")
	b := testBallot(3, "b")
	cert := ClaimCertificate{Key: scoped, ConfigGeneration: 1, Ballot: b, ValueDigest: f.value.MustDigest(), SourceHost: "ghost"}
	for _, v := range f.voters[:2] {
		res, err := v.c.ClaimAccept(ctx, scoped, b, f.value, 1, v.signer, unreachable)
		if err != nil || !res.Accepted {
			t.Fatalf("%s: %+v %v", v.name, res, err)
		}
		cert.Accepts = append(cert.Accepts, *res.Accept)
	}
	want := f.want
	want.Key = scoped
	if err := f.verifier.Verify(cert, want); err != nil {
		t.Fatalf("a genuine scoped certificate was refused: %v", err)
	}
	relabel := func(k ClaimKey) (ClaimCertificate, CertExpectation) {
		c := cert
		c.Key = k
		c.Accepts = nil
		for _, a := range cert.Accepts {
			a.Key = k
			c.Accepts = append(c.Accepts, a)
		}
		w := want
		w.Key = k
		return c, w
	}
	for _, k := range []ClaimKey{scoped.Legacy(), scopedKey("inc-2")} {
		c, w := relabel(k)
		if err := f.verifier.Verify(c, w); err == nil || !strings.Contains(err.Error(), "signature does not verify") {
			t.Errorf("an accept signed at %s verified for %s: %v", scoped, k, err)
		}
	}
	// And a legacy certificate (the fixture's) relabelled to an incarnation.
	legacy := f.cert
	legacy.Key = scopedKey("inc-1")
	legacy.Accepts = nil
	for _, a := range f.cert.Accepts {
		a.Key = legacy.Key
		legacy.Accepts = append(legacy.Accepts, a)
	}
	w := f.want
	w.Key = legacy.Key
	if err := f.verifier.Verify(legacy, w); err == nil {
		t.Error("a legacy accept verified for an incarnation")
	}
}

// TestVerifyClaimCertificate_BindsTheIncarnation: a destination executes a
// scoped certificate only against its own live row of the incarnation the
// certificate names. A re-created workload is another incarnation. A legacy
// certificate binds none, as before the incarnation existed.
//
// Mutation: drop certificateIncarnationIsLive from VerifyClaimCertificate —
// the certificate verifies against the re-created workload.
func TestVerifyClaimCertificate_BindsTheIncarnation(t *testing.T) {
	ctx := context.Background()
	f := newCertFixture(t)
	dest := f.voters[2]
	refused := func(t *testing.T, p ActionProof, contains string) {
		t.Helper()
		if _, err := VerifyClaimCertificate(ctx, dest.c, f.verifier, p); err == nil || !strings.Contains(err.Error(), contains) {
			t.Fatalf("want a refusal mentioning %q, got %v", contains, err)
		}
	}
	scopedProof := func(inc string) ActionProof {
		k := scopedKey(inc)
		b := testBallot(4, "b")
		cert := ClaimCertificate{Key: k, ConfigGeneration: 1, Ballot: b, ValueDigest: f.value.MustDigest(), SourceHost: "ghost"}
		for _, v := range f.voters[:2] {
			res, err := v.c.ClaimAccept(ctx, k, b, f.value, 1, v.signer, unreachable)
			if err != nil || !res.Accepted {
				t.Fatalf("%s: %+v %v", v.name, res, err)
			}
			cert.Accepts = append(cert.Accepts, *res.Accept)
		}
		enc, err := cert.Encode()
		if err != nil {
			t.Fatal(err)
		}
		p := *f.value.Proof
		p.ClaimCertificate = enc
		return p
	}

	refused(t, scopedProof("never-created"), "no single live vm/vm-1 row")

	if err := InsertVM(ctx, dest.c, VMRecord{Name: "vm-1", HostName: "ghost", Spec: `{}`, State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	first, _ := GetVM(ctx, dest.c, "vm-1")
	p := scopedProof(first.CreatedAt)
	if _, err := VerifyClaimCertificate(ctx, dest.c, f.verifier, p); err != nil {
		t.Fatalf("a certificate for the live incarnation was refused: %v", err)
	}
	legacy := *f.value.Proof
	legacy.ClaimCertificate, _ = f.cert.Encode()
	if _, err := VerifyClaimCertificate(ctx, dest.c, f.verifier, legacy); err != nil {
		t.Fatalf("a legacy certificate was refused: %v", err)
	}

	// Deleted and re-created under the same name: a new incarnation.
	if err := DeleteVM(ctx, dest.c, "vm-1"); err != nil {
		t.Fatal(err)
	}
	if err := InsertVM(ctx, dest.c, VMRecord{Name: "vm-1", HostName: "ghost", Spec: `{}`, State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	second, _ := GetVM(ctx, dest.c, "vm-1")
	if second.CreatedAt == first.CreatedAt {
		t.Fatal("the re-created VM has the first one's created_at; the rest is vacuous")
	}
	refused(t, p, "the live row here is incarnation")
}

// TestClaimCertificateReplaces_LegacyUpgradesToItsIncarnation: a legacy
// certificate may be replaced by the same decision re-certified at its
// incarnation-scoped key (the bridge), never the reverse, and never by another
// incarnation's.
func TestClaimCertificateReplaces_LegacyUpgradesToItsIncarnation(t *testing.T) {
	enc := func(k ClaimKey, gen int64) string {
		s, err := ClaimCertificate{Key: k, ConfigGeneration: gen, ValueDigest: "d"}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	all := func(string) bool { return true }
	legacy, inc1, inc2 := enc(workloadKey(), 1), enc(scopedKey("inc-1"), 2), enc(scopedKey("inc-2"), 2)
	verifiesNext := func(cur string) func(string) bool {
		return func(raw string) bool { return raw != cur }
	}
	if !ClaimCertificateReplaces(legacy, inc1, verifiesNext(legacy)) {
		t.Error("a legacy certificate that no longer verifies was not replaced by its incarnation-scoped re-certification")
	}
	if ClaimCertificateReplaces(inc1, enc(workloadKey(), 3), all) {
		t.Error("a legacy certificate replaced an incarnation-scoped one")
	}
	if ClaimCertificateReplaces(inc1, inc2, verifiesNext(inc1)) {
		t.Error("one incarnation's certificate replaced another's")
	}
}
