package corrosion

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

// TestAbandonProof_OnlyAProofThatNeverStarted: a destination signs an
// abandonment only for a proof it has not started, and once it has, it
// refuses to claim the proof or record a start checkpoint for it — decided in
// the same transaction as each (docs/design/recovery-claims.md §3.12).
//
// Mutations: drop the start-checkpoint check in AbandonProof — the started
// promote is abandoned; drop the abandonment check in the claim guard — the
// abandoned proof is claimed; drop it in AppendProofStepUnlessAbandoned — the
// abandoned promote records its start.
func TestAbandonProof_OnlyAProofThatNeverStarted(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	me := c.HostName()
	key := ClaimKey{TargetKind: ClaimKindVM, TargetName: "vm1", OwnerEpoch: 3}
	write := func(t *testing.T, p ActionProof) {
		t.Helper()
		if err := WriteActionProof(ctx, c, p); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("never seen here", func(t *testing.T) {
		if err := c.AbandonProof(ctx, "p-unseen", key, "test"); err != nil {
			t.Fatalf("a proof this node never saw could not be abandoned: %v", err)
		}
		write(t, ActionProof{ID: "p-unseen", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1", DestHost: me, Coordinator: "a"})
		if err := ClaimActionProof(ctx, c, "p-unseen", me); !errors.Is(err, ErrProofAbandoned) {
			t.Fatalf("an abandoned proof that arrived later was claimed: %v", err)
		}
		if err := ClaimActionProofFenced(ctx, c, "p-unseen", me, &TermFence{Key: LeaseKeyFailover, Term: 1, Coordinator: "a"}); !errors.Is(err, ErrProofAbandoned) {
			t.Fatalf("an abandoned proof was claimed through the fenced path: %v", err)
		}
	})
	t.Run("a promote whose build failed before the start", func(t *testing.T) {
		write(t, ActionProof{ID: "p-built", Action: ActionPromote, TargetKind: "vm", TargetName: "vm1", DestHost: me, Coordinator: "a"})
		if err := ClaimActionProof(ctx, c, "p-built", me); err != nil {
			t.Fatal(err)
		}
		if err := c.AbandonProof(ctx, "p-built", key, "test"); err != nil {
			t.Fatalf("a claimed promote that never recorded a start could not be abandoned: %v", err)
		}
		if err := AppendProofStepUnlessAbandoned(ctx, c, "p-built", "start_attempted"); !errors.Is(err, ErrProofAbandoned) {
			t.Fatalf("the abandoned promote recorded its start checkpoint: %v", err)
		}
	})
	t.Run("a promote that recorded its start", func(t *testing.T) {
		write(t, ActionProof{ID: "p-started", Action: ActionPromote, TargetKind: "vm", TargetName: "vm1", DestHost: me, Coordinator: "a"})
		if err := ClaimActionProof(ctx, c, "p-started", me); err != nil {
			t.Fatal(err)
		}
		if err := AppendProofStepUnlessAbandoned(ctx, c, "p-started", "start_attempted"); err != nil {
			t.Fatal(err)
		}
		if err := c.AbandonProof(ctx, "p-started", key, "test"); !errors.Is(err, ErrProofExecuted) {
			t.Fatalf("a promote that may already be running was abandoned: %v", err)
		}
	})
	t.Run("a claimed reschedule", func(t *testing.T) {
		write(t, ActionProof{ID: "p-resched", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1", DestHost: me, Coordinator: "a"})
		if err := ClaimActionProof(ctx, c, "p-resched", me); err != nil {
			t.Fatal(err)
		}
		if err := c.AbandonProof(ctx, "p-resched", key, "test"); !errors.Is(err, ErrProofExecuted) {
			t.Fatalf("a reschedule this node claimed — and so is starting — was abandoned: %v", err)
		}
	})
}

// TestVerifyAbandonment: an abandonment verifies only as the named
// destination's, for the named proof and key, signed with its CA-issued
// certificate.
//
// Mutation: skip the signature check in VerifyAbandonment — the tampered
// abandonment verifies.
func TestVerifyAbandonment(t *testing.T) {
	ca := newClaimTestCA(t)
	d := newClaimTestVoter(t, ca, "d")
	v, err := LoadClaimVerifier(ca.pkiDir(t, "verifier"))
	if err != nil {
		t.Fatal(err)
	}
	key := ClaimKey{TargetKind: ClaimKindVM, TargetName: "vm1", OwnerEpoch: 3}
	ab, err := d.signer.SignAbandonment("p1", key, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyAbandonment(ab, "d", "p1", key); err != nil {
		t.Fatalf("a genuine abandonment was refused: %v", err)
	}
	if err := v.VerifyAbandonment(ab, "e", "p1", key); err == nil {
		t.Error("an abandonment verified as another host's")
	}
	if err := v.VerifyAbandonment(ab, "d", "p2", key); err == nil {
		t.Error("an abandonment verified for another proof")
	}
	other := key
	other.Attempt = 1
	if err := v.VerifyAbandonment(ab, "d", "p1", other); err == nil {
		t.Error("an abandonment verified for another attempt")
	}
	tampered := ab
	tampered.Signature = append([]byte(nil), ab.Signature...)
	tampered.Signature[len(tampered.Signature)-1] ^= 0xff
	if err := v.VerifyAbandonment(tampered, "d", "p1", key); err == nil {
		t.Error("a tampered abandonment verified")
	}
}

// TestRemovedHostEvidence: a destination is superseded by removal only when
// this replica holds all three facts — fenced proof-grade, no live hosts
// row, and its certificate in the installed CRL — and refuses while any is
// missing, so replica lag delays a supersede and never admits one (§3.12).
//
// Mutation: skip the revocation check — the removed but unrevoked host's
// evidence holds.
func TestRemovedHostEvidence(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	ca := newClaimTestCA(t)
	pkiDir := ca.pkiDir(t, "me")
	serial, err := pki.CertSerial(filepath.Join(ca.pkiDir(t, "dead"), "host.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := InsertHost(ctx, c, HostRecord{Name: "dead", Address: "10.0.0.9", State: "fenced", CertSerial: serial}); err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, wantOK bool, what string) {
		t.Helper()
		err := RemovedHostEvidence(ctx, c, pkiDir, "dead")
		if wantOK && err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if !wantOK && err == nil {
			t.Fatalf("%s: the evidence held", what)
		}
	}
	check(t, false, "no fence")
	if err := InsertFenceLog(ctx, c, FenceLogRecord{ID: "f1", HostName: "dead", Method: "manual", Result: "manual-confirmed"}); err != nil {
		t.Fatal(err)
	}
	check(t, false, "fenced but still a member")
	if err := DeleteHost(ctx, c, "dead"); err != nil {
		t.Fatal(err)
	}
	check(t, false, "fenced and removed but not revoked")
	if err := pki.AppendToCRL(ca.cert, ca.key, filepath.Join(pkiDir, "crl.pem"), serial); err != nil {
		t.Fatal(err)
	}
	check(t, true, "fenced, removed and revoked")
	_ = os.Remove(filepath.Join(pkiDir, "crl.pem"))
	check(t, false, "the CRL is gone again")
}
