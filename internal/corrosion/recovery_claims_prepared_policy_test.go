package corrosion

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

func preparedLaterCertificate(t *testing.T, f *certFixture, kind string) (ClaimCertificate, time.Time) {
	t.Helper()
	caRaw, err := os.ReadFile(f.ca.cert)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.ParseCertPEM(caRaw)
	if err != nil {
		t.Fatal(err)
	}
	keyRaw, err := os.ReadFile(f.ca.key)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyRaw)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	next := f.cert
	next.ConfigGeneration = 2
	next.Ballot = testBallot(3, "b")
	next.Accepts = nil
	expiry := time.Now().Truncate(time.Second).Add(2 * time.Second)
	for _, v := range f.voters[:2] {
		leaf, err := pki.ParseCertPEM([]byte(v.signer.certPEM))
		if err != nil {
			t.Fatal(err)
		}
		leaf.SerialNumber = new(big.Int).Add(leaf.SerialNumber, big.NewInt(17))
		switch kind {
		case "wrong-cn":
			leaf.RawSubject = nil
			leaf.Subject.CommonName = "wrong-host"
		case "client-only":
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		case "expired", "historical-expired":
			leaf.NotAfter = time.Now().Add(-time.Minute)
		case "future":
			leaf.NotBefore = time.Now().Add(time.Hour)
		case "expiry-after-wait":
			leaf.NotAfter = expiry
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		accept, err := v.signer.Sign(next.Key, 2, next.Ballot, next.ValueDigest, v.inc)
		if err != nil {
			t.Fatal(err)
		}
		accept.CertPEM = string(certPEM)
		if kind == "wrong-member" {
			accept.Voter = "outside"
		}
		if kind == "wrong-incarnation" {
			accept.VoterIncarnation += "-old"
		}
		accept.Signature, err = signRaw(v.signer, acceptPayload(accept.Key, accept.ConfigGeneration, accept.Ballot, accept.ValueDigest, accept.Voter, accept.VoterIncarnation))
		if err != nil {
			t.Fatal(err)
		}
		next.Accepts = append(next.Accepts, accept)
		if kind == "revoked" || kind == "historical-revoked" || kind == "renewal-blind" || kind == "renewal-blind-after-policy" {
			if err := pki.AppendToCRL(f.ca.cert, f.ca.key, filepath.Join(f.verifier.pkiDir, "crl.pem"), leaf.SerialNumber.Text(16)); err != nil {
				t.Fatal(err)
			}
		}
		if kind == "rebound-policy" || kind == "pinned" || kind == "no-pin" || kind == "renewal-blind" || kind == "pinned-after-policy" || kind == "no-pin-after-policy" || kind == "renewal-blind-after-policy" {
			if err := os.WriteFile(filepath.Join(v.pki, "host.crt"), certPEM, 0644); err != nil {
				t.Fatal(err)
			}
			if _, _, err := pki.RenewLocal(f.ca.cert, f.ca.key, v.pki, v.name); err != nil {
				t.Fatal(err)
			}
			renewed, err := pki.ServedHostCertificate(v.pki)
			if err != nil {
				t.Fatal(err)
			}
			if !pki.NoteSuccessor(f.verifier.pkiDir, renewed) {
				t.Fatal("renewal observation not learned")
			}
		}
	}
	if kind == "duplicate-majority" {
		next.Accepts = []ClaimAccept{next.Accepts[0], next.Accepts[0]}
	}
	return next, expiry
}

func TestPreparedProofWriterAndAEHonorOrdinaryPredicates(t *testing.T) {
	for _, kind := range []string{"rebound-policy", "wrong-cn", "wrong-member", "wrong-incarnation", "duplicate-majority", "expired", "historical-expired", "future", "revoked", "pinned", "client-only", "no-pin", "historical-revoked", "renewal-blind", "pinned-after-policy", "no-pin-after-policy", "renewal-blind-after-policy"} {
		t.Run(kind, func(t *testing.T) {
			f := newCertFixture(t)
			ctx := context.Background()
			a, b := f.voters[0].c, f.voters[1].c
			adoptHandBuilt(t, 2, membersOf(f.voters...), f.voters...)
			next, _ := preparedLaterCertificate(t, f, kind)
			verifier := f.verifier
			var policy atomic.Bool
			switch kind {
			case "rebound-policy":
				if err := pki.PublishHostTrustPolicy(verifier.pkiDir, &policy, true); err != nil {
					t.Fatal(err)
				}
				verifier = verifier.WithSerialPin().WithHostTrustPolicy(&policy).WithHostTrustPolicy(&policy)
				if err := pki.PublishHostTrustPolicy(verifier.pkiDir, &policy, false); err != nil {
					t.Fatal(err)
				}
			case "pinned":
				verifier = verifier.WithSerialPin()
			case "pinned-after-policy":
				verifier = verifier.WithHostTrustPolicy(&policy).WithSerialPin()
			case "no-pin-after-policy":
				verifier = verifier.WithSerialPin().WithHostTrustPolicy(&policy).WithoutSerialPin()
			case "renewal-blind-after-policy":
				verifier = verifier.WithSerialPin().WithHostTrustPolicy(&policy).RenewalBlind()
			case "no-pin":
				verifier = verifier.WithSerialPin().WithoutSerialPin()
			case "historical-revoked", "historical-expired":
				verifier = verifier.WithSerialPin().Historical()
			case "renewal-blind":
				verifier = verifier.RenewalBlind()
			}
			for _, c := range []*Client{a, b} {
				c.SetRecoveryClaimGate(func() bool { return true })
				c.SetClaimCertificateVerifier(func() *ClaimVerifier { return verifier })
			}
			oldRaw, _ := f.cert.Encode()
			nextRaw, _ := next.Encode()
			proof := *f.value.Proof
			proof.ClaimCertificate = oldRaw
			if err := WriteActionProof(ctx, a, proof); err != nil {
				t.Fatal(err)
			}
			proof.ClaimCertificate = nextRaw
			err := SetProofClaimCertificate(ctx, a, proof)
			allow := kind == "client-only" || kind == "no-pin" || kind == "historical-revoked" || kind == "renewal-blind" || kind == "no-pin-after-policy" || kind == "renewal-blind-after-policy"
			if allow && err != nil {
				t.Fatal("ordinary compatible certificate was refused", err)
			}
			if !allow && !errors.Is(err, ErrNoRowsAffected) {
				t.Fatalf("prepared writer ignored %s: %v", kind, err)
			}
			if err := WriteActionProof(ctx, b, proof); err != nil {
				t.Fatal(err)
			}
			if err := a.MergeSensitiveStateBytesLWW(b.DumpSensitiveStateBytes()); err != nil {
				t.Fatal(err)
			}
			if err := b.MergeSensitiveStateBytesLWW(a.DumpSensitiveStateBytes()); err != nil {
				t.Fatal(err)
			}
			want := oldRaw
			if allow {
				want = nextRaw
			}
			for _, c := range []*Client{a, b} {
				got, ok, err := GetActionProof(ctx, c, proof.ID)
				if err != nil || !ok || got.ClaimCertificate != want {
					t.Fatalf("prepared writer/AE winner ignored %s: %v", kind, err)
				}
			}
		})
	}
}

func TestPreparedProofFinalComparisonRechecksTimeAfterDBWait(t *testing.T) {
	for _, merge := range []bool{false, true} {
		t.Run(map[bool]string{false: "writer", true: "anti-entropy"}[merge], func(t *testing.T) {
			f := newCertFixture(t)
			ctx := context.Background()
			a, b := f.voters[0].c, f.voters[1].c
			adoptHandBuilt(t, 2, membersOf(f.voters...), f.voters...)
			for _, c := range []*Client{a, b} {
				c.SetRecoveryClaimGate(func() bool { return true })
			}
			next, expiry := preparedLaterCertificate(t, f, "expiry-after-wait")
			oldRaw, _ := f.cert.Encode()
			nextRaw, _ := next.Encode()
			proof := *f.value.Proof
			proof.ClaimCertificate = oldRaw
			if err := WriteActionProof(ctx, a, proof); err != nil {
				t.Fatal(err)
			}
			proof.ClaimCertificate = nextRaw
			if err := WriteActionProof(ctx, b, proof); err != nil {
				t.Fatal(err)
			}
			dump := b.DumpSensitiveStateBytes()
			locked := make(chan struct{})
			a.SetClaimCertificateVerifier(func() *ClaimVerifier { a.mu.Lock(); close(locked); return f.verifier })
			done := make(chan error, 1)
			go func() {
				if merge {
					done <- a.MergeSensitiveStateBytesLWW(dump)
				} else {
					done <- SetProofClaimCertificate(ctx, a, proof)
				}
			}()
			<-locked
			time.Sleep(time.Until(expiry) + 30*time.Millisecond)
			a.mu.Unlock()
			err := <-done
			if merge && err != nil {
				t.Fatal(err)
			}
			if !merge && !errors.Is(err, ErrNoRowsAffected) {
				t.Fatal("expired certificate won after DB wait", err)
			}
			got, ok, err := GetActionProof(ctx, a, proof.ID)
			if err != nil || !ok || got.ClaimCertificate != oldRaw {
				t.Fatal("final comparison froze certificate time before DB wait", err)
			}
		})
	}
}
