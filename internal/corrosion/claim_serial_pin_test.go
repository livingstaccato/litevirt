package corrosion

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

// The serial pin (§3.10 step 5): an accept counts only when signed with the
// certificate recorded for its voter, or that certificate's CA-attested
// successor. A renewed voter's REPLACED key — whose revocation the voter chain
// may hold — signs nothing that counts. History is not pinned.
//
// Mutations: drop pinRefuses from verifyAccept (the replaced key's accept
// counts); drop the successor clause in pinRefuses (the renewed voter's accept
// is refused while the record still names its predecessor); pin historical
// verification (history signed with the old key stops verifying).
func TestClaimVerifier_SerialPin(t *testing.T) {
	f := newCertFixture(t)
	a, b := f.voters[0], f.voters[1]
	rec := map[string]string{"a": a.signer.Serial(), "b": b.signer.Serial(), "c": f.voters[2].signer.Serial()}
	var lookupErr error
	pinned := f.verifier.PinnedTo(func(n string) (string, bool, error) {
		s, ok := rec[n]
		return s, ok, lookupErr
	})
	if err := pinned.Verify(f.cert, f.want); err != nil {
		t.Fatalf("accepts signed with the recorded certificates were refused: %v", err)
	}

	// a renews; the record moves on. Its old-key accept no longer counts.
	if _, _, err := pki.RenewLocal(f.ca.cert, f.ca.key, a.pki, "a"); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(a.pki, "host.crt"), filepath.Join(a.pki, "host.key"))
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := ClaimSignerFromKeyPair("a", leafed(t, &pair))
	if err != nil {
		t.Fatal(err)
	}
	rec["a"] = renewed.Serial()
	if err := pinned.Verify(f.cert, f.want); err == nil || !strings.Contains(err.Error(), "recorded") {
		t.Fatalf("an accept signed with a replaced key counted: %v", err)
	}
	if err := pinned.Historical().Verify(f.cert, f.want); err != nil {
		t.Fatalf("history signed before the renewal stopped verifying: %v", err)
	}
	if err := f.verifier.Verify(f.cert, f.want); err != nil {
		t.Fatalf("the unpinned verifier changed: %v", err)
	}

	// The record still names the predecessor: the successor's accept counts.
	rec["a"] = a.signer.Serial()
	acc, err := renewed.Sign(f.cert.Key, f.cert.ConfigGeneration, f.cert.Ballot, f.cert.ValueDigest, a.inc)
	if err != nil {
		t.Fatal(err)
	}
	c := f.cert
	c.Accepts = []ClaimAccept{acc, f.cert.Accepts[1]}
	if err := pinned.Verify(c, f.want); err != nil {
		t.Fatalf("the successor of the recorded certificate was refused: %v", err)
	}

	// An unreadable record refuses.
	lookupErr = errors.New("database locked")
	if err := pinned.Verify(f.cert, f.want); err == nil {
		t.Fatal("verified although the recorded serials could not be read")
	}
}

// WithRevoked answers "would this still verify with these revoked?" without
// touching the installed CRL.
//
// Mutation: ignore extraRevoked in revoked().
func TestClaimVerifier_WithRevoked(t *testing.T) {
	f := newCertFixture(t)
	if err := f.verifier.WithRevoked(f.voters[0].signer.Serial()).Verify(f.cert, f.want); err == nil {
		t.Fatal("verified with a signer's certificate treated as revoked")
	}
	if err := f.verifier.WithRevoked(f.voters[2].signer.Serial()).Verify(f.cert, f.want); err != nil {
		t.Fatalf("revoking a non-signer broke verification: %v", err)
	}
	if err := f.verifier.Verify(f.cert, f.want); err != nil {
		t.Fatalf("WithRevoked changed the original verifier: %v", err)
	}
}

func leafed(t *testing.T, p *tls.Certificate) *tls.Certificate {
	t.Helper()
	l, err := x509.ParseCertificate(p.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	p.Leaf = l
	return p
}

// The destination check pins on its own replica's hosts rows: an accept whose
// certificate is not the one recorded for its voter does not count, and the
// recovery switch (WithoutSerialPin) turns that off.
//
// Mutation: drop the PinnedTo wrapping in VerifyClaimCertificate — the accept
// signed with a no-longer-recorded certificate counts.
func TestVerifyClaimCertificate_PinsToRecordedSerials(t *testing.T) {
	ctx := context.Background()
	f := newCertFixture(t)
	dest := f.voters[2]
	enc, err := f.cert.Encode()
	if err != nil {
		t.Fatal(err)
	}
	proof := *f.value.Proof
	proof.ClaimCertificate = enc
	for _, v := range f.voters {
		if err := InsertHost(ctx, dest.c, HostRecord{Name: v.name, Address: "10.0.0.1", State: "active",
			CertSerial: v.signer.Serial()}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := VerifyClaimCertificate(ctx, dest.c, f.verifier, proof); err != nil {
		t.Fatalf("accepts signed with the recorded certificates were refused: %v", err)
	}
	if err := dest.c.Execute(ctx, recordOwnCertSerialSQL, "0123456789abcdef", dest.c.NowTS(), "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyClaimCertificate(ctx, dest.c, f.verifier, proof); err == nil || !strings.Contains(err.Error(), "recorded") {
		t.Fatalf("an accept signed with a certificate no longer recorded counted: %v", err)
	}
	if _, err := VerifyClaimCertificate(ctx, dest.c, f.verifier.WithoutSerialPin(), proof); err != nil {
		t.Fatalf("the recovery switch did not turn the pin off: %v", err)
	}
}
