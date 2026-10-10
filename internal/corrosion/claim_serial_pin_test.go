package corrosion

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

// renewVoter renews v's certificate in place and returns a signer for the
// successor.
func renewVoter(t *testing.T, f *certFixture, v *claimTestVoter) *ClaimSigner {
	t.Helper()
	if _, _, err := pki.RenewLocal(f.ca.cert, f.ca.key, v.pki, v.name); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(v.pki, "host.crt"), filepath.Join(v.pki, "host.key"))
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := ClaimSignerFromKeyPair(v.name, leafed(t, &pair))
	if err != nil {
		t.Fatal(err)
	}
	return renewed
}

// The serial pin (§3.10 step 5): an accept signed with a certificate the CA
// has replaced does not count. Its only authority is the CA-signed successor —
// here collected from the renewed voter's own accept, as a node collects it
// from a handshake — and no replicated row enters into it. Without that
// proof nothing is refused; history is never pinned; and a successor the CA
// revoked unused (an abandoned renewal) hands the identity back.
//
// Mutations: make pinRefuses return nil (the replaced key's accept counts);
// drop noteSuccessors from Verify (the successor in the row proves nothing,
// so the replaced key's accept counts); pin historical verification (history
// signed with the old key stops verifying); ignore a revoked successor in
// pki.SupersededBy (the abandoned renewal keeps the old certificate refused).
func TestClaimVerifier_SerialPin(t *testing.T) {
	f := newCertFixture(t)
	a := f.voters[0]
	pinned := f.verifier.WithSerialPin()
	if err := pinned.Verify(f.cert, f.want); err != nil {
		t.Fatalf("accepts signed with current certificates were refused: %v", err)
	}

	renewed := renewVoter(t, f, a)
	if err := pinned.Verify(f.cert, f.want); err != nil {
		t.Fatalf("refused with no CA proof of a replacement held: %v", err)
	}

	// The renewed voter's accept carries its successor certificate: that is
	// the CA's proof a's previous certificate is replaced.
	acc, err := renewed.Sign(f.cert.Key, f.cert.ConfigGeneration, f.cert.Ballot, f.cert.ValueDigest, a.inc)
	if err != nil {
		t.Fatal(err)
	}
	withNew := f.cert
	withNew.Accepts = []ClaimAccept{acc, f.cert.Accepts[1]}
	if err := pinned.Verify(withNew, f.want); err != nil {
		t.Fatalf("the renewed voter's accept was refused: %v", err)
	}
	if err := pinned.Verify(f.cert, f.want); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("an accept signed with a replaced key counted: %v", err)
	}
	if err := pinned.Historical().Verify(f.cert, f.want); err != nil {
		t.Fatalf("history signed before the renewal stopped verifying: %v", err)
	}
	if err := f.verifier.Verify(f.cert, f.want); err != nil {
		t.Fatalf("the unpinned verifier changed: %v", err)
	}

	// The CA revokes the successor unused: the renewal was abandoned and a's
	// previous certificate is its identity again.
	if err := pki.GenerateCRL(f.ca.cert, f.ca.key, filepath.Join(f.verifier.pkiDir, "crl.pem"),
		[]string{renewed.Serial()}); err != nil {
		t.Fatal(err)
	}
	if err := pinned.Verify(f.cert, f.want); err != nil {
		t.Fatalf("an abandoned renewal kept the certificate it would have replaced refused: %v", err)
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

// The destination check pins whatever its replica's hosts rows say: once it
// holds the CA's proof that a voter's certificate was replaced, an accept
// signed with it does not count — even with hosts.cert_serial written back to
// the replaced serial, which any peer can do. The recovery switch
// (WithoutSerialPin) turns the pin off.
//
// Mutation: drop the WithSerialPin wrapping in VerifyClaimCertificate — the
// accept signed with the replaced certificate counts.
func TestVerifyClaimCertificate_PinsReplacedCertificatesWhateverTheRowSays(t *testing.T) {
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
		t.Fatalf("accepts signed with current certificates were refused: %v", err)
	}
	renewed := renewVoter(t, f, f.voters[0])
	succ, err := pki.ParseCertPEM([]byte(renewed.certPEM))
	if err != nil {
		t.Fatal(err)
	}
	pki.NoteSuccessor(f.verifier.pkiDir, succ)
	// The row still names (or was written back to) the replaced serial.
	if err := dest.c.Execute(ctx, recordOwnCertSerialSQL, f.voters[0].signer.Serial(), dest.c.NowTS(), "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyClaimCertificate(ctx, dest.c, f.verifier, proof); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("an accept signed with a replaced certificate counted because the row names it: %v", err)
	}
	if _, err := VerifyClaimCertificate(ctx, dest.c, f.verifier.WithoutSerialPin(), proof); err != nil {
		t.Fatalf("the recovery switch did not turn the pin off: %v", err)
	}
}
