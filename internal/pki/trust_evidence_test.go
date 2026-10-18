package pki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Losing original PEM framing would break the signed evidence digest. Losing
// either incomparable CRL must refuse reconciliation even if serials overlap.
func TestCompletedTrustEvidenceRoundTrip(t *testing.T) {
	dir := setupPKI(t)
	ctx := context.Background()
	path := filepath.Join(dir, "ca.crt")
	root, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	root = append([]byte("\n"), root...)
	if err := os.WriteFile(path, root, 0600); err != nil {
		t.Fatal(err)
	}
	if err := GenerateCRL(path, filepath.Join(dir, "ca.key"), filepath.Join(dir, "crl.pem"), []string{"ab01"}); err != nil {
		t.Fatal(err)
	}
	v, err := CaptureHostTrust(ctx, dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := v.PublicEvidence()
	if err != nil {
		t.Fatal("actual captured public evidence unavailable:", err)
	}
	e, err := DecodeHostTrustEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	if e.Digest() != v.EvidenceDigest() || e.RootDigest() != v.RootDigest() {
		t.Fatal("exact evidence inputs lost")
	}
	if bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatal("private key escaped")
	}
	if err := ReconcileCompletedHostTrust(ctx, dir, "test-host", e); err != nil {
		t.Fatal("completed floor refused:", err)
	}
	if err := os.Remove(filepath.Join(dir, "crl.pem")); err != nil {
		t.Fatal(err)
	}
	if err := ReconcileCompletedHostTrust(ctx, dir, "test-host", e); err == nil {
		t.Fatal("missing established signed CRL accepted")
	}
}

func TestCompletedTrustEvidenceCoveringCRLUnion(t *testing.T) {
	dir := setupPKI(t)
	ctx := context.Background()
	ca, key, err := loadCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	makeCRL := func(number int64, serials ...int64) []byte {
		t.Helper()
		entries := make([]x509.RevocationListEntry, 0, len(serials))
		for _, serial := range serials {
			entries = append(entries, x509.RevocationListEntry{SerialNumber: big.NewInt(serial), RevocationTime: time.Now().Add(-time.Minute)})
		}
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour), RevokedCertificateEntries: entries}, ca, key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	}
	left, right := makeCRL(77, 101), makeCRL(77, 102)
	if _, _, err := InstallCRLs(dir, [][]byte{left, right}); err != nil {
		t.Fatal(err)
	}
	view, err := CaptureHostTrust(ctx, dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := view.PublicEvidence()
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := DecodeHostTrustEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.crls) != 2 {
		t.Fatal("historical incomparable signed branches were discarded")
	}
	for _, tc := range []struct {
		name string
		body []byte
		ok   bool
	}{
		{"equal-forks", append(bytes.Clone(left), right...), true},
		{"covering-newer", makeCRL(78, 101, 102, 103), true},
		{"higher-number-omits-branch", makeCRL(999, 101), false},
		{"missing-established", nil, false},
		{"corrupt-established", []byte("corrupt"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fresh := t.TempDir()
			for _, name := range []string{"ca.crt", "host.crt", "host.key"} {
				b, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(fresh, name), b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.body != nil {
				if err := os.WriteFile(filepath.Join(fresh, "crl.pem"), tc.body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := ReconcileCompletedHostTrust(ctx, fresh, "test-host", evidence)
			if (err == nil) != tc.ok {
				t.Fatalf("completed full-union reconciliation = %v want success %t", err, tc.ok)
			}
		})
	}
	if _, installed, err := InstallCRLs(dir, [][]byte{makeCRL(79, 101, 102, 103)}); err != nil || !installed {
		t.Fatal("supported covering installation refused", installed, err)
	}
	if err := ReconcileCompletedHostTrust(ctx, dir, "test-host", evidence); err != nil {
		t.Fatal("covering installation lost completed floor", err)
	}
	for _, write := range []func() error{
		func() error {
			return GenerateCRL(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), filepath.Join(dir, "crl.pem"), []string{"104"})
		},
		func() error {
			return AppendToCRL(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), filepath.Join(dir, "crl.pem"), "105")
		},
	} {
		if err := write(); err != nil {
			t.Fatal(err)
		}
		if err := ReconcileCompletedHostTrust(ctx, dir, "test-host", evidence); err != nil {
			t.Fatal("supported covering mint refused", err)
		}
	}
}

func TestCompletedTrustEvidenceSuccessorAndDurability(t *testing.T) {
	issuer := setupPKI(t)
	dir := observerPKI(t, issuer, "observer")
	if _, _, err := RenewLocal(filepath.Join(issuer, "ca.crt"), filepath.Join(issuer, "ca.key"), issuer, "test-host"); err != nil {
		t.Fatal(err)
	}
	cert, err := ServedHostCertificate(issuer)
	if err != nil {
		t.Fatal(err)
	}
	NoteSuccessor(dir, cert)
	ctx := context.Background()
	view, err := CaptureHostTrust(ctx, dir, "observer")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := view.PublicEvidence()
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := DecodeHostTrustEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	fresh := t.TempDir()
	for _, name := range []string{"ca.crt", "host.crt", "host.key"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fresh, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := ReconcileCompletedHostTrust(ctx, fresh, "observer", evidence); err == nil {
		t.Fatal("completed successor vanished on fresh owner")
	}
	NoteSuccessor(fresh, cert)
	if err := ReconcileCompletedHostTrust(ctx, fresh, "observer", evidence); err != nil {
		t.Fatal("supported durable successor repair did not progress", err)
	}
	t.Cleanup(func() { trustDurabilitySeam = nil })
	trustDurabilitySeam = func(string) error { return errors.New("durability unavailable") }
	if err := ReconcileCompletedHostTrust(ctx, fresh, "observer", evidence); err == nil {
		t.Fatal("failed durable reopen restored completed floors")
	}
	trustDurabilitySeam = nil
	if err := ReconcileCompletedHostTrust(ctx, fresh, "observer", evidence); err != nil {
		t.Fatal("repaired durable reopen refused", err)
	}
}

func TestCompletedTrustRecordedPeerDistinctFromServedLeaf(t *testing.T) {
	issuer := setupPKI(t)
	observer := observerPKI(t, issuer, "observer")
	view, err := CaptureHostTrust(context.Background(), observer, "observer")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := view.PublicEvidence()
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := DecodeHostTrustEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := ServedHostKeyPair(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if err := evidence.VerifyRecordedPeer(pair.Certificate, "test-host"); err != nil {
		t.Fatal("authentic distinct peer refused", err)
	}
	if err := evidence.VerifyRecordedHost(pair.Certificate, "test-host"); err == nil {
		t.Fatal("peer substituted for captured served leaf")
	}
	if err := evidence.VerifyRecordedPeer(pair.Certificate, "different-name"); err == nil {
		t.Fatal("wrong peer name accepted")
	}
	foreign := setupPKI(t)
	other, err := ServedHostKeyPair(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err := evidence.VerifyRecordedPeer(other.Certificate, "test-host"); err == nil {
		t.Fatal("foreign-domain peer accepted")
	}
}

func TestRecordedLocalHostInertExactIdentity(t *testing.T) {
	dir := setupPKI(t)
	view, err := CaptureHostTrust(context.Background(), dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := view.PublicEvidence()
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := DecodeHostTrustEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := evidence.RecordedLocalHost("test-host")
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "test-host" {
		t.Fatal("wrong recorded identity")
	}
	if _, err = evidence.RecordedLocalHost("peer"); err == nil {
		t.Fatal("peer substituted for local identity")
	}
	foreign := setupPKI(t)
	pair, err := ServedHostKeyPair(foreign)
	if err != nil {
		t.Fatal(err)
	}
	changed := *evidence
	changed.leaf = pair.Certificate[0]
	if _, err = changed.RecordedLocalHost("test-host"); err == nil {
		t.Fatal("same-name foreign signed root accepted")
	}
	changed = *evidence
	changed.leaf = bytes.Clone(evidence.leaf)
	changed.leaf[len(changed.leaf)-1] ^= 1
	if _, err = changed.RecordedLocalHost("test-host"); err == nil {
		t.Fatal("changed leaf signature accepted")
	}
}

func TestRecordedLocalHostRequiresCompleteLegacyChain(t *testing.T) {
	dir := setupPKI(t)
	view, err := CaptureHostTrust(context.Background(), dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := view.PublicEvidence()
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := DecodeHostTrustEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	ca, key, err := loadCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1234), Subject: pkix.Name{CommonName: "intermediate"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, template, ca, &intermediateKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(evidence.leaf)
	if err != nil {
		t.Fatal(err)
	}
	leaf.NotBefore = template.NotBefore
	leaf.NotAfter = template.NotAfter
	evidence.leaf, err = x509.CreateCertificate(rand.Reader, leaf, intermediate, leaf.PublicKey, intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = evidence.VerifyRecordedHost([][]byte{evidence.leaf, intermediateDER}, "test-host"); err != nil {
		t.Fatal("genuine full original chain refused", err)
	}
	if _, err = evidence.RecordedLocalHost("test-host"); err == nil {
		t.Fatal("legacy evidence silently invented missing intermediate")
	}
}
