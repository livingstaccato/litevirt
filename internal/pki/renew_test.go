package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readLeaf(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCertPEM(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func csrFor(t *testing.T, key any, cn string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn},
		DNSNames: []string{"evil.example"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// A renewal keeps the identity — subject, SANs, usages — over the REQUESTED
// key, gets a full lifetime, and names its predecessor. Names the request asks
// for are ignored.
func TestSignRenewal_KeepsTheIdentityAndNamesThePredecessor(t *testing.T) {
	dir := setupPKI(t)
	prev := readLeaf(t, filepath.Join(dir, "host.crt"))
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certPEM, err := SignRenewal(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), prev, "test-host", csrFor(t, key, "test-host"))
	if err != nil {
		t.Fatal(err)
	}
	next, err := ParseCertPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !next.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("the certificate is not for the requested key")
	}
	if next.SerialNumber.Cmp(prev.SerialNumber) == 0 {
		t.Fatal("the renewal reused the serial")
	}
	if next.Subject.CommonName != "test-host" || strings.Join(next.DNSNames, ",") != strings.Join(prev.DNSNames, ",") {
		t.Fatalf("subject/DNS SANs changed (or the request's names were taken): %v %v", next.Subject, next.DNSNames)
	}
	if len(next.IPAddresses) != len(prev.IPAddresses) || !next.IPAddresses[0].Equal(prev.IPAddresses[0]) {
		t.Fatalf("IP SANs changed: %v -> %v", prev.IPAddresses, next.IPAddresses)
	}
	if !hasUsage(next, x509.ExtKeyUsageServerAuth) || !hasUsage(next, x509.ExtKeyUsageClientAuth) || next.IsCA {
		t.Fatal("the renewal is not a host certificate")
	}
	if time.Until(next.NotAfter) < 4*365*24*time.Hour {
		t.Fatalf("the renewal does not get a full lifetime: %s", next.NotAfter)
	}
	got, ok := RenewedFromSerial(next)
	if !ok || got != strings.ToLower(prev.SerialNumber.Text(16)) {
		t.Fatalf("RenewedFromSerial = %q, %v; want %s", got, ok, prev.SerialNumber.Text(16))
	}
	if _, ok := RenewedFromSerial(prev); ok {
		t.Fatal("a first-issue certificate reads as a renewal")
	}
	pool := x509.NewCertPool()
	pool.AddCert(readLeaf(t, filepath.Join(dir, "ca.crt")))
	if _, err := next.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("an unknown non-critical extension must not break verification: %v", err)
	}
}

// Signing refuses what is not this CA's host certificate for this host, a
// request its key did not sign, a key of the wrong kind, and the old key.
//
// Mutation: drop csr.CheckSignature — the tampered request is signed.
func TestSignRenewal_Refusals(t *testing.T) {
	dir := setupPKI(t)
	ca, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	prev := readLeaf(t, filepath.Join(dir, "host.crt"))
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	good := csrFor(t, key, "test-host")
	if _, err := SignRenewal(ca, caKey, prev, "other-host", good); err == nil {
		t.Error("renewed another host's certificate under a different name")
	}
	other := t.TempDir()
	if err := GenerateCA(filepath.Join(other, "ca.crt"), filepath.Join(other, "ca.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := SignRenewal(filepath.Join(other, "ca.crt"), filepath.Join(other, "ca.key"), prev, "test-host", good); err == nil {
		t.Error("renewed a certificate another CA issued")
	}
	cli := filepath.Join(dir, "client.crt")
	if err := GenerateClientCert(ca, caKey, cli, filepath.Join(dir, "client.key"), "test-host"); err != nil {
		t.Fatal(err)
	}
	if _, err := SignRenewal(ca, caKey, readLeaf(t, cli), "test-host", good); err == nil {
		t.Error("renewed a client certificate into a host certificate")
	}
	block, _ := pem.Decode(good)
	bad := append([]byte(nil), block.Bytes...)
	bad[len(bad)-5] ^= 0xff // corrupt the signature
	if _, err := SignRenewal(ca, caKey, prev, "test-host", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: bad})); err == nil {
		t.Error("signed a request its key did not sign")
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := SignRenewal(ca, caKey, prev, "test-host", csrFor(t, rk, "test-host")); err == nil {
		t.Error("signed an RSA key the claim signer cannot use")
	}
	hostKey, err := loadPairChecked(filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignRenewal(ca, caKey, prev, "test-host", csrFor(t, hostKey.PrivateKey, "test-host")); err == nil {
		t.Error("renewed onto the installed key")
	}
}

// The local renewal path is adopted by the running identity source: same CA,
// same CN, the new key generated on this host.
func TestRenewLocal_IsAdoptedByTheRunningIdentity(t *testing.T) {
	dir := setupPKI(t)
	src := hostIdentitySource(dir)
	prev, err := src.Leaf()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := RenewLocal(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), dir, "test-host"); err != nil {
		t.Fatal(err)
	}
	now, err := src.Leaf()
	if err != nil {
		t.Fatal(err)
	}
	if from, ok := RenewedFromSerial(now); !ok || from != strings.ToLower(prev.SerialNumber.Text(16)) {
		t.Fatalf("the running identity did not adopt the renewal (serving %s)", now.SerialNumber.Text(16))
	}
}
