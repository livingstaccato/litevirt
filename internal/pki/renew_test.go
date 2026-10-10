package pki

import (
	"crypto/tls"
	"crypto/x509"
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

// A renewal keeps the identity — subject, SANs, usages — gets a new key and a
// full lifetime, and names its predecessor.
func TestRenewHostCert_KeepsTheIdentityAndNamesThePredecessor(t *testing.T) {
	dir := setupPKI(t)
	prev := readLeaf(t, filepath.Join(dir, "host.crt"))
	certPEM, keyPEM, err := RenewHostCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), prev, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("renewed cert and key do not match: %v", err)
	}
	next, _ := x509.ParseCertificate(pair.Certificate[0])
	if next.SerialNumber.Cmp(prev.SerialNumber) == 0 {
		t.Fatal("the renewal reused the serial")
	}
	if next.Subject.CommonName != "test-host" || strings.Join(next.DNSNames, ",") != strings.Join(prev.DNSNames, ",") {
		t.Fatalf("subject/DNS SANs changed: %v %v", next.Subject, next.DNSNames)
	}
	if len(next.IPAddresses) != len(prev.IPAddresses) || !next.IPAddresses[0].Equal(prev.IPAddresses[0]) {
		t.Fatalf("IP SANs changed: %v -> %v", prev.IPAddresses, next.IPAddresses)
	}
	if !hasUsage(next, x509.ExtKeyUsageServerAuth) || !hasUsage(next, x509.ExtKeyUsageClientAuth) {
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

// Renewal refuses what is not this CA's host certificate for this host.
func TestRenewHostCert_RefusesAnotherHostOrAnotherCA(t *testing.T) {
	dir := setupPKI(t)
	prev := readLeaf(t, filepath.Join(dir, "host.crt"))
	if _, _, err := RenewHostCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), prev, "other-host"); err == nil {
		t.Fatal("renewed another host's certificate under a different name")
	}
	other := t.TempDir()
	if err := GenerateCA(filepath.Join(other, "ca.crt"), filepath.Join(other, "ca.key")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RenewHostCert(filepath.Join(other, "ca.crt"), filepath.Join(other, "ca.key"), prev, "test-host"); err == nil {
		t.Fatal("renewed a certificate another CA issued")
	}
	cli := filepath.Join(dir, "client.crt")
	if err := GenerateClientCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), cli, filepath.Join(dir, "client.key"), "test-host"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RenewHostCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), readLeaf(t, cli), "test-host"); err == nil {
		t.Fatal("renewed a client certificate into a host certificate")
	}
}

// The renewed pair is adopted by the running identity source: same CA, same CN.
func TestRenewHostCert_IsAdoptedByTheRunningIdentity(t *testing.T) {
	dir := setupPKI(t)
	src := hostIdentitySource(dir)
	prev, err := src.Leaf()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := RenewHostCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), prev, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".k"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".c"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Rename(filepath.Join(dir, ".k"), filepath.Join(dir, "host.key"))
	_ = os.Rename(filepath.Join(dir, ".c"), filepath.Join(dir, "host.crt"))
	now, err := src.Leaf()
	if err != nil {
		t.Fatal(err)
	}
	if from, ok := RenewedFromSerial(now); !ok || from != strings.ToLower(prev.SerialNumber.Text(16)) {
		t.Fatalf("the running identity did not adopt the renewal (serving %s)", now.SerialNumber.Text(16))
	}
}
