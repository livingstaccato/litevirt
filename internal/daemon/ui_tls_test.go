package daemon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

// writeUICert installs a self-signed server certificate for node-0 as the
// custom UI pair, valid until notAfter, and returns its serial.
func writeUICert(t *testing.T, pkiDir string, notAfter time.Time) *big.Int {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial := big.NewInt(time.Now().UnixNano())
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "node-0"},
		DNSNames: []string{"node-0"}, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	for _, f := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{pki.UIKeyName, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600},
		{pki.UICertName, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644},
	} {
		tmp := filepath.Join(pkiDir, "."+f.name)
		if err := os.WriteFile(tmp, f.data, f.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, filepath.Join(pkiDir, f.name)); err != nil {
			t.Fatal(err)
		}
	}
	return serial
}

func uiPKI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateHostCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"),
		filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), "node-0", net.IPv4(127, 0, 0, 1)); err != nil {
		t.Fatal(err)
	}
	return dir
}

func served(t *testing.T, u *uiTLS) *x509.Certificate {
	t.Helper()
	c, err := u.getCertificate(&tls.ClientHelloInfo{ServerName: "node-0"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Leaf != nil {
		return c.Leaf
	}
	l, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// The custom certificate wins while installed, is replaced without a restart,
// and clearing it hands the UI back to the cluster certificate. Under
// ui_tls: auto the listener wants TLS exactly while a custom pair is installed.
//
// Mutations: drop the customPair branch in getCertificate — the cluster
// certificate is served over a custom one; make wantTLS ignore
// customInstalled — auto mode never switches to TLS.
func TestUITLS_CustomCertificateLifecycle(t *testing.T) {
	dir := uiPKI(t)
	u := newUITLS(dir, "auto")
	hostSerial := served(t, u).SerialNumber
	if u.wantTLS() {
		t.Fatal("auto mode wants TLS with no certificate source")
	}

	first := writeUICert(t, dir, time.Now().Add(90*24*time.Hour))
	if got := served(t, u).SerialNumber; got.Cmp(first) != 0 {
		t.Fatalf("served %s, want the custom certificate %s", got, first)
	}
	if !u.wantTLS() {
		t.Fatal("auto mode does not want TLS with a custom certificate installed")
	}

	second := writeUICert(t, dir, time.Now().Add(365*24*time.Hour))
	if got := served(t, u).SerialNumber; got.Cmp(second) != 0 {
		t.Fatalf("a replaced custom certificate was not picked up: served %s, want %s", got, second)
	}

	for _, f := range []string{pki.UICertName, pki.UIKeyName} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	if got := served(t, u).SerialNumber; got.Cmp(hostSerial) != 0 {
		t.Fatalf("a cleared custom certificate is still served (%s)", got)
	}
	if u.wantTLS() {
		t.Fatal("auto mode still wants TLS after the custom certificate was cleared")
	}
	if !newUITLS(dir, "on").wantTLS() {
		t.Fatal("ui_tls: on does not want TLS")
	}
}

// An expired custom certificate is not served when something valid can be.
//
// Mutation: drop the NotAfter check in customPair.
func TestUITLS_AnExpiredCustomCertificateFallsBack(t *testing.T) {
	dir := uiPKI(t)
	u := newUITLS(dir, "auto")
	hostSerial := served(t, u).SerialNumber
	// Valid when loaded, expired by the time it is asked for.
	writeUICert(t, dir, time.Now().Add(1500*time.Millisecond))
	_ = served(t, u)
	time.Sleep(2 * time.Second)
	if got := served(t, u).SerialNumber; got.Cmp(hostSerial) != 0 {
		t.Fatalf("served an expired custom certificate (%s)", got)
	}
}

// ACME answers when no custom certificate is installed, and the cluster
// certificate answers when ACME cannot.
func TestUITLS_ACMEThenClusterCertificate(t *testing.T) {
	dir := uiPKI(t)
	u := newUITLS(dir, "auto")
	acmeCert := &tls.Certificate{Leaf: &x509.Certificate{SerialNumber: big.NewInt(42)}}
	u.acmeOn = true
	u.acme = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if h.ServerName == "ui.example.test" {
			return acmeCert, nil
		}
		return nil, errors.New("not covered")
	}
	if c, err := u.getCertificate(&tls.ClientHelloInfo{ServerName: "ui.example.test"}); err != nil || c != acmeCert {
		t.Fatalf("ACME's certificate was not served: %v", err)
	}
	if got := served(t, u).SerialNumber; got.Int64() == 42 {
		t.Fatal("ACME's certificate was served for a name it does not cover")
	}
	if !u.wantTLS() {
		t.Fatal("ACME configured but TLS not wanted")
	}
	custom := writeUICert(t, dir, time.Now().Add(90*24*time.Hour))
	if c, _ := u.getCertificate(&tls.ClientHelloInfo{ServerName: "ui.example.test"}); c.Leaf.SerialNumber.Cmp(custom) != 0 {
		t.Fatal("a custom certificate does not take precedence over ACME")
	}
}

// The expiry watch covers the custom certificate while it is installed.
func TestCertWatch_ReportsTheUICertificate(t *testing.T) {
	dir := uiPKI(t)
	u := newUITLS(dir, "auto")
	n := &recordingNotifier{}
	w := &certWatch{host: "node-0", notifier: n, alerts: map[string]certAlert{}}
	w.addUI(u)
	w.tick(t.Context(), time.Now())
	if len(n.got) != 0 {
		t.Fatalf("notified with no UI certificate installed: %v", n.got)
	}
	writeUICert(t, dir, time.Now().Add(10*24*time.Hour))
	w.tick(t.Context(), time.Now())
	if len(n.got) != 1 || n.got[0] != "certificate.expiring/warn/node-0/ui" {
		t.Fatalf("got %v, want one ui warning", n.got)
	}
}
