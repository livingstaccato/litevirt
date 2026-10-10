package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

func writeLocalUICert(t *testing.T, dnsNames []string, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "hv-b"},
		DNSNames: dnsNames, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "chain.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// A valid certificate lands as ui.crt + ui.key (0600) and leaves no backup or
// staged copy of the key behind; clear removes both.
//
// Mutation: install ui.key with mode 0644 — the mode check fails.
func TestHostUICert_SetInstallsAndClearRemoves(t *testing.T) {
	host := t.TempDir()
	r := &dirTarget{Dir: host}
	crt, key := writeLocalUICert(t, []string{"node-b", "hv-b.corp.example"}, time.Now().Add(90*24*time.Hour))
	if err := hostUICertSet(r, "node-b", "10.0.50.11", UICertOptions{CertPath: crt, KeyPath: key}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(host, pki.UIKeyName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("ui.key is mode %04o", fi.Mode().Perm())
	}
	if _, err := pki.UICertSource(host).Get(); err != nil {
		t.Fatalf("the daemon would not serve what was installed: %v", err)
	}
	entries, _ := os.ReadDir(host)
	if len(entries) != 2 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("left extra files beside the pair: %v", names)
	}
	if err := hostUICertClear(r, "node-b"); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(host); len(entries) != 0 {
		t.Fatalf("clear left %d files", len(entries))
	}
}

// Anything the validation refuses is never sent: the host is untouched.
//
// Mutation: skip ValidateServingChain — the expired certificate is installed.
func TestHostUICert_RefusedCertificateTouchesNothing(t *testing.T) {
	host := t.TempDir()
	r := &dirTarget{Dir: host}
	for name, tc := range map[string]struct {
		dns      []string
		notAfter time.Time
		names    []string
	}{
		"expired":          {[]string{"node-b"}, time.Now().Add(-time.Hour), nil},
		"wrong host":       {[]string{"elsewhere.corp.example"}, time.Now().Add(time.Hour), nil},
		"stated name miss": {[]string{"node-b"}, time.Now().Add(time.Hour), []string{"hv-b.corp.example"}},
	} {
		crt, key := writeLocalUICert(t, tc.dns, tc.notAfter)
		if err := hostUICertSet(r, "node-b", "10.0.50.11", UICertOptions{CertPath: crt, KeyPath: key, Names: tc.names}); err == nil {
			t.Errorf("%s: installed", name)
		}
		if entries, _ := os.ReadDir(host); len(entries) != 0 {
			t.Fatalf("%s: a refused certificate left %d files on the host", name, len(entries))
		}
	}
}
