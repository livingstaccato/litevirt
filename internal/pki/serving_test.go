package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// corpPKI is a three-level corporate PKI: root -> intermediate -> leaf.
type corpPKI struct {
	root, inter, leaf          *x509.Certificate
	rootKey, interKey, leafKey crypto.Signer
}

type leafOpts struct {
	dns       []string
	ips       []net.IP
	notBefore time.Time
	notAfter  time.Time
	isCA      bool
	eku       []x509.ExtKeyUsage
	key       crypto.Signer
}

func mustCert(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newCorpPKI(t *testing.T, o leafOpts) *corpPKI {
	t.Helper()
	p := &corpPKI{}
	now := time.Now()
	p.rootKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Corp Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	p.root = mustCert(t, rootT, rootT, p.rootKey.Public(), p.rootKey)
	p.interKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Corp Issuing CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	p.inter = mustCert(t, interT, p.root, p.interKey.Public(), p.rootKey)
	if o.key == nil {
		o.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	p.leafKey = o.key
	if o.notBefore.IsZero() {
		o.notBefore = now.Add(-time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = now.Add(365 * 24 * time.Hour)
	}
	if o.eku == nil {
		o.eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	leafT := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "hv-b"},
		DNSNames: o.dns, IPAddresses: o.ips, NotBefore: o.notBefore, NotAfter: o.notAfter,
		ExtKeyUsage: o.eku, KeyUsage: x509.KeyUsageDigitalSignature, IsCA: o.isCA, BasicConstraintsValid: o.isCA}
	p.leaf = mustCert(t, leafT, p.inter, o.key.Public(), p.interKey)
	return p
}

func pemOf(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

func keyPEMOf(t *testing.T, k crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

var hostNames = ServingCertCheck{AnyOf: []string{"node-b", "10.0.50.11"}}

func TestValidateServingChain_AcceptsAnOrderedCorporateChain(t *testing.T) {
	p := newCorpPKI(t, leafOpts{dns: []string{"hv-b.corp.example", "node-b"}})
	leaf, err := ValidateServingChain(pemOf(p.leaf, p.inter), keyPEMOf(t, p.leafKey), hostNames)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "hv-b" {
		t.Fatalf("returned %s, want the leaf", leaf.Subject)
	}
	// With the root appended too.
	if _, err := ValidateServingChain(pemOf(p.leaf, p.inter, p.root), keyPEMOf(t, p.leafKey), hostNames); err != nil {
		t.Fatal(err)
	}
	// Operator-stated names must ALL be covered.
	if _, err := ValidateServingChain(pemOf(p.leaf, p.inter), keyPEMOf(t, p.leafKey),
		ServingCertCheck{AllOf: []string{"hv-b.corp.example"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateServingChain(pemOf(p.leaf, p.inter), keyPEMOf(t, p.leafKey),
		ServingCertCheck{AllOf: []string{"hv-b.corp.example", "other.corp.example"}}); err == nil {
		t.Fatal("accepted a certificate that does not cover a stated name")
	}
}

// Each property the installer promises to check, broken one at a time.
//
// Mutations (each turns its case green): drop the CheckSignatureFrom order
// check (wrong order / missing intermediate); drop the NotAfter check
// (expired); drop the leaf.IsCA check; drop the serverAuth EKU check; drop
// checkKeyStrength's RSA floor; drop checkCoverage.
func TestValidateServingChain_RefusesEachDefect(t *testing.T) {
	now := time.Now()
	ok := leafOpts{dns: []string{"node-b"}}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		opts  leafOpts
		chain func(p *corpPKI) []byte
		key   func(p *corpPKI) crypto.Signer
		want  string
	}{
		{"key mismatch", ok, func(p *corpPKI) []byte { return pemOf(p.leaf, p.inter) },
			func(*corpPKI) crypto.Signer { return other }, "do not form a pair"},
		{"wrong order", ok, func(p *corpPKI) []byte { return pemOf(p.leaf, p.root, p.inter) }, nil, "in order"},
		{"missing intermediate", ok, func(p *corpPKI) []byte { return pemOf(p.leaf, p.root) }, nil, "in order"},
		{"leaf not first", ok, func(p *corpPKI) []byte { return pemOf(p.inter, p.leaf) },
			func(p *corpPKI) crypto.Signer { return p.interKey }, "CA certificate"},
		{"expired", leafOpts{dns: []string{"node-b"}, notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-time.Hour)},
			func(p *corpPKI) []byte { return pemOf(p.leaf, p.inter) }, nil, "expired"},
		{"not yet valid", leafOpts{dns: []string{"node-b"}, notBefore: now.Add(time.Hour), notAfter: now.Add(48 * time.Hour)},
			func(p *corpPKI) []byte { return pemOf(p.leaf, p.inter) }, nil, "not valid until"},
		{"client-only EKU", leafOpts{dns: []string{"node-b"}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
			func(p *corpPKI) []byte { return pemOf(p.leaf, p.inter) }, nil, "server authentication"},
		{"weak RSA", leafOpts{dns: []string{"node-b"}, key: weak},
			func(p *corpPKI) []byte { return pemOf(p.leaf, p.inter) }, nil, "2048"},
		{"names not covered", leafOpts{dns: []string{"elsewhere.corp.example"}},
			func(p *corpPKI) []byte { return pemOf(p.leaf, p.inter) }, nil, "covers none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newCorpPKI(t, tc.opts)
			k := p.leafKey
			if tc.key != nil {
				k = tc.key(p)
			}
			_, err := ValidateServingChain(tc.chain(p), keyPEMOf(t, k), hostNames)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// An IP SAN covers the host's address, and an error never prints key bytes.
func TestValidateServingChain_IPSANAndNoKeyInErrors(t *testing.T) {
	p := newCorpPKI(t, leafOpts{ips: []net.IP{net.ParseIP("10.0.50.11")}})
	if _, err := ValidateServingChain(pemOf(p.leaf, p.inter), keyPEMOf(t, p.leafKey), hostNames); err != nil {
		t.Fatal(err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyPEM := keyPEMOf(t, other)
	_, err := ValidateServingChain(pemOf(p.leaf, p.inter), keyPEM, hostNames)
	body := strings.Join(strings.Split(string(keyPEM), "\n")[1:3], "")
	if err == nil || strings.Contains(err.Error(), body[:20]) {
		t.Fatalf("error leaks key material or is nil: %v", err)
	}
}

// The daemon's source applies the same structural checks on its FIRST load:
// a chain written by hand in the wrong order is never served.
//
// Mutation: apply pairCheck only after the first load — the shuffled chain is
// served.
func TestUICertSource_RefusesABadChainOnFirstLoad(t *testing.T) {
	dir := t.TempDir()
	p := newCorpPKI(t, leafOpts{dns: []string{"node-b"}})
	if err := os.WriteFile(filepath.Join(dir, UICertName), pemOf(p.leaf, p.root, p.inter), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, UIKeyName), keyPEMOf(t, p.leafKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := UICertSource(dir).Get(); err == nil {
		t.Fatal("a shuffled chain loaded")
	}
	if err := os.WriteFile(filepath.Join(dir, UICertName), pemOf(p.leaf, p.inter), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := UICertSource(dir).Get()
	if err != nil || c.Leaf == nil || c.Leaf.Subject.CommonName != "hv-b" {
		t.Fatalf("a good chain did not load: %v", err)
	}
}
