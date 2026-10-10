package acmedns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// memDNS is a Provider over a map, standing in for the zone.
type memDNS struct {
	mu      sync.Mutex
	txt     map[string][]string
	removed int
	// prefix replaces "_acme-challenge." when set — the mutation hook for a
	// provider writing the wrong owner name.
	present func(fqdn string) string
}

func (m *memDNS) Present(_ context.Context, fqdn, v string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.present != nil {
		fqdn = m.present(fqdn)
	}
	m.txt[fqdn] = append(m.txt[fqdn], v)
	return nil
}

func (m *memDNS) CleanUp(_ context.Context, fqdn, v string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.present != nil {
		fqdn = m.present(fqdn)
	}
	kept := m.txt[fqdn][:0]
	for _, x := range m.txt[fqdn] {
		if x != v {
			kept = append(kept, x)
		}
	}
	m.txt[fqdn] = kept
	m.removed++
	return nil
}

func (m *memDNS) Visible(_ context.Context, fqdn, v string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.present != nil {
		fqdn = m.present(fqdn)
	}
	for _, x := range m.txt[fqdn] {
		if x == v {
			return true, nil
		}
	}
	return false, nil
}

func (m *memDNS) has(fqdn, v string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.txt[fqdn] {
		if x == v {
			return true
		}
	}
	return false
}

// fakeCA is a minimal RFC 8555 server: it validates dns-01 by reading memDNS
// for base64url(sha256(token "." thumbprint)) at _acme-challenge.<name>.
type fakeCA struct {
	t      *testing.T
	srv    *httptest.Server
	dns    *memDNS
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate

	mu        sync.Mutex
	thumb     string
	ids       []string // authorization identifiers (a wildcard's base)
	wild      []bool
	reqIDs    []string // identifiers as ordered
	authz     []string // status per identifier
	rename    string   // when set, every authorization names this instead (a hostile CA)
	finalized bool
	certPEM   []byte
	issued    int
}

func newFakeCA(t *testing.T, d *memDNS) *fakeCA {
	t.Helper()
	ca := &fakeCA{t: t, dns: d}
	ca.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake ACME CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ca.caKey.PublicKey, ca.caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca.caCert, _ = x509.ParseCertificate(der)
	ca.srv = httptest.NewServer(http.HandlerFunc(ca.serve))
	t.Cleanup(ca.srv.Close)
	return ca
}

func (ca *fakeCA) url(p string) string { return ca.srv.URL + p }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (ca *fakeCA) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("n%d", time.Now().UnixNano()))
	if r.URL.Path == "/dir" {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce": ca.url("/nonce"), "newAccount": ca.url("/acct"), "newOrder": ca.url("/order")})
		return
	}
	if r.URL.Path == "/nonce" {
		w.WriteHeader(http.StatusOK)
		return
	}
	var jws struct{ Protected, Payload string }
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &jws)
	prot, _ := base64.RawURLEncoding.DecodeString(jws.Protected)
	payload, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
	ca.mu.Lock()
	defer ca.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch p := r.URL.Path; {
	case p == "/acct":
		var h struct {
			JWK struct{ Crv, Kty, X, Y string } `json:"jwk"`
		}
		_ = json.Unmarshal(prot, &h)
		x, _ := base64.RawURLEncoding.DecodeString(h.JWK.X)
		y, _ := base64.RawURLEncoding.DecodeString(h.JWK.Y)
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if ca.thumb == "" {
			ca.thumb, _ = acme.JWKThumbprint(pub)
		}
		w.Header().Set("Location", ca.url("/acct/1"))
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"valid"}`))
	case p == "/order":
		var req struct {
			Identifiers []struct{ Type, Value string }
		}
		_ = json.Unmarshal(payload, &req)
		ca.ids, ca.wild, ca.reqIDs, ca.authz, ca.finalized = nil, nil, nil, nil, false
		for _, id := range req.Identifiers {
			base := strings.TrimPrefix(id.Value, "*.")
			if ca.rename != "" {
				base = ca.rename
			}
			ca.ids = append(ca.ids, base)
			ca.wild = append(ca.wild, strings.HasPrefix(id.Value, "*."))
			ca.reqIDs = append(ca.reqIDs, id.Value)
			ca.authz = append(ca.authz, "pending")
		}
		w.Header().Set("Location", ca.url("/order/1"))
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(ca.orderLocked())
	case p == "/order/1":
		w.Header().Set("Location", ca.url("/order/1"))
		_ = json.NewEncoder(w).Encode(ca.orderLocked())
	case strings.HasPrefix(p, "/authz/"):
		var n int
		fmt.Sscanf(p, "/authz/%d", &n)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": ca.authz[n], "identifier": map[string]string{"type": "dns", "value": ca.ids[n]}, "wildcard": ca.wild[n],
			"challenges": []map[string]string{{"type": "dns-01", "url": ca.url(fmt.Sprintf("/chal/%d", n)),
				"token": fmt.Sprintf("tok%d", n), "status": ca.authz[n]}},
		})
	case strings.HasPrefix(p, "/chal/"):
		var n int
		fmt.Sscanf(p, "/chal/%d", &n)
		sum := sha256.Sum256([]byte(fmt.Sprintf("tok%d.%s", n, ca.thumb)))
		if ca.dns.has("_acme-challenge."+ca.ids[n]+".", b64(sum[:])) {
			ca.authz[n] = "valid"
		} else {
			ca.authz[n] = "invalid"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"type": "dns-01", "url": ca.url(p),
			"token": fmt.Sprintf("tok%d", n), "status": ca.authz[n]})
	case p == "/finalize/1":
		var req struct{ CSR string }
		_ = json.Unmarshal(payload, &req)
		der, _ := base64.RawURLEncoding.DecodeString(req.CSR)
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// As Boulder does: the CN counts as a requested name, and every name
		// in the request must be one the order authorised.
		names := map[string]bool{}
		for _, id := range ca.reqIDs {
			names[id] = true
		}
		for _, n := range append([]string{csr.Subject.CommonName}, csr.DNSNames...) {
			if n != "" && !names[n] {
				http.Error(w, `{"type":"urn:ietf:params:acme:error:badCSR","detail":"CSR names `+n+`, not in the order"}`, http.StatusBadRequest)
				return
			}
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), DNSNames: csr.DNSNames,
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		leaf, err := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, csr.PublicKey, ca.caKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ca.certPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.caCert.Raw})...)
		ca.finalized = true
		ca.issued++
		w.Header().Set("Location", ca.url("/order/1"))
		_ = json.NewEncoder(w).Encode(ca.orderLocked())
	case p == "/cert/1":
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(ca.certPEM)
	default:
		http.NotFound(w, r)
	}
}

func (ca *fakeCA) orderLocked() map[string]any {
	status := "ready"
	for _, s := range ca.authz {
		switch s {
		case "invalid":
			status = "invalid"
		case "pending":
			if status != "invalid" {
				status = "pending"
			}
		}
	}
	var authz, ids []any
	for i, id := range ca.reqIDs {
		authz = append(authz, ca.url(fmt.Sprintf("/authz/%d", i)))
		ids = append(ids, map[string]string{"type": "dns", "value": id})
	}
	o := map[string]any{"status": status, "identifiers": ids, "authorizations": authz, "finalize": ca.url("/finalize/1")}
	if ca.finalized {
		o["status"] = "valid"
		o["certificate"] = ca.url("/cert/1")
	}
	return o
}

func newIssuer(t *testing.T, ca *fakeCA, d *memDNS, dir string) *Issuer {
	return &Issuer{DirectoryURL: ca.url("/dir"), Domains: []string{"ui.example.test", "alt.example.test"},
		CacheDir: dir, Provider: d, PropagationTimeout: 5 * time.Second}
}

// One DNS-01 issuance end to end: a record per name at _acme-challenge,
// validated by the CA, removed afterwards, the certificate served for the
// names it covers and cached with private keys at 0600.
//
// Mutations: publish at the bare name instead of _acme-challenge.<name> (the
// CA invalidates and Obtain fails); drop the CleanUp defer (records remain).
func TestIssuer_ObtainsOverDNS01(t *testing.T) {
	d := &memDNS{txt: map[string][]string{}}
	ca := newFakeCA(t, d)
	dir := t.TempDir()
	iss := newIssuer(t, ca, d, dir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := iss.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	c, err := iss.GetCertificate(&tls.ClientHelloInfo{ServerName: "alt.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if !coversAll(c.Leaf, iss.Domains) {
		t.Fatalf("issued certificate covers %v", c.Leaf.DNSNames)
	}
	if _, err := iss.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.test"}); err == nil {
		t.Fatal("served the certificate for a name it does not cover")
	}
	if _, err := iss.GetCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("served the certificate to a hello without SNI")
	}
	for fqdn, vals := range d.txt {
		if len(vals) != 0 {
			t.Fatalf("challenge record %s left behind: %v", fqdn, vals)
		}
	}
	for _, f := range []string{accountKeyFile, keyFile} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s is mode %04o", f, fi.Mode().Perm())
		}
	}

	// A restart serves the cached certificate without a new issuance.
	again := newIssuer(t, ca, d, dir)
	if err := again.loadCached(); err != nil {
		t.Fatal(err)
	}
	if again.needsRenewal(time.Now()) {
		t.Fatal("a fresh cached certificate reads as due for renewal")
	}
	if !again.needsRenewal(c.Leaf.NotAfter.Add(-24 * time.Hour)) {
		t.Fatal("a certificate a day from expiry is not due for renewal")
	}
	if ca.issued != 1 {
		t.Fatalf("issued %d certificates", ca.issued)
	}
}

// A record at the wrong owner name is not a proof; the issuance fails and
// nothing is served.
func TestIssuer_AWrongRecordFails(t *testing.T) {
	d := &memDNS{txt: map[string][]string{}, present: func(fqdn string) string {
		return strings.TrimPrefix(fqdn, "_acme-challenge.")
	}}
	ca := newFakeCA(t, d)
	iss := newIssuer(t, ca, d, t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := iss.Obtain(ctx); err == nil {
		t.Fatal("issued without a valid challenge record")
	}
	if iss.Current() != nil {
		t.Fatal("serving a certificate after a failed issuance")
	}
	if d.removed == 0 {
		t.Fatal("the challenge record was not cleaned up after a failure")
	}
}

// A wildcard listed first: the request's CN is the wildcard itself, which the
// CA (enforcing CN ⊆ SANs as Boulder does) accepts, and the challenge is
// published at the base name.
//
// Mutation: CN = Domains[0] without "*." — the fake CA refuses the finalize.
func TestIssuer_AWildcardFirstOrder(t *testing.T) {
	d := &memDNS{txt: map[string][]string{}}
	ca := newFakeCA(t, d)
	iss := &Issuer{DirectoryURL: ca.url("/dir"), Domains: []string{"*.hv.example.test"},
		CacheDir: t.TempDir(), Provider: d, PropagationTimeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := iss.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := iss.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.hv.example.test"}); err != nil {
		t.Fatal(err)
	}
}

// A CA that asks to validate a name the issuer never requested gets no record.
//
// Mutation: drop the requested() check — a record is published for the CA's
// name.
func TestIssuer_RefusesAnAuthorizationForAnotherName(t *testing.T) {
	d := &memDNS{txt: map[string][]string{}}
	ca := newFakeCA(t, d)
	ca.rename = "victim.example.test"
	iss := newIssuer(t, ca, d, t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := iss.Obtain(ctx); err == nil {
		t.Fatal("issued for a name the CA substituted")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.txt["_acme-challenge.victim.example.test."]) != 0 || d.removed != 0 {
		t.Fatal("published a record for a name the issuer never asked for")
	}
}

// A record a crashed run left behind is removed at the next start.
//
// Mutation: drop sweepPending from Run — the record stays.
func TestIssuer_SweepsRecordsACrashLeft(t *testing.T) {
	d := &memDNS{txt: map[string][]string{"_acme-challenge.ui.example.test.": {"stale"}}}
	dir := t.TempDir()
	iss := &Issuer{Domains: []string{"ui.example.test"}, CacheDir: dir, Provider: d}
	iss.notePending(pendingRecord{FQDN: "_acme-challenge.ui.example.test.", Value: "stale"}, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Run sweeps, then returns at the first wait
	iss.Run(ctx)
	if d.has("_acme-challenge.ui.example.test.", "stale") {
		t.Fatal("a challenge record left by a crash was not removed")
	}
	if len(iss.readPending()) != 0 {
		t.Fatal("the pending list still holds the removed record")
	}
}
