package acmedns

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/litevirt/litevirt/internal/secretfile"
)

// Issuer obtains and renews one certificate for Domains over DNS-01 and
// serves it from GetCertificate.
//
// State lives in CacheDir: the ACME account key, the certificate chain and its
// key (both keys 0600), so a restart serves the cached certificate at once and
// does not re-issue. Renewal starts RenewBefore ahead of expiry and retries
// with backoff; until a certificate exists, GetCertificate errs and the caller
// falls back to another certificate.
type Issuer struct {
	DirectoryURL string
	Email        string
	Domains      []string
	CacheDir     string
	Provider     Provider
	// PropagationTimeout bounds the wait for the record to be visible on the
	// provider's server; PropagationDelay is waited after that, for
	// secondaries that serve the zone too.
	PropagationTimeout time.Duration
	PropagationDelay   time.Duration
	// RenewBefore is how long before expiry renewal starts. Default 30 days.
	RenewBefore time.Duration

	mu   sync.RWMutex
	cert *tls.Certificate

	pendingMu sync.Mutex
}

const (
	accountKeyFile = "dns01-account.key"
	certFile       = "dns01.crt"
	keyFile        = "dns01.key"
)

// Current returns the certificate being served, or nil.
func (i *Issuer) Current() *tls.Certificate {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.cert
}

// GetCertificate serves the issued certificate for a ServerName it covers.
// Anything else — no certificate yet, a name outside Domains, no SNI — is an
// error, so the caller's fallback answers instead (as autocert's HostPolicy
// does for HTTP-01).
func (i *Issuer) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := i.Current()
	if c == nil {
		return nil, errors.New("acme dns-01: no certificate issued yet")
	}
	if hello == nil || hello.ServerName == "" {
		return nil, errors.New("acme dns-01: no server name in the TLS hello")
	}
	if err := c.Leaf.VerifyHostname(hello.ServerName); err != nil {
		return nil, fmt.Errorf("acme dns-01: %s is not covered by the issued certificate", hello.ServerName)
	}
	return c, nil
}

// requested reports whether name (an authorization identifier, a wildcard's
// base without "*.") is one this issuer asked for.
func (i *Issuer) requested(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, d := range i.Domains {
		if strings.ToLower(strings.TrimPrefix(strings.TrimSuffix(d, "."), "*.")) == name {
			return true
		}
	}
	return false
}

type pendingRecord struct {
	FQDN  string `json:"fqdn"`
	Value string `json:"value"`
}

const pendingFile = "dns01-pending.json"

func (i *Issuer) readPending() []pendingRecord {
	b, err := os.ReadFile(filepath.Join(i.CacheDir, pendingFile))
	if err != nil {
		return nil
	}
	var out []pendingRecord
	_ = json.Unmarshal(b, &out)
	return out
}

// notePending adds (or removes) a record from the list of challenge records
// published and not yet removed.
func (i *Issuer) notePending(r pendingRecord, add bool) {
	i.pendingMu.Lock()
	defer i.pendingMu.Unlock()
	var out []pendingRecord
	for _, p := range i.readPending() {
		if p != r {
			out = append(out, p)
		}
	}
	if add {
		out = append(out, r)
	}
	b, _ := json.Marshal(out)
	if err := os.MkdirAll(i.CacheDir, 0o700); err == nil {
		_ = secretfile.Write(filepath.Join(i.CacheDir, pendingFile), b, 0o600)
	}
}

// sweepPending removes challenge records an earlier run published and never
// cleaned up (a crash between Present and CleanUp).
func (i *Issuer) sweepPending(ctx context.Context) {
	for _, r := range i.readPending() {
		if err := i.Provider.CleanUp(ctx, r.FQDN, r.Value); err != nil {
			slog.Warn("acme dns-01: could not remove a challenge record left by an earlier run", "record", r.FQDN, "error", err)
			continue
		}
		i.notePending(r, false)
	}
}

// Run serves the cached certificate and keeps it renewed until ctx ends.
func (i *Issuer) Run(ctx context.Context) {
	i.sweepPending(ctx)
	if err := i.loadCached(); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("acme dns-01: ignoring the cached certificate", "error", err)
	}
	backoff := time.Minute
	for {
		wait := 12 * time.Hour
		if i.needsRenewal(time.Now()) {
			if err := i.Obtain(ctx); err != nil {
				slog.Error("acme dns-01: could not obtain a certificate; retrying",
					"domains", i.Domains, "retry_in", backoff, "error", err)
				wait = backoff
				if backoff *= 2; backoff > time.Hour {
					backoff = time.Hour
				}
			} else {
				backoff = time.Minute
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (i *Issuer) renewBefore() time.Duration {
	if i.RenewBefore > 0 {
		return i.RenewBefore
	}
	return 30 * 24 * time.Hour
}

func (i *Issuer) needsRenewal(now time.Time) bool {
	c := i.Current()
	return c == nil || c.Leaf.NotAfter.Sub(now) < i.renewBefore() || !coversAll(c.Leaf, i.Domains)
}

func coversAll(leaf *x509.Certificate, domains []string) bool {
	have := map[string]bool{}
	for _, n := range leaf.DNSNames {
		have[strings.ToLower(n)] = true
	}
	for _, d := range domains {
		if !have[strings.ToLower(d)] {
			return false
		}
	}
	return true
}

func (i *Issuer) loadCached() error {
	pair, err := tls.LoadX509KeyPair(filepath.Join(i.CacheDir, certFile), filepath.Join(i.CacheDir, keyFile))
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	pair.Leaf = leaf
	i.mu.Lock()
	i.cert = &pair
	i.mu.Unlock()
	slog.Info("acme dns-01: serving the cached certificate", "domains", leaf.DNSNames,
		"not_after", leaf.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

func (i *Issuer) client() (*acme.Client, error) {
	key, err := i.accountKey()
	if err != nil {
		return nil, err
	}
	return &acme.Client{DirectoryURL: i.DirectoryURL, Key: key}, nil
}

// accountKey loads the ACME account key, creating it (0600) on first use.
func (i *Issuer) accountKey() (crypto.Signer, error) {
	path := filepath.Join(i.CacheDir, accountKeyFile)
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("acme dns-01: %s holds no PEM block", path)
		}
		return x509.ParseECPrivateKey(block.Bytes)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(i.CacheDir, 0o700); err != nil {
		return nil, err
	}
	if err := secretfile.Write(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// Obtain runs one issuance: account, order, one DNS-01 challenge per
// authorization, finalize, store, serve.
func (i *Issuer) Obtain(ctx context.Context) error {
	if len(i.Domains) == 0 {
		return errors.New("acme dns-01: no domains configured")
	}
	cl, err := i.client()
	if err != nil {
		return fmt.Errorf("account key: %w", err)
	}
	acct := &acme.Account{}
	if i.Email != "" {
		acct.Contact = []string{"mailto:" + i.Email}
	}
	if _, err := cl.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("register ACME account: %w", err)
	}
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(i.Domains...))
	if err != nil {
		return fmt.Errorf("create order: %w", err)
	}
	for _, u := range order.AuthzURLs {
		if err := i.authorize(ctx, cl, u); err != nil {
			return err
		}
	}
	if order, err = cl.WaitOrder(ctx, order.URI); err != nil {
		return fmt.Errorf("wait for the order: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	// The CN is Domains[0] verbatim — a wildcard included. A CA counts the CN
	// as a requested name, and one that is not among the SANs (the bare base
	// of a wildcard) makes the finalize fail.
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: i.Domains[0]},
		DNSNames: i.Domains,
	}, key)
	if err != nil {
		return err
	}
	der, _, err := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("finalize the order: %w", err)
	}
	return i.store(der, key)
}

// authorize satisfies one authorization over DNS-01, removing the record
// afterwards whatever the outcome.
func (i *Issuer) authorize(ctx context.Context, cl *acme.Client, url string) error {
	z, err := cl.GetAuthorization(ctx, url)
	if err != nil {
		return fmt.Errorf("read authorization: %w", err)
	}
	if z.Status == acme.StatusValid {
		return nil
	}
	// The owner name comes from the CA. Publish only for a name this issuer
	// asked for: a directory answering with another name would otherwise get a
	// TXT record written anywhere the TSIG key reaches.
	if !i.requested(z.Identifier.Value) {
		return fmt.Errorf("the CA asked to validate %q, which is not one of %v; refusing", z.Identifier.Value, i.Domains)
	}
	var chal *acme.Challenge
	for _, c := range z.Challenges {
		if c.Type == "dns-01" {
			chal = c
			break
		}
	}
	if chal == nil {
		return fmt.Errorf("the CA offered no dns-01 challenge for %s", z.Identifier.Value)
	}
	value, err := cl.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return err
	}
	fqdn := "_acme-challenge." + strings.TrimPrefix(z.Identifier.Value, "*.") + "."
	// Remember the record before publishing it, so one a crash leaves behind is
	// removed at the next start (sweepPending).
	i.notePending(pendingRecord{FQDN: fqdn, Value: value}, true)
	if err := i.Provider.Present(ctx, fqdn, value); err != nil {
		return fmt.Errorf("publish the challenge record: %w", err)
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := i.Provider.CleanUp(cctx, fqdn, value); err != nil {
			slog.Warn("acme dns-01: could not remove the challenge record; it is retried at the next start",
				"record", fqdn, "error", err)
			return
		}
		i.notePending(pendingRecord{FQDN: fqdn, Value: value}, false)
	}()
	if err := i.waitVisible(ctx, fqdn, value); err != nil {
		return err
	}
	if _, err := cl.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accept the challenge for %s: %w", z.Identifier.Value, err)
	}
	if _, err := cl.WaitAuthorization(ctx, z.URI); err != nil {
		return fmt.Errorf("the CA did not validate %s: %w", z.Identifier.Value, err)
	}
	return nil
}

func (i *Issuer) waitVisible(ctx context.Context, fqdn, value string) error {
	timeout := i.PropagationTimeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	deadline := time.Now().Add(timeout)
	for {
		ok, err := i.Provider.Visible(ctx, fqdn, value)
		if ok {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the challenge record %s did not become visible within %s (last error: %v)", fqdn, timeout, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if i.PropagationDelay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(i.PropagationDelay):
		}
	}
	return nil
}

// store checks what the CA returned and makes it the served certificate.
func (i *Issuer) store(der [][]byte, key *ecdsa.PrivateKey) error {
	if len(der) == 0 {
		return errors.New("the CA returned no certificate")
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return fmt.Errorf("the CA returned an unparseable certificate: %w", err)
	}
	if !coversAll(leaf, i.Domains) {
		return fmt.Errorf("the CA's certificate covers %v, not %v", leaf.DNSNames, i.Domains)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return errors.New("the CA's certificate is not for the key in the request")
	}
	var chain []byte
	for _, d := range der {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	if err := os.MkdirAll(i.CacheDir, 0o700); err != nil {
		return err
	}
	// Key first: a reader that finds the new chain also finds its key.
	if err := secretfile.Write(filepath.Join(i.CacheDir, keyFile), keyPEM, 0o600); err != nil {
		return err
	}
	if err := secretfile.Write(filepath.Join(i.CacheDir, certFile), chain, 0o644); err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return err
	}
	pair.Leaf = leaf
	i.mu.Lock()
	i.cert = &pair
	i.mu.Unlock()
	slog.Info("acme dns-01: certificate issued", "domains", leaf.DNSNames, "serial", leaf.SerialNumber.Text(16),
		"not_after", leaf.NotAfter.UTC().Format(time.RFC3339))
	return nil
}
