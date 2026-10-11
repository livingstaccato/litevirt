// Package oidctest is an in-process OpenID Connect provider for tests: real
// discovery, a real JWKS, RS256-signed ID tokens, an authorization endpoint
// that signs in a test-chosen user and redirects with a code, and a token
// endpoint that enforces client authentication, the exact redirect_uri and
// PKCE S256. It is strict where a real IdP is, so a client that skips PKCE,
// swaps the redirect or replays a code fails against it.
//
// It is test support only: nothing in the daemon imports it.
package oidctest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// User is who the provider signs in at its authorization endpoint.
type User struct {
	Subject           string   // `sub`
	PreferredUsername string   // `preferred_username`; "" omits it
	Email             string   // `email`
	Groups            []string // the groups claim (GroupsClaim)
	AMR               []string // `amr`; nil omits it
}

// Provider is the fake IdP.
type Provider struct {
	Server       *httptest.Server
	Issuer       string
	ClientID     string
	ClientSecret string
	// GroupsClaim names the claim the groups go in (default "groups").
	GroupsClaim string
	// ExtraAudience, when set, is added to every ID token's aud (and azp is
	// set to ClientID unless AZP overrides it).
	ExtraAudience string
	AZP           string
	// NonceOverride, when set, replaces the nonce the client sent.
	NonceOverride string
	// TokenTTL is the ID token lifetime (default 5 minutes); negative mints
	// an already-expired token.
	TokenTTL time.Duration

	key   *rsa.PrivateKey
	keyID string

	mu        sync.Mutex
	redirects map[string]bool
	user      *User
	codes     map[string]*grant
	// Exchanges counts successful token exchanges.
	Exchanges int
	// LastAuthorize is the last authorization request's query, for asserting
	// what the client sent (PKCE method, nonce, scope, redirect).
	LastAuthorize url.Values
}

type grant struct {
	challenge string
	nonce     string
	redirect  string
	user      User
	used      bool
}

// New starts a TLS provider (httptest's self-signed certificate; CAFile writes
// it out for a client to trust). redirects are the registered redirect URIs.
func New(t testing.TB, clientID, clientSecret string, redirects ...string) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("oidctest: key: %v", err)
	}
	p := &Provider{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		GroupsClaim:  "groups",
		key:          key,
		keyID:        "oidctest-1",
		redirects:    map[string]bool{},
		codes:        map[string]*grant{},
	}
	for _, r := range redirects {
		p.redirects[r] = true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/jwks", p.jwks)
	mux.HandleFunc("/authorize", p.authorize)
	mux.HandleFunc("/token", p.token)
	// Its own CA per provider (httptest's built-in certificate is one fixed
	// certificate shared by every server, so two providers would trust each
	// other and a "wrong CA" test could not fail).
	p.Server = httptest.NewUnstartedServer(mux)
	p.Server.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}
	p.Server.StartTLS()
	p.Issuer = p.Server.URL
	t.Cleanup(p.Server.Close)
	return p
}

// RegisterRedirect adds a registered redirect URI.
func (p *Provider) RegisterRedirect(u string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.redirects[u] = true
}

// SignIn sets the user the authorization endpoint signs in (nil: refuse with
// error=access_denied).
func (p *Provider) SignIn(u *User) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if u == nil {
		p.user = nil
		return
	}
	cp := *u
	p.user = &cp
}

// CAFile writes the provider's certificate as PEM under dir and returns the
// path, for a realm's ca_file.
func (p *Provider) CAFile(t testing.TB, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "oidctest-ca.pem")
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Server.Certificate().Raw})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("oidctest: write CA: %v", err)
	}
	return path
}

// BrowserClient is an http.Client that trusts the provider (and, through
// extra, any other test TLS servers) and does NOT follow redirects, so a test
// steps through the browser's hops itself.
func (p *Provider) BrowserClient(extra ...*httptest.Server) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(p.Server.Certificate())
	for _, s := range extra {
		pool.AddCert(s.Certificate())
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                p.Issuer,
		"authorization_endpoint":                p.Issuer + "/authorize",
		"token_endpoint":                        p.Issuer + "/token",
		"jwks_uri":                              p.Issuer + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := p.key.Public().(*rsa.PublicKey)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "kid": p.keyID, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// authorize signs in the configured user at once (no consent page) and
// redirects back with a code, as a real IdP does after its own login.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.LastAuthorize = q
	redirect := q.Get("redirect_uri")
	if q.Get("client_id") != p.ClientID || !p.redirects[redirect] {
		// Never redirect to an unregistered URI (RFC 6749 §4.1.2.1).
		http.Error(w, "unknown client or unregistered redirect_uri", http.StatusBadRequest)
		return
	}
	back, _ := url.Parse(redirect)
	bq := back.Query()
	bq.Set("state", q.Get("state"))
	switch {
	case q.Get("response_type") != "code":
		bq.Set("error", "unsupported_response_type")
	case q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "":
		bq.Set("error", "invalid_request")
	case p.user == nil:
		bq.Set("error", "access_denied")
	default:
		code := randString()
		p.codes[code] = &grant{
			challenge: q.Get("code_challenge"),
			nonce:     q.Get("nonce"),
			redirect:  redirect,
			user:      *p.user,
		}
		bq.Set("code", code)
	}
	back.RawQuery = bq.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthErr(w, "invalid_request")
		return
	}
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != p.ClientID || secret != p.ClientSecret {
		w.WriteHeader(http.StatusUnauthorized)
		oauthErr(w, "invalid_client")
		return
	}
	p.mu.Lock()
	g := p.codes[r.PostForm.Get("code")]
	if g == nil || g.used || r.PostForm.Get("grant_type") != "authorization_code" ||
		r.PostForm.Get("redirect_uri") != g.redirect {
		p.mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		oauthErr(w, "invalid_grant")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		p.mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		oauthErr(w, "invalid_grant")
		return
	}
	g.used = true
	p.Exchanges++
	nonce := g.nonce
	if p.NonceOverride != "" {
		nonce = p.NonceOverride
	}
	u := g.user
	ttl := p.TokenTTL
	extraAud, azp := p.ExtraAudience, p.AZP
	p.mu.Unlock()
	if ttl == 0 {
		ttl = 5 * time.Minute
	}

	now := time.Now()
	claims := map[string]any{
		"iss":   p.Issuer,
		"sub":   u.Subject,
		"iat":   now.Unix(),
		"exp":   now.Add(ttl).Unix(),
		"nonce": nonce,
	}
	if extraAud != "" {
		claims["aud"] = []string{p.ClientID, extraAud}
		if azp == "" {
			azp = p.ClientID
		}
		claims["azp"] = azp
	} else {
		claims["aud"] = p.ClientID
	}
	if u.PreferredUsername != "" {
		claims["preferred_username"] = u.PreferredUsername
	}
	if u.Email != "" {
		claims["email"] = u.Email
	}
	if u.Groups != nil {
		claims[p.GroupsClaim] = u.Groups
	}
	if u.AMR != nil {
		claims["amr"] = u.AMR
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", p.keyID))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	idTok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": randString(),
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     idTok,
	})
}

// selfSigned is a fresh self-signed certificate for 127.0.0.1 and localhost.
func selfSigned(t testing.TB) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("oidctest: tls key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "oidctest"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("oidctest: tls cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func oauthErr(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func randString() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
