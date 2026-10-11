package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/auth/oidctest"
)

const (
	flowClientID = "litevirt"
	flowSecret   = "s3cret"
	flowWebCB    = "https://node-1.example:7445/oidc/callback"
	flowCLICB    = "http://127.0.0.1:18765/oidc/callback"
)

// newFlowRealm is a realm against a strict TLS provider, trusting it only
// through ca_file.
func newFlowRealm(t *testing.T, mutate func(*OIDCConfig)) (*OIDCRealm, *oidctest.Provider) {
	t.Helper()
	idp := oidctest.New(t, flowClientID, flowSecret, flowWebCB, flowCLICB)
	idp.SignIn(&oidctest.User{Subject: "sub-alice", PreferredUsername: "alice", Groups: []string{"lv-admins"}})
	cfg := OIDCConfig{
		ShortName:      "corp",
		IssuerURL:      idp.Issuer,
		ClientID:       flowClientID,
		ClientSecret:   flowSecret,
		RedirectURL:    flowWebCB,
		CLIRedirectURL: flowCLICB,
		CAFile:         idp.CAFile(t, t.TempDir()),
		SubjectClaim:   "preferred_username",
	}
	if mutate != nil {
		mutate(&cfg)
	}
	r, err := NewOIDCRealm(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewOIDCRealm: %v", err)
	}
	return r, idp
}

// visit plays the browser at the IdP: it follows the auth URL and returns the
// redirect the IdP answered with.
func visit(t *testing.T, idp *oidctest.Provider, authURL string) *url.URL {
	t.Helper()
	resp, err := idp.BrowserClient().Get(authURL)
	if err != nil {
		t.Fatalf("GET auth url: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("IdP answered %d, want a redirect", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestOIDCBeginFlow_WebFlowEndToEnd(t *testing.T) {
	r, idp := newFlowRealm(t, nil)
	start, err := r.BeginFlow(OIDCClientWeb)
	if err != nil {
		t.Fatal(err)
	}
	if start.RedirectURI != flowWebCB {
		t.Fatalf("redirect = %q, want the configured web callback", start.RedirectURI)
	}
	if len(start.State) < 43 { // 256 bits, base64url
		t.Fatalf("state %q is shorter than 256 random bits", start.State)
	}
	if d := time.Until(start.ExpiresAt); d <= 0 || d > 10*time.Minute+time.Second {
		t.Fatalf("expiry in %s, want within 10 minutes", d)
	}
	back := visit(t, idp, start.AuthURL)
	q := idp.LastAuthorize
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("redirect_uri") != flowWebCB {
		t.Fatalf("authorization request %v: want S256, a nonce and the web redirect", q)
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Fatalf("scope %q lacks openid", q.Get("scope"))
	}
	if back.Query().Get("state") != start.State {
		t.Fatalf("IdP returned state %q", back.Query().Get("state"))
	}
	p, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Subject != "alice" || p.Realm != "oidc:corp" || p.ExternalID != idp.Issuer+"|sub-alice" {
		t.Fatalf("principal %+v", p)
	}
	if len(p.Groups) != 1 || p.Groups[0] != "lv-admins" {
		t.Fatalf("groups %v", p.Groups)
	}
}

// TestOIDCBeginFlow_StateIsSingleUse: a callback replayed with the same state
// (and even a fresh code) is refused once the state has been used.
func TestOIDCBeginFlow_StateIsSingleUse(t *testing.T) {
	r, idp := newFlowRealm(t, nil)
	start, _ := r.BeginFlow(OIDCClientWeb)
	back := visit(t, idp, start.AuthURL)
	if _, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State}); err != nil {
		t.Fatal(err)
	}
	// A second code minted against the same flow parameters (an attacker
	// replaying the authorization request) cannot use the spent state.
	back2 := visit(t, idp, start.AuthURL)
	_, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back2.Query().Get("code"), OIDCState: start.State})
	if !errors.Is(err, ErrOIDCFlowUnknown) || !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("replayed state: %v, want ErrOIDCFlowUnknown (an ErrInvalidCredentials)", err)
	}
	if idp.Exchanges != 1 {
		t.Fatalf("%d exchanges, want 1: a spent state must not reach the token endpoint", idp.Exchanges)
	}
}

// TestOIDCBeginFlow_CLIUsesTheLoopbackRedirect: the CLI client gets the
// configured loopback redirect, and the exchange replays it.
func TestOIDCBeginFlow_CLIUsesTheLoopbackRedirect(t *testing.T) {
	r, idp := newFlowRealm(t, nil)
	start, err := r.BeginFlow(OIDCClientCLI)
	if err != nil {
		t.Fatal(err)
	}
	if start.RedirectURI != flowCLICB {
		t.Fatalf("redirect = %q, want cli_redirect_url", start.RedirectURI)
	}
	back := visit(t, idp, start.AuthURL)
	if back.Host != "127.0.0.1:18765" {
		t.Fatalf("IdP sent the browser to %s", back)
	}
	if _, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State}); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
}

func TestOIDCBeginFlow_CLIUnconfiguredIsRefused(t *testing.T) {
	r, _ := newFlowRealm(t, func(c *OIDCConfig) { c.CLIRedirectURL = "" })
	if _, err := r.BeginFlow(OIDCClientCLI); !errors.Is(err, ErrOIDCClientNotConfigured) {
		t.Fatalf("cli flow with no cli_redirect_url: %v", err)
	}
	if _, err := r.BeginFlow("mobile"); !errors.Is(err, ErrOIDCClientNotConfigured) {
		t.Fatalf("unknown client: %v", err)
	}
}

// TestOIDCAuthenticate_RedirectIsNotTheCallersToChoose: a callback naming a
// redirect other than the flow's is refused before any exchange.
func TestOIDCAuthenticate_RedirectIsNotTheCallersToChoose(t *testing.T) {
	r, idp := newFlowRealm(t, nil)
	start, _ := r.BeginFlow(OIDCClientWeb)
	back := visit(t, idp, start.AuthURL)
	_, err := r.Authenticate(context.Background(), Credentials{
		OIDCCode: back.Query().Get("code"), OIDCState: start.State,
		OIDCRedirectURI: "https://evil.example/cb",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("foreign redirect_uri: %v, want ErrInvalidCredentials", err)
	}
	if idp.Exchanges != 0 {
		t.Fatal("a foreign redirect_uri reached the token endpoint")
	}
}

// TestOIDCBeginFlow_WebRedirectMustBeTLS: an http redirect to anything but a
// loopback address would carry the code in cleartext.
func TestOIDCBeginFlow_WebRedirectMustBeTLS(t *testing.T) {
	for _, tc := range []struct {
		url string
		ok  bool
	}{
		{"https://litevirt.corp/oidc/callback", true},
		{"http://127.0.0.1:7445/oidc/callback", true},
		{"http://litevirt.corp/oidc/callback", false},
		{"http://10.0.0.5:7445/oidc/callback", false},
		{"https://litevirt.corp/oidc/callback#frag", false},
	} {
		r, _ := newFlowRealm(t, func(c *OIDCConfig) { c.RedirectURL = tc.url })
		_, err := r.BeginFlow(OIDCClientWeb)
		if (err == nil) != tc.ok {
			t.Errorf("redirect_url %q: err=%v, want ok=%v", tc.url, err, tc.ok)
		}
	}
}

func TestOIDCConfig_CLIRedirectMustBeLoopbackHTTP(t *testing.T) {
	idp := oidctest.New(t, flowClientID, flowSecret)
	for _, bad := range []string{
		"https://127.0.0.1:18765/cb",
		"http://localhost:18765/cb",
		"http://10.0.0.1:18765/cb",
		"http://127.0.0.1/cb",
		"http://127.0.0.1:0/cb",
		"http://127.0.0.1:18765/cb?x=1",
	} {
		_, err := NewOIDCRealm(context.Background(), OIDCConfig{
			ShortName: "x", IssuerURL: idp.Issuer, ClientID: flowClientID,
			RedirectURL: flowWebCB, CLIRedirectURL: bad, CAFile: idp.CAFile(t, t.TempDir()),
		})
		if err == nil {
			t.Errorf("cli_redirect_url %q accepted", bad)
		}
	}
}

// TestOIDCRealm_TrustsOnlyTheConfiguredCA: the IdP is verified against
// ca_file, and never by skipping verification: another CA, or none (the
// system store does not hold the test CA), fails discovery.
func TestOIDCRealm_TrustsOnlyTheConfiguredCA(t *testing.T) {
	idp := oidctest.New(t, flowClientID, flowSecret, flowWebCB)
	other := oidctest.New(t, flowClientID, flowSecret, flowWebCB)
	base := OIDCConfig{ShortName: "x", IssuerURL: idp.Issuer, ClientID: flowClientID, ClientSecret: flowSecret, RedirectURL: flowWebCB}

	wrong := base
	wrong.CAFile = other.CAFile(t, t.TempDir())
	if _, err := NewOIDCRealm(context.Background(), wrong); !errors.Is(err, ErrRealmUnavailable) {
		t.Fatalf("another CA: %v, want discovery to fail TLS verification", err)
	}
	if _, err := NewOIDCRealm(context.Background(), base); !errors.Is(err, ErrRealmUnavailable) {
		t.Fatalf("no ca_file: %v, want the system store to refuse the test CA", err)
	}
	right := base
	right.CAFile = idp.CAFile(t, t.TempDir())
	if _, err := NewOIDCRealm(context.Background(), right); err != nil {
		t.Fatalf("the right CA: %v", err)
	}
}

// TestOIDCRealm_TokenEndpointAlsoUsesTheCA: the exchange and the JWKS fetch
// go through the same verified client as discovery (not the default one).
func TestOIDCRealm_TokenEndpointAlsoUsesTheCA(t *testing.T) {
	r, idp := newFlowRealm(t, nil)
	start, _ := r.BeginFlow(OIDCClientWeb)
	back := visit(t, idp, start.AuthURL)
	p, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State})
	if err != nil || p == nil {
		t.Fatalf("exchange through the CA-pinned client: %v", err)
	}
}

func TestOIDCAuthenticate_RejectsAWrongNonce(t *testing.T) {
	r, idp := newFlowRealm(t, nil)
	idp.NonceOverride = "not-the-flows-nonce"
	start, _ := r.BeginFlow(OIDCClientWeb)
	back := visit(t, idp, start.AuthURL)
	if _, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong nonce: %v", err)
	}
}

func TestOIDCAuthenticate_RejectsAnExpiredIDToken(t *testing.T) {
	r, idp := newFlowRealm(t, nil)
	idp.TokenTTL = -time.Minute
	start, _ := r.BeginFlow(OIDCClientWeb)
	back := visit(t, idp, start.AuthURL)
	if _, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expired id token: %v", err)
	}
}

// TestOIDCAuthenticate_MultiAudienceNeedsAZP: a token issued to another client
// that merely lists this one among its audiences is refused.
func TestOIDCAuthenticate_MultiAudienceNeedsAZP(t *testing.T) {
	r, idp := newFlowRealm(t, nil)
	idp.ExtraAudience = "other-client"
	idp.AZP = "other-client"
	start, _ := r.BeginFlow(OIDCClientWeb)
	back := visit(t, idp, start.AuthURL)
	if _, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("azp of another client: %v", err)
	}
	idp.AZP = "" // azp = this client
	start, _ = r.BeginFlow(OIDCClientWeb)
	back = visit(t, idp, start.AuthURL)
	if _, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State}); err != nil {
		t.Fatalf("azp of this client: %v", err)
	}
}

// TestOIDCBeginFlow_BoundsInFlightFlows: beginning a flow needs no credential,
// so the store is bounded.
func TestOIDCBeginFlow_BoundsInFlightFlows(t *testing.T) {
	r, _ := newFlowRealm(t, nil)
	r.maxFlows = 3
	for i := 0; i < 3; i++ {
		if _, err := r.BeginFlow(OIDCClientWeb); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.BeginFlow(OIDCClientWeb); !errors.Is(err, ErrOIDCTooManyFlows) {
		t.Fatalf("flow over the bound: %v", err)
	}
}

// TestOIDCRealm_ScopesAlwaysCarryOpenID: configured scopes without openid would
// get no ID token, and so no identity.
func TestOIDCRealm_ScopesAlwaysCarryOpenID(t *testing.T) {
	r, idp := newFlowRealm(t, func(c *OIDCConfig) { c.Scopes = []string{"profile", "groups"} })
	start, _ := r.BeginFlow(OIDCClientWeb)
	visit(t, idp, start.AuthURL)
	if s := idp.LastAuthorize.Get("scope"); !strings.Contains(" "+s+" ", " openid ") {
		t.Fatalf("scope %q lacks openid", s)
	}
}
