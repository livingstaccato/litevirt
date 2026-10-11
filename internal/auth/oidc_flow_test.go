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
	start, err := r.BeginFlow(OIDCClientWeb, "203.0.113.1")
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
	p, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State, OIDCBinding: start.Binding})
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
	start, _ := r.BeginFlow(OIDCClientWeb, "203.0.113.1")
	back := visit(t, idp, start.AuthURL)
	if _, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State, OIDCBinding: start.Binding}); err != nil {
		t.Fatal(err)
	}
	// A second code minted against the same flow parameters (an attacker
	// replaying the authorization request) cannot use the spent state.
	back2 := visit(t, idp, start.AuthURL)
	_, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back2.Query().Get("code"), OIDCState: start.State, OIDCBinding: start.Binding})
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
	start, err := r.BeginFlow(OIDCClientCLI, "203.0.113.1")
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
	if _, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State, OIDCBinding: start.Binding}); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
}

func TestOIDCBeginFlow_CLIUnconfiguredIsRefused(t *testing.T) {
	r, _ := newFlowRealm(t, func(c *OIDCConfig) { c.CLIRedirectURL = "" })
	if _, err := r.BeginFlow(OIDCClientCLI, "203.0.113.1"); !errors.Is(err, ErrOIDCClientNotConfigured) {
		t.Fatalf("cli flow with no cli_redirect_url: %v", err)
	}
	if _, err := r.BeginFlow("mobile", "203.0.113.1"); !errors.Is(err, ErrOIDCClientNotConfigured) {
		t.Fatalf("unknown client: %v", err)
	}
}

// TestOIDCAuthenticate_RedirectIsNotTheCallersToChoose: a callback naming a
// redirect other than the flow's is refused before any exchange.
func TestOIDCAuthenticate_RedirectIsNotTheCallersToChoose(t *testing.T) {
	r, idp := newFlowRealm(t, nil)
	start, _ := r.BeginFlow(OIDCClientWeb, "203.0.113.1")
	back := visit(t, idp, start.AuthURL)
	_, err := r.Authenticate(context.Background(), Credentials{
		OIDCCode: back.Query().Get("code"), OIDCState: start.State, OIDCBinding: start.Binding,
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
		_, err := r.BeginFlow(OIDCClientWeb, "203.0.113.1")
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
	start, _ := r.BeginFlow(OIDCClientWeb, "203.0.113.1")
	back := visit(t, idp, start.AuthURL)
	p, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State, OIDCBinding: start.Binding})
	if err != nil || p == nil {
		t.Fatalf("exchange through the CA-pinned client: %v", err)
	}
}

func TestOIDCAuthenticate_RejectsAWrongNonce(t *testing.T) {
	r, idp := newFlowRealm(t, nil)
	idp.NonceOverride = "not-the-flows-nonce"
	start, _ := r.BeginFlow(OIDCClientWeb, "203.0.113.1")
	back := visit(t, idp, start.AuthURL)
	if _, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State, OIDCBinding: start.Binding}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong nonce: %v", err)
	}
}

func TestOIDCAuthenticate_RejectsAnExpiredIDToken(t *testing.T) {
	r, idp := newFlowRealm(t, nil)
	idp.TokenTTL = -time.Minute
	start, _ := r.BeginFlow(OIDCClientWeb, "203.0.113.1")
	back := visit(t, idp, start.AuthURL)
	if _, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State, OIDCBinding: start.Binding}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expired id token: %v", err)
	}
}

// TestOIDCAuthenticate_MultiAudienceNeedsAZP: a token issued to another client
// that merely lists this one among its audiences is refused.
func TestOIDCAuthenticate_MultiAudienceNeedsAZP(t *testing.T) {
	r, idp := newFlowRealm(t, nil)
	idp.ExtraAudience = "other-client"
	idp.AZP = "other-client"
	start, _ := r.BeginFlow(OIDCClientWeb, "203.0.113.1")
	back := visit(t, idp, start.AuthURL)
	if _, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State, OIDCBinding: start.Binding}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("azp of another client: %v", err)
	}
	idp.AZP = "" // azp = this client
	start, _ = r.BeginFlow(OIDCClientWeb, "203.0.113.1")
	back = visit(t, idp, start.AuthURL)
	if _, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State, OIDCBinding: start.Binding}); err != nil {
		t.Fatalf("azp of this client: %v", err)
	}
}

// redeemable reports whether start's flow is still held: it plays the IdP and
// redeems it.
func redeemable(t *testing.T, r *OIDCRealm, idp *oidctest.Provider, start OIDCFlowStart) bool {
	t.Helper()
	back := visit(t, idp, start.AuthURL)
	_, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State, OIDCBinding: start.Binding})
	if err != nil && !errors.Is(err, ErrOIDCFlowUnknown) {
		t.Fatalf("redeem: %v", err)
	}
	return err == nil
}

// TestOIDCBeginFlow_ASharedAddressNeverBlocks (re-review N1): clients behind
// one address (a proxy, a NAT) share its bound, and going over it evicts that
// address's OWN oldest flow — 100 begins from it never refuse, its newest flow
// is still redeemable, and a flow begun from another address survives.
func TestOIDCBeginFlow_ASharedAddressNeverBlocks(t *testing.T) {
	r, idp := newFlowRealm(t, nil)
	victim, err := r.BeginFlow(OIDCClientWeb, "203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	var last OIDCFlowStart
	for i := 0; i < 100; i++ {
		last, err = r.BeginFlow(OIDCClientWeb, "198.51.100.66")
		if err != nil {
			t.Fatalf("begin %d from the shared address was refused: %v", i, err)
		}
	}
	if n := r.flowsFromLocked("198.51.100.66"); n != r.maxFlowsPerAddr {
		t.Fatalf("the shared address holds %d flows, want its bound %d", n, r.maxFlowsPerAddr)
	}
	if !redeemable(t, r, idp, last) {
		t.Fatal("the shared address's newest sign-in was evicted")
	}
	if !redeemable(t, r, idp, victim) {
		t.Fatal("another address's sign-in did not survive the flood")
	}
}

// TestOIDCBeginFlow_AFullStoreEvictsFairly (re-review N2): when the realm is
// full, the flow evicted is the oldest of the address holding the most, so a
// user with one sign-in in progress outlasts a flood.
func TestOIDCBeginFlow_AFullStoreEvictsFairly(t *testing.T) {
	r, idp := newFlowRealm(t, nil)
	r.maxFlows = 8
	r.maxFlowsPerAddr = 100
	victim, err := r.BeginFlow(OIDCClientWeb, "203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	for i := 0; i < 50; i++ {
		if _, err := r.BeginFlow(OIDCClientWeb, "198.51.100.66"); err != nil {
			t.Fatalf("a begin on a full store: %v", err)
		}
	}
	if n := len(r.stateStore); n != 8 {
		t.Fatalf("store holds %d flows, want its bound 8", n)
	}
	if !redeemable(t, r, idp, victim) {
		t.Fatal("the victim's single sign-in (the OLDEST flow) was evicted by another address's flood")
	}
}

// TestOIDCBeginFlow_IPv6CountsByItsSlash64 (re-review N2): one /64 is one
// client for the bound; an IPv4-mapped address is its IPv4 form.
func TestOIDCBeginFlow_IPv6CountsByItsSlash64(t *testing.T) {
	r, idp := newFlowRealm(t, nil)
	r.maxFlowsPerAddr = 2
	first, _ := r.BeginFlow(OIDCClientWeb, "2001:db8:1:2::1")
	other, _ := r.BeginFlow(OIDCClientWeb, "2001:db8:1:3::1")
	r.BeginFlow(OIDCClientWeb, "2001:db8:1:2::ffff:1")
	r.BeginFlow(OIDCClientWeb, "2001:db8:1:2:aaaa::9")
	if redeemable(t, r, idp, first) {
		t.Fatal("three addresses of one /64 were counted as three clients")
	}
	if !redeemable(t, r, idp, other) {
		t.Fatal("another /64's sign-in was evicted")
	}
	if a, b := flowAddrKey("::ffff:192.0.2.7"), flowAddrKey("192.0.2.7"); a != b {
		t.Fatalf("mapped %q vs plain %q", a, b)
	}
}

// TestOIDCAuthenticate_RedemptionNeedsTheBinding: the code and state travel in
// the callback URL; without the beginner's binding secret they redeem
// nothing, the code is never presented to the IdP, and the flow is spent
// (review M1, M2).
func TestOIDCAuthenticate_RedemptionNeedsTheBinding(t *testing.T) {
	r, idp := newFlowRealm(t, nil)
	start, _ := r.BeginFlow(OIDCClientWeb, "203.0.113.1")
	if start.Binding == "" || strings.Contains(start.AuthURL, start.Binding) {
		t.Fatal("the binding is empty or travels in the auth URL")
	}
	back := visit(t, idp, start.AuthURL)
	code := back.Query().Get("code")
	for _, b := range []string{"", "not-the-binding"} {
		start2, _ := r.BeginFlow(OIDCClientWeb, "203.0.113.1")
		back2 := visit(t, idp, start2.AuthURL)
		if _, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back2.Query().Get("code"), OIDCState: start2.State, OIDCBinding: b}); !errors.Is(err, ErrOIDCFlowBindingMismatch) {
			t.Fatalf("binding %q: %v, want ErrOIDCFlowBindingMismatch", b, err)
		}
		if _, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back2.Query().Get("code"), OIDCState: start2.State, OIDCBinding: start2.Binding}); !errors.Is(err, ErrOIDCFlowUnknown) {
			t.Fatalf("after a mismatched redemption the flow must be spent: %v", err)
		}
	}
	if idp.Exchanges != 0 {
		t.Fatalf("%d codes reached the IdP without the binding", idp.Exchanges)
	}
	if _, err := r.Authenticate(context.Background(), Credentials{OIDCCode: code, OIDCState: start.State, OIDCBinding: start.Binding}); err != nil {
		t.Fatalf("with the binding: %v", err)
	}
}

// TestOIDCAuthenticate_SingleAudienceForeignAZPRefused: azp present names the
// party the token was issued to; it must be this client even with one
// audience (review M7).
func TestOIDCAuthenticate_SingleAudienceForeignAZPRefused(t *testing.T) {
	r, idp := newFlowRealm(t, nil)
	idp.AZP = "other-client"
	start, _ := r.BeginFlow(OIDCClientWeb, "203.0.113.1")
	back := visit(t, idp, start.AuthURL)
	if _, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State, OIDCBinding: start.Binding}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("single audience, foreign azp: %v", err)
	}
	idp.AZP = flowClientID
	start, _ = r.BeginFlow(OIDCClientWeb, "203.0.113.1")
	back = visit(t, idp, start.AuthURL)
	if _, err := r.Authenticate(context.Background(), Credentials{OIDCCode: back.Query().Get("code"), OIDCState: start.State, OIDCBinding: start.Binding}); err != nil {
		t.Fatalf("single audience, our azp: %v", err)
	}
}

// TestOIDCRealm_ScopesAlwaysCarryOpenID: configured scopes without openid would
// get no ID token, and so no identity.
func TestOIDCRealm_ScopesAlwaysCarryOpenID(t *testing.T) {
	r, idp := newFlowRealm(t, func(c *OIDCConfig) { c.Scopes = []string{"profile", "groups"} })
	start, _ := r.BeginFlow(OIDCClientWeb, "203.0.113.1")
	visit(t, idp, start.AuthURL)
	if s := idp.LastAuthorize.Get("scope"); !strings.Contains(" "+s+" ", " openid ") {
		t.Fatalf("scope %q lacks openid", s)
	}
}
