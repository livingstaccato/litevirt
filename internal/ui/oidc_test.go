package ui

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
)

// oidcMock is the UI mock with an OIDC realm, a BeginOIDCLogin, and a Login
// that, like the daemon, refuses a code redeemed without the flow's binding.
type oidcMock struct {
	*mockGRPC
	begins    int
	lastBegin *pb.BeginOIDCLoginRequest
	beginErr  error
	logins    []*pb.LoginRequest
	redirect  string // the realm's redirect_uri; "" = https://node-1:7445/oidc/callback
	// realms are the advertised realms ("" = local, ldap:corp, oidc:kanidm);
	// redirects overrides redirect per realm; flowRealm is the realm holding
	// state st-1 (default oidc:kanidm): Login for any other realm answers
	// "state unknown", as the daemon does.
	realms    []string
	redirects map[string]string
	flowRealm string
}

const mockBinding = "bind-1"

func (m *oidcMock) ListRealms(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.ListRealmsResponse, error) {
	if m.realms != nil {
		return &pb.ListRealmsResponse{Realms: m.realms}, nil
	}
	return &pb.ListRealmsResponse{Realms: []string{"local", "ldap:corp", "oidc:kanidm"}}, nil
}

func (m *oidcMock) BeginOIDCLogin(_ context.Context, in *pb.BeginOIDCLoginRequest, _ ...grpc.CallOption) (*pb.BeginOIDCLoginResponse, error) {
	m.begins++
	m.lastBegin = in
	if m.beginErr != nil {
		return nil, m.beginErr
	}
	return &pb.BeginOIDCLoginResponse{
		AuthUrl:     "https://idp.example/authorize?state=st-1",
		State:       "st-1",
		RedirectUri: m.redirectFor(in.Realm),
		Binding:     mockBinding,
	}, nil
}

func (m *oidcMock) Login(ctx context.Context, in *pb.LoginRequest, opts ...grpc.CallOption) (*pb.LoginResponse, error) {
	m.logins = append(m.logins, in)
	flowRealm := m.flowRealm
	if flowRealm == "" {
		flowRealm = "oidc:kanidm"
	}
	if in.OidcCode != "" && in.Realm != flowRealm {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials: OIDC login state unknown, expired or already used on this node")
	}
	if in.OidcCode != "" && in.OidcBinding != mockBinding {
		m.lastLoginReq = in
		return nil, status.Error(codes.Unauthenticated, "invalid credentials: this OIDC login was not begun by this client")
	}
	return m.mockGRPC.Login(ctx, in, opts...)
}

func (m *oidcMock) redirectFor(realm string) string {
	if r, ok := m.redirects[realm]; ok {
		return r
	}
	return m.redirectURI()
}

func (m *oidcMock) redirectURI() string {
	if m.redirect != "" {
		return m.redirect
	}
	return "https://node-1:7445/oidc/callback"
}

func newOIDCUI(t *testing.T) (*Server, *oidcMock) {
	t.Helper()
	m := &oidcMock{mockGRPC: newDefaultMock()}
	s, err := NewServer(m, "test-cluster")
	if err != nil {
		t.Fatal(err)
	}
	return s, m
}

func serve(s *Server, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.csrfGuard(s.Handler()).ServeHTTP(w, r)
	return w
}

func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// begin runs GET /oidc/login and returns the flow cookie it set.
func begin(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	w := serve(s, httptest.NewRequest("GET", "/oidc/login?realm=oidc:kanidm", nil))
	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), "https://idp.example/authorize") {
		t.Fatalf("begin: %d to %q", w.Code, w.Header().Get("Location"))
	}
	c := cookieNamed(w, oidcFlowCookieNameSecure)
	if c == nil || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.MaxAge <= 0 ||
		!strings.HasPrefix(c.Value, mockBinding+".") {
		t.Fatalf("flow cookie %+v: want __Host-, HttpOnly, Secure, SameSite=Lax, Path=/, short-lived, carrying the binding", c)
	}
	if strings.Contains(w.Header().Get("Location"), mockBinding) || strings.Contains(w.Header().Get("Location"), "lvs_") {
		t.Fatal("a binding or session token in a URL")
	}
	return c
}

func TestOIDCUI_LoginPageOffersOIDCRealmsAsButtons(t *testing.T) {
	s, _ := newOIDCUI(t)
	w := serve(s, httptest.NewRequest("GET", "/login", nil))
	body := w.Body.String()
	if !strings.Contains(body, `href="/oidc/login?realm=oidc%3akanidm"`) && !strings.Contains(body, `href="/oidc/login?realm=oidc:kanidm"`) {
		t.Fatalf("no sign-in button for oidc:kanidm:\n%s", body)
	}
	if strings.Contains(body, `<option value="oidc:kanidm"`) {
		t.Fatal("an OIDC realm in the password realm dropdown: it takes no password")
	}
	if !strings.Contains(body, `<option value="ldap:corp"`) {
		t.Fatal("the LDAP realm left the password dropdown")
	}
}

// TestOIDCUI_BeginPassesTheBrowserAddress (review I1): the daemon sees only the
// UI's loopback connection, so the UI names the browser for the per-address
// bound.
func TestOIDCUI_BeginPassesTheBrowserAddress(t *testing.T) {
	s, m := newOIDCUI(t)
	r := httptest.NewRequest("GET", "/oidc/login?realm=oidc:kanidm", nil)
	r.RemoteAddr = "198.51.100.7:51234"
	serve(s, r)
	if m.lastBegin == nil || m.lastBegin.ClientAddress != "198.51.100.7" || m.lastBegin.Client != "web" {
		t.Fatalf("begin request %+v", m.lastBegin)
	}
}

// TestOIDCUI_CookieFollowsTheRedirectScheme (review M3, re-review N4): the
// cookie is chosen by the realm's redirect_url, not the request: an https
// redirect gets the __Host- cookie even when the request looks like plain http
// (a TLS proxy that omits X-Forwarded-Proto); only a plain-http (loopback)
// redirect gets the plain one.
func TestOIDCUI_CookieFollowsTheRedirectScheme(t *testing.T) {
	s, m := newOIDCUI(t)
	w := serve(s, httptest.NewRequest("GET", "/oidc/login?realm=oidc:kanidm", nil)) // plain http, no X-Forwarded-Proto
	c := cookieNamed(w, oidcFlowCookieNameSecure)
	if c == nil || !c.Secure || c.Path != "/" || c.Domain != "" || !c.HttpOnly {
		t.Fatalf("flow cookie for an https redirect %+v, want __Host-: Secure, Path=/, no Domain, HttpOnly", c)
	}
	if cookieNamed(w, oidcFlowCookieName) != nil && cookieNamed(w, oidcFlowCookieName).MaxAge >= 0 {
		t.Fatal("the un-prefixed cookie was set for an https redirect")
	}

	m.redirect = "http://127.0.0.1:7445/oidc/callback"
	w = serve(s, httptest.NewRequest("GET", "/oidc/login?realm=oidc:kanidm", nil))
	if c := cookieNamed(w, oidcFlowCookieName); c == nil || c.Secure || c.MaxAge <= 0 {
		t.Fatalf("flow cookie for a loopback http redirect %+v, want the plain one", c)
	}
}

// TestOIDCUI_APlantedPlainCookieIsIgnoredForAnHTTPSRealm (re-review N4): a
// plain lv_oidc_flow cookie (which a sibling host or a plain-http answer can
// set) never carries a binding for a realm whose redirect is https.
func TestOIDCUI_APlantedPlainCookieIsIgnoredForAnHTTPSRealm(t *testing.T) {
	s, m := newOIDCUI(t)
	begin(t, s) // learns that oidc:kanidm's redirect is https
	r := httptest.NewRequest("GET", "/oidc/callback?code=c&state=st-1", nil)
	r.AddCookie(&http.Cookie{Name: oidcFlowCookieName, Value: mockBinding + "." + "b2lkYzprYW5pZG0"}) // "oidc:kanidm"
	w := serve(s, r)
	if cookieNamed(w, sessionCookieName) != nil {
		t.Fatal("a planted plain cookie redeemed an https realm's flow")
	}
	for _, l := range m.logins {
		if l.OidcBinding != "" {
			t.Fatalf("the planted cookie's binding was sent: %+v", l)
		}
	}
}

// TestOIDCUI_BrowserAddressThroughATrustedProxy (re-review N1): behind a
// listed proxy the UI names the forwarded browser; from an unlisted peer the
// header is ignored.
func TestOIDCUI_BrowserAddressThroughATrustedProxy(t *testing.T) {
	s, m := newOIDCUI(t)
	p, _ := auth.ParseTrustedProxies([]string{"127.0.0.1"})
	s.SetTrustedProxies(p)
	for peer, want := range map[string]string{"127.0.0.1:4000": "198.51.100.7", "203.0.113.9:4000": "203.0.113.9"} {
		r := httptest.NewRequest("GET", "/oidc/login?realm=oidc:kanidm", nil)
		r.RemoteAddr = peer
		r.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.7")
		serve(s, r)
		if m.lastBegin.ClientAddress != want {
			t.Errorf("peer %s: client_address %q, want %q", peer, m.lastBegin.ClientAddress, want)
		}
	}
}

func TestOIDCUI_CallbackCompletesTheLogin(t *testing.T) {
	s, m := newOIDCUI(t)
	m.loginResp = &pb.LoginResponse{Token: "lvs_tok", Username: "olga", Role: "viewer", ExpiresAt: "2099-01-01T00:00:00Z"}
	flow := begin(t, s)
	r := httptest.NewRequest("GET", "/oidc/callback?code=the-code&state=st-1", nil)
	r.AddCookie(flow)
	w := serve(s, r)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/" {
		t.Fatalf("callback: %d to %q", w.Code, w.Header().Get("Location"))
	}
	if got := m.lastLoginReq; got == nil || got.Realm != "oidc:kanidm" || got.OidcCode != "the-code" || got.OidcState != "st-1" || got.OidcBinding != mockBinding {
		t.Fatalf("Login request %+v", got)
	}
	if c := cookieNamed(w, sessionCookieName); c == nil || c.Value != "lvs_tok" || !c.HttpOnly {
		t.Fatalf("session cookie %+v", c)
	}
	if c := cookieNamed(w, oidcFlowCookieNameSecure); c == nil || c.MaxAge >= 0 {
		t.Fatalf("the flow cookie was not cleared: %+v", c)
	}
	if w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("callback headers %v: the code-bearing URL must not leak via Referer or caches", w.Header())
	}
}

// TestOIDCUI_CallbackNotBegunByThisBrowserBurnsTheFlow (login CSRF, review
// M2): a callback with no flow cookie, or another flow's, gets no session,
// and is still handed to the daemon without the right binding so the flow is
// consumed (single use) and its code can never be redeemed.
func TestOIDCUI_CallbackNotBegunByThisBrowserBurnsTheFlow(t *testing.T) {
	s, m := newOIDCUI(t)
	m.loginResp = &pb.LoginResponse{Token: "lvs_tok", Username: "mallory", ExpiresAt: "2099-01-01T00:00:00Z"}
	flow := begin(t, s)
	for name, c := range map[string]*http.Cookie{
		"no cookie":        nil,
		"another flow's":   {Name: oidcFlowCookieNameSecure, Value: "bind-2." + strings.SplitN(flow.Value, ".", 2)[1]},
		"a garbled cookie": {Name: oidcFlowCookieNameSecure, Value: "nonsense"},
	} {
		m.logins = nil
		r := httptest.NewRequest("GET", "/oidc/callback?code=the-code&state=st-1", nil)
		if c != nil {
			r.AddCookie(c)
		}
		w := serve(s, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", name, w.Code)
		}
		if len(m.logins) == 0 {
			t.Errorf("%s: the flow was not handed to the daemon to be consumed", name)
		}
		for _, l := range m.logins {
			if l.OidcBinding == mockBinding {
				t.Errorf("%s: redeemed with the real binding", name)
			}
		}
		if cookieNamed(w, sessionCookieName) != nil {
			t.Errorf("%s: a session cookie was set", name)
		}
		if !strings.Contains(w.Body.String(), msgOIDCNotThisLogin) {
			t.Errorf("%s: page does not say the sign-in was not started here", name)
		}
	}
}

// TestOIDCUI_NoAttackerOrIdPTextOnThePage (review M6): the realm in a crafted
// link, the IdP's error and error_description, and the daemon's detail never
// reach the page; fixed messages do.
func TestOIDCUI_NoAttackerOrIdPTextOnThePage(t *testing.T) {
	s, m := newOIDCUI(t)
	w := serve(s, httptest.NewRequest("GET", "/oidc/login?realm="+url.QueryEscape("oidc:Call 555-0100 for help"), nil))
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "555-0100") || m.begins != 0 {
		t.Fatalf("crafted realm: %d, begins %d, body echoes it: %v", w.Code, m.begins, strings.Contains(w.Body.String(), "555-0100"))
	}

	flow := begin(t, s)
	r := httptest.NewRequest("GET", "/oidc/callback?state=st-1&error=access_denied%3Cscript%3E&error_description=Call+555-0100", nil)
	r.AddCookie(flow)
	w = serve(s, r)
	body := w.Body.String()
	if w.Code != http.StatusUnauthorized || len(m.logins) != 0 || strings.Contains(body, "access_denied") ||
		strings.Contains(body, "555-0100") || !strings.Contains(body, msgOIDCIdPRefused) {
		t.Fatalf("IdP error: %d, logins %d, body:\n%s", w.Code, len(m.logins), body)
	}

	m.beginErr = status.Error(codes.Unavailable, "realm unavailable: oauth2: Response: {\"secret-ish\":\"idp-internal\"}")
	w = serve(s, httptest.NewRequest("GET", "/oidc/login?realm=oidc:kanidm", nil))
	if strings.Contains(w.Body.String(), "idp-internal") || !strings.Contains(w.Body.String(), msgOIDCUnavailable) {
		t.Fatalf("daemon detail on the page:\n%s", w.Body.String())
	}
	m.beginErr = nil

	m.loginErr = status.Error(codes.PermissionDenied, `the account "Call 555-0100" is bound to another directory entry`)
	flow = begin(t, s)
	r = httptest.NewRequest("GET", "/oidc/callback?code=c&state=st-1", nil)
	r.AddCookie(flow)
	w = serve(s, r)
	if strings.Contains(w.Body.String(), "555-0100") || !strings.Contains(w.Body.String(), msgOIDCRefused) {
		t.Fatalf("refusal detail on the page:\n%s", w.Body.String())
	}

	m.loginErr = nil
	form := url.Values{"realm": {"oidc:Call 555-0100"}, "oidc_pending": {"h"}, "totp_code": {"123456"}}
	pr := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	pr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pr.Header.Set("Sec-Fetch-Site", "same-origin")
	w = serve(s, pr)
	if strings.Contains(w.Body.String(), "555-0100") {
		t.Fatal("a posted realm was echoed on the page")
	}
}

// TestOIDCUI_SecondFactorTravelsInTheForm: a login that stops for the factor
// sets no session, renders the code form carrying the handle in the body, and
// the posted form resumes it with the handle (not a code or password).
func TestOIDCUI_SecondFactorTravelsInTheForm(t *testing.T) {
	s, m := newOIDCUI(t)
	m.loginResp = &pb.LoginResponse{Requires_2Fa: true, OidcPending: "handle-1"}
	flow := begin(t, s)
	r := httptest.NewRequest("GET", "/oidc/callback?code=the-code&state=st-1", nil)
	r.AddCookie(flow)
	w := serve(s, r)
	if w.Code != http.StatusOK || cookieNamed(w, sessionCookieName) != nil {
		t.Fatalf("challenge: %d, session cookie %v", w.Code, cookieNamed(w, sessionCookieName))
	}
	body := w.Body.String()
	if !strings.Contains(body, `name="oidc_pending" value="handle-1"`) || !strings.Contains(body, `name="totp_code"`) ||
		strings.Contains(body, `name="password"`) {
		t.Fatalf("challenge form:\n%s", body)
	}

	m.loginResp = &pb.LoginResponse{Token: "lvs_tok", Username: "olga", ExpiresAt: "2099-01-01T00:00:00Z"}
	form := url.Values{"realm": {"oidc:kanidm"}, "oidc_pending": {"handle-1"}, "totp_code": {"123456"}}
	pr := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	pr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pr.Header.Set("Sec-Fetch-Site", "same-origin")
	w = serve(s, pr)
	got := m.lastLoginReq
	if got == nil || got.OidcPending != "handle-1" || got.TotpCode != "123456" || got.Realm != "oidc:kanidm" || got.OidcCode != "" || got.Password != "" {
		t.Fatalf("resume request %+v", got)
	}
	if c := cookieNamed(w, sessionCookieName); c == nil || c.Value != "lvs_tok" {
		t.Fatalf("resume: %d, session cookie %+v", w.Code, c)
	}
}

// TestOIDCUI_LoopbackHTTPRealmCallbackWithAPlainCookie (re-review 2, M4): a
// developer's loopback-http redirect (main allows it) still completes: the
// plain cookie is the flow's, and its binding is honoured for that realm.
func TestOIDCUI_LoopbackHTTPRealmCallbackWithAPlainCookie(t *testing.T) {
	s, m := newOIDCUI(t)
	m.redirect = "http://127.0.0.1:7445/oidc/callback"
	m.loginResp = &pb.LoginResponse{Token: "lvs_tok", Username: "dev", ExpiresAt: "2099-01-01T00:00:00Z"}
	w := serve(s, httptest.NewRequest("GET", "/oidc/login?realm=oidc:kanidm", nil))
	flow := cookieNamed(w, oidcFlowCookieName)
	if flow == nil || flow.Secure {
		t.Fatalf("plain flow cookie %+v", flow)
	}
	r := httptest.NewRequest("GET", "/oidc/callback?code=c&state=st-1", nil)
	r.AddCookie(flow)
	w = serve(s, r)
	if c := cookieNamed(w, sessionCookieName); c == nil || c.Value != "lvs_tok" {
		t.Fatalf("loopback-http callback: %d, session %+v", w.Code, c)
	}
	if got := m.lastLoginReq; got == nil || got.OidcBinding != mockBinding {
		t.Fatalf("Login request %+v: want the plain cookie's binding", got)
	}
}

// TestOIDCUI_APlainCookieUnlocksOnlyItsOwnRealm (re-review 2, M1): on a node
// with an https realm and a loopback-http realm, a planted plain cookie that
// names the http realm carries its binding to that realm only; the https
// realm, which holds the flow, gets no binding — so the flow is burned and
// nobody is signed in.
func TestOIDCUI_APlainCookieUnlocksOnlyItsOwnRealm(t *testing.T) {
	s, m := newOIDCUI(t)
	m.realms = []string{"local", "oidc:corp", "oidc:dev"}
	m.redirects = map[string]string{"oidc:dev": "http://127.0.0.1:7445/oidc/callback", "oidc:corp": "https://node-1:7445/oidc/callback"}
	m.flowRealm = "oidc:corp"
	m.loginResp = &pb.LoginResponse{Token: "lvs_attacker", Username: "mallory", ExpiresAt: "2099-01-01T00:00:00Z"}
	// The node learns oidc:dev is plain http. Unless this begin succeeds, the
	// planted plain cookie is dropped and the test proves nothing (re-review
	// 3, m1).
	w := serve(s, httptest.NewRequest("GET", "/oidc/login?realm=oidc:dev", nil))
	if c := cookieNamed(w, oidcFlowCookieName); w.Code != http.StatusFound || c == nil || c.Secure {
		t.Fatalf("setup: begin oidc:dev answered %d with flow cookie %+v, want 302 and a plain cookie", w.Code, c)
	}
	r := httptest.NewRequest("GET", "/oidc/callback?code=c&state=st-1", nil)
	r.AddCookie(&http.Cookie{Name: oidcFlowCookieName, Value: mockBinding + ".b2lkYzpkZXY"}) // "oidc:dev"
	m.logins = nil
	w = serve(s, r)
	if cookieNamed(w, sessionCookieName) != nil {
		t.Fatal("a plain cookie naming the http realm unlocked the https realm's flow")
	}
	sawCorp, devGotBinding := false, false
	for _, l := range m.logins {
		if l.Realm == "oidc:dev" && l.OidcBinding == mockBinding {
			devGotBinding = true // the plain cookie was accepted, for its own realm
		}
		if l.Realm == "oidc:corp" {
			sawCorp = true
			if l.OidcBinding != "" {
				t.Fatalf("the https realm was sent the plain cookie's binding: %+v", l)
			}
		}
	}
	if !sawCorp {
		t.Fatal("the https realm's flow was not handed to the daemon to be burned")
	}
	if !devGotBinding {
		t.Fatalf("setup: the plain cookie's binding never reached its own realm (logins %+v), so the test proves nothing", m.logins)
	}
}

// TestOIDCUI_WarnsOnForwardingFromAnUnlistedPeer (re-review 2, M2; re-review
// 3, m2): a sign-in with X-Forwarded-For from a peer not in trusted_proxies is
// logged, at most once per interval PER PEER; a listed proxy is not. The
// limiter is per peer, so a client that reaches the UI directly and sends the
// header cannot spend the warning a misconfigured proxy would raise.
func TestOIDCUI_WarnsOnForwardingFromAnUnlistedPeer(t *testing.T) {
	s, _ := newOIDCUI(t)
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	begin := func(peer string) {
		r := httptest.NewRequest("GET", "/oidc/login?realm=oidc:kanidm", nil)
		r.RemoteAddr = peer
		r.Header.Set("X-Forwarded-For", "198.51.100.7")
		serve(s, r)
	}
	warned := func(peer string) int {
		return strings.Count(logs.String(), "peer="+peer+"\n")
	}
	begin("10.0.0.5:4000")
	begin("10.0.0.5:4001")
	if n := warned("10.0.0.5"); n != 1 {
		t.Fatalf("%d warnings for two sign-ins from an unlisted proxy, want 1 (rate-limited)\n%s", n, logs.String())
	}

	// An attacker reaching the UI directly takes its own warning, as often
	// as it likes, and from as many addresses as it likes; the proxy is
	// still named.
	for i := 0; i < 3*untrustedForwardWarnPeers; i++ {
		begin(fmt.Sprintf("192.0.2.%d:5555", i%(2*untrustedForwardWarnPeers)+1))
	}
	begin("10.0.0.6:4000")
	if warned("192.0.2.1") == 0 || warned("10.0.0.6") != 1 {
		t.Fatalf("a direct client's forwarding hid a misconfigured proxy's warning:\n%s", logs.String())
	}
	if n := s.untrustedForwardWarns.len(); n > untrustedForwardWarnPeers {
		t.Fatalf("the warning limiter holds %d peers, want at most %d", n, untrustedForwardWarnPeers)
	}

	logs.Reset()
	p, _ := auth.ParseTrustedProxies([]string{"10.0.0.0/8"})
	s.SetTrustedProxies(p)
	begin("10.0.0.77:4000") // never warned about, so only the listing silences it
	if strings.Contains(logs.String(), "not in trusted_proxies") {
		t.Fatal("warned about a listed proxy")
	}
}

// TestUntrustedForwardWarns_PerPeerWindowAndLRU: one warning per peer per
// window, measured on the monotonic clock; the set is bounded, and a full
// set forgets the least recently seen peer.
func TestUntrustedForwardWarns_PerPeerWindowAndLRU(t *testing.T) {
	var l untrustedForwardWarns
	t0 := time.Now()
	if !l.allow("a", t0) || l.allow("a", t0.Add(untrustedForwardWarnEvery-time.Second)) {
		t.Fatal("a peer was warned about twice inside one window")
	}
	if !l.allow("a", t0.Add(untrustedForwardWarnEvery)) {
		t.Fatal("a peer was not warned about again after the window")
	}
	if !l.allow("b", t0) {
		t.Fatal("another peer's warning was suppressed by the first peer's")
	}
	// Fill the set from scratch, oldest first; p0 is then seen again, so p1
	// is the least recently seen and a new peer evicts it, not p0.
	var l2 untrustedForwardWarns
	t1 := t0.Add(time.Hour)
	for i := 0; i < untrustedForwardWarnPeers; i++ {
		l2.allow(fmt.Sprintf("p%d", i), t1.Add(time.Duration(i)*time.Millisecond))
	}
	if l2.allow("p0", t1.Add(time.Second)) {
		t.Fatal("a peer still in the set was warned about again inside its window")
	}
	if !l2.allow("new", t1.Add(2*time.Second)) {
		t.Fatal("a new peer was not warned about when the set was full")
	}
	if n := l2.len(); n != untrustedForwardWarnPeers {
		t.Fatalf("the set holds %d peers, want its bound %d", n, untrustedForwardWarnPeers)
	}
	if l2.allow("p0", t1.Add(3*time.Second)) {
		t.Fatal("the most recently seen peer was evicted instead of the least recently seen")
	}
	if !l2.allow("p1", t1.Add(3*time.Second)) {
		t.Fatal("the least recently seen peer was kept when the set was full")
	}
}
