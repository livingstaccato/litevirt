package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// oidcMock is the UI mock with an OIDC realm, a BeginOIDCLogin, and a Login
// that, like the daemon, refuses a code redeemed without the flow's binding.
type oidcMock struct {
	*mockGRPC
	begins    int
	lastBegin *pb.BeginOIDCLoginRequest
	beginErr  error
	logins    []*pb.LoginRequest
}

const mockBinding = "bind-1"

func (m *oidcMock) ListRealms(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.ListRealmsResponse, error) {
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
		RedirectUri: "https://node-1:7445/oidc/callback",
		Binding:     mockBinding,
	}, nil
}

func (m *oidcMock) Login(ctx context.Context, in *pb.LoginRequest, opts ...grpc.CallOption) (*pb.LoginResponse, error) {
	m.logins = append(m.logins, in)
	if in.OidcCode != "" && in.OidcBinding != mockBinding {
		m.lastLoginReq = in
		return nil, status.Error(codes.Unauthenticated, "invalid credentials: this OIDC login was not begun by this client")
	}
	return m.mockGRPC.Login(ctx, in, opts...)
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
	c := cookieNamed(w, oidcFlowCookieName)
	if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.MaxAge <= 0 ||
		!strings.HasPrefix(c.Value, mockBinding+".") {
		t.Fatalf("flow cookie %+v: want HttpOnly, SameSite=Lax, Path=/, short-lived, carrying the binding", c)
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

// TestOIDCUI_HostPrefixedCookieOverHTTPS (review M3): over https the flow
// cookie is __Host- (Secure, Path=/, no Domain), so a sibling host cannot
// plant one.
func TestOIDCUI_HostPrefixedCookieOverHTTPS(t *testing.T) {
	s, _ := newOIDCUI(t)
	w := serve(s, httptest.NewRequest("GET", "https://node-1:7445/oidc/login?realm=oidc:kanidm", nil))
	c := cookieNamed(w, oidcFlowCookieNameSecure)
	if c == nil || !c.Secure || c.Path != "/" || c.Domain != "" || !c.HttpOnly {
		t.Fatalf("flow cookie over https %+v, want __Host-: Secure, Path=/, no Domain, HttpOnly", c)
	}
	if cookieNamed(w, oidcFlowCookieName) != nil {
		t.Fatal("the un-prefixed cookie was set over https")
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
	if c := cookieNamed(w, oidcFlowCookieName); c == nil || c.MaxAge >= 0 {
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
		"another flow's":   {Name: oidcFlowCookieName, Value: "bind-2." + strings.SplitN(flow.Value, ".", 2)[1]},
		"a garbled cookie": {Name: oidcFlowCookieName, Value: "nonsense"},
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
