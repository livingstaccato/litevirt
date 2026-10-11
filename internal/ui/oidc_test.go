package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// oidcMock is the UI mock with an OIDC realm and a BeginOIDCLogin.
type oidcMock struct {
	*mockGRPC
	begins int
}

func (m *oidcMock) ListRealms(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.ListRealmsResponse, error) {
	return &pb.ListRealmsResponse{Realms: []string{"local", "ldap:corp", "oidc:kanidm"}}, nil
}

func (m *oidcMock) BeginOIDCLogin(_ context.Context, in *pb.BeginOIDCLoginRequest, _ ...grpc.CallOption) (*pb.BeginOIDCLoginResponse, error) {
	m.begins++
	return &pb.BeginOIDCLoginResponse{
		AuthUrl:     "https://idp.example/authorize?state=st-1",
		State:       "st-1",
		RedirectUri: "https://node-1:7445/oidc/callback",
	}, nil
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
	if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != oidcCallbackPath || c.MaxAge <= 0 {
		t.Fatalf("flow cookie %+v: want HttpOnly, SameSite=Lax, scoped to the callback, short-lived", c)
	}
	if strings.Contains(w.Header().Get("Location"), "lvs_") {
		t.Fatal("a session token in a URL")
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
	if got := m.lastLoginReq; got == nil || got.Realm != "oidc:kanidm" || got.OidcCode != "the-code" || got.OidcState != "st-1" {
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

// TestOIDCUI_CallbackNotBegunByThisBrowserIsRefused: login CSRF. A callback
// with no flow cookie, or another flow's, never reaches Login, so the code is
// not spent and no session is set.
func TestOIDCUI_CallbackNotBegunByThisBrowserIsRefused(t *testing.T) {
	s, m := newOIDCUI(t)
	m.loginResp = &pb.LoginResponse{Token: "lvs_tok", Username: "mallory", ExpiresAt: "2099-01-01T00:00:00Z"}
	flow := begin(t, s)
	for name, c := range map[string]*http.Cookie{
		"no cookie":        nil,
		"another flow's":   {Name: oidcFlowCookieName, Value: "st-2." + strings.SplitN(flow.Value, ".", 2)[1]},
		"a garbled cookie": {Name: oidcFlowCookieName, Value: "nonsense"},
	} {
		m.lastLoginReq = nil
		r := httptest.NewRequest("GET", "/oidc/callback?code=the-code&state=st-1", nil)
		if c != nil {
			r.AddCookie(c)
		}
		w := serve(s, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", name, w.Code)
		}
		if m.lastLoginReq != nil {
			t.Errorf("%s: Login was called (the code was spent)", name)
		}
		if cookieNamed(w, sessionCookieName) != nil {
			t.Errorf("%s: a session cookie was set", name)
		}
	}
}

func TestOIDCUI_IdPErrorIsShownSanitisedAndCallsNothing(t *testing.T) {
	s, m := newOIDCUI(t)
	flow := begin(t, s)
	r := httptest.NewRequest("GET", "/oidc/callback?state=st-1&error=access_denied%3Cscript%3E&error_description=%3Cb%3Eevil", nil)
	r.AddCookie(flow)
	w := serve(s, r)
	if w.Code != http.StatusUnauthorized || m.lastLoginReq != nil {
		t.Fatalf("IdP error: %d, login called=%v", w.Code, m.lastLoginReq != nil)
	}
	if body := w.Body.String(); strings.Contains(body, "denied<script") || strings.Contains(body, "evil") || !strings.Contains(body, "access_deniedscript") {
		t.Fatalf("IdP error rendered unsafely or not at all:\n%s", body)
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
