package ui

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func passwordLogin(remote, xff string) *http.Request {
	r := httptest.NewRequest("POST", "/login", strings.NewReader("username=admin&password=secret"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", "probe-agent/1")
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

// O2: the UI reaches the daemon over 127.0.0.1, so it must pass the browser's
// address or every UI session records 127.0.0.1. X-Forwarded-For is believed
// only from a trusted_proxies peer — the OIDC sign-in bound's trust model.
func TestUILogin_PassesTheBrowsersAddress(t *testing.T) {
	cases := []struct {
		name    string
		trusted []netip.Prefix
		remote  string
		xff     string
		want    string
	}{
		{"direct browser", nil, "203.0.113.7:51000", "", "203.0.113.7"},
		{"XFF from an untrusted peer is ignored", nil, "203.0.113.7:51000", "198.51.100.1", "203.0.113.7"},
		{"XFF from a trusted proxy names the browser",
			[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, "10.1.2.3:443", "198.51.100.1", "198.51.100.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mock := newDefaultMock()
			s := newTestUIServer(t, mock)
			s.SetTrustedProxies(c.trusted)
			serveRequest(s, passwordLogin(c.remote, c.xff))
			got := mock.lastLoginReq
			if got == nil {
				t.Fatal("no Login call")
			}
			if got.ClientAddress != c.want {
				t.Errorf("ClientAddress = %q, want %q", got.ClientAddress, c.want)
			}
			if got.UserAgent != "probe-agent/1" {
				t.Errorf("UserAgent = %q, want the browser's", got.UserAgent)
			}
		})
	}
}

func TestUIOIDCCallbackAndSecondFactor_PassTheBrowsersAddress(t *testing.T) {
	s, m := newOIDCUI(t)
	m.loginResp = &pb.LoginResponse{Requires_2Fa: true, OidcPending: "handle-1"}
	flow := begin(t, s)
	r := httptest.NewRequest("GET", "/oidc/callback?code=the-code&state=st-1", nil)
	r.RemoteAddr = "203.0.113.8:5000"
	r.AddCookie(flow)
	serve(s, r)
	if got := m.lastLoginReq; got == nil || got.ClientAddress != "203.0.113.8" {
		t.Fatalf("callback Login request %+v: want ClientAddress 203.0.113.8", got)
	}

	m.loginResp = &pb.LoginResponse{Token: "lvs_tok", Username: "olga", ExpiresAt: "2099-01-01T00:00:00Z"}
	form := url.Values{"realm": {"oidc:kanidm"}, "oidc_pending": {"handle-1"}, "totp_code": {"123456"}}
	pr := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	pr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pr.Header.Set("Sec-Fetch-Site", "same-origin")
	pr.RemoteAddr = "203.0.113.9:5000"
	serve(s, pr)
	if got := m.lastLoginReq; got == nil || got.OidcPending != "handle-1" || got.ClientAddress != "203.0.113.9" {
		t.Fatalf("second-factor Login request %+v: want ClientAddress 203.0.113.9", got)
	}
}
