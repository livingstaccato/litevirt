// Fleet scenarios for the OIDC sign-in flow: a strict fake identity provider
// (real discovery, JWKS, RS256 ID tokens, PKCE S256, exact redirect matching,
// its own TLS CA) and two real daemons, each with its own web UI over TLS and
// its own oidc:corp realm whose redirect is that node's callback. What only a
// multi-node run can show: the flow lives on the node that began it, a
// callback arriving at another node is refused without spending the code, and
// the session the flow mints is an ordinary replicated session every node
// honours.
package fleet

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/auth/oidctest"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/ui"
)

type oidcFleetT struct {
	c    *Cluster
	idp  *oidctest.Provider
	uis  map[string]*httptest.Server // node name → its web UI
	clis map[string]string           // node name → its cli_redirect_url
}

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func newOIDCFleet(t *testing.T) *oidcFleetT {
	t.Helper()
	ctx := context.Background()
	c, _ := latchedFleet(t, 2, 1011)
	f := &oidcFleetT{c: c, uis: map[string]*httptest.Server{}, clis: map[string]string{}}
	f.idp = oidctest.New(t, "litevirt", "s3cret")
	f.idp.SignIn(&oidctest.User{Subject: "sub-alice", PreferredUsername: "alice", Groups: []string{"lv-operators"}})
	caFile := f.idp.CAFile(t, t.TempDir())
	for _, n := range c.Nodes {
		srv, err := ui.NewServer(c.SelfClient(n), n.Name)
		if err != nil {
			t.Fatal(err)
		}
		ts := httptest.NewTLSServer(srv.Handler())
		t.Cleanup(ts.Close)
		f.uis[n.Name] = ts
		web := ts.URL + "/oidc/callback"
		cliCB := fmt.Sprintf("http://127.0.0.1:%d/oidc/callback", freeLoopbackPort(t))
		f.clis[n.Name] = cliCB
		f.idp.RegisterRedirect(web)
		f.idp.RegisterRedirect(cliCB)
		realm, err := auth.NewOIDCRealm(ctx, auth.OIDCConfig{
			ShortName: "corp", IssuerURL: f.idp.Issuer, ClientID: "litevirt", ClientSecret: "s3cret",
			RedirectURL: web, CLIRedirectURL: cliCB, CAFile: caFile, SubjectClaim: "preferred_username",
		})
		if err != nil {
			t.Fatalf("%s: NewOIDCRealm: %v", n.Name, err)
		}
		reg := auth.NewRegistry()
		reg.Register(auth.NewLocalRealm(n.DB))
		reg.Register(realm)
		n.Server.SetRealmRegistry(reg)
	}
	return f
}

// browser is one user agent: a cookie jar shared across the UIs (cookies are
// not port-scoped, as in a real browser for one host) and no automatic
// redirects, so the test sees each hop.
func (f *oidcFleetT) browser(t *testing.T) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	extra := make([]*httptest.Server, 0, len(f.uis))
	for _, s := range f.uis {
		extra = append(extra, s)
	}
	b := f.idp.BrowserClient(extra...)
	b.Jar = jar
	return b
}

func get(t *testing.T, b *http.Client, u string) *http.Response {
	t.Helper()
	resp, err := b.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func location(t *testing.T, resp *http.Response) string {
	t.Helper()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("%s answered %d, want a redirect", resp.Request.URL.Path, resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

func sessionCookie(resp *http.Response) string {
	for _, c := range resp.Cookies() {
		if c.Name == "lv_session" && c.MaxAge >= 0 {
			return c.Value
		}
	}
	return ""
}

// beginAtIdP begins a web login on node n's UI and plays the browser at the
// IdP; it returns the callback URL the IdP sent the browser to.
func (f *oidcFleetT) beginAtIdP(t *testing.T, b *http.Client, n *Node) *url.URL {
	t.Helper()
	toIdP := location(t, get(t, b, f.uis[n.Name].URL+"/oidc/login?realm=oidc:corp"))
	if !strings.HasPrefix(toIdP, f.idp.Issuer+"/authorize?") {
		t.Fatalf("%s's UI sent the browser to %q, not the IdP", n.Name, toIdP)
	}
	back, err := url.Parse(location(t, get(t, b, toIdP)))
	if err != nil {
		t.Fatal(err)
	}
	if back.Query().Get("code") == "" {
		t.Fatalf("the IdP answered %s with no code", back)
	}
	return back
}

func whoami(t *testing.T, f *oidcFleetT, n *Node, token string) *pb.WhoamiResponse {
	t.Helper()
	w, err := f.c.bearerClient(n, token).Whoami(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("Whoami on %s with the OIDC session: %v", n.Name, err)
	}
	return w
}

// TestFleet_OIDC_WebLoginMintsAReplicatedSession: begin on node-0's UI, the
// IdP sends the browser back to node-0's callback, node-0 exchanges the code
// and mints a session in oidc:corp; once replicated, node-1 honours it too.
func TestFleet_OIDC_WebLoginMintsAReplicatedSession(t *testing.T) {
	f := newOIDCFleet(t)
	a, b := f.c.Nodes[0], f.c.Nodes[1]
	br := f.browser(t)
	back := f.beginAtIdP(t, br, a)
	if !strings.HasPrefix(back.String(), f.uis[a.Name].URL+"/oidc/callback?") {
		t.Fatalf("the IdP sent the browser to %s, not %s's callback", back, a.Name)
	}
	resp := get(t, br, back.String())
	if loc := location(t, resp); loc != "/" {
		t.Fatalf("callback sent the browser to %q", loc)
	}
	tok := sessionCookie(resp)
	if !strings.HasPrefix(tok, "lvs_") {
		t.Fatalf("no session cookie after the callback (cookies %v)", resp.Cookies())
	}
	if w := whoami(t, f, a, tok); w.Username != "alice" || w.Realm != "oidc:corp" {
		t.Fatalf("Whoami on %s: %+v, want alice in oidc:corp", a.Name, w)
	}
	f.c.WaitConverged(t, convergeTimeout)
	if w := whoami(t, f, b, tok); w.Username != "alice" {
		t.Fatalf("Whoami on %s: %+v", b.Name, w)
	}
	if f.idp.Exchanges != 1 {
		t.Fatalf("%d token exchanges, want 1", f.idp.Exchanges)
	}
	// The callback replayed (same browser, same URL) mints nothing more.
	resp = get(t, br, back.String())
	if tok2 := sessionCookie(resp); tok2 != "" {
		t.Fatalf("a replayed callback minted a session")
	}
}

// TestFleet_OIDC_CallbackAtAnotherNodeIsRefused: the flow (state, PKCE
// verifier, nonce) lives only on the node that began it. A callback delivered
// to the other node finds no flow: refused, no session, and the code is not
// even presented to the IdP.
func TestFleet_OIDC_CallbackAtAnotherNodeIsRefused(t *testing.T) {
	f := newOIDCFleet(t)
	a, b := f.c.Nodes[0], f.c.Nodes[1]
	br := f.browser(t)
	back := f.beginAtIdP(t, br, a)
	elsewhere := f.uis[b.Name].URL + "/oidc/callback?" + back.RawQuery
	resp := get(t, br, elsewhere)
	if resp.StatusCode != http.StatusUnauthorized || sessionCookie(resp) != "" {
		t.Fatalf("callback at %s for a flow begun on %s: %d, cookies %v; want 401 and no session",
			b.Name, a.Name, resp.StatusCode, resp.Cookies())
	}
	if f.idp.Exchanges != 0 {
		t.Fatalf("the other node presented the code to the IdP (%d exchanges)", f.idp.Exchanges)
	}
}

// TestFleet_OIDC_CLILoopbackLogin drives `lv login --realm oidc:corp`'s flow
// (internal/cli.OIDCLogin) against node-1: the node hands out its loopback
// redirect, the "browser" follows the IdP back to the CLI's listener, and the
// CLI completes the login on the same node.
func TestFleet_OIDC_CLILoopbackLogin(t *testing.T) {
	f := newOIDCFleet(t)
	n := f.c.Nodes[1]
	br := f.browser(t)
	opened := ""
	resp, err := cli.OIDCLogin(context.Background(), f.c.SelfClient(n), cli.OIDCLoginOptions{
		Realm:   "oidc:corp",
		Timeout: 30 * time.Second,
		OpenBrowser: func(u string) error {
			opened = u
			go func() {
				r, err := br.Get(u)
				if err != nil {
					return
				}
				r.Body.Close()
				if loc := r.Header.Get("Location"); loc != "" {
					if r2, err := http.Get(loc); err == nil {
						r2.Body.Close()
					}
				}
			}()
			return nil
		},
	})
	if err != nil {
		t.Fatalf("CLI OIDC login: %v", err)
	}
	if !strings.Contains(opened, url.QueryEscape(f.clis[n.Name])) {
		t.Fatalf("the CLI opened %q, which does not carry %s's cli_redirect_url", opened, n.Name)
	}
	if w := whoami(t, f, n, resp.Token); w.Username != "alice" || w.Realm != "oidc:corp" {
		t.Fatalf("Whoami: %+v", w)
	}
}

// TestFleet_OIDC_SecondFactorThroughTheUI: with the login policy covering
// oidc:corp and a factor enrolled for alice, the callback mints no session; it
// renders the code form carrying the node's handle, and the posted code
// completes the login on that node.
func TestFleet_OIDC_SecondFactorThroughTheUI(t *testing.T) {
	ctx := context.Background()
	f := newOIDCFleet(t)
	a := f.c.Nodes[0]
	br := f.browser(t)

	// First login makes alice's shadow; then a factor and a policy.
	resp := get(t, br, f.beginAtIdP(t, br, a).String())
	if sessionCookie(resp) == "" {
		t.Fatal("first login made no session")
	}
	enr, err := auth.EnrollTOTP(ctx, a.DB, "alice", "phone")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.SelfClient(a).SetLoginPolicy(ctx, &pb.SetLoginPolicyRequest{Require_2Fa: "oidc:corp"}); err != nil {
		t.Fatalf("SetLoginPolicy: %v", err)
	}

	br = f.browser(t)
	resp = get(t, br, f.beginAtIdP(t, br, a).String())
	if resp.StatusCode != http.StatusOK || sessionCookie(resp) != "" {
		t.Fatalf("covered login: %d, session %q; want the code form and no session", resp.StatusCode, sessionCookie(resp))
	}
	body := readAll(t, resp)
	m := regexp.MustCompile(`name="oidc_pending" value="([^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no oidc_pending in the form:\n%s", body)
	}
	code, err := totp.GenerateCodeCustom(enr.SecretBase32, time.Now().UTC(), totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatal(err)
	}
	post, err := br.PostForm(f.uis[a.Name].URL+"/login", url.Values{
		"realm": {"oidc:corp"}, "oidc_pending": {m[1]}, "totp_code": {code},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer post.Body.Close()
	tok := sessionCookie(post)
	if post.StatusCode != http.StatusFound || tok == "" {
		t.Fatalf("posting the code: %d, cookies %v", post.StatusCode, post.Cookies())
	}
	if w := whoami(t, f, a, tok); w.Username != "alice" || w.GetRequires_2FaEnrollment() {
		t.Fatalf("Whoami: %+v, want a full session for alice", w)
	}
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}
