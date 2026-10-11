package e2e

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// OIDC sign-in against a real identity provider (lab 1's kanidm). The fleet
// tests prove the flow against a strict fake; only a live IdP proves litevirt
// speaks to a real one: its discovery document, its signing algorithm, its
// PKCE enforcement, its redirect matching and its claims.
//
// The test plays the browser: it begins the login on the node's UI, signs the
// user in at kanidm through kanidm's JSON API (the same calls the lab's
// tools/idm-vm/oidc-login.py makes, no browser needed), lets kanidm redirect
// back to the node's callback, and checks the session the node set.
//
// Opt-in, on top of LITEVIRT_E2E=1 (it touches nothing but logins):
//
//	E2E_OIDC=1
//	E2E_OIDC_UI       the node's UI base URL whose realm is configured,
//	                  e.g. https://10.77.0.16:8080 (its redirect_url's origin)
//	E2E_OIDC_SECRETS  a directory holding <user>.password and, for an MFA
//	                  user, <user>.totp (kanidm-cred.py's JSON); never commit it
//	E2E_OIDC_REALM    default oidc:kanidm
//	E2E_OIDC_USERS    default lvadmin,lvoper,lvview,lvmfa
//	E2E_OIDC_UI_CA    CA the UI's certificate chains to (default
//	                  /etc/litevirt/pki/ca.crt)
//	E2E_OIDC_IDP_CA   CA kanidm's certificate chains to (default: system store)
//
// Run on a cluster node that resolves the IdP (lab 1: node-6). Credentials are
// read from files, never from the command line.

func oidcE2E(t *testing.T) (ui, realm, secrets string, users []string) {
	t.Helper()
	if os.Getenv("E2E_OIDC") != "1" {
		t.Skip("set E2E_OIDC=1 (and E2E_OIDC_UI, E2E_OIDC_SECRETS) to run the OIDC sign-in against a live IdP")
	}
	ui = strings.TrimRight(os.Getenv("E2E_OIDC_UI"), "/")
	secrets = os.Getenv("E2E_OIDC_SECRETS")
	if ui == "" || secrets == "" {
		t.Fatal("E2E_OIDC=1 needs E2E_OIDC_UI and E2E_OIDC_SECRETS")
	}
	realm = envOr("E2E_OIDC_REALM", "oidc:kanidm")
	users = strings.Split(envOr("E2E_OIDC_USERS", "lvadmin,lvoper,lvview,lvmfa"), ",")
	return
}

// oidcBrowser trusts the UI's CA and the IdP's (system store plus
// E2E_OIDC_IDP_CA), keeps cookies, and follows no redirect on its own.
func oidcBrowser(t *testing.T) *http.Client {
	t.Helper()
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, f := range []string{envOr("E2E_OIDC_UI_CA", "/etc/litevirt/pki/ca.crt"), os.Getenv("E2E_OIDC_IDP_CA")} {
		if f == "" {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil || !pool.AppendCertsFromPEM(b) {
			t.Fatalf("CA %s: %v", f, err)
		}
	}
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar:           jar,
		Timeout:       30 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// kanidmTOTP computes the current code from kanidm-cred.py's JSON
// ({"secret_b32", "algo", "step", "digits"}).
func kanidmTOTP(t *testing.T, path string) uint32 {
	t.Helper()
	var spec struct {
		Secret string `json:"secret_b32"`
		Algo   string `json:"algo"`
		Step   int64  `json:"step"`
		Digits int    `json:"digits"`
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &spec); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	s := strings.ToUpper(spec.Secret)
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	key, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("%s: secret: %v", path, err)
	}
	var h func() hash.Hash
	switch spec.Algo {
	case "sha1":
		h = sha1.New
	case "sha512":
		h = sha512.New
	default:
		h = sha256.New
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(time.Now().Unix()/spec.Step))
	mac := hmac.New(h, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < spec.Digits; i++ {
		mod *= 10
	}
	return v % mod
}

// kanidmJSON posts body as JSON to the IdP and decodes the answer.
func kanidmJSON(t *testing.T, br *http.Client, method, u string, body any, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, u, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := br.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

// kanidmSignIn runs kanidm's auth state machine for user and returns its
// bearer.
func kanidmSignIn(t *testing.T, br *http.Client, idp, user, secrets string) string {
	t.Helper()
	pw, err := os.ReadFile(filepath.Join(secrets, user+".password"))
	if err != nil {
		t.Fatalf("password for %s: %v", user, err)
	}
	resp, raw := kanidmJSON(t, br, "POST", idp+"/v1/auth",
		map[string]any{"step": map[string]any{"init2": map[string]any{"username": user, "issue": "token", "privileged": false}}}, nil)
	hdr := map[string]string{"X-KANIDM-AUTH-SESSION-ID": resp.Header.Get("X-KANIDM-AUTH-SESSION-ID")}
	var st struct {
		State map[string]json.RawMessage `json:"state"`
	}
	_ = json.Unmarshal(raw, &st)
	var choose []string
	_ = json.Unmarshal(st.State["choose"], &choose)
	mech := "password"
	for _, c := range choose {
		if c == "passwordmfa" {
			mech = "passwordmfa"
		}
	}
	kanidmJSON(t, br, "POST", idp+"/v1/auth", map[string]any{"step": map[string]any{"begin": mech}}, hdr)
	var creds []map[string]any
	if mech == "passwordmfa" {
		creds = append(creds, map[string]any{"totp": kanidmTOTP(t, filepath.Join(secrets, user+".totp"))})
	}
	creds = append(creds, map[string]any{"password": strings.TrimRight(string(pw), "\r\n")})
	for _, c := range creds {
		_, raw = kanidmJSON(t, br, "POST", idp+"/v1/auth", map[string]any{"step": map[string]any{"cred": c}}, hdr)
		st.State = nil
		_ = json.Unmarshal(raw, &st)
		if _, denied := st.State["denied"]; denied {
			t.Fatalf("kanidm denied %s (%s)", user, mech)
		}
	}
	var tok string
	if err := json.Unmarshal(st.State["success"], &tok); err != nil || tok == "" {
		t.Fatalf("kanidm sign-in for %s did not finish (%s)", user, mech)
	}
	return tok
}

// kanidmAuthorise asks kanidm, as the signed-in user, to answer litevirt's
// authorization request, and returns the redirect it sends the browser to.
func kanidmAuthorise(t *testing.T, br *http.Client, authURL, bearer string) string {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	idp := u.Scheme + "://" + u.Host
	params := map[string]string{}
	for k, v := range u.Query() {
		params[k] = v[0]
	}
	if params["code_challenge_method"] != "S256" || params["nonce"] == "" || params["state"] == "" {
		t.Fatalf("litevirt's authorization request lacks S256 PKCE, a nonce or a state: %v", params)
	}
	hdr := map[string]string{"Authorization": "Bearer " + bearer}
	resp, raw := kanidmJSON(t, br, "POST", idp+"/oauth2/authorise", params, hdr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/oauth2/authorise: HTTP %d: %.300s", resp.StatusCode, raw)
	}
	var consent struct {
		ConsentRequested *struct {
			ConsentToken string `json:"consent_token"`
		} `json:"ConsentRequested"`
	}
	if json.Unmarshal(raw, &consent) == nil && consent.ConsentRequested != nil {
		resp, raw = kanidmJSON(t, br, "POST", idp+"/oauth2/authorise/permit", consent.ConsentRequested.ConsentToken, hdr)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatalf("kanidm sent no redirect (HTTP %d): %.300s", resp.StatusCode, raw)
	}
	return loc
}

// TestOIDC_LiveIdPSignInThroughTheWebUI signs each lab user in through the
// node's UI and kanidm, and checks the session: set, usable, and in the realm.
// lvmfa signs in with password + TOTP at kanidm (its account policy); with no
// litevirt login policy covering the realm, that is all litevirt asks.
func TestOIDC_LiveIdPSignInThroughTheWebUI(t *testing.T) {
	ui, realm, secrets, users := oidcE2E(t)
	for _, user := range users {
		user := strings.TrimSpace(user)
		t.Run(user, func(t *testing.T) {
			br := oidcBrowser(t)
			resp, err := br.Get(ui + "/oidc/login?realm=" + url.QueryEscape(realm))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			authURL := resp.Header.Get("Location")
			if resp.StatusCode != http.StatusFound || authURL == "" {
				t.Fatalf("begin: HTTP %d, Location %q", resp.StatusCode, authURL)
			}
			au, _ := url.Parse(authURL)
			bearer := kanidmSignIn(t, br, au.Scheme+"://"+au.Host, user, secrets)
			callback := kanidmAuthorise(t, br, authURL, bearer)
			if !strings.HasPrefix(callback, ui+"/oidc/callback?") {
				t.Fatalf("kanidm redirected to %q, not this node's callback", callback)
			}

			// A callback for this flow at the node without the browser's flow
			// cookie is refused (login CSRF): a fresh client has none.
			fresh := oidcBrowser(t)
			if r, err := fresh.Get(callback); err == nil {
				r.Body.Close()
				if r.StatusCode != http.StatusForbidden {
					t.Fatalf("a callback from a browser that did not begin the login: HTTP %d, want 403", r.StatusCode)
				}
			}

			resp, err = br.Get(callback)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && regexp.MustCompile(`name="oidc_pending"`).Match(body) {
				t.Fatalf("litevirt asked %s for its own second factor; this test expects no login policy covering %s", user, realm)
			}
			var session string
			for _, c := range resp.Cookies() {
				if c.Name == "lv_session" && c.MaxAge >= 0 {
					session = c.Value
				}
			}
			if resp.StatusCode != http.StatusFound || session == "" {
				t.Fatalf("callback: HTTP %d, no session (body %.400s)", resp.StatusCode, body)
			}
			if strings.Contains(resp.Header.Get("Location"), session) {
				t.Fatal("the session token is in a URL")
			}

			// The session works: the dashboard renders instead of bouncing
			// to /login.
			resp, err = br.Get(ui + "/")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusFound {
				t.Fatalf("dashboard with the OIDC session bounced to %q: the session is not accepted", resp.Header.Get("Location"))
			}

			// The callback replayed mints nothing: the state is single-use.
			resp, err = br.Get(callback)
			if err == nil {
				resp.Body.Close()
				for _, c := range resp.Cookies() {
					if c.Name == "lv_session" && c.MaxAge >= 0 && c.Value != "" && c.Value != session {
						t.Fatal("a replayed callback minted a second session")
					}
				}
			}
			fmt.Printf("oidc e2e: %s signed in through %s\n", user, realm)
		})
	}
}
