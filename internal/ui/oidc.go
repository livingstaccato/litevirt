package ui

import (
	"crypto/subtle"
	"encoding/base64"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// oidcFlowCookieName binds an OIDC login to the browser that began it. The
// state alone proves the callback belongs to SOME flow this node began; the
// cookie proves it belongs to THIS browser's flow, so an attacker cannot send a
// victim through a callback for a login the attacker began (login CSRF, RFC
// 6749 §10.12) and leave the victim signed in as the attacker.
const oidcFlowCookieName = "lv_oidc_flow"

// oidcCallbackPath is where the IdP returns the browser. The realm's
// redirect_url must name this path on this node's UI.
const oidcCallbackPath = "/oidc/callback"

// handleOIDCLogin begins an OIDC login: it asks the daemon on THIS node to
// start a flow, binds it to the browser with a short-lived HttpOnly cookie, and
// sends the browser to the IdP. GET, so an SSO link works; it changes nothing
// but the in-memory flow store, which the daemon bounds.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	realm := r.URL.Query().Get("realm")
	if !strings.HasPrefix(realm, "oidc:") {
		s.renderLoginPage(w, loginPageData{Realms: s.availableRealms(), OIDCRealms: s.oidcRealms(),
			Error: "Choose an OIDC realm to sign in with."})
		return
	}
	resp, err := s.grpc.BeginOIDCLogin(r.Context(), &pb.BeginOIDCLoginRequest{Realm: realm, Client: "web"})
	if err != nil {
		slog.Warn("UI OIDC login could not begin", "realm", realm, "code", status.Code(err), "error", status.Convert(err).Message())
		s.renderLoginPage(w, loginPageData{Realms: s.availableRealms(), OIDCRealms: s.oidcRealms(),
			Error: "Sign-in through " + realm + " is not available: " + status.Convert(err).Message()})
		return
	}
	maxAge := 600
	if exp, perr := time.Parse(time.RFC3339, resp.ExpiresAt); perr == nil {
		if secs := int(time.Until(exp).Seconds()); secs > 0 {
			maxAge = secs
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oidcFlowCookieName,
		Value:    resp.State + "." + base64.RawURLEncoding.EncodeToString([]byte(realm)),
		Path:     oidcCallbackPath,
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		// Lax: the IdP's redirect back is a top-level GET navigation, which
		// carries a Lax cookie; a cross-site subrequest does not.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
	http.Redirect(w, r, resp.AuthUrl, http.StatusFound)
}

// handleOIDCCallback completes an OIDC login the IdP has sent back. The code
// and state are passed to Login on THIS node (the UI's gRPC client is the
// local daemon), which exchanges the code with the PKCE verifier, verifies the
// ID token, maps the principal and applies the login policy exactly as a
// password login does. Neither the code, the state nor any token is logged or
// put in another URL.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	q := r.URL.Query()
	cookieState, realm, ok := readOIDCFlowCookie(r)
	clearOIDCFlowCookie(w, r)
	page := loginPageData{Realms: s.availableRealms(), OIDCRealms: s.oidcRealms()}

	if idpErr := q.Get("error"); idpErr != "" {
		// The IdP refused (the user cancelled, or policy). Its error code is
		// shown sanitised; error_description is attacker-controllable text in
		// a URL anyone can craft, so it is not echoed.
		page.Error = "The identity provider did not sign you in (" + sanitizeOAuthError(idpErr) + ")."
		page.status = http.StatusUnauthorized
		s.renderLoginPage(w, page)
		return
	}
	code, state := q.Get("code"), q.Get("state")
	if code == "" || state == "" {
		page.Error = "The identity provider's answer is incomplete; sign in again."
		page.status = http.StatusBadRequest
		s.renderLoginPage(w, page)
		return
	}
	if !ok || subtle.ConstantTimeCompare([]byte(cookieState), []byte(state)) != 1 {
		// No cookie, or another flow's: this browser did not begin this
		// login. Refused without spending the code, so the browser that did
		// begin it is not harmed.
		slog.Warn("UI OIDC callback refused: not begun by this browser", "has_cookie", ok)
		page.Error = "This sign-in was not started from this browser (or it expired). Sign in again."
		page.status = http.StatusForbidden
		s.renderLoginPage(w, page)
		return
	}

	resp, err := s.grpc.Login(r.Context(), &pb.LoginRequest{
		Realm:     realm,
		OidcCode:  code,
		OidcState: state,
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		slog.Warn("UI OIDC login failed", "realm", realm, "code", status.Code(err), "error", status.Convert(err).Message())
		page.Realm = realm
		page.Error = oidcLoginFailureMessage(err)
		page.status = httpStatusFor(err)
		s.renderLoginPage(w, page)
		return
	}
	if resp.Requires_2Fa {
		// The code is spent; the daemon holds the verified principal under
		// oidc_pending, which travels in the form body (never a URL).
		page.Realm = realm
		page.Requires2FA = true
		page.OIDCPending = resp.OidcPending
		s.renderLoginPage(w, page)
		return
	}
	s.finishLogin(w, r, resp)
}

// handleOIDCSecondFactor resumes an OIDC login that stopped for litevirt's
// second factor (from the login form when it carries oidc_pending).
func (s *Server) handleOIDCSecondFactor(w http.ResponseWriter, r *http.Request, realm, pending, totp string) {
	noStore(w)
	resp, err := s.grpc.Login(r.Context(), &pb.LoginRequest{
		Realm:       realm,
		OidcPending: pending,
		TotpCode:    totp,
		UserAgent:   r.UserAgent(),
	})
	page := loginPageData{Realms: s.availableRealms(), OIDCRealms: s.oidcRealms(), Realm: realm}
	if err != nil {
		slog.Warn("UI OIDC second factor failed", "realm", realm, "code", status.Code(err))
		if status.Code(err) == codes.Unauthenticated && strings.Contains(status.Convert(err).Message(), "invalid second factor") {
			// The handle survives a wrong code (up to its attempt bound).
			page.Requires2FA = true
			page.OIDCPending = pending
			page.Error = "Invalid authenticator code."
		} else {
			page.Error = oidcLoginFailureMessage(err)
		}
		page.status = httpStatusFor(err)
		s.renderLoginPage(w, page)
		return
	}
	if resp.Requires_2Fa {
		page.Requires2FA = true
		page.OIDCPending = resp.OidcPending
		s.renderLoginPage(w, page)
		return
	}
	s.finishLogin(w, r, resp)
}

// oidcLoginFailureMessage is what the login page says about a refused OIDC
// login. The daemon's refusals for lifecycle, bindings and local-account
// collisions are meant for the user and are shown; anything else is generic.
func oidcLoginFailureMessage(err error) string {
	switch status.Code(err) {
	case codes.PermissionDenied, codes.FailedPrecondition, codes.Unavailable, codes.ResourceExhausted:
		return "Sign-in refused: " + status.Convert(err).Message()
	case codes.Unauthenticated:
		if m := status.Convert(err).Message(); strings.Contains(m, "state unknown") {
			return "This sign-in is unknown or expired on this node. Sign in again (the identity provider must send you back to the node you started on)."
		}
	}
	return "Sign-in through the identity provider failed."
}

// readOIDCFlowCookie returns the state and realm the browser's flow cookie
// carries.
func readOIDCFlowCookie(r *http.Request) (state, realm string, ok bool) {
	c, err := r.Cookie(oidcFlowCookieName)
	if err != nil || c.Value == "" {
		return "", "", false
	}
	st, enc, found := strings.Cut(c.Value, ".")
	if !found || st == "" {
		return "", "", false
	}
	b, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil || !strings.HasPrefix(string(b), "oidc:") {
		return "", "", false
	}
	return st, string(b), true
}

func clearOIDCFlowCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: oidcFlowCookieName, Value: "", Path: oidcCallbackPath, MaxAge: -1,
		HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteLaxMode,
	})
}

// noStore keeps an auth response (it carries a code in its URL or a handle in
// its body) out of caches and out of the Referer of whatever the page loads.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

// sanitizeOAuthError keeps an RFC 6749 error code's own alphabet.
func sanitizeOAuthError(e string) string {
	var b strings.Builder
	for _, c := range e {
		if c == '_' || c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		}
		if b.Len() >= 64 {
			break
		}
	}
	if b.Len() == 0 {
		return "error"
	}
	return b.String()
}

// oidcRealms are the OIDC realms the daemon advertises, for the login page's
// sign-in buttons.
func (s *Server) oidcRealms() []string {
	var out []string
	for _, r := range s.allRealms() {
		if strings.HasPrefix(r, "oidc:") {
			out = append(out, r)
		}
	}
	return out
}
