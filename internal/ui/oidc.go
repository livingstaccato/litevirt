package ui

import (
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The flow cookie binds an OIDC login to the browser that began it. It
// carries the flow's binding secret (BeginOIDCLoginResponse.binding), which
// never appears in a URL: the daemon refuses to redeem the flow without it, so
// an attacker cannot send a victim through a callback for a login the attacker
// began (login CSRF, RFC 6749 §10.12), and a (code, state) pair lifted from a
// URL redeems nothing anywhere (RFC 9700 §4.5).
//
// Over https it is a __Host- cookie (Secure, Path=/, no Domain), so a sibling
// host cannot plant one (cookie tossing). Plain http (a loopback developer
// setup) cannot carry that prefix and uses the plain name.
const (
	oidcFlowCookieName       = "lv_oidc_flow"
	oidcFlowCookieNameSecure = "__Host-lv_oidc_flow"
)

// oidcCallbackPath is where the IdP returns the browser. The realm's
// redirect_url must name this path on this node's UI.
const oidcCallbackPath = "/oidc/callback"

// Fixed messages for the login page. Nothing the IdP, a crafted link or the
// daemon's detail (account names, IdP error bodies) says is shown: the detail
// goes to the log and the audit log only.
const (
	msgOIDCChooseRealm  = "Choose one of the sign-in options below."
	msgOIDCUnavailable  = "Sign-in through the identity provider is not available right now. Try again, or use another sign-in option."
	msgOIDCBusy         = "Too many sign-ins are in progress from your address. Finish one, or try again in a few minutes."
	msgOIDCIdPRefused   = "The identity provider did not sign you in."
	msgOIDCIncomplete   = "The identity provider's answer is incomplete. Sign in again."
	msgOIDCNotThisLogin = "This sign-in was not started from this browser on this node, or it expired. Sign in again."
	msgOIDCRefused      = "Sign-in refused. An administrator can see why in the audit log."
	msgOIDCFailed       = "Sign-in through the identity provider failed. Sign in again."
	msgOIDCBadCode      = "Invalid authenticator code."
)

// handleOIDCLogin begins an OIDC login: it asks the daemon on THIS node to
// start a flow, binds it to the browser with a short-lived HttpOnly cookie, and
// sends the browser to the IdP. GET, so an SSO link works; it changes nothing
// but the in-memory flow store, which the daemon bounds per client address
// (passed here: the daemon sees only this UI's loopback connection).
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	page := loginPageData{Realms: s.availableRealms(), OIDCRealms: s.oidcRealms()}
	realm := r.URL.Query().Get("realm")
	if !slices.Contains(page.OIDCRealms, realm) {
		page.Error = msgOIDCChooseRealm
		page.status = http.StatusBadRequest
		s.renderLoginPage(w, page)
		return
	}
	resp, err := s.grpc.BeginOIDCLogin(r.Context(), &pb.BeginOIDCLoginRequest{
		Realm: realm, Client: "web", ClientAddress: browserAddress(r),
	})
	if err != nil {
		slog.Warn("UI OIDC login could not begin", "realm", realm, "code", status.Code(err), "error", status.Convert(err).Message())
		page.Error = msgOIDCUnavailable
		if status.Code(err) == codes.ResourceExhausted {
			page.Error = msgOIDCBusy
		}
		page.status = httpStatusFor(err)
		s.renderLoginPage(w, page)
		return
	}
	maxAge := 600
	if exp, perr := time.Parse(time.RFC3339, resp.ExpiresAt); perr == nil {
		if secs := int(time.Until(exp).Seconds()); secs > 0 {
			maxAge = secs
		}
	}
	c := oidcFlowCookie(r)
	c.Value = resp.Binding + "." + base64.RawURLEncoding.EncodeToString([]byte(realm))
	c.MaxAge = maxAge
	http.SetCookie(w, c)
	http.Redirect(w, r, resp.AuthUrl, http.StatusFound)
}

// handleOIDCCallback completes an OIDC login the IdP has sent back. The code,
// the state and the browser's binding secret are passed to Login on THIS node
// (the UI's gRPC client is the local daemon), which consumes the flow, refuses
// a redeemer without the binding before the code is ever presented, exchanges
// the code with the PKCE verifier, verifies the ID token, maps the principal
// and applies the login policy exactly as a password login does.
//
// A callback from a browser without the right cookie is still sent to the
// daemon (with whatever binding it holds, possibly none), so the flow is
// consumed — single-use — and its code can never be redeemed by anyone.
// Neither the code, the state, the binding nor any token is logged or put in
// another URL.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	q := r.URL.Query()
	binding, cookieRealm := readOIDCFlowCookie(r)
	clearOIDCFlowCookie(w, r)
	page := loginPageData{Realms: s.availableRealms(), OIDCRealms: s.oidcRealms()}

	if idpErr := q.Get("error"); idpErr != "" {
		// The IdP refused (the user cancelled, or policy). Its error code is
		// logged, never shown: error and error_description are text anyone
		// can put in a URL.
		slog.Info("UI OIDC callback: the identity provider refused", "error", sanitizeOAuthError(idpErr))
		page.Error = msgOIDCIdPRefused
		page.status = http.StatusUnauthorized
		s.renderLoginPage(w, page)
		return
	}
	code, state := q.Get("code"), q.Get("state")
	if code == "" || state == "" {
		page.Error = msgOIDCIncomplete
		page.status = http.StatusBadRequest
		s.renderLoginPage(w, page)
		return
	}

	// The realm the cookie names first; then, with no cookie or for a flow of
	// another realm, every other OIDC realm, so whichever holds the state
	// consumes it.
	realms := page.OIDCRealms
	if slices.Contains(realms, cookieRealm) {
		realms = append([]string{cookieRealm}, slices.DeleteFunc(slices.Clone(realms), func(x string) bool { return x == cookieRealm })...)
	}
	var resp *pb.LoginResponse
	var err error
	realm := ""
	for _, rn := range realms {
		realm = rn
		resp, err = s.grpc.Login(r.Context(), &pb.LoginRequest{
			Realm:       rn,
			OidcCode:    code,
			OidcState:   state,
			OidcBinding: binding,
			UserAgent:   r.UserAgent(),
		})
		if !oidcStateUnknown(err) {
			break
		}
	}
	if err == nil && resp == nil {
		err = status.Error(codes.Unauthenticated, "state unknown")
	}
	if err != nil {
		slog.Warn("UI OIDC login failed", "realm", realm, "has_cookie", binding != "", "code", status.Code(err), "error", status.Convert(err).Message())
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

// oidcStateUnknown reports a refusal because the realm holds no such flow.
func oidcStateUnknown(err error) bool {
	return status.Code(err) == codes.Unauthenticated && strings.Contains(status.Convert(err).Message(), "state unknown")
}

// handleOIDCSecondFactor resumes an OIDC login that stopped for litevirt's
// second factor (from the login form when it carries oidc_pending).
func (s *Server) handleOIDCSecondFactor(w http.ResponseWriter, r *http.Request, realm, pending, totp string) {
	noStore(w)
	page := loginPageData{Realms: s.availableRealms(), OIDCRealms: s.oidcRealms()}
	if !slices.Contains(page.OIDCRealms, realm) {
		// The realm is form input; only a configured one is echoed back.
		page.Error = msgOIDCChooseRealm
		page.status = http.StatusBadRequest
		s.renderLoginPage(w, page)
		return
	}
	page.Realm = realm
	resp, err := s.grpc.Login(r.Context(), &pb.LoginRequest{
		Realm:       realm,
		OidcPending: pending,
		TotpCode:    totp,
		UserAgent:   r.UserAgent(),
	})
	if err != nil {
		slog.Warn("UI OIDC second factor failed", "realm", realm, "code", status.Code(err), "error", status.Convert(err).Message())
		if status.Code(err) == codes.Unauthenticated && strings.Contains(status.Convert(err).Message(), "invalid second factor") {
			// The handle survives a wrong code (up to its attempt bound).
			page.Requires2FA = true
			page.OIDCPending = pending
			page.Error = msgOIDCBadCode
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

// oidcLoginFailureMessage is the fixed message the login page shows for a
// refused OIDC login; the daemon's own message (which may carry an account
// name or the IdP's error body) is logged, never shown.
func oidcLoginFailureMessage(err error) string {
	switch status.Code(err) {
	case codes.PermissionDenied, codes.FailedPrecondition:
		return msgOIDCRefused
	case codes.Unavailable:
		return msgOIDCUnavailable
	case codes.ResourceExhausted:
		return msgOIDCBusy
	case codes.Unauthenticated:
		if oidcStateUnknown(err) || strings.Contains(status.Convert(err).Message(), "not begun by this client") {
			return msgOIDCNotThisLogin
		}
	}
	return msgOIDCFailed
}

// browserAddress is the browser's address as this UI sees it (the TCP peer;
// a forwarding header is not trusted).
func browserAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// oidcFlowCookie is the flow cookie's attributes for r: __Host- over https.
func oidcFlowCookie(r *http.Request) *http.Cookie {
	c := &http.Cookie{
		Name:     oidcFlowCookieName,
		Path:     "/",
		HttpOnly: true,
		// Lax: the IdP's redirect back is a top-level GET navigation, which
		// carries a Lax cookie; a cross-site subrequest does not.
		SameSite: http.SameSiteLaxMode,
	}
	if requestIsHTTPS(r) {
		c.Name = oidcFlowCookieNameSecure
		c.Secure = true
	}
	return c
}

// readOIDCFlowCookie returns the binding secret and realm the browser's flow
// cookie carries ("" when there is none or it is malformed).
func readOIDCFlowCookie(r *http.Request) (binding, realm string) {
	name := oidcFlowCookieName
	if requestIsHTTPS(r) {
		name = oidcFlowCookieNameSecure
	}
	c, err := r.Cookie(name)
	if err != nil || c.Value == "" {
		return "", ""
	}
	b, enc, found := strings.Cut(c.Value, ".")
	if !found || b == "" {
		return "", ""
	}
	rb, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil || !strings.HasPrefix(string(rb), "oidc:") {
		return "", ""
	}
	return b, string(rb)
}

func clearOIDCFlowCookie(w http.ResponseWriter, r *http.Request) {
	c := oidcFlowCookie(r)
	c.MaxAge = -1
	http.SetCookie(w, c)
}

// noStore keeps an auth response (it carries a code in its URL or a handle in
// its body) out of caches and out of the Referer of whatever the page loads.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

// sanitizeOAuthError keeps an RFC 6749 error code's own alphabet, for logs.
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
// sign-in buttons and as the only realm names the page ever echoes.
func (s *Server) oidcRealms() []string {
	var out []string
	for _, r := range s.allRealms() {
		if strings.HasPrefix(r, "oidc:") {
			out = append(out, r)
		}
	}
	return out
}
