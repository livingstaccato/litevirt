package ui

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
)

// The flow cookie binds an OIDC login to the browser that began it. It
// carries the flow's binding secret (BeginOIDCLoginResponse.binding), which
// never appears in a URL: the daemon refuses to redeem the flow without it, so
// an attacker cannot send a victim through a callback for a login the attacker
// began (login CSRF, RFC 6749 §10.12), and a (code, state) pair lifted from a
// URL redeems nothing anywhere (RFC 9700 §4.5).
//
// Which cookie is decided by the realm's configured redirect_url, the URL the
// browser actually comes back on — not by anything in the request (a proxy
// that omits X-Forwarded-Proto must not downgrade it): an https redirect gets
// a __Host- cookie (Secure, Path=/, no Domain), so a sibling host or a
// plain-http answer for the name cannot plant one (cookie tossing), and the
// callback for such a realm accepts only that cookie. Only a plain-http
// redirect — allowed solely to a loopback address — uses the plain name.
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
	s.warnUntrustedForwarding(r)
	resp, err := s.grpc.BeginOIDCLogin(r.Context(), &pb.BeginOIDCLoginRequest{
		Realm: realm, Client: "web", ClientAddress: auth.ClientAddress(r, s.trustedProxies),
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
	secure := strings.HasPrefix(strings.ToLower(resp.RedirectUri), "https://")
	s.oidcSecureRealms.Store(realm, secure)
	c := oidcFlowCookie(secure)
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
	binding, cookieRealm := s.readOIDCFlowCookie(r)
	clearOIDCFlowCookies(w)
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
		// The cookie's binding goes only to the realm the cookie names
		// (re-review 2, M1): a plain cookie naming a loopback-http realm must
		// not unlock another realm's flow. Every other realm gets no binding,
		// so a flow it holds is still consumed (burned).
		b := ""
		if rn == cookieRealm {
			b = binding
		}
		resp, err = s.grpc.Login(r.Context(), &pb.LoginRequest{
			Realm:       rn,
			OidcCode:    code,
			OidcState:   state,
			OidcBinding: b,
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

// untrustedForwardWarnEvery rate-limits warnUntrustedForwarding.
const untrustedForwardWarnEvery = 10 * time.Minute

// warnUntrustedForwarding logs, at most once per untrustedForwardWarnEvery,
// that a sign-in arrived with X-Forwarded-For from a peer not listed in
// trusted_proxies (re-review 2, M2): a proxy in front of the UI that is not
// listed makes every browser share the proxy's per-address bound. The
// header itself is never believed from such a peer.
func (s *Server) warnUntrustedForwarding(r *http.Request) {
	if r.Header.Get("X-Forwarded-For") == "" || auth.PeerTrusted(r, s.trustedProxies) {
		return
	}
	now := time.Now().UnixNano()
	last := s.lastUntrustedForwardWarn.Load()
	if last != 0 && now-last < int64(untrustedForwardWarnEvery) {
		return
	}
	if !s.lastUntrustedForwardWarn.CompareAndSwap(last, now) {
		return
	}
	slog.Warn("an OIDC sign-in arrived with X-Forwarded-For from a peer not in trusted_proxies: the header is "+
		"ignored, so every browser behind that proxy shares its address's bound of in-progress sign-ins. If the "+
		"peer is your reverse proxy, list it in trusted_proxies", "peer", auth.ClientAddress(r, nil))
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

// oidcFlowCookie is the flow cookie's attributes: __Host- (Secure) when the
// realm's redirect is https.
func oidcFlowCookie(secure bool) *http.Cookie {
	c := &http.Cookie{
		Name:     oidcFlowCookieName,
		Path:     "/",
		HttpOnly: true,
		// Lax: the IdP's redirect back is a top-level GET navigation, which
		// carries a Lax cookie; a cross-site subrequest does not.
		SameSite: http.SameSiteLaxMode,
	}
	if secure {
		c.Name = oidcFlowCookieNameSecure
		c.Secure = true
	}
	return c
}

// readOIDCFlowCookie returns the binding secret and realm the browser's flow
// cookie carries ("" when there is none, it is malformed, or it is a plain
// cookie for a realm whose redirect is https — a planted one).
func (s *Server) readOIDCFlowCookie(r *http.Request) (binding, realm string) {
	if b, rn := parseOIDCFlowCookie(r, oidcFlowCookieNameSecure); b != "" {
		return b, rn
	}
	b, rn := parseOIDCFlowCookie(r, oidcFlowCookieName)
	if b == "" {
		return "", ""
	}
	if secure, known := s.oidcSecureRealms.Load(rn); !known || secure.(bool) {
		return "", ""
	}
	return b, rn
}

func parseOIDCFlowCookie(r *http.Request, name string) (binding, realm string) {
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

// clearOIDCFlowCookies expires both flow cookie names.
func clearOIDCFlowCookies(w http.ResponseWriter) {
	for _, secure := range []bool{true, false} {
		c := oidcFlowCookie(secure)
		c.MaxAge = -1
		http.SetCookie(w, c)
	}
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
