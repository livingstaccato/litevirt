package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// OIDCConfig describes one OIDC provider. Multiple realms may coexist
// (one per IdP). The realm name is "oidc:<short-name>" (e.g. "oidc:corp-okta")
// so role-bindings reference a specific provider.
type OIDCConfig struct {
	// ShortName ends up as the realm name suffix: "oidc:<ShortName>".
	ShortName string

	// IssuerURL is the OIDC discovery URL root (e.g. "https://accounts.google.com").
	IssuerURL string

	// ClientID / ClientSecret were issued by the IdP for this litevirt cluster.
	ClientID     string
	ClientSecret string

	// RedirectURL is litevirt's UI callback URL the IdP must whitelist. It
	// is per node: the callback must reach the node that began the login,
	// because that node alone holds the flow's state, verifier and nonce.
	RedirectURL string

	// CLIRedirectURL is the loopback URL `lv login --realm oidc:<name>`
	// listens on (RFC 8252 §7.3), e.g. http://127.0.0.1:18765/oidc/callback.
	// Empty: the CLI flow is off for this realm. The IdP must list it too.
	CLIRedirectURL string

	// CAFile is a PEM bundle the IdP's certificate must chain to. Empty:
	// the system trust store. Never "skip verification".
	CAFile string

	// Scopes always includes "openid"; "profile email groups" are added so
	// SyncGroups can populate Principal.Groups.
	Scopes []string

	// GroupsClaim is the claim name carrying group memberships. Defaults
	// to "groups" (Okta, Auth0, Keycloak, Azure AD with proper config).
	GroupsClaim string

	// EmailClaim defaults to "email".
	EmailClaim string

	// NameClaim defaults to "name" for the human-friendly display name.
	NameClaim string

	// SubjectClaim defaults to "sub" — the stable per-user IdP identifier.
	// Override only if an IdP issues unstable subs.
	SubjectClaim string

	// HTTPClient is optional; when nil, oauth2 uses the default. Tests
	// inject an httptest-backed client so the OIDC realm talks to a
	// mock provider over an in-process listener.
	HTTPClient ContextClient
}

// ContextClient is a minimal interface so tests can swap the http client
// without depending directly on net/http.
type ContextClient interface {
	WithContext(ctx context.Context) context.Context
}

// OIDCRealm authenticates users against an OIDC provider via the
// authorization-code flow. ID tokens are validated using the provider's
// JWKS (auto-fetched from IssuerURL/.well-known/openid-configuration).
type OIDCRealm struct {
	cfg          OIDCConfig
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauthCfg     *oauth2.Config
	groupsClaim  string
	emailClaim   string
	nameClaim    string
	subjectClaim string

	// httpClient talks to the IdP (discovery, JWKS, token endpoint). Nil:
	// the default client and the system trust store.
	httpClient *http.Client

	mu          sync.Mutex
	stateStore  map[string]oidcFlow // in-flight auth-code flows; cleaned on use or expiry
	stateExpiry time.Duration
	maxFlows    int
	// maxFlowsPerAddr bounds the flows one client address holds, so a flood
	// from one source cannot fill the store for everyone else.
	maxFlowsPerAddr int
}

// oidcFlow is the server-side state for one in-flight authorization-code
// exchange. It is held in-memory on the node that issued AuthURL — the IdP
// redirects the browser back to the same node, so cluster consensus isn't
// needed.
//
//   - expiry binds the CSRF state to a short window.
//   - verifier is the PKCE code_verifier; its S256 challenge went to the IdP
//     in AuthURL, and the verifier is replayed at the token endpoint so an
//     intercepted authorization code is useless without it (RFC 7636).
//   - nonce must echo back in the ID token's `nonce` claim, binding the token
//     to this login and defeating ID-token replay/injection (OIDC core §3.1.2).
//   - redirect is the redirect_uri the flow was begun with; the token
//     exchange replays exactly that one (RFC 6749 §4.1.3), and a callback
//     naming another is refused.
//   - binding is the SHA-256 of a per-flow secret handed only to whoever
//     began the flow (never in a URL); redeeming the flow must present it,
//     so a (code, state) pair alone — both travel in the callback URL —
//     redeems nothing (RFC 9700 §4.5). hasBinding is false only for the
//     AuthURL test helper's flows.
//   - addr is the client address that began it (the per-address bound).
type oidcFlow struct {
	expiry     time.Time
	verifier   string
	nonce      string
	redirect   string
	binding    [32]byte
	hasBinding bool
	addr       string
}

// OIDC flow clients: which configured redirect a flow returns to.
const (
	// OIDCClientWeb returns to RedirectURL, the node's web UI callback.
	OIDCClientWeb = "web"
	// OIDCClientCLI returns to CLIRedirectURL, the CLI's loopback listener.
	OIDCClientCLI = "cli"
)

// defaultMaxOIDCFlows bounds the in-flight flows one realm holds. Beginning a
// flow needs no credential, so without a bound anyone who can reach the node
// could grow this map for the length of the state expiry. When it is full the
// OLDEST flow is evicted rather than the new one refused, so a flood cannot
// lock real users out; defaultMaxOIDCFlowsPerAddr stops one address from
// filling it at all.
const (
	defaultMaxOIDCFlows        = 4096
	defaultMaxOIDCFlowsPerAddr = 16
)

// ErrOIDCFlowUnknown: the callback's state names no flow this node holds — it
// was never begun here, it expired, or it was already used. It wraps
// ErrInvalidCredentials, so callers that only know that error still refuse.
var ErrOIDCFlowUnknown = fmt.Errorf("%w: OIDC login state unknown, expired or already used on this node "+
	"(a login must finish on the node it began on, within 10 minutes, once)", ErrInvalidCredentials)

// ErrOIDCTooManyFlows: this client address already holds its bound of
// in-flight flows.
var ErrOIDCTooManyFlows = errors.New("too many OIDC logins in progress from this address; finish one, or retry in a few minutes")

// ErrOIDCFlowBindingMismatch: the flow exists but the redeemer did not present
// the binding secret its beginner was given. The flow is consumed (single use)
// and the code is never presented to the IdP. It wraps ErrInvalidCredentials.
var ErrOIDCFlowBindingMismatch = fmt.Errorf("%w: this OIDC login was not begun by this client", ErrInvalidCredentials)

// ErrOIDCClientNotConfigured: the realm has no redirect for the requested
// client (no cli_redirect_url for the CLI), or the configured one is unsafe.
var ErrOIDCClientNotConfigured = errors.New("OIDC login for this client is not configured")

// OIDCFlowStart is what BeginFlow hands the caller: the URL to send the user
// to, the state the callback will carry, the redirect it will arrive on, and
// when the flow stops being accepted.
//
// Binding is the per-flow secret the redeemer must present
// (Credentials.OIDCBinding). It is never put in a URL: the web UI keeps it in
// an HttpOnly cookie, the CLI in memory.
type OIDCFlowStart struct {
	AuthURL     string
	State       string
	RedirectURI string
	ExpiresAt   time.Time
	Binding     string
}

// NewOIDCRealm initialises a realm by fetching the provider's discovery
// document. Returns ErrRealmUnavailable if the IdP is unreachable —
// callers may register the realm anyway and retry on reload.
func NewOIDCRealm(ctx context.Context, cfg OIDCConfig) (*OIDCRealm, error) {
	if cfg.ShortName == "" {
		return nil, fmt.Errorf("oidc: ShortName required")
	}
	if cfg.IssuerURL == "" || cfg.ClientID == "" {
		return nil, fmt.Errorf("oidc: IssuerURL and ClientID required")
	}
	if cfg.CLIRedirectURL != "" {
		if err := validateLoopbackRedirect(cfg.CLIRedirectURL); err != nil {
			return nil, fmt.Errorf("oidc: cli_redirect_url: %w", err)
		}
	}
	var httpClient *http.Client
	if cfg.CAFile != "" {
		c, err := httpClientForCA(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("oidc: ca_file: %w", err)
		}
		httpClient = c
		ctx = oidc.ClientContext(ctx, c)
	}
	if cfg.HTTPClient != nil {
		ctx = cfg.HTTPClient.WithContext(ctx)
	}
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRealmUnavailable, err)
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email", "groups"}
	} else if !slices.Contains(scopes, oidc.ScopeOpenID) {
		// Without openid the IdP issues no ID token, and nothing else
		// identifies the user.
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}
	r := &OIDCRealm{
		cfg:             cfg,
		provider:        provider,
		verifier:        provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		groupsClaim:     defaultStr(cfg.GroupsClaim, "groups"),
		emailClaim:      defaultStr(cfg.EmailClaim, "email"),
		nameClaim:       defaultStr(cfg.NameClaim, "name"),
		subjectClaim:    defaultStr(cfg.SubjectClaim, "sub"),
		httpClient:      httpClient,
		stateStore:      map[string]oidcFlow{},
		stateExpiry:     10 * time.Minute,
		maxFlows:        defaultMaxOIDCFlows,
		maxFlowsPerAddr: defaultMaxOIDCFlowsPerAddr,
		oauthCfg: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
	}
	return r, nil
}

// Name returns "oidc:<ShortName>".
func (r *OIDCRealm) Name() string { return "oidc:" + r.cfg.ShortName }

// AuthURL returns the URL the UI should redirect the user to. The caller's
// `state` is the CSRF token the callback must present back. AuthURL also mints
// a PKCE code_verifier and a nonce, stashes both alongside the state, and
// sends the S256 challenge + nonce to the IdP so Authenticate can later prove
// the code wasn't intercepted and the ID token isn't a replay.
//
// It uses the configured RedirectURL and a caller-chosen state, and its flow
// carries NO binding secret. It is test support only; every login route uses
// BeginFlow (which mints the state and the binding itself and bounds the store).
func (r *OIDCRealm) AuthURL(state string) string {
	verifier := oauth2.GenerateVerifier()
	nonce := oauth2.GenerateVerifier() // reused as a high-entropy random nonce
	r.mu.Lock()
	r.putFlowLocked(state, oidcFlow{verifier: verifier, nonce: nonce, redirect: r.cfg.RedirectURL})
	r.mu.Unlock()
	return r.authCodeURL(state, verifier, nonce, r.cfg.RedirectURL)
}

// BeginFlow starts one authorization-code + PKCE login for client (OIDCClientWeb
// or OIDCClientCLI). The state is 256 random bits minted here, single-use, and
// held only on this node for stateExpiry along with the PKCE verifier, the
// nonce and the redirect the IdP will send the browser to.
//
// The redirect is never the caller's: it is the realm's configured one for that
// client, so the allow-list is exactly the configuration. A web redirect must be
// https, or http to a loopback address; a CLI redirect is http to 127.0.0.1
// (checked at load).
//
// addr is the client address beginning the flow (the browser's for the web UI,
// the gRPC peer's otherwise); one address holds at most maxFlowsPerAddr flows.
func (r *OIDCRealm) BeginFlow(client, addr string) (OIDCFlowStart, error) {
	var redirect string
	switch client {
	case "", OIDCClientWeb:
		redirect = r.cfg.RedirectURL
		if redirect == "" {
			return OIDCFlowStart{}, fmt.Errorf("%w: realm %s has no redirect_url", ErrOIDCClientNotConfigured, r.Name())
		}
		if err := validateWebRedirect(redirect); err != nil {
			return OIDCFlowStart{}, fmt.Errorf("%w: realm %s redirect_url: %v", ErrOIDCClientNotConfigured, r.Name(), err)
		}
	case OIDCClientCLI:
		redirect = r.cfg.CLIRedirectURL
		if redirect == "" {
			return OIDCFlowStart{}, fmt.Errorf("%w: realm %s has no cli_redirect_url, so `lv login` cannot "+
				"receive the IdP's answer; set it (and register it with the IdP) or log in through the web UI",
				ErrOIDCClientNotConfigured, r.Name())
		}
	default:
		return OIDCFlowStart{}, fmt.Errorf("%w: unknown OIDC client %q (want web or cli)", ErrOIDCClientNotConfigured, client)
	}
	state, err := randomToken()
	if err != nil {
		return OIDCFlowStart{}, err
	}
	binding, err := randomToken()
	if err != nil {
		return OIDCFlowStart{}, err
	}
	verifier := oauth2.GenerateVerifier()
	nonce := oauth2.GenerateVerifier()
	r.mu.Lock()
	r.pruneLocked(time.Now())
	if r.flowsFromLocked(addr) >= r.maxFlowsPerAddr {
		r.mu.Unlock()
		return OIDCFlowStart{}, ErrOIDCTooManyFlows
	}
	for len(r.stateStore) >= r.maxFlows {
		r.evictOldestLocked()
	}
	exp := r.putFlowLocked(state, oidcFlow{verifier: verifier, nonce: nonce, redirect: redirect,
		binding: sha256.Sum256([]byte(binding)), hasBinding: true, addr: addr})
	r.mu.Unlock()
	return OIDCFlowStart{
		AuthURL:     r.authCodeURL(state, verifier, nonce, redirect),
		State:       state,
		RedirectURI: redirect,
		ExpiresAt:   exp,
		Binding:     binding,
	}, nil
}

// authCodeURL is the IdP authorization URL for one flow: PKCE S256 only (the
// plain method is never offered), the flow's nonce, and its redirect.
func (r *OIDCRealm) authCodeURL(state, verifier, nonce, redirect string) string {
	cfg := *r.oauthCfg
	cfg.RedirectURL = redirect
	return cfg.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oidc.Nonce(nonce),
	)
}

// Authenticate consumes an OIDC code-flow callback. Credentials must carry
// OIDCCode and OIDCState. The state is single-use: it is removed before the
// exchange whatever the outcome. The exchange replays the flow's own redirect;
// OIDCRedirectURI, when set, must equal it.
//
// The ID token is verified by go-oidc against the discovery document's JWKS
// (signature, issuer, audience = client_id, expiry), then here for the flow's
// nonce and, with several audiences, azp.
//
// Returns ErrOIDCFlowUnknown (an ErrInvalidCredentials) for a state this node
// does not hold; ErrInvalidCredentials when ID-token verification fails;
// ErrRealmUnavailable on transient IdP errors (token endpoint down).
func (r *OIDCRealm) Authenticate(ctx context.Context, creds Credentials) (*Principal, error) {
	if creds.OIDCCode == "" || creds.OIDCState == "" {
		return nil, ErrInvalidCredentials
	}
	flow, ok := r.consumeFlow(creds.OIDCState)
	if !ok {
		return nil, ErrOIDCFlowUnknown
	}
	// Whoever redeems must be whoever began: the binding secret is not in the
	// callback URL. Checked after the flow is consumed, so a mismatched
	// redemption also ends the flow, and before the exchange, so the code is
	// never presented to the IdP.
	if flow.hasBinding {
		got := sha256.Sum256([]byte(creds.OIDCBinding))
		if subtle.ConstantTimeCompare(got[:], flow.binding[:]) != 1 {
			return nil, ErrOIDCFlowBindingMismatch
		}
	}
	// The exchange replays the redirect the flow began with. A caller naming
	// another one is refused rather than obeyed: the redirect is not the
	// caller's to choose (the allow-list is the realm's configuration).
	if creds.OIDCRedirectURI != "" && creds.OIDCRedirectURI != flow.redirect {
		return nil, fmt.Errorf("%w: redirect_uri is not the one this login began with", ErrInvalidCredentials)
	}
	if r.httpClient != nil {
		ctx = oidc.ClientContext(ctx, r.httpClient)
	}
	if r.cfg.HTTPClient != nil {
		ctx = r.cfg.HTTPClient.WithContext(ctx)
	}

	cfg := *r.oauthCfg
	cfg.RedirectURL = flow.redirect
	// Replay the PKCE verifier so the IdP can confirm this caller is the same
	// one that initiated the flow — an intercepted code alone won't exchange.
	tok, err := cfg.Exchange(ctx, creds.OIDCCode, oauth2.VerifierOption(flow.verifier))
	if err != nil {
		return nil, fmt.Errorf("%w: token exchange: %v", ErrRealmUnavailable, err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return nil, fmt.Errorf("%w: no id_token in token response", ErrRealmUnavailable)
	}
	idTok, err := r.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("%w: id-token verify: %v", ErrInvalidCredentials, err)
	}
	// The ID token must carry back the exact nonce we issued for this flow.
	// A mismatch (or a token minted for a different login) is a replay/
	// injection attempt.
	if idTok.Nonce != flow.nonce {
		return nil, fmt.Errorf("%w: id-token nonce mismatch", ErrInvalidCredentials)
	}

	var claims map[string]interface{}
	if err := idTok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	// The party the token was issued to must be this client (OIDC Core
	// §3.1.3.7, items 4 and 5): with several audiences azp is required; with
	// one, an azp that is present must still name this client. The verifier
	// above only checked that this client is among the audiences.
	azp, hasAZP := claims["azp"]
	if len(idTok.Audience) > 1 || hasAZP {
		if s, _ := azp.(string); s != r.cfg.ClientID {
			return nil, fmt.Errorf("%w: id-token azp is not this client", ErrInvalidCredentials)
		}
	}
	subject := stringClaim(claims, r.subjectClaim)
	if subject == "" {
		return nil, fmt.Errorf("%w: missing %q claim", ErrInvalidCredentials, r.subjectClaim)
	}

	p := &Principal{
		Subject: subject,
		// The account is bound to (issuer, sub) — the IdP's stable identity
		// of this person — whatever claim names the account (rereview N5).
		ExternalID: idTok.Issuer + "|" + idTok.Subject,
		Realm:      r.Name(),
		Email:      stringClaim(claims, r.emailClaim),
		Name:       stringClaim(claims, r.nameClaim),
		Groups:     stringSliceClaim(claims, r.groupsClaim),
		Claims:     flattenClaims(claims),
	}
	return p, nil
}

// SyncGroups is a no-op — OIDC group memberships arrive as ID-token
// claims at login time, not via a separate sync API. Reserved for future
// use if we add a back-channel claim-refresh.
func (r *OIDCRealm) SyncGroups(ctx context.Context) error { return nil }

// Errors EnsureUserShadow wraps, so the login RPC can answer with the right code.
var (
	// ErrShadowPending: transient; this node cannot decide yet. Retry.
	ErrShadowPending = errors.New("not decidable on this node yet")
	// ErrExternalUnproven: durable until an administrator marks the user
	// external (`lv user mark-external`) or its credential row arrives.
	ErrExternalUnproven = errors.New("not known to be an external user")
	// ErrLocalAccount: the name belongs to a local account.
	ErrLocalAccount = errors.New("a local account holds this name")
)

// EnsureUserShadow creates a row in the local users table for an OIDC
// principal so existing handlers (RBAC, audit) can reference the user
// by username. The shadow row has password_hash="" so password login is
// impossible — the user can ONLY arrive via the realm.
//
// Idempotent: subsequent calls update display fields without touching
// the password.
func EnsureUserShadow(ctx context.Context, db *corrosion.Client, p *Principal, defaultRole string) error {
	if p == nil || p.Subject == "" {
		return errors.New("nil principal")
	}
	// Every lookup normalizes the name (corrosion.NormalizeUsername), and so
	// does the shadow this writes: a directory subject typed `ALICE` is the
	// account `alice`, never a second one beside it (t1-auth-review I2). On
	// return p.Subject is the account's name as stored, which is what every
	// per-account row is keyed on.
	existing, err := corrosion.GetUser(ctx, db, p.Subject)
	if err != nil {
		return err
	}
	if existing != nil {
		// REFUSE a name that already belongs to another authority. users is keyed
		// on username alone, so adopting the row silently hands this principal
		// whatever role that row carries — mintSession reads the role from the row,
		// not from the principal. An account in a configured LDAP or OIDC directory
		// named after a local administrator could therefore mint a local admin
		// session with neither the local password nor the local second factor.
		//
		// Refusing rather than namespacing: a rename would have to move the row's
		// RBAC bindings, tokens and sessions with it, and doing that silently
		// during a login is a larger and more surprising act than declining one.
		// The operator renames one side.
		// REFUSE to let an external principal adopt a LOCAL account. users is
		// keyed on username alone, so adopting the row hands this principal
		// whatever role it carries — mintSession reads the role from the row, not
		// from the principal — and an account in a configured LDAP or OIDC
		// directory named after a local administrator could otherwise mint a local
		// admin session with neither the local password nor the local second
		// factor.
		//
		// A non-empty password_hash is what identifies a local account: local users
		// are created with one, and the shadow rows written below are created with
		// "" precisely because an external subject has no local credential. The
		// realm COLUMN cannot answer this — nothing in the tree ever writes it, so
		// every row reads back as 'local' whatever authority created it.
		//
		// Residual, deliberately left: two EXTERNAL realms that share a username
		// still collide with each other, because neither row carries a credential
		// to tell them apart. Closing that needs the realm column actually
		// populated, which is a new replicated statement shape — a previous-release
		// peer cannot decode an unregistered shape and back-pressures its whole
		// replication stream — so it belongs with a capability gate and its own
		// change, not here.
		//
		// Refusing rather than namespacing: a rename would have to carry the row's
		// RBAC bindings, tokens and sessions with it, and doing that silently
		// during a login is a larger and more surprising act than declining one.
		//
		// Once credentials_clear_v1 has latched, a local account's users row
		// carries an EMPTY password_hash and its hash lives in user_credentials,
		// which anti-entropy can deliver after the users row. An empty hash is
		// then not proof of anything: UserLocalCredential judges the row
		// external only on positive evidence, and when it cannot tell the login
		// is refused rather than guessed — transiently while this node is not
		// credentials-live, durably once it is (an administrator then marks the
		// user external with `lv user mark-external`).
		if p.Realm != "local" {
			// Judged, and named, by the STORED name (credentials-clear M1):
			// GetUser matches the normalized name, so p.Subject may be another
			// spelling (an OIDC subject is not normalized), and
			// UserLocalCredential matches exactly.
			local, known, err := corrosion.UserLocalCredential(ctx, db, existing.Username)
			if err != nil {
				return fmt.Errorf("check whether %q is a local account: %w", existing.Username, err)
			}
			if !known {
				if !db.CredentialsLive() {
					return fmt.Errorf("%w: user %q exists but this node cannot tell yet whether it is "+
						"a local account; retry shortly, or log in through another node", ErrShadowPending, existing.Username)
				}
				return fmt.Errorf("%w: user %q exists with no local password and no record that it is an "+
					"external user. If it is one, an administrator can run `lv user mark-external %s`; "+
					"if it is a local account, its credential has not reached this node yet",
					ErrExternalUnproven, existing.Username, existing.Username)
			}
			if local || existing.PasswordHash != "" {
				return fmt.Errorf("%w: user %q already exists as a local account; refusing to "+
					"authenticate it from realm %q, because that would adopt the local account's "+
					"role — rename one of the two", ErrLocalAccount, existing.Username, p.Realm)
			}
		}
		p.Subject = existing.Username
		return nil
	}
	// A new shadow is a new users row, newer than anything the cluster holds
	// under this name. On a node whose users table has not synced, "no row"
	// may only mean "not here yet", and the shadow would replace the cluster's
	// local account cluster-wide (pre-existing; colonelpanik/litevirt#268
	// review). Wait for the node to sync.
	if !db.UsersSynced() {
		return fmt.Errorf("%w: this node has not synced its users yet, so it cannot tell whether %q "+
			"is already an account; retry shortly, or log in through another node", ErrShadowPending, p.Subject)
	}
	role := defaultRole
	if role == "" {
		role = "viewer"
	}
	name := corrosion.NormalizeUsername(p.Subject)
	if name == "" {
		return errors.New("empty subject")
	}
	// A deleted account under a variant spelling (a legacy `Bob` shadow from
	// before names were normalized) is brought back under ITS name, so it
	// returns with its own lifecycle: a disabled `Bob` stays disabled when
	// `bob` logs in again, instead of a fresh `bob` row with none.
	if variant, err := corrosion.DeletedVariantOf(ctx, db, name); err != nil {
		return err
	} else if variant != "" {
		name = variant
	}
	if err := corrosion.InsertUser(ctx, db, name, role, ""); err != nil {
		return err
	}
	p.Subject = name
	return nil
}

// rememberFlow stores the per-login PKCE verifier + nonce under the CSRF
// state with a 10-minute expiry so the callback can validate it. Held
// in-memory; cluster-wide consensus is not needed because the auth-code flow
// always returns to the node that issued AuthURL.
func (r *OIDCRealm) rememberFlow(state, verifier, nonce string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.putFlowLocked(state, oidcFlow{verifier: verifier, nonce: nonce, redirect: r.cfg.RedirectURL})
}

// putFlowLocked prunes expired flows and stores f under state with a fresh
// expiry; r.mu must be held.
func (r *OIDCRealm) putFlowLocked(state string, f oidcFlow) time.Time {
	now := time.Now()
	r.pruneLocked(now)
	f.expiry = now.Add(r.stateExpiry)
	r.stateStore[state] = f
	return f.expiry
}

// flowsFromLocked counts the flows addr holds; r.mu must be held.
func (r *OIDCRealm) flowsFromLocked(addr string) int {
	n := 0
	for _, f := range r.stateStore {
		if f.addr == addr {
			n++
		}
	}
	return n
}

// evictOldestLocked drops the flow that expires first; r.mu must be held.
func (r *OIDCRealm) evictOldestLocked() {
	var oldest string
	var at time.Time
	for s, f := range r.stateStore {
		if oldest == "" || f.expiry.Before(at) {
			oldest, at = s, f.expiry
		}
	}
	delete(r.stateStore, oldest)
}

func (r *OIDCRealm) pruneLocked(now time.Time) {
	for s, f := range r.stateStore {
		if now.After(f.expiry) {
			delete(r.stateStore, s)
		}
	}
}

// consumeFlow removes and validates a flow by its state token. Returns
// ok=false if the state is unknown or expired — both are treated as CSRF/
// replay failures.
func (r *OIDCRealm) consumeFlow(state string) (oidcFlow, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.stateStore[state]
	if !ok {
		return oidcFlow{}, false
	}
	delete(r.stateStore, state)
	if time.Now().After(f.expiry) {
		return oidcFlow{}, false
	}
	return f, true
}

func defaultStr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func stringClaim(c map[string]interface{}, key string) string {
	if v, ok := c[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func stringSliceClaim(c map[string]interface{}, key string) []string {
	v, ok := c[key]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		// Some IdPs return groups as a comma-separated string.
		if t == "" {
			return nil
		}
		return []string{t}
	}
	return nil
}

func flattenClaims(c map[string]interface{}) map[string]string {
	out := map[string]string{}
	for k, v := range c {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// randomToken is 256 random bits, base64url without padding.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// validateWebRedirect: the web callback carries the authorization code, so it
// must travel over TLS — https, or http only to a loopback address (a
// developer's own machine). No fragment (RFC 6749 §3.1.2).
func validateWebRedirect(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Fragment != "" || u.Host == "" {
		return fmt.Errorf("%q must be an absolute URL with no fragment", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if ip := net.ParseIP(u.Hostname()); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("%q must be https (http only to a loopback address): the authorization code travels on it", raw)
}

// validateLoopbackRedirect: the CLI's redirect is a listener on the user's own
// machine (RFC 8252 §7.3): http to the IPv4 loopback literal, an explicit port
// (the IdP matches it exactly), and no query or fragment.
func validateLoopbackRedirect(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Port() == "0" ||
		u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("%q must be http://127.0.0.1:<port>/<path> with no query or fragment", raw)
	}
	return nil
}

// httpClientForCA is a client that trusts only the CAs in path (PEM). TLS 1.2
// at least; certificate and host-name verification always on.
func httpClientForCA(path string) (*http.Client, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%s holds no PEM certificate", path)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, nil
}

// OIDCFlowStarter is the realm side of beginning an OIDC login, so callers can
// find it on a registered Realm without depending on *OIDCRealm.
type OIDCFlowStarter interface {
	BeginFlow(client, addr string) (OIDCFlowStart, error)
}

var _ OIDCFlowStarter = (*OIDCRealm)(nil)
