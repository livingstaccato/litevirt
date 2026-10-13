package grpcapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/auth/oidctest"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const oidcWebCB = "https://node-1.example:7445/oidc/callback"

// oidcServer is a login-policy server with a real OIDC realm (oidc:corp)
// against a strict TLS provider that signs in olga.
func oidcServer(t *testing.T) (*Server, *oidctest.Provider) {
	t.Helper()
	idp := oidctest.New(t, "litevirt", "s3cret", oidcWebCB)
	idp.SignIn(&oidctest.User{Subject: "sub-olga", PreferredUsername: "olga"})
	realm, err := auth.NewOIDCRealm(context.Background(), auth.OIDCConfig{
		ShortName: "corp", IssuerURL: idp.Issuer, ClientID: "litevirt", ClientSecret: "s3cret",
		RedirectURL: oidcWebCB, CAFile: idp.CAFile(t, t.TempDir()), SubjectClaim: "preferred_username",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := policyRealmServer(t, realm)
	s.loginThrottle = newLoginThrottle()
	seedAdmins(t, s)
	return s, idp
}

// oidcCallback begins a flow on s and plays the browser at the IdP, returning
// the code and state the IdP sent back.
func oidcCallback(t *testing.T, s *Server, idp *oidctest.Provider) (code, state, binding string) {
	t.Helper()
	begin, err := s.BeginOIDCLogin(context.Background(), &pb.BeginOIDCLoginRequest{Realm: "oidc:corp", Client: "web"})
	if err != nil {
		t.Fatalf("BeginOIDCLogin: %v", err)
	}
	if begin.RedirectUri != oidcWebCB || begin.State == "" || begin.ExpiresAt == "" {
		t.Fatalf("begin = %+v", begin)
	}
	resp, err := idp.BrowserClient().Get(begin.AuthUrl)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("IdP answered %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	return loc.Query().Get("code"), loc.Query().Get("state"), begin.Binding
}

// TestBeginOIDCLogin_IsPreSession: it is reachable with no bearer, through
// the real interceptor, like Login.
func TestBeginOIDCLogin_IsPreSession(t *testing.T) {
	s, _ := oidcServer(t)
	if !skipAuth["/litevirt.v1.LiteVirt/BeginOIDCLogin"] {
		t.Fatal("BeginOIDCLogin is not in skipAuth: a browser with no session could never start a login")
	}
	if err := runUnary(s, context.Background(), "/litevirt.v1.LiteVirt/BeginOIDCLogin"); err != nil {
		t.Fatalf("BeginOIDCLogin through the interceptor with no bearer: %v", err)
	}
	if !preSessionAuthMethods["/litevirt.v1.LiteVirt/BeginOIDCLogin"] {
		t.Fatal("BeginOIDCLogin is not gated with the pre-session methods: a node mid-reseed would send users through the IdP for a login it then refuses")
	}
}

func TestBeginOIDCLogin_Refusals(t *testing.T) {
	s, _ := oidcServer(t)
	ctx := context.Background()
	_, err := s.BeginOIDCLogin(ctx, &pb.BeginOIDCLoginRequest{Realm: "local"})
	wantCode(t, "a password realm", err, codes.InvalidArgument)
	_, err = s.BeginOIDCLogin(ctx, &pb.BeginOIDCLoginRequest{Realm: "oidc:nope"})
	wantCode(t, "an unconfigured realm", err, codes.Unimplemented)
	_, err = s.BeginOIDCLogin(ctx, &pb.BeginOIDCLoginRequest{Realm: "oidc:corp", Client: "cli"})
	wantCode(t, "the CLI client with no cli_redirect_url", err, codes.FailedPrecondition)
}

// TestOIDCLogin_FlowMintsASessionLikeALocalLogin: begin → IdP → Login with
// code+state makes the shadow, binds the entry and mints a session in the
// realm, which the interceptor accepts.
func TestOIDCLogin_FlowMintsASessionLikeALocalLogin(t *testing.T) {
	s, idp := oidcServer(t)
	code, state, binding := oidcCallback(t, s, idp)
	r, err := s.Login(context.Background(), &pb.LoginRequest{Realm: "oidc:corp", OidcCode: code, OidcState: state, OidcBinding: binding})
	if err != nil || r.Token == "" {
		t.Fatalf("OIDC login: %+v %v", r, err)
	}
	if r.Username != "olga" || r.Role != "viewer" {
		t.Fatalf("login answered %+v, want the shadow olga (viewer)", r)
	}
	if err := runUnary(s, bearerCtx(r.Token), "/litevirt.v1.LiteVirt/ListHosts"); err != nil {
		t.Fatalf("the session is not accepted: %v", err)
	}
	sess, err := corrosion.ListSessionsForUser(context.Background(), s.db, "olga")
	if err != nil || len(sess) != 1 || sess[0].Realm != "oidc:corp" {
		t.Fatalf("sessions %+v %v, want one in oidc:corp", sess, err)
	}
	// The same code and state cannot mint a second session.
	_, err = s.Login(context.Background(), &pb.LoginRequest{Realm: "oidc:corp", OidcCode: code, OidcState: state, OidcBinding: binding})
	wantCode(t, "a replayed callback", err, codes.Unauthenticated)
}

// TestOIDCLogin_UnknownStateDoesNotLockOthersOut: OIDC logins share the
// anonymous throttle bucket of their source address; stray callbacks (unknown
// state, which no one can guess) must not trip it for everyone.
func TestOIDCLogin_UnknownStateDoesNotLockOthersOut(t *testing.T) {
	s, idp := oidcServer(t)
	for i := 0; i < 2*defaultLoginMaxFailures; i++ {
		_, err := s.Login(context.Background(), &pb.LoginRequest{Realm: "oidc:corp", OidcCode: "x", OidcState: "forged"})
		wantCode(t, "an unknown state", err, codes.Unauthenticated)
	}
	code, state, binding := oidcCallback(t, s, idp)
	if r, err := s.Login(context.Background(), &pb.LoginRequest{Realm: "oidc:corp", OidcCode: code, OidcState: state, OidcBinding: binding}); err != nil || r.Token == "" {
		t.Fatalf("a real login after stray callbacks: %+v %v", r, err)
	}
}

// TestOIDCLogin_SecondFactorResumesWithTheHandle: under a policy covering the
// realm, an enrolled user's OIDC login stops for litevirt's factor with an
// oidc_pending handle and no session; the handle plus the code completes it,
// once; a wrong code is counted; the handle is bound to its realm.
func TestOIDCLogin_SecondFactorResumesWithTheHandle(t *testing.T) {
	s, idp := oidcServer(t)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "olga", "viewer", ""); err != nil {
		t.Fatal(err)
	}
	enr, err := auth.EnrollTOTP(ctx, s.db, "olga", "phone")
	if err != nil {
		t.Fatal(err)
	}
	setPolicy(t, s, "all")

	code, state, binding := oidcCallback(t, s, idp)
	r, err := s.Login(ctx, &pb.LoginRequest{Realm: "oidc:corp", OidcCode: code, OidcState: state, OidcBinding: binding})
	if err != nil || !r.GetRequires_2Fa() || r.Token != "" || r.GetOidcPending() == "" {
		t.Fatalf("covered OIDC login without the factor: %+v %v, want a challenge with a handle and no session", r, err)
	}
	h := r.GetOidcPending()

	_, err = s.Login(ctx, &pb.LoginRequest{Realm: "ldap:other", OidcPending: h, TotpCode: totpCode(t, enr.SecretBase32)})
	wantCode(t, "a handle sent to another (non-OIDC) realm", err, codes.InvalidArgument)
	_, err = s.Login(ctx, &pb.LoginRequest{Realm: "oidc:other", OidcPending: h, TotpCode: totpCode(t, enr.SecretBase32)})
	wantCode(t, "a handle sent to another OIDC realm", err, codes.Unauthenticated)
	_, err = s.Login(ctx, &pb.LoginRequest{Realm: "oidc:corp", OidcPending: "forged", TotpCode: totpCode(t, enr.SecretBase32)})
	wantCode(t, "a forged handle", err, codes.Unauthenticated)
	_, err = s.Login(ctx, &pb.LoginRequest{Realm: "oidc:corp", OidcPending: h, TotpCode: "000000"})
	wantCode(t, "a wrong factor", err, codes.Unauthenticated)

	ok, err := s.Login(ctx, &pb.LoginRequest{Realm: "oidc:corp", OidcPending: h, TotpCode: totpCode(t, enr.SecretBase32)})
	if err != nil || ok.Token == "" || ok.Username != "olga" {
		t.Fatalf("the handle with the right factor: %+v %v", ok, err)
	}
	if err := runUnary(s, bearerCtx(ok.Token), "/litevirt.v1.LiteVirt/ListHosts"); err != nil {
		t.Fatalf("a session that presented its factor is not a full one: %v", err)
	}
	// Used once: the handle is gone (a resend of the same code would also be
	// refused as a TOTP replay, so the store itself is asserted).
	if _, live := s.oidcPending.reserve(h, "oidc:corp"); live {
		t.Fatal("the handle outlived the login it completed")
	}
	_, err = s.Login(ctx, &pb.LoginRequest{Realm: "oidc:corp", OidcPending: h, TotpCode: totpCode(t, enr.SecretBase32)})
	wantCode(t, "a used handle", err, codes.Unauthenticated)
}

// TestOIDCLogin_SecondFactorHandleHasAnAttemptBound: a handle survives a few
// wrong codes, not unlimited ones.
func TestOIDCLogin_SecondFactorHandleHasAnAttemptBound(t *testing.T) {
	s, idp := oidcServer(t)
	s.loginThrottle = nil // the per-account throttle would stop this first; the handle's own bound is under test
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "olga", "viewer", ""); err != nil {
		t.Fatal(err)
	}
	enr, err := auth.EnrollTOTP(ctx, s.db, "olga", "phone")
	if err != nil {
		t.Fatal(err)
	}
	setPolicy(t, s, "all")
	code, state, binding := oidcCallback(t, s, idp)
	r, err := s.Login(ctx, &pb.LoginRequest{Realm: "oidc:corp", OidcCode: code, OidcState: state, OidcBinding: binding})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < oidcPendingMaxAttempts; i++ {
		_, _ = s.Login(ctx, &pb.LoginRequest{Realm: "oidc:corp", OidcPending: r.GetOidcPending(), TotpCode: "000000"})
	}
	_, err = s.Login(ctx, &pb.LoginRequest{Realm: "oidc:corp", OidcPending: r.GetOidcPending(), TotpCode: totpCode(t, enr.SecretBase32)})
	wantCode(t, "the right factor after the attempt bound", err, codes.Unauthenticated)
}

// peerAt is a caller at ip presenting the host certificate test-host (a
// trusted host once the test inserts its row): from loopback that is this
// node's UI or REST gateway, from elsewhere a peer.
func peerAt(ip string) context.Context {
	return mtlsPeerCtx("test-host", tcpAddr(ip), "")
}

// beginAt begins a web flow on s as peer, naming claimed as the client
// address, and returns a function reporting whether the flow is still held.
func beginAt(t *testing.T, s *Server, idp *oidctest.Provider, peerIP, claimed string) func() bool {
	t.Helper()
	b, err := s.BeginOIDCLogin(peerAt(peerIP), &pb.BeginOIDCLoginRequest{Realm: "oidc:corp", ClientAddress: claimed})
	if err != nil {
		t.Fatalf("BeginOIDCLogin from %s: %v", peerIP, err)
	}
	return func() bool {
		resp, err := idp.BrowserClient().Get(b.AuthUrl)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		loc, _ := url.Parse(resp.Header.Get("Location"))
		_, err = s.Login(context.Background(), &pb.LoginRequest{Realm: "oidc:corp",
			OidcCode: loc.Query().Get("code"), OidcState: b.State, OidcBinding: b.Binding})
		return err == nil
	}
}

// TestBeginOIDCLogin_BoundPerClientAddress (review I1, re-review N1): a
// remote caller is bounded by its own address whatever client_address it
// claims, so its own earlier flow is what its flood evicts; this node's
// loopback callers (the UI, the REST gateway) name the end client, so one
// browser's flood leaves another browser's sign-in alone. Nothing refuses.
func TestBeginOIDCLogin_BoundPerClientAddress(t *testing.T) {
	s, idp := oidcServer(t)
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "test-host", Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	own := beginAt(t, s, idp, "10.0.0.9", "192.0.2.1")
	for i := 0; i < 40; i++ {
		beginAt(t, s, idp, "10.0.0.9", fmt.Sprintf("192.0.2.%d", i+2))
	}
	if own() {
		t.Fatal("a remote caller rotating client_address was not bounded by its own address")
	}
	victim := beginAt(t, s, idp, "127.0.0.1", "203.0.113.1")
	for i := 0; i < 40; i++ {
		beginAt(t, s, idp, "127.0.0.1", "198.51.100.66")
	}
	if !victim() {
		t.Fatal("one browser's flood through the UI evicted another browser's sign-in")
	}

	// Round 1, I1: the lv-cli certificate over loopback is not the UI; its
	// claimed addresses are ignored and its flood evicts its own flow.
	cli := func(claimed string) *pb.BeginOIDCLoginResponse {
		b, err := s.BeginOIDCLogin(mtlsPeerCtx("lv-cli", tcpAddr("127.0.0.1"), ""), &pb.BeginOIDCLoginRequest{Realm: "oidc:corp", ClientAddress: claimed})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	first := cli("192.0.2.200")
	for i := 0; i < 40; i++ {
		cli(fmt.Sprintf("192.0.2.%d", i+100))
	}
	resp, err := idp.BrowserClient().Get(first.AuthUrl)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if _, err := s.Login(context.Background(), &pb.LoginRequest{Realm: "oidc:corp",
		OidcCode: loc.Query().Get("code"), OidcState: first.State, OidcBinding: first.Binding}); err == nil {
		t.Fatal("the lv-cli certificate rotating client_address was not bounded by its own address")
	}
}

// TestOIDCLogin_RedemptionWithoutTheBindingSpendsTheFlow (review M1, M2): the
// code and state alone (both in the callback URL) redeem nothing through the
// RPC; the flow is spent, the code never reaches the IdP, the refusal is
// audited and does not count against the shared throttle bucket.
func TestOIDCLogin_RedemptionWithoutTheBindingSpendsTheFlow(t *testing.T) {
	s, idp := oidcServer(t)
	code, state, binding := oidcCallback(t, s, idp)
	for i := 0; i < 2*defaultLoginMaxFailures; i++ {
		c2, s2, _ := oidcCallback(t, s, idp)
		_, err := s.Login(context.Background(), &pb.LoginRequest{Realm: "oidc:corp", OidcCode: c2, OidcState: s2})
		wantCode(t, "no binding", err, codes.Unauthenticated)
	}
	if idp.Exchanges != 0 {
		t.Fatalf("%d codes were exchanged without the binding", idp.Exchanges)
	}
	if row := lastAuditRow(t, s, "auth.login"); !strings.Contains(row.detail, "did not begin it") {
		t.Fatalf("audit %+v", row)
	}
	if r, err := s.Login(context.Background(), &pb.LoginRequest{Realm: "oidc:corp", OidcCode: code, OidcState: state, OidcBinding: binding}); err != nil || r.Token == "" {
		t.Fatalf("the beginner, after the refusals: %+v %v", r, err)
	}
}

// TestOIDCPending_AttemptBoundIsAtomic (review M4): concurrent guesses with
// one handle each reserve an attempt under the lock; no more than the bound
// ever get to check a code.
func TestOIDCPending_AttemptBoundIsAtomic(t *testing.T) {
	var st oidcPendingStore
	h, err := st.put("oidc:corp", &auth.Principal{Subject: "olga", Realm: "oidc:corp"})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var got atomic.Int32
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := st.reserve(h, "oidc:corp"); ok {
				got.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := got.Load(); n != oidcPendingMaxAttempts {
		t.Fatalf("%d of 50 concurrent guesses got an attempt, want exactly %d", n, oidcPendingMaxAttempts)
	}
}
