package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ── helpers ────────────────────────────────────────────────────────────────

// loginPolicyServer is a test server on which the login_policy release
// feature is open (its gate hands every write the grant), as on a fully rolled
// cluster. failover_scope_v1 too, because the second-factor policy is a
// cluster_policies row.
func loginPolicyServer(t *testing.T) *Server {
	t.Helper()
	s := testServer(t)
	s.SetGate(fakeServerGate{
		enforcedTok: map[string]bool{capabilities.ForwardedIdentityV1: true},
		durablyLatchedTok: map[string]bool{
			capabilities.FailoverScopeV1: true,
		},
	})
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: true})
	s.db.SetClusterPolicyGate(func() bool { return true })
	return s
}

// loginPolicyRefusal is the release-feature gate's refusal of a login rule
// before the feature can open.
var loginPolicyRefusal = "the cluster upgrade must finish first (" + string(capabilities.FeatureLoginPolicy) +
	" needs " + capabilities.ReleaseToken + ")"

// lpGrant is the grant the gate hands a login-rules writer once it is open.
func lpGrant(t *testing.T) capabilities.FeatureGrant {
	t.Helper()
	return capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
}

func bearerCtx(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+token))
}

func login(t *testing.T, s *Server, user, pw string) *pb.LoginResponse {
	t.Helper()
	resp, err := s.Login(context.Background(), &pb.LoginRequest{Username: user, Password: pw})
	if err != nil {
		t.Fatalf("Login(%s): %v", user, err)
	}
	return resp
}

// mintAPIToken creates an API token for user and returns its plaintext.
func mintAPIToken(t *testing.T, s *Server, user string) string {
	t.Helper()
	tok, err := s.CreateToken(adminCtx(), &pb.CreateTokenRequest{Username: user, Name: "auto-" + user})
	if err != nil {
		t.Fatalf("CreateToken(%s): %v", user, err)
	}
	return tok.Token
}

func setDisabled(t *testing.T, s *Server, user string, disabled bool) {
	t.Helper()
	if _, err := s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: user, Disabled: &disabled}); err != nil {
		t.Fatalf("SetUserAccount(%s, disabled=%t): %v", user, disabled, err)
	}
}

func setExpiry(t *testing.T, s *Server, user, exp string) {
	t.Helper()
	if _, err := s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: user, ExpiresAt: &exp}); err != nil {
		t.Fatalf("SetUserAccount(%s, expires=%q): %v", user, exp, err)
	}
}

// writeLifecycle writes a raw lifecycle attribute, bypassing every guard, to
// put a replica in a state a peer (or a later release) could have left it in.
func writeLifecycle(t *testing.T, s *Server, user, attr, value string) {
	t.Helper()
	if err := s.db.Execute(context.Background(),
		`INSERT INTO user_lifecycle (username, attribute, value, set_by, updated_at) VALUES (?, ?, ?, 'peer', ?)
		 ON CONFLICT(username, attribute) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		user, attr, value, s.db.NowTS()); err != nil {
		t.Fatalf("write lifecycle: %v", err)
	}
}

// seedAdmins adds a second unrestricted admin, so the last-admin guard is not
// what a test runs into.
func seedAdmins(t *testing.T, s *Server) {
	t.Helper()
	seedUser(t, s, "admin", "admin", "admin-pw")
	seedUser(t, s, "root2", "admin", "root2-pw")
}

// ── account lifecycle: every authentication path ─────────────────────────────

// TestAccountDisable_EveryCredentialStopsWorking: a disabled account's live
// session, its API token, both of those forwarded by a peer, a fresh password
// login and a WebAuthn-style mint are all refused. Re-enabling brings the API
// token back but not the session the disable ended.
func TestAccountDisable_EveryCredentialStopsWorking(t *testing.T) {
	s := loginPolicyServer(t)
	s.SetForwardedIdentity(true)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "peer-1", Address: "10.0.0.9", State: "active"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	sess := login(t, s, "bob", "bob-pw").Token
	tok := mintAPIToken(t, s, "bob")

	// Sanity: everything works before the disable, or the refusals prove nothing.
	for name, ctx := range map[string]context.Context{
		"session":           bearerCtx(sess),
		"token":             bearerCtx(tok),
		"forwarded session": withFwdBearer(mtlsPeerCtx("peer-1", tcpAddr("10.0.0.9"), ""), "Bearer "+sess),
		"forwarded token":   withFwdBearer(mtlsPeerCtx("peer-1", tcpAddr("10.0.0.9"), ""), "Bearer "+tok),
	} {
		got, err := s.authenticate(ctx)
		if err != nil || callerUsername(got) != "bob" {
			t.Fatalf("%s before the disable: user=%q err=%v", name, callerUsername(got), err)
		}
	}

	setDisabled(t, s, "bob", true)

	for name, ctx := range map[string]context.Context{
		"session":           bearerCtx(sess),
		"token":             bearerCtx(tok),
		"forwarded session": withFwdBearer(mtlsPeerCtx("peer-1", tcpAddr("10.0.0.9"), ""), "Bearer "+sess),
		"forwarded token":   withFwdBearer(mtlsPeerCtx("peer-1", tcpAddr("10.0.0.9"), ""), "Bearer "+tok),
	} {
		_, err := s.authenticate(ctx)
		wantCode(t, name+" of a disabled account", err, codes.Unauthenticated)
	}
	_, err := s.Login(context.Background(), &pb.LoginRequest{Username: "bob", Password: "bob-pw"})
	wantCode(t, "password login of a disabled account", err, codes.Unauthenticated)
	if !strings.Contains(err.Error(), "disabled") {
		t.Errorf("login refusal %q does not say the account is disabled", err)
	}
	// FinishWebAuthnLogin's only path to a session.
	_, _, _, err = s.mintSession(context.Background(), "bob", "local", "10.0.0.9", "webauthn", "webauthn")
	wantCode(t, "WebAuthn mint for a disabled account", err, codes.Unauthenticated)
	// A wrong password still reads as a wrong password: the disabled state is
	// told only to someone who holds the credential.
	_, err = s.Login(context.Background(), &pb.LoginRequest{Username: "bob", Password: "nope"})
	if status.Code(err) != codes.Unauthenticated || strings.Contains(err.Error(), "disabled") {
		t.Errorf("wrong password for a disabled account: %v, want a plain invalid-credentials refusal", err)
	}

	setDisabled(t, s, "bob", false)
	if got, err := s.authenticate(bearerCtx(tok)); err != nil || callerUsername(got) != "bob" {
		t.Errorf("API token after re-enable: user=%q err=%v, want it working again", callerUsername(got), err)
	}
	_, err = s.authenticate(bearerCtx(sess))
	wantCode(t, "the session the disable ended, after re-enable", err, codes.Unauthenticated)
	// A login inside the skew margin after the re-enable is told to retry
	// (it would mint a session the cut-off refuses); after it, it works.
	_, err = s.Login(context.Background(), &pb.LoginRequest{Username: "bob", Password: "bob-pw"})
	wantCode(t, "a login inside the cut-off margin", err, codes.Unavailable)
	time.Sleep(corrosion.SessionCutoffSkewMargin + 1100*time.Millisecond)
	if _, err := s.authenticate(bearerCtx(login(t, s, "bob", "bob-pw").Token)); err != nil {
		t.Fatalf("a session minted after the margin: %v", err)
	}
}

// TestAccountDisable_RefusedBeforeTheSessionRevokeArrives: on a node the
// disable has reached but the disabling node's session revokes have not —
// they are separate rows, replicated separately — every credential is still
// refused, because the check is on the account, not on the session row.
func TestAccountDisable_RefusedBeforeTheSessionRevokeArrives(t *testing.T) {
	s := loginPolicyServer(t)
	s.SetForwardedIdentity(true)
	seedUser(t, s, "bob", "operator", "bob-pw")
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "peer-1", Address: "10.0.0.9", State: "active"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	sess := login(t, s, "bob", "bob-pw").Token
	tok := mintAPIToken(t, s, "bob")
	writeLifecycle(t, s, "bob", corrosion.UserAttrDisabled, "true") // arrived; the revokes have not
	for name, ctx := range map[string]context.Context{
		"session":           bearerCtx(sess),
		"token":             bearerCtx(tok),
		"forwarded session": withFwdBearer(mtlsPeerCtx("peer-1", tcpAddr("10.0.0.9"), ""), "Bearer "+sess),
		"forwarded token":   withFwdBearer(mtlsPeerCtx("peer-1", tcpAddr("10.0.0.9"), ""), "Bearer "+tok),
	} {
		_, err := s.authenticate(ctx)
		wantCode(t, name+" of a disabled account whose session is not revoked", err, codes.Unauthenticated)
	}
}

// TestAccountDisable_NoSecondFactorPromptForADisabledAccount: a disabled
// account that has a factor is refused at the password, not asked for the
// factor (which would tell the caller nothing useful and invite a guess).
func TestAccountDisable_NoSecondFactorPromptForADisabledAccount(t *testing.T) {
	s := loginPolicyServer(t)
	seedUser(t, s, "bob", "operator", "bob-pw")
	if _, err := auth.EnrollTOTP(context.Background(), s.db, "bob", "phone"); err != nil {
		t.Fatal(err)
	}
	writeLifecycle(t, s, "bob", corrosion.UserAttrDisabled, "true")
	r, err := s.Login(context.Background(), &pb.LoginRequest{Username: "bob", Password: "bob-pw"})
	if status.Code(err) != codes.Unauthenticated || r.GetRequires_2Fa() {
		t.Fatalf("disabled account with a factor: %+v %v, want Unauthenticated and no challenge", r, err)
	}
}

// TestAccountLifecycle_UnreadableTableRefuses: a lifecycle read that fails
// refuses the credential rather than reading as "no row, so active".
func TestAccountLifecycle_UnreadableTableRefuses(t *testing.T) {
	s := loginPolicyServer(t)
	seedUser(t, s, "bob", "operator", "bob-pw")
	tok := mintAPIToken(t, s, "bob")
	if err := s.db.Execute(context.Background(), `DROP TABLE user_lifecycle`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	_, err := s.authenticate(bearerCtx(tok))
	wantCode(t, "token with an unreadable lifecycle table", err, codes.Unavailable)
}

// TestAccountExpiry_ExpiredRefusedFutureAllowed: an expiry in the past refuses
// every credential; one in the future refuses nothing; "never" clears it.
func TestAccountExpiry_ExpiredRefusedFutureAllowed(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "carol", "viewer", "carol-pw")
	tok := mintAPIToken(t, s, "carol")

	// A future expiry as a replica holds it (setting one through the RPC is
	// also a session cut-off, tested in the fix-round tests).
	writeLifecycle(t, s, "carol", corrosion.UserAttrExpiresAt, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	sess := login(t, s, "carol", "carol-pw").Token
	if _, err := s.authenticate(bearerCtx(tok)); err != nil {
		t.Fatalf("token with a future expiry: %v", err)
	}
	if _, err := s.authenticate(bearerCtx(sess)); err != nil {
		t.Fatalf("session with a future expiry: %v", err)
	}

	// An expiry passes on its own: write it straight into the replica, as the
	// passage of time would leave it, without the RPC's session sweep.
	writeLifecycle(t, s, "carol", corrosion.UserAttrExpiresAt, time.Now().Add(-time.Second).UTC().Format(time.RFC3339))
	_, err := s.authenticate(bearerCtx(tok))
	wantCode(t, "token of an expired account", err, codes.Unauthenticated)
	_, err = s.authenticate(bearerCtx(sess))
	wantCode(t, "session of an expired account", err, codes.Unauthenticated)
	_, err = s.Login(context.Background(), &pb.LoginRequest{Username: "carol", Password: "carol-pw"})
	wantCode(t, "login of an expired account", err, codes.Unauthenticated)

	setExpiry(t, s, "carol", "never")
	if _, err := s.authenticate(bearerCtx(tok)); err != nil {
		t.Errorf("token after the expiry was cleared: %v", err)
	}
}

// TestAccountLifecycle_UnreadableStateFailsClosed: a value this build cannot
// read (a later release's, or corruption) is never taken to mean "active".
func TestAccountLifecycle_UnreadableStateFailsClosed(t *testing.T) {
	for _, tc := range []struct{ attr, value string }{
		{corrosion.UserAttrDisabled, "yes"},
		{corrosion.UserAttrDisabled, ""},
		{corrosion.UserAttrExpiresAt, "30d"},
	} {
		s := loginPolicyServer(t)
		seedUser(t, s, "dave", "viewer", "dave-pw")
		tok := mintAPIToken(t, s, "dave")
		writeLifecycle(t, s, "dave", tc.attr, tc.value)
		_, err := s.authenticate(bearerCtx(tok))
		wantCode(t, tc.attr+"="+tc.value, err, codes.Unauthenticated)
	}
}

// TestAccountLifecycle_EnforcedBeforeThisNodeLatches: a node whose own latch
// has not formed yet still enforces a row a latched peer wrote. Skipping the
// read until the local gate opens would leave a window in which this node
// accepts a disabled account.
func TestAccountLifecycle_EnforcedBeforeThisNodeLatches(t *testing.T) {
	s := testServer(t) // no gate at all: nothing latched here
	seedUser(t, s, "erin", "viewer", "erin-pw")
	tok := mintAPIToken(t, s, "erin")
	writeLifecycle(t, s, "erin", corrosion.UserAttrDisabled, "true") // arrived by replication
	_, err := s.authenticate(bearerCtx(tok))
	wantCode(t, "a replicated disable on an unlatched node", err, codes.Unauthenticated)
}

// ── SetUserAccount: preconditions ────────────────────────────────────────────

// TestSetUserAccount_RefusedBeforeTheLatch: nothing may be written until every
// host decodes and enforces it.
func TestSetUserAccount_RefusedBeforeTheLatch(t *testing.T) {
	s := testServer(t) // no release-feature gate: every feature is refused
	s.SetGate(fakeServerGate{durablyLatchedTok: map[string]bool{}})
	seedUser(t, s, "bob", "viewer", "pw")
	yes := true
	_, err := s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: "bob", Disabled: &yes})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), loginPolicyRefusal) {
		t.Fatalf("SetUserAccount before the latch: %v, want FailedPrecondition %q", err, loginPolicyRefusal)
	}
	rows, _ := s.db.Query(context.Background(), `SELECT username FROM user_lifecycle`)
	if len(rows) != 0 {
		t.Fatalf("a refused change was written: %d rows", len(rows))
	}
	// And the corrosion writer refuses on its own without the gate's grant,
	// whatever the RPC does.
	if err := corrosion.SetUserLifecycle(context.Background(), s.db, capabilities.FeatureGrant{}, "bob", &yes, nil, "x"); err != corrosion.ErrLoginPolicyGateClosed {
		t.Fatalf("SetUserLifecycle with no grant: %v, want ErrLoginPolicyGateClosed", err)
	}
}

func TestSetUserAccount_AdminOnlyAndValidated(t *testing.T) {
	s := loginPolicyServer(t)
	seedUser(t, s, "bob", "operator", "pw")
	yes := true
	opCtx := context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, "bob"), ctxKeyRole, "operator")
	_, err := s.SetUserAccount(opCtx, &pb.SetUserAccountRequest{Username: "bob", Disabled: &yes})
	wantCode(t, "operator disabling an account", err, codes.PermissionDenied)
	_, err = s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: "ghost", Disabled: &yes})
	wantCode(t, "unknown user", err, codes.NotFound)
	_, err = s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: "bob"})
	wantCode(t, "nothing to change", err, codes.InvalidArgument)
	bad := "30d"
	_, err = s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: "bob", ExpiresAt: &bad})
	wantCode(t, "malformed expiry", err, codes.InvalidArgument)
	off := "2026-12-31T01:00:00+01:00"
	u, err := s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: "bob", ExpiresAt: &off})
	if err != nil || u.GetExpiresAt() != "2026-12-31T00:00:00Z" {
		t.Fatalf("offset expiry: %+v %v, want normalized to 2026-12-31T00:00:00Z", u, err)
	}
}

// TestSetUserAccount_LastAdminGuard: the last admin that is enabled with no
// expiry can be neither disabled nor given an expiry; another admin that is
// itself disabled or expiring does not count as the one that remains.
func TestSetUserAccount_LastAdminGuard(t *testing.T) {
	s := loginPolicyServer(t)
	seedUser(t, s, "admin", "admin", "pw")
	seedUser(t, s, "root2", "admin", "pw")
	yes := true
	soon := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)

	setDisabled(t, s, "root2", true) // allowed: "admin" remains
	_, err := s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: "admin", Disabled: &yes})
	wantCode(t, "disabling the last unrestricted admin", err, codes.FailedPrecondition)
	_, err = s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: "admin", ExpiresAt: &soon})
	wantCode(t, "expiring the last unrestricted admin", err, codes.FailedPrecondition)

	setDisabled(t, s, "root2", false)
	setExpiry(t, s, "root2", soon) // root2 now expires: it is not unrestricted
	_, err = s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: "admin", Disabled: &yes})
	wantCode(t, "disabling admin while the other admin has an expiry", err, codes.FailedPrecondition)

	l, _ := corrosion.GetUserLifecycle(context.Background(), s.db, "admin")
	if !l.Unrestricted() {
		t.Fatalf("a refused change was written: %+v", l)
	}
	// A non-admin is never guarded.
	seedUser(t, s, "bob", "viewer", "pw")
	setDisabled(t, s, "bob", true)
}

// TestListUsers_ShowsAccountState: `lv user ls` reports disable and expiry.
func TestListUsers_ShowsAccountState(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "viewer", "pw")
	setDisabled(t, s, "bob", true)
	setExpiry(t, s, "bob", "2030-01-01T00:00:00Z")
	resp, err := s.ListUsers(adminCtx(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range resp.Users {
		if u.Username == "bob" && (!u.Disabled || u.ExpiresAt != "2030-01-01T00:00:00Z") {
			t.Fatalf("bob listed as %+v", u)
		}
		if u.Username == "admin" && (u.Disabled || u.ExpiresAt != "") {
			t.Fatalf("admin listed as %+v", u)
		}
	}
}

// TestDeleteUser_ResetsLifecycle: a name deleted and re-created starts enabled.
func TestDeleteUser_ResetsLifecycle(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "viewer", "pw")
	setDisabled(t, s, "bob", true)
	if _, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "bob"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(adminCtx(), &pb.CreateUserRequest{Username: "bob", Password: "pw2"}); err != nil {
		t.Fatal(err)
	}
	login(t, s, "bob", "pw2")
}

// TestResetAdmin_ReEnablesTheAdminAccount: `lv user reset-admin` is the
// documented way back in when every admin has been disabled or expired.
func TestResetAdmin_ReEnablesTheAdminAccount(t *testing.T) {
	s := loginPolicyServer(t)
	seedUser(t, s, "admin", "admin", "old")
	writeLifecycle(t, s, "admin", corrosion.UserAttrDisabled, "true")
	writeLifecycle(t, s, "admin", corrosion.UserAttrExpiresAt, "2000-01-01T00:00:00Z")
	hash, _ := bcrypt.GenerateFromPassword([]byte("fresh-password"), auth.BcryptCost)
	if err := corrosion.ResetAdminPassword(context.Background(), s.db, s.withLoginPolicy, string(hash), false); err != nil {
		t.Fatalf("ResetAdminPassword: %v", err)
	}
	login(t, s, "admin", "fresh-password")

	// With the gate closed it refuses rather than resetting a password the
	// account still cannot use: the daemon's gate refuses, and with no gate
	// at all (reset-admin with the daemon down) the writer refuses.
	writeLifecycle(t, s, "admin", corrosion.UserAttrDisabled, "true")
	s.SetReleaseFeatureGate(nil)
	if err := corrosion.ResetAdminPassword(context.Background(), s.db, s.withLoginPolicy, string(hash), false); err == nil ||
		!strings.Contains(err.Error(), loginPolicyRefusal) {
		t.Fatalf("ResetAdminPassword with the gate closed on a disabled admin: %v, want %q", err, loginPolicyRefusal)
	}
	if err := corrosion.ResetAdminPassword(context.Background(), s.db, nil, string(hash), false); !errors.Is(err, corrosion.ErrLoginPolicyGateClosed) {
		t.Fatalf("ResetAdminPassword with no gate on a disabled admin: %v, want ErrLoginPolicyGateClosed", err)
	}
}

// ── mandatory second factor ──────────────────────────────────────────────────

func setPolicy(t *testing.T, s *Server, v string) *pb.LoginPolicy {
	t.Helper()
	p, err := s.SetLoginPolicy(adminCtx(), &pb.SetLoginPolicyRequest{Require_2Fa: v})
	if err != nil {
		t.Fatalf("SetLoginPolicy(%q): %v", v, err)
	}
	return p
}

func totpCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, time.Now().UTC(), totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// runUnary drives one request through the real auth interceptor.
func runUnary(s *Server, ctx context.Context, method string) error {
	_, err := s.UnaryAuthInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method},
		func(context.Context, interface{}) (interface{}, error) { return nil, nil })
	return err
}

// TestTwoFactorPolicy_UnenrolledUserGetsEnrollmentOnlySession: a covered user
// with no factor is not locked out; the session can enroll a factor for itself
// and nothing else, and the enrollment ends it.
func TestTwoFactorPolicy_UnenrolledUserGetsEnrollmentOnlySession(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "admin", "bob-pw") // an admin: the role must not leak through
	setPolicy(t, s, "all")

	resp := login(t, s, "bob", "bob-pw")
	if !resp.GetRequires_2FaEnrollment() || resp.Token == "" || resp.Role != "" {
		t.Fatalf("login under the policy with no factor: %+v, want an enrollment-only token and no role", resp)
	}
	ctx := bearerCtx(resp.Token)
	for _, m := range []string{"ListHosts", "CreateUser", "GrantRole", "ChangePassword", "CreateToken", "ListVMs"} {
		wantCode(t, "enrollment-only session calling "+m,
			runUnary(s, ctx, "/litevirt.v1.LiteVirt/"+m), codes.PermissionDenied)
	}
	if err := runUnary(s, ctx, "/litevirt.v1.LiteVirt/Whoami"); err != nil {
		t.Fatalf("Whoami from an enrollment-only session: %v", err)
	}
	actx, err := s.authenticate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if who, _ := s.Whoami(actx, &emptypb.Empty{}); !who.GetRequires_2FaEnrollment() || who.GetRole() != "" {
		t.Fatalf("Whoami: %+v, want requires_2fa_enrollment and no role", who)
	}
	// The same session relayed by a peer is confined the same way.
	s.SetForwardedIdentity(true)
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "peer-1", Address: "10.0.0.9", State: "active"}); err != nil {
		t.Fatal(err)
	}
	fctx, err := s.authenticate(withFwdBearer(mtlsPeerCtx("peer-1", tcpAddr("10.0.0.9"), ""), "Bearer "+resp.Token))
	if err != nil || !callerEnrollOnly(fctx) || callerRole(fctx) != "" {
		t.Fatalf("forwarded enrollment-only session: enrollOnly=%v role=%q err=%v", callerEnrollOnly(fctx), callerRole(fctx), err)
	}
	// Even an admin's enrollment-only session cannot enroll for someone else.
	_, err = s.EnrollTOTP(actx, &pb.EnrollTOTPRequest{Username: "root2"})
	wantCode(t, "enrollment-only admin enrolling another user", err, codes.PermissionDenied)

	code, err := s.IssueEnrollmentCode(adminCtx(), &pb.IssueEnrollmentCodeRequest{Username: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	enr, err := s.EnrollTOTP(actx, &pb.EnrollTOTPRequest{Label: "phone", EnrollmentCode: code.GetCode()})
	if err != nil || !enr.GetSessionEnded() {
		t.Fatalf("self-enrollment: ended=%v err=%v, want the session ended", enr.GetSessionEnded(), err)
	}
	_, err = s.authenticate(ctx)
	wantCode(t, "the enrollment-only session after enrolling", err, codes.Unauthenticated)

	// The next login must present the new factor, and then it is a full session.
	r2 := login(t, s, "bob", "bob-pw")
	if !r2.GetRequires_2Fa() || r2.Token != "" {
		t.Fatalf("login after enrolling: %+v, want a second-factor challenge", r2)
	}
	r3, err := s.Login(context.Background(), &pb.LoginRequest{Username: "bob", Password: "bob-pw", TotpCode: totpCode(t, enr.SecretBase32)})
	if err != nil || r3.GetRequires_2FaEnrollment() || r3.Role != "admin" {
		t.Fatalf("login with the factor: %+v %v, want a full admin session", r3, err)
	}
	if err := runUnary(s, bearerCtx(r3.Token), "/litevirt.v1.LiteVirt/ListHosts"); err != nil {
		t.Fatalf("full session after enrolling: %v", err)
	}
}

// TestTwoFactorPolicy_SessionIsJudgedByWhatItsLoginPresented: a session is
// full or confined by what its own login presented, recorded when it was
// minted, never re-derived from the account's factors now (review C1). One
// that presented a factor stays full when the factor is later removed (a
// lost-device reset); the account's next login is confined.
func TestTwoFactorPolicy_SessionIsJudgedByWhatItsLoginPresented(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	enr, err := auth.EnrollTOTP(context.Background(), s.db, "bob", "phone")
	if err != nil {
		t.Fatal(err)
	}
	setPolicy(t, s, "local")
	r, err := s.Login(context.Background(), &pb.LoginRequest{Username: "bob", Password: "bob-pw", TotpCode: totpCode(t, enr.SecretBase32)})
	if err != nil || r.GetRequires_2FaEnrollment() {
		t.Fatalf("login with a factor: %+v %v", r, err)
	}
	if err := runUnary(s, bearerCtx(r.Token), "/litevirt.v1.LiteVirt/ListHosts"); err != nil {
		t.Fatalf("full session: %v", err)
	}
	if _, err := s.DisableTwoFactor(adminCtx(), &pb.DisableTwoFactorRequest{Username: "bob", Method: "totp", Label: "phone"}); err != nil {
		t.Fatal(err)
	}
	if err := runUnary(s, bearerCtx(r.Token), "/litevirt.v1.LiteVirt/ListHosts"); err != nil {
		t.Fatalf("a session that presented a factor, after the factor was removed: %v", err)
	}
	if r2 := login(t, s, "bob", "bob-pw"); !r2.GetRequires_2FaEnrollment() {
		t.Fatalf("the next login after the factor was removed: %+v, want enrollment-only", r2)
	}
}

// fakeRealm authenticates any password (or OIDC code) as subject, so a test
// can drive Login through a realm other than local.
type fakeRealm struct{ name, subject string }

func (f fakeRealm) Name() string { return f.name }
func (f fakeRealm) Authenticate(_ context.Context, c auth.Credentials) (*auth.Principal, error) {
	if c.Password == "" && c.OIDCCode == "" {
		return nil, auth.ErrInvalidCredentials
	}
	return &auth.Principal{Subject: f.subject, Realm: f.name}, nil
}
func (fakeRealm) SyncGroups(context.Context) error { return nil }

func policyRealmServer(t *testing.T, realms ...auth.Realm) *Server {
	t.Helper()
	s := loginPolicyServer(t)
	reg := auth.NewRegistry()
	reg.Register(auth.NewLocalRealm(s.db))
	for _, r := range realms {
		reg.Register(r)
	}
	s.realmRegistry = reg
	return s
}

// TestTwoFactorPolicy_ExternalRealmMustPresentTheFactor: LocalRealm demands an
// enrolled factor on its own; an external realm does not, so without the
// policy's own check an LDAP user who enrolled a factor would never be asked
// for it. Under the policy they are; outside it they are not.
func TestTwoFactorPolicy_ExternalRealmMustPresentTheFactor(t *testing.T) {
	s := policyRealmServer(t, fakeRealm{name: "ldap:corp", subject: "lena"})
	seedAdmins(t, s)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "lena", "viewer", ""); err != nil { // the shadow row
		t.Fatal(err)
	}
	enr, err := auth.EnrollTOTP(ctx, s.db, "lena", "phone")
	if err != nil {
		t.Fatal(err)
	}
	req := &pb.LoginRequest{Username: "lena", Password: "dir-pw", Realm: "ldap:corp"}

	setPolicy(t, s, "local") // ldap:corp not covered: today's behaviour
	if r, err := s.Login(ctx, req); err != nil || r.Token == "" || r.GetRequires_2Fa() {
		t.Fatalf("uncovered realm: %+v %v, want a plain session", r, err)
	}

	setPolicy(t, s, "local,ldap:corp")
	r, err := s.Login(ctx, req)
	if err != nil || !r.GetRequires_2Fa() || r.Token != "" {
		t.Fatalf("covered realm with a factor, no code: %+v %v, want a second-factor challenge", r, err)
	}
	bad := &pb.LoginRequest{Username: "lena", Password: "dir-pw", Realm: "ldap:corp", TotpCode: "000000"}
	_, err = s.Login(ctx, bad)
	wantCode(t, "covered realm with a wrong code", err, codes.Unauthenticated)
	good := &pb.LoginRequest{Username: "lena", Password: "dir-pw", Realm: "ldap:corp", TotpCode: totpCode(t, enr.SecretBase32)}
	if r, err := s.Login(ctx, good); err != nil || r.Token == "" {
		t.Fatalf("covered realm with the code: %+v %v", r, err)
	}
}

// TestTwoFactorPolicy_OIDCNeedsTheCodeWithTheOIDCCode: an OIDC code is single
// use, so a login without the factor gets no session: it is answered with a
// challenge and an oidc_pending handle (the code cannot be resent), and the
// factor sent with the code in one call still works.
func TestTwoFactorPolicy_OIDCNeedsTheCodeWithTheOIDCCode(t *testing.T) {
	s := policyRealmServer(t, fakeRealm{name: "oidc:corp", subject: "olga"})
	seedAdmins(t, s)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "olga", "viewer", ""); err != nil {
		t.Fatal(err)
	}
	enr, err := auth.EnrollTOTP(ctx, s.db, "olga", "phone")
	if err != nil {
		t.Fatal(err)
	}
	setPolicy(t, s, "all")
	ch, err := s.Login(ctx, &pb.LoginRequest{Realm: "oidc:corp", OidcCode: "c", OidcState: "s"})
	if err != nil || ch.Token != "" || !ch.GetRequires_2Fa() || ch.GetOidcPending() == "" {
		t.Fatalf("OIDC login without the factor: %+v %v, want a challenge with a handle and no session", ch, err)
	}
	r, err := s.Login(ctx, &pb.LoginRequest{Realm: "oidc:corp", OidcCode: "c", OidcState: "s", TotpCode: totpCode(t, enr.SecretBase32)})
	if err != nil || r.Token == "" {
		t.Fatalf("OIDC login with the factor: %+v %v", r, err)
	}
}

// TestSetLoginPolicy_EndsSessionsInNewlyCoveredRealms: the policy is true from
// the moment it is set. Sessions in realms it newly covers end; sessions in
// realms it already covered, or does not cover, do not.
func TestSetLoginPolicy_EndsSessionsInNewlyCoveredRealms(t *testing.T) {
	s := policyRealmServer(t, fakeRealm{name: "ldap:corp", subject: "lena"})
	seedAdmins(t, s)
	seedUser(t, s, "bob", "viewer", "bob-pw")
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "lena", "viewer", ""); err != nil {
		t.Fatal(err)
	}
	local := login(t, s, "bob", "bob-pw").Token
	ldap, err := s.Login(ctx, &pb.LoginRequest{Username: "lena", Password: "x", Realm: "ldap:corp"})
	if err != nil {
		t.Fatal(err)
	}

	p := setPolicy(t, s, "ldap:corp")
	if p.GetSessionsRevoked() != 1 {
		t.Errorf("sessions ended = %d, want 1 (the ldap:corp one)", p.GetSessionsRevoked())
	}
	_, err = s.authenticate(bearerCtx(ldap.Token))
	wantCode(t, "a session in the newly covered realm", err, codes.Unauthenticated)
	if _, err := s.authenticate(bearerCtx(local)); err != nil {
		t.Fatalf("a session in an uncovered realm: %v", err)
	}
	// A session opened under the policy (lena has no factor: enrollment-only)
	// is not ended by re-setting it, nor by widening it to another realm.
	again, err := s.Login(ctx, &pb.LoginRequest{Username: "lena", Password: "x", Realm: "ldap:corp"})
	if err != nil || !again.GetRequires_2FaEnrollment() {
		t.Fatalf("login under the policy: %+v %v", again, err)
	}
	if p := setPolicy(t, s, "ldap:corp"); p.GetSessionsRevoked() != 0 {
		t.Errorf("re-setting the same policy ended %d sessions, want 0", p.GetSessionsRevoked())
	}
	if p := setPolicy(t, s, "all"); p.GetSessionsRevoked() != 1 {
		t.Errorf("widening to all ended %d sessions, want 1 (bob's local one, not lena's)", p.GetSessionsRevoked())
	}
	if _, err := s.authenticate(bearerCtx(again.Token)); err != nil {
		t.Errorf("a session in an already-covered realm was ended by widening the policy: %v", err)
	}
}

func TestSetLoginPolicy_RefusedBeforeTheLatchAndValidated(t *testing.T) {
	s := testServer(t) // no release-feature gate: every feature is refused
	s.db.SetClusterPolicyGate(func() bool { return true })
	s.SetGate(fakeServerGate{durablyLatchedTok: map[string]bool{capabilities.FailoverScopeV1: true}})
	_, err := s.SetLoginPolicy(adminCtx(), &pb.SetLoginPolicyRequest{Require_2Fa: "all"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), loginPolicyRefusal) {
		t.Fatalf("SetLoginPolicy before the latch: %v, want FailedPrecondition %q", err, loginPolicyRefusal)
	}
	if p, _ := corrosion.GetTwoFactorPolicy(context.Background(), s.db); !p.Off() {
		t.Fatalf("a refused policy was written: %+v", p)
	}

	s = loginPolicyServer(t)
	for _, bad := range []string{"everyone", "ldap:", "local,,ldap:x", "oidc:a b"} {
		_, err := s.SetLoginPolicy(adminCtx(), &pb.SetLoginPolicyRequest{Require_2Fa: bad})
		wantCode(t, "policy "+bad, err, codes.InvalidArgument)
	}
	opCtx := context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, "op"), ctxKeyRole, "operator")
	_, err = s.SetLoginPolicy(opCtx, &pb.SetLoginPolicyRequest{Require_2Fa: "all"})
	wantCode(t, "operator setting the policy", err, codes.PermissionDenied)
}

// TestTwoFactorPolicy_UnknownStoredValueEnforcedAsAll: a later release's
// value is enforced as the strictest reading this build has.
func TestTwoFactorPolicy_UnknownStoredValueEnforcedAsAll(t *testing.T) {
	s := loginPolicyServer(t)
	seedUser(t, s, "bob", "viewer", "bob-pw")
	if err := s.db.Execute(context.Background(),
		`INSERT INTO cluster_policies (key, value, set_by, updated_at) VALUES (?, 'admins-only:v2', 'future', ?)`,
		corrosion.LoginTwoFactorPolicyKey, s.db.NowTS()); err != nil {
		t.Fatal(err)
	}
	if r := login(t, s, "bob", "bob-pw"); !r.GetRequires_2FaEnrollment() {
		t.Fatalf("login under an unknown policy value: %+v, want enrollment-only", r)
	}
}

// TestTwoFactorPolicy_UnhydratedCredentialsRefuse: an emptied user_2fa reads
// as "no factor", which would hand whoever holds the password an
// enrollment-only session for an account that HAS a factor — and so the
// chance to enroll their own. Refused instead.
func TestTwoFactorPolicy_UnhydratedCredentialsRefuse(t *testing.T) {
	s := loginPolicyServer(t)
	seedUser(t, s, "bob", "viewer", "bob-pw")
	setPolicy(t, s, "all")
	r := login(t, s, "bob", "bob-pw") // hydrated: enrollment-only
	code, err := s.IssueEnrollmentCode(adminCtx(), &pb.IssueEnrollmentCodeRequest{Username: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	s.db.MarkCredentialsUnhydrated()
	// The session is judged by what its login presented, which needs no
	// factor table; it stays confined.
	wantCode(t, "a confined session on an unhydrated node",
		runUnary(s, bearerCtx(r.Token), "/litevirt.v1.LiteVirt/ListHosts"), codes.PermissionDenied)
	// But it may not enroll: an empty user_2fa cannot tell "no factor" from
	// "factor not here yet".
	actx, aerr := s.authenticate(bearerCtx(r.Token))
	if aerr != nil {
		t.Fatal(aerr)
	}
	_, err = s.EnrollTOTP(actx, &pb.EnrollTOTPRequest{Label: "x", EnrollmentCode: code.GetCode()})
	wantCode(t, "enrollment on an unhydrated node", err, codes.Unavailable)
	_, err = s.Login(context.Background(), &pb.LoginRequest{Username: "bob", Password: "bob-pw"})
	if err == nil {
		t.Fatal("login on an unhydrated node under the policy succeeded")
	}
}

// TestTwoFactorPolicy_OffChangesNothing: with no policy, a user with no factor
// gets a full session, exactly as before.
func TestTwoFactorPolicy_OffChangesNothing(t *testing.T) {
	s := loginPolicyServer(t)
	seedUser(t, s, "bob", "operator", "bob-pw")
	r := login(t, s, "bob", "bob-pw")
	if r.GetRequires_2FaEnrollment() || r.Role != "operator" {
		t.Fatalf("login with the policy off: %+v", r)
	}
	if err := runUnary(s, bearerCtx(r.Token), "/litevirt.v1.LiteVirt/ListHosts"); err != nil {
		t.Fatalf("full session: %v", err)
	}
}
