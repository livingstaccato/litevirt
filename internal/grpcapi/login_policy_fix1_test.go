package grpcapi

// Fix round 1 of the login-rules review (t1-auth-review.md). Each test names
// the finding it closes.

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// enrollOnlyCtx authenticates token and fails unless it is enrollment-only.
func mustBeConfined(t *testing.T, s *Server, what, token string) {
	t.Helper()
	err := runUnary(s, bearerCtx(token), "/litevirt.v1.LiteVirt/ListHosts")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("%s: ListHosts = %v, want PermissionDenied (still confined)", what, err)
	}
	actx, err := s.authenticate(bearerCtx(token))
	if err != nil {
		t.Fatalf("%s: authenticate: %v", what, err)
	}
	if !callerEnrollOnly(actx) || callerRole(actx) != "" {
		t.Fatalf("%s: enrollOnly=%v role=%q, want confined with no role", what, callerEnrollOnly(actx), callerRole(actx))
	}
}

// C1(a): a password-only session stays confined when ANOTHER session of the
// same account enrolls the first factor.
func TestC1_PasswordOnlySessionStaysConfinedWhenAnotherEnrolls(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "admin", "bob-pw")
	setPolicyFull(t, s, &pb.SetLoginPolicyRequest{Require_2Fa: "all", AllowSelfEnroll: true,
		EnrollBy: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	attacker := login(t, s, "bob", "bob-pw").Token
	victim := login(t, s, "bob", "bob-pw").Token
	vctx, err := s.authenticate(bearerCtx(victim))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnrollTOTP(vctx, &pb.EnrollTOTPRequest{Label: "phone"}); err != nil {
		t.Fatalf("victim enrolls: %v", err)
	}
	mustBeConfined(t, s, "the attacker's password-only session after the victim enrolled", attacker)
	// And it may not enroll a factor of its own now that one exists.
	actx, _ := s.authenticate(bearerCtx(attacker))
	_, err = s.EnrollTOTP(actx, &pb.EnrollTOTPRequest{Label: "attacker"})
	wantCode(t, "password-only session enrolling a second factor", err, codes.PermissionDenied)
}

// C1(b): an admin enrolling a factor for the user does not promote the
// user's password-only sessions.
func TestC1_AdminEnrollingForUserDoesNotPromote(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	setPolicy(t, s, "all")
	sess := login(t, s, "bob", "bob-pw").Token
	if _, err := s.EnrollTOTP(adminCtx(), &pb.EnrollTOTPRequest{Username: "bob", Label: "phone"}); err != nil {
		t.Fatal(err)
	}
	mustBeConfined(t, s, "a password-only session after an admin enrolled the user", sess)
}

// C1(c): a lost-device reset (factor removed, then re-enrolled) does not
// promote any password-only session opened in between.
func TestC1_LostDeviceResetDoesNotPromote(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	if _, err := auth.EnrollTOTP(context.Background(), s.db, "bob", "old"); err != nil {
		t.Fatal(err)
	}
	setPolicy(t, s, "all")
	if _, err := s.DisableTwoFactor(adminCtx(), &pb.DisableTwoFactorRequest{Username: "bob", Method: "totp", Label: "old"}); err != nil {
		t.Fatal(err)
	}
	between := login(t, s, "bob", "bob-pw").Token
	if _, err := s.EnrollTOTP(adminCtx(), &pb.EnrollTOTPRequest{Username: "bob", Label: "new"}); err != nil {
		t.Fatal(err)
	}
	mustBeConfined(t, s, "a session opened during the lost-device reset", between)
}

// C1(f): a session minted where the policy had not arrived yet, without a
// factor, is confined once the policy arrives, even though the account has
// a factor enrolled. The setter's revocation sweep never saw it.
func TestC1_SessionMintedBeforeThePolicyArrivedIsConfined(t *testing.T) {
	s := policyRealmServer(t, fakeRealm{name: "ldap:corp", subject: "lena"})
	seedAdmins(t, s)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "lena", "operator", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.EnrollTOTP(ctx, s.db, "lena", "phone"); err != nil {
		t.Fatal(err)
	}
	r, err := s.Login(ctx, &pb.LoginRequest{Username: "lena", Password: "x", Realm: "ldap:corp"})
	if err != nil || r.Token == "" {
		t.Fatalf("login with the policy off: %+v %v", r, err)
	}
	// The policy row arrives by replication: no sweep runs here.
	p, _ := corrosion.ParseTwoFactorPolicy("all")
	if err := corrosion.SetTwoFactorPolicy(ctx, s.db, lpGrant(t), p, "peer"); err != nil {
		t.Fatal(err)
	}
	mustBeConfined(t, s, "a session minted before the policy arrived", r.Token)
}

// C1(e): an enrollment through a forwarded identity ends the forwarded session.
func TestC1_ForwardedEnrollmentEndsTheSession(t *testing.T) {
	s := loginPolicyServer(t)
	s.SetForwardedIdentity(true)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "peer-1", Address: "10.0.0.9", State: "active"}); err != nil {
		t.Fatal(err)
	}
	setPolicyFull(t, s, &pb.SetLoginPolicyRequest{Require_2Fa: "all", AllowSelfEnroll: true,
		EnrollBy: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	tok := login(t, s, "bob", "bob-pw").Token
	fctx, err := s.authenticate(withFwdBearer(mtlsPeerCtx("peer-1", tcpAddr("10.0.0.9"), ""), "Bearer "+tok))
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.EnrollTOTP(fctx, &pb.EnrollTOTPRequest{Label: "phone"})
	if err != nil || !r.GetSessionEnded() {
		t.Fatalf("forwarded enrollment: ended=%v err=%v, want the session ended", r.GetSessionEnded(), err)
	}
	_, err = s.authenticate(bearerCtx(tok))
	wantCode(t, "the session after a forwarded enrollment", err, codes.Unauthenticated)
}

// I2: a disabled directory user cannot come back in with a variant spelling.
func TestI2_VariantSpellingOfADisabledUserIsRefused(t *testing.T) {
	for _, typed := range []string{"ALICE", "Alice", " alice", "alice "} {
		s := policyRealmServer(t, fakeRealm{name: "ldap:corp", subject: typed})
		seedAdmins(t, s)
		ctx := context.Background()
		if err := corrosion.InsertUser(ctx, s.db, "alice", "operator", ""); err != nil {
			t.Fatal(err)
		}
		writeLifecycle(t, s, "alice", corrosion.UserAttrDisabled, "true")
		_, err := s.Login(ctx, &pb.LoginRequest{Username: typed, Password: "dir-pw", Realm: "ldap:corp"})
		wantCode(t, "disabled alice logging in as "+typed, err, codes.Unauthenticated)
		rows, _ := s.db.Query(ctx, `SELECT username FROM users WHERE deleted_at IS NULL AND username != 'alice' AND username NOT IN ('admin','root2')`)
		if len(rows) != 0 {
			t.Fatalf("login as %q created a second account %q", typed, rows[0].String("username"))
		}
	}
}

// I2: two existing accounts that differ only in case are never merged
// silently: a lookup refuses with an error naming both.
func TestI2_CaseDuplicatesRefuseClearly(t *testing.T) {
	s := loginPolicyServer(t)
	seedUser(t, s, "bob", "viewer", "pw1")
	seedUser(t, s, "Bob", "admin", "pw2")
	_, err := s.Login(context.Background(), &pb.LoginRequest{Username: "bob", Password: "pw1"})
	if err == nil || !strings.Contains(err.Error(), "differ only in") {
		t.Fatalf("login with case-duplicate accounts: %v, want a refusal naming the duplicate", err)
	}
}

// I3: a delegated revoke can never take a principal to zero bindings: it
// leaves a NoAccess sentinel at the path in the same batch, so no sequence of
// delegated revokes on any nodes empties the principal.
func TestI3_DelegatedRevokeLeavesASentinel(t *testing.T) {
	s := delegationServer(t)
	if _, err := s.RevokeRole(patCtx(), &pb.RevokeRoleRequest{Id: "carol-view"}); err != nil {
		t.Fatalf("delegated revoke of carol's only binding: %v", err)
	}
	rows, err := corrosion.ListBindingsForPrincipal(context.Background(), s.db, "user:carol@local")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Role != "NoAccess" || rows[0].Path != "/projects/acme/vms/web" {
		t.Fatalf("carol's bindings after the revoke = %+v, want exactly a NoAccess sentinel at the path", rows)
	}
	if s.RequirePerm(userCtx("carol", "operator"), "/projects/other", "vm.start", "operator") == nil {
		t.Fatal("carol fell back to her cluster-wide legacy operator role")
	}
	// The sentinel is a cluster admin's to remove.
	_, err = s.RevokeRole(patCtx(), &pb.RevokeRoleRequest{Id: rows[0].ID})
	wantCode(t, "delegated revoke of the sentinel", err, codes.PermissionDenied)
}

// I4: DeleteUser counts only admins that can log in.
func TestI4_DeleteUserGuardIgnoresDisabledAdmins(t *testing.T) {
	s := loginPolicyServer(t)
	seedUser(t, s, "alice", "admin", "pw")
	seedUser(t, s, "bob", "admin", "pw")
	writeLifecycle(t, s, "bob", corrosion.UserAttrDisabled, "true")
	_, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "alice"})
	wantCode(t, "deleting the only usable admin", err, codes.FailedPrecondition)
}

// I4: the admin floor counts only usable admins, and never re-enables a
// disabled one: it brings back a deleted admin that can log in.
func TestI4_AdminFloorCountsUsableAdmins(t *testing.T) {
	s := loginPolicyServer(t)
	ctx := context.Background()
	seedUser(t, s, "alice", "admin", "pw")
	seedUser(t, s, "bob", "admin", "pw")
	if err := corrosion.DeleteUser(ctx, s.db, "alice"); err != nil {
		t.Fatal(err)
	}
	writeLifecycle(t, s, "bob", corrosion.UserAttrDisabled, "true")
	who, err := corrosion.ReinstateAdminIfNoneRemain(ctx, s.db, s.withLoginPolicyIfAvailable)
	if err != nil || who != "alice" {
		t.Fatalf("floor with only a disabled live admin: reinstated %q, %v; want alice", who, err)
	}
	if l, _ := corrosion.GetUserLifecycle(ctx, s.db, "bob"); !l.Disabled {
		t.Fatal("the floor re-enabled a disabled admin")
	}
}

// I7: an existing `*` binding does not gain delegation: perm.modify must be
// granted explicitly.
func TestI7_WildcardDoesNotDelegate(t *testing.T) {
	s := delegationServer(t)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "ada", "viewer", "x"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: "ada-admin", Path: "/projects/acme", Role: "Admin", Principal: "user:ada@local", Propagate: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.authEngine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	err := grant(s, userCtx("ada", "viewer"), "/projects/acme", "VMOperator", "user:bob@local", true)
	wantCode(t, "grant by an Admin-on-project binding without perm.modify", err, codes.PermissionDenied)
	if !strings.Contains(err.Error(), `role "admin" required`) {
		t.Errorf("refusal %q: want the plain admin-required refusal", err)
	}
}

// M36 (review m10): the decisive case for the perm.modify check — the caller
// holds the role's verbs at the path but not perm.modify there.
func TestDelegatedGrant_HoldsVerbsButNotPermModify(t *testing.T) {
	s := delegationServer(t)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "olaf", "viewer", "x"); err != nil {
		t.Fatal(err)
	}
	for _, b := range []corrosion.RoleBindingRecord{
		{ID: "olaf-op", Path: "/projects", Role: "Operator", Principal: "user:olaf@local", Propagate: true},
		{ID: "olaf-perm", Path: "/projects/acme", Role: "PermissionAdmin", Principal: "user:olaf@local", Propagate: true},
	} {
		if err := corrosion.InsertRoleBinding(ctx, s.db, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.authEngine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	err := grant(s, userCtx("olaf", "viewer"), "/projects/other", "VMOperator", "user:bob@local", true)
	wantCode(t, "grant where olaf holds the verbs but not perm.modify", err, codes.PermissionDenied)
	if !strings.Contains(err.Error(), "lacks perm.modify") {
		t.Errorf("refusal %q: want it to name the missing perm.modify", err)
	}
}

// I8: a node in WAL quarantine refuses user bearers, sessions and tokens
// alike, and still serves local-root and peer mTLS.
func TestI8_QuarantinedNodeRefusesUserBearers(t *testing.T) {
	s := loginPolicyServer(t)
	seedUser(t, s, "bob", "operator", "bob-pw")
	sess := login(t, s, "bob", "bob-pw").Token
	tok := mintAPIToken(t, s, "bob")
	s.db.SetWriteQuarantine(func() string { return "binary below latched token x_v1" })
	for name, tk := range map[string]string{"session": sess, "token": tok} {
		_, err := s.authenticate(bearerCtx(tk))
		wantCode(t, name+" on a quarantined node", err, codes.Unavailable)
	}
	_, err := s.Login(context.Background(), &pb.LoginRequest{Username: "bob", Password: "bob-pw"})
	wantCode(t, "login on a quarantined node", err, codes.Unavailable)
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "peer-1", Address: "10.0.0.9", State: "active"}); err == nil {
		t.Fatal("expected the quarantined node to refuse a replicated write")
	}
	if got, err := s.authenticate(mtlsPeerCtx("test-host", tcpAddr("127.0.0.1"), "")); err != nil || callerUsername(got) != "admin" {
		t.Fatalf("local-root on a quarantined node: %v", err)
	}
}

// m2: a session from before a disable stays dead after the re-enable, even
// one whose row reached this node after the disable's sweep had run.
func TestM2_SessionFromBeforeADisableStaysDeadAfterReEnable(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "bob-pw")
	before := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	setDisabled(t, s, "bob", true)
	// A session minted on another node before the disable, arriving now.
	if err := corrosion.InsertSession(context.Background(), s.db, corrosion.SessionRecord{
		ID: "late", Username: "bob", Realm: "local", CreatedAt: before, LastUsedAt: time.Now().UTC().Format(time.RFC3339),
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	setDisabled(t, s, "bob", false)
	_, err := s.authenticate(bearerCtx(SessionTokenPrefix + "late"))
	wantCode(t, "a pre-disable session after re-enable", err, codes.Unauthenticated)
}

// m3: deleting a disabled directory user does not re-enable them on their next
// directory login; only an explicit CreateUser starts a name afresh.
func TestM3_DeletedDisabledShadowStaysDisabled(t *testing.T) {
	s := policyRealmServer(t, fakeRealm{name: "ldap:corp", subject: "lena"})
	seedAdmins(t, s)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "lena", "viewer", ""); err != nil {
		t.Fatal(err)
	}
	setDisabled(t, s, "lena", true)
	if _, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "lena"}); err != nil {
		t.Fatal(err)
	}
	_, err := s.Login(ctx, &pb.LoginRequest{Username: "lena", Password: "x", Realm: "ldap:corp"})
	wantCode(t, "a deleted disabled directory user logging in again", err, codes.Unauthenticated)
}

// m10: the Login half of the unhydrated refusal, through a realm that does
// not refuse on its own (LocalRealm does).
func TestTwoFactorPolicy_UnhydratedLDAPLoginRefuses(t *testing.T) {
	s := policyRealmServer(t, fakeRealm{name: "ldap:corp", subject: "lena"})
	seedAdmins(t, s)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "lena", "viewer", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.EnrollTOTP(ctx, s.db, "lena", "phone"); err != nil {
		t.Fatal(err)
	}
	setPolicy(t, s, "all")
	s.db.MarkCredentialsUnhydrated()
	r, err := s.Login(ctx, &pb.LoginRequest{Username: "lena", Password: "x", Realm: "ldap:corp"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("LDAP login on an unhydrated node under the policy: %+v %v, want Unavailable", r, err)
	}
}

var _ = emptypb.Empty{}

func setPolicyFull(t *testing.T, s *Server, req *pb.SetLoginPolicyRequest) *pb.LoginPolicy {
	t.Helper()
	p, err := s.SetLoginPolicy(adminCtx(), req)
	if err != nil {
		t.Fatalf("SetLoginPolicy(%+v): %v", req, err)
	}
	return p
}
