package grpcapi

// Fix round 4 of the login rules (t1-auth-rereview-3.md: I1, m-1..m-9).

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// rawDelete tombstones username the way a build before the login rules did:
// the users row only. No session or token is revoked and no cut-off written
// (re-review 1, N2).
func rawDelete(t *testing.T, s *Server, username string) {
	t.Helper()
	if err := s.db.Execute(context.Background(), `UPDATE users SET deleted_at = ?, updated_at = ? WHERE username = ?`,
		time.Now().UTC().Format(time.RFC3339), s.db.NowTS(), username); err != nil {
		t.Fatal(err)
	}
}

func wantMessage(t *testing.T, what string, err error, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(status.Convert(err).Message(), p) {
			t.Errorf("%s: %q does not name %q", what, status.Convert(err).Message(), p)
		}
	}
}

// I1a: a case-duplicate admin pair is admins the floor counts: each is
// reachable by `lv user delete --exact`. The floor reinstates nothing, and the
// deliberately deleted admin stays deleted.
func TestI1a_AmbiguousAdminPairSatisfiesTheFloor(t *testing.T) {
	s := loginPolicyServer(t)
	ctx := context.Background()
	seedUser(t, s, "admin", "admin", "pw1")
	seedUser(t, s, "Admin", "admin", "pw2")
	seedUser(t, s, "oldops", "admin", "old-pw")
	rawDelete(t, s, "oldops")
	if ok, err := corrosion.UsableAdminExists(ctx, s.db); err != nil || !ok {
		t.Fatalf("UsableAdminExists with only a duplicate admin pair = %v, %v; want true", ok, err)
	}
	s.db.MarkReplicaCaughtUpForTests("peer")
	for i := 0; i < 2; i++ {
		if who, err := s.db.EnsureAdminFloor(ctx, 0); err != nil || who != "" {
			t.Fatalf("admin floor with a duplicate admin pair reinstated %q (%v)", who, err)
		}
	}
	if who, err := corrosion.ReinstateAdminIfNoneRemain(ctx, s.db); err != nil || who != "" {
		t.Fatalf("ReinstateAdminIfNoneRemain with a duplicate admin pair reinstated %q (%v)", who, err)
	}
	if u, _ := corrosion.GetUser(ctx, s.db, "oldops"); u != nil {
		t.Fatal("the deliberately deleted admin oldops is live again")
	}
}

// I1a: the floor never revives a deleted account's old password, sessions,
// API tokens or second factors — not for an admin deleted by this build, and
// not for one deleted by a build that revoked nothing. The reinstated account
// needs a fresh credential from root (`lv user reset-admin --user`).
func TestI1a_FloorNeverRevivesOldCredentials(t *testing.T) {
	for _, c := range []struct {
		name   string
		gate   bool
		delete func(t *testing.T, s *Server)
	}{
		{"pre-upgrade delete, gate closed", false, func(t *testing.T, s *Server) { rawDelete(t, s, "oldops") }},
		{"pre-upgrade delete, gate open", true, func(t *testing.T, s *Server) { rawDelete(t, s, "oldops") }},
		{"this build's delete", true, func(t *testing.T, s *Server) {
			if _, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "oldops"}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := loginPolicyServer(t)
			ctx := context.Background()
			seedUser(t, s, "alice", "admin", "alice-pw")
			seedUser(t, s, "oldops", "admin", "old-pw")
			tok := mintAPIToken(t, s, "oldops")
			sess := login(t, s, "oldops", "old-pw").Token
			if _, err := auth.EnrollTOTP(ctx, s.db, "oldops", "phone"); err != nil {
				t.Fatal(err)
			}
			c.delete(t, s)
			gate := c.gate
			s.db.SetLoginPolicyGate(func() bool { return gate })
			// The one live admin is disabled: no admin can log in.
			writeLifecycle(t, s, "alice", corrosion.UserAttrDisabled, "true")
			who, err := corrosion.ReinstateAdminIfNoneRemain(ctx, s.db)
			if err != nil || who != "oldops" {
				t.Fatalf("floor reinstated %q, %v; want oldops", who, err)
			}
			s.db.SetLoginPolicyGate(func() bool { return true })
			_, err = s.Login(ctx, &pb.LoginRequest{Username: "oldops", Password: "old-pw"})
			wantCode(t, "the reinstated account's old password", err, codes.Unauthenticated)
			_, err = s.authenticate(bearerCtx(tok))
			wantCode(t, "the reinstated account's old API token", err, codes.Unauthenticated)
			_, err = s.authenticate(bearerCtx(sess))
			wantCode(t, "the reinstated account's old session", err, codes.Unauthenticated)
			if f, _ := corrosion.ListUser2FA(ctx, s.db, "oldops"); len(f) != 0 {
				t.Errorf("the reinstated account kept %d old second factors", len(f))
			}
			// Root gives it a fresh credential, and that works at once.
			time.Sleep(10 * time.Millisecond)
			if err := corrosion.ResetAdminPasswordFor(ctx, s.db, "oldops", mustHash(t, "fresh-pw-0123456789"), false); err != nil {
				t.Fatalf("reset-admin --user oldops: %v", err)
			}
			_, err = s.Login(ctx, &pb.LoginRequest{Username: "oldops", Password: "fresh-pw-0123456789"})
			if status.Code(err) == codes.Unavailable {
				// A delete seconds ago keeps its later cut-off (m-5): the
				// login waits out the margin, as its message says.
				time.Sleep(corrosion.SessionCutoffSkewMargin + time.Second)
				_, err = s.Login(ctx, &pb.LoginRequest{Username: "oldops", Password: "fresh-pw-0123456789"})
			}
			if err != nil {
				t.Fatalf("login with the fresh credential: %v", err)
			}
			if _, err := s.Login(ctx, &pb.LoginRequest{Username: "admin", Password: "fresh-pw-0123456789"}); err == nil {
				t.Fatal("reset-admin --user oldops reset some other account")
			}
		})
	}
}

// I1b: the delete guard judges ambiguity as it will be after the delete, so a
// pair that are the only admins is resolved with `--exact --id`.
func TestI1b_ExactDeleteResolvesASoleAdminPair(t *testing.T) {
	s := loginPolicyServer(t)
	seedUser(t, s, "root2", "admin", "pw1")
	seedUser(t, s, "ROOT2", "admin", "pw2")
	v, err := s.ListUserVariants(adminCtx(), &pb.ListUserVariantsRequest{Username: "root2"})
	if err != nil {
		t.Fatal(err)
	}
	id := ""
	for _, x := range v.Variants {
		if x.Username == "ROOT2" {
			id = x.Id
		}
	}
	if _, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "ROOT2", Exact: true, ExactId: id}); err != nil {
		t.Fatalf("resolving a sole-admin duplicate pair with --exact --id: %v", err)
	}
	if u, _ := corrosion.GetUserExact(context.Background(), s.db, "root2"); u == nil {
		t.Fatal("the surviving spelling root2 is gone")
	}
}

// I1b: a last-admin refusal names actions a logged-in admin can take, with
// their arguments, including resolving a duplicate pair.
func TestI1b_LastAdminRefusalsAreActionable(t *testing.T) {
	s := loginPolicyServer(t)
	seedUser(t, s, "alice", "admin", "pw")
	seedUser(t, s, "root2", "admin", "pw")
	seedUser(t, s, "ROOT2", "admin", "pw")
	_, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "alice"})
	wantCode(t, "deleting the only unambiguous admin", err, codes.FailedPrecondition)
	wantMessage(t, "delete refusal", err, "lv user create <username> --role admin", "lv user delete --exact root2")
	yes := true
	_, err = s.SetUserAccount(adminCtx(), &pb.SetUserAccountRequest{Username: "alice", Disabled: &yes})
	wantCode(t, "disabling the only unambiguous admin", err, codes.FailedPrecondition)
	wantMessage(t, "disable refusal", err, "lv user create <username> --role admin", "lv user delete --exact root2")
}

// m-9: the id alone chooses the account; typing the other spelling with the
// right id deletes the account the id names.
func TestM9_ExactDeleteResolvesByID(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "viewer", "pw1")
	seedUser(t, s, "Bob", "operator", "pw2")
	v, err := s.ListUserVariants(adminCtx(), &pb.ListUserVariantsRequest{Username: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	id := ""
	for _, x := range v.Variants {
		if x.Username == "Bob" {
			id = x.Id
		}
	}
	if _, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "bob", Exact: true, ExactId: id}); err != nil {
		t.Fatalf("exact delete typed as the other spelling, with Bob's id: %v", err)
	}
	ctx := context.Background()
	if u, _ := corrosion.GetUserExact(ctx, s.db, "Bob"); u != nil {
		t.Fatal("Bob, whom the id names, is still live")
	}
	if u, _ := corrosion.GetUserExact(ctx, s.db, "bob"); u == nil {
		t.Fatal("bob, whom the id does not name, was deleted")
	}
}

// m-4: the binding refusals name the command with its arguments.
func TestM4_BindingRefusalsNameTheFullCommand(t *testing.T) {
	r := newIDRealm("ldap:corp", "alice", "entryUUID:u-1")
	s := policyRealmServer(t, r)
	seedAdmins(t, s)
	ctx := context.Background()
	if _, err := s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "pw", Realm: "ldap:corp"}); err != nil {
		t.Fatal(err)
	}
	r.id.Store("entryUUID:u-2")
	_, err := s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "pw", Realm: "ldap:corp"})
	wantCode(t, "a login through another entry", err, codes.PermissionDenied)
	wantMessage(t, "mismatch refusal", err, "lv user unbind alice ldap:corp")

	r.id.Store("entryUUID:u-1")
	reg := auth.NewRegistry()
	reg.Register(auth.NewLocalRealm(s.db))
	reg.Register(newIDRealm("ldap:corp", "x2", "entryUUID:u-1"))
	s.realmRegistry = reg
	_, err = s.Login(ctx, &pb.LoginRequest{Username: "x2", Password: "pw", Realm: "ldap:corp"})
	wantCode(t, "a second account for a bound entry", err, codes.PermissionDenied)
	wantMessage(t, "entry-bound refusal", err, "lv user unbind alice ldap:corp")
}

// m-4: one spelling of an ambiguous pair is unbound by its exact name.
func TestM4_UnbindOneSpellingOfAnAmbiguousPair(t *testing.T) {
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "Alice", "viewer", "pw1")
	seedUser(t, s, "alice", "viewer", "pw2")
	ctx := context.Background()
	if err := corrosion.BindIdentity(ctx, s.db, "Alice", "ldap:corp", "entryUUID:u-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClearIdentityBinding(adminCtx(), &pb.ClearIdentityBindingRequest{Username: "Alice", Realm: "ldap:corp"}); err != nil {
		t.Fatalf("unbind Alice of the pair: %v", err)
	}
	if id, _ := corrosion.GetIdentityBinding(ctx, s.db, "Alice", "ldap:corp"); id != "" {
		t.Fatalf("Alice is still bound to %q", id)
	}
}

// bindingRow writes a binding as a replica receives it from a node that bound
// the account while this one had not heard of the earlier binding.
func bindingRow(t *testing.T, s *Server, user, realm, id string, boundAt time.Time) {
	t.Helper()
	if err := s.db.Execute(context.Background(),
		`INSERT INTO user_identity_bindings (username, realm, external_id, bound_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, NULL)`,
		user, realm, id, boundAt.UTC().Format(time.RFC3339), s.db.NowTS()); err != nil {
		t.Fatalf("replicate a binding of %s to %s: %v", user, id, err)
	}
}

// m-1: a later binding from a lagging node never displaces the first; the
// conflict is audited.
func TestM1_FirstBinderWins(t *testing.T) {
	r := newIDRealm("ldap:corp", "alice", "entryUUID:u-1")
	s := policyRealmServer(t, r)
	seedAdmins(t, s)
	ctx := context.Background()
	loginAs := func() error {
		_, err := s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "pw", Realm: "ldap:corp"})
		return err
	}
	if err := loginAs(); err != nil {
		t.Fatal(err)
	}
	// A node that never received alice's binding let a recycled entry bind
	// her a minute later; its write is the newer one.
	bindingRow(t, s, "alice", "ldap:corp", "entryUUID:u-evil", time.Now().Add(time.Minute))
	if err := loginAs(); err != nil {
		t.Fatalf("the first binder after a later conflicting binding: %v", err)
	}
	r.id.Store("entryUUID:u-evil")
	wantCode(t, "the later binder", loginAs(), codes.PermissionDenied)
	rows, _ := s.db.Query(ctx, `SELECT 1 FROM audit_log WHERE action = 'auth.identity_conflict' AND target = 'alice'
		AND detail LIKE '%resolved: first binding%'`)
	if len(rows) == 0 {
		t.Error("the binding conflict was not audited")
	}
}

// m-1: two bindings too close together to order by clocks are a conflict no
// one wins: logins refuse until an admin unbinds.
func TestM1_ConcurrentBindingsRefuseUntilUnbound(t *testing.T) {
	r := newIDRealm("ldap:corp", "bob", "entryUUID:b-1")
	s := policyRealmServer(t, r)
	seedAdmins(t, s)
	ctx := context.Background()
	now := time.Now()
	bindingRow(t, s, "bob", "ldap:corp", "entryUUID:b-1", now)
	bindingRow(t, s, "bob", "ldap:corp", "entryUUID:b-2", now.Add(time.Second))
	_, err := s.Login(ctx, &pb.LoginRequest{Username: "bob", Password: "pw", Realm: "ldap:corp"})
	wantCode(t, "a login while two bindings are unordered", err, codes.PermissionDenied)
	wantMessage(t, "conflict refusal", err, "lv user unbind bob ldap:corp")
	if _, err := s.ClearIdentityBinding(adminCtx(), &pb.ClearIdentityBindingRequest{Username: "bob", Realm: "ldap:corp"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, &pb.LoginRequest{Username: "bob", Password: "pw", Realm: "ldap:corp"}); err != nil {
		t.Fatalf("login after the conflict was unbound: %v", err)
	}
}

// m-1: one entry bound to two accounts by two nodes: the first binding owns
// the entry, and its account still logs in.
func TestM1_EntryBoundToTwoAccountsFirstOwns(t *testing.T) {
	r := newIDRealm("ldap:corp", "alice", "entryUUID:u-1")
	s := policyRealmServer(t, r)
	seedAdmins(t, s)
	ctx := context.Background()
	now := time.Now()
	bindingRow(t, s, "alice", "ldap:corp", "entryUUID:u-1", now.Add(-time.Hour))
	bindingRow(t, s, "x2", "ldap:corp", "entryUUID:u-1", now)
	if _, err := s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "pw", Realm: "ldap:corp"}); err != nil {
		t.Fatalf("the entry's first account: %v", err)
	}
	reg := auth.NewRegistry()
	reg.Register(auth.NewLocalRealm(s.db))
	reg.Register(newIDRealm("ldap:corp", "x2", "entryUUID:u-1"))
	s.realmRegistry = reg
	_, err := s.Login(ctx, &pb.LoginRequest{Username: "x2", Password: "pw", Realm: "ldap:corp"})
	wantCode(t, "the entry's later account", err, codes.PermissionDenied)
}

// altIDRealm is an LDAP-like realm whose entry carries several immutable ids.
type altIDRealm struct {
	name, subject, id string
	all               []string
}

func (r altIDRealm) Name() string { return r.name }
func (r altIDRealm) Authenticate(_ context.Context, c auth.Credentials) (*auth.Principal, error) {
	if c.Password == "" {
		return nil, auth.ErrInvalidCredentials
	}
	return &auth.Principal{Subject: r.subject, Realm: r.name, ExternalID: r.id, ExternalIDs: r.all}, nil
}
func (altIDRealm) SyncGroups(context.Context) error { return nil }

// m-3: a directory that starts returning a stronger id (389 DS enabling
// entryUUID) does not lock out an account bound by the id it returned before;
// a DN never stands in for an immutable id.
func TestM3_AnyImmutableIDOfTheEntryMatches(t *testing.T) {
	ctx := context.Background()
	r := altIDRealm{name: "ldap:corp", subject: "alice", id: "entryUUID:u-1",
		all: []string{"entryUUID:u-1", "nsUniqueId:n-1", "dn:uid=alice,ou=users,dc=corp,dc=example"}}
	s := policyRealmServer(t, r)
	seedAdmins(t, s)
	bindingRow(t, s, "alice", "ldap:corp", "nsUniqueId:n-1", time.Now().Add(-time.Hour))
	if _, err := s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "pw", Realm: "ldap:corp"}); err != nil {
		t.Fatalf("an account bound by nsUniqueId, its entry now led by entryUUID: %v", err)
	}
	// A re-created entry at the same DN: a new entryUUID; only the DN agrees.
	r2 := altIDRealm{name: "ldap:corp", subject: "carol", id: "entryUUID:c-2",
		all: []string{"entryUUID:c-2", "dn:uid=carol,ou=users,dc=corp,dc=example"}}
	s2 := policyRealmServer(t, r2)
	seedAdmins(t, s2)
	bindingRow(t, s2, "carol", "ldap:corp", "entryUUID:c-1", time.Now().Add(-time.Hour))
	_, err := s2.Login(ctx, &pb.LoginRequest{Username: "carol", Password: "pw", Realm: "ldap:corp"})
	wantCode(t, "a re-created entry at the same DN", err, codes.PermissionDenied)
}

// m-5: a lifecycle cut-off never moves backwards — not by reset-admin, not by
// an enable or disable from a node whose clock is behind.
func TestM5_CutoffNeverMovesBackwards(t *testing.T) {
	s := loginPolicyServer(t)
	ctx := context.Background()
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "pw")
	ahead := time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339)
	for _, u := range []string{"admin", "bob"} {
		writeLifecycle(t, s, u, corrosion.UserAttrSessionsNotBefore, ahead)
	}
	writeLifecycle(t, s, "admin", corrosion.UserAttrDisabled, "true")
	if err := corrosion.ResetAdminPassword(ctx, s.db, mustHash(t, "fresh-pw-0123456789"), false); err != nil {
		t.Fatal(err)
	}
	setDisabled(t, s, "bob", true)
	for _, u := range []string{"admin", "bob"} {
		l, err := corrosion.GetUserLifecycle(ctx, s.db, u)
		if err != nil || l.SessionsNotBefore < ahead {
			t.Errorf("%s: sessions_not_before moved back from %s to %s (%v)", u, ahead, l.SessionsNotBefore, err)
		}
	}
}

// m-6: TokenPredates has the sessions' skew margin; a token is never minted
// inside it (CreateToken asks the caller to retry), so none is born dead.
func TestM6_TokenCutoffHasASkewMargin(t *testing.T) {
	nb := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	l := corrosion.UserLifecycle{TokensNotBefore: nb.Format(time.RFC3339)}
	if !l.TokenPredates(nb.Add(2 * time.Second).Format(time.RFC3339)) {
		t.Error("a token stamped 2 s after the cut-off by a fast clock passes it")
	}
	if l.TokenPredates(nb.Add(corrosion.SessionCutoffSkewMargin + time.Second).Format(time.RFC3339)) {
		t.Error("a token stamped well after the cut-off is refused")
	}
	s := loginPolicyServer(t)
	seedAdmins(t, s)
	seedUser(t, s, "bob", "operator", "pw")
	if _, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "bob"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := s.CreateUser(adminCtx(), &pb.CreateUserRequest{Username: "bob", Password: "pw2"}); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateToken(adminCtx(), &pb.CreateTokenRequest{Username: "bob", Name: "early"})
	wantCode(t, "a token minted inside the margin after a re-create", err, codes.Unavailable)
	time.Sleep(corrosion.SessionCutoffSkewMargin + time.Second)
	if _, err := s.authenticate(bearerCtx(mintAPIToken(t, s, "bob"))); err != nil {
		t.Fatalf("a token made after the margin: %v", err)
	}
}

// I1a (coordinator addition): an external (LDAP/OIDC) admin the floor
// reinstates stays external — no local password, its directory login works,
// its identity binding is kept — while its old API token stays cut off.
func TestI1a_FloorKeepsAnExternalAdminExternal(t *testing.T) {
	for _, c := range []struct {
		name   string
		delete func(t *testing.T, s *Server)
	}{
		{"this build's delete", func(t *testing.T, s *Server) {
			if _, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "ext"}); err != nil {
				t.Fatal(err)
			}
		}},
		{"pre-upgrade delete", func(t *testing.T, s *Server) { rawDelete(t, s, "ext") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newIDRealm("ldap:corp", "ext", "entryUUID:e-1")
			s := policyRealmServer(t, r)
			ctx := context.Background()
			seedUser(t, s, "alice", "admin", "alice-pw")
			extLogin := func() error {
				_, err := s.Login(ctx, &pb.LoginRequest{Username: "ext", Password: "pw", Realm: "ldap:corp"})
				return err
			}
			if err := extLogin(); err != nil {
				t.Fatal(err)
			}
			if err := s.db.Execute(ctx, `UPDATE users SET role = 'admin', updated_at = ? WHERE username = 'ext'`, s.db.NowTS()); err != nil {
				t.Fatal(err)
			}
			tok := mintAPIToken(t, s, "ext")
			c.delete(t, s)
			writeLifecycle(t, s, "alice", corrosion.UserAttrDisabled, "true")
			if who, err := corrosion.ReinstateAdminIfNoneRemain(ctx, s.db); err != nil || who != "ext" {
				t.Fatalf("floor reinstated %q, %v; want ext", who, err)
			}
			if u, _ := corrosion.GetUser(ctx, s.db, "ext"); u == nil || u.PasswordHash != "" {
				t.Fatalf("the reinstated external admin is %+v; want it external, with no local password", u)
			}
			_, err := s.authenticate(bearerCtx(tok))
			wantCode(t, "the external admin's old API token", err, codes.Unauthenticated)
			// Before its own entry logs in again: the binding came back with
			// the account, so another entry answering to "ext" is refused.
			r.id.Store("entryUUID:e-2")
			wantCode(t, "another entry after the reinstatement (binding kept)", extLogin(), codes.PermissionDenied)
			r.id.Store("entryUUID:e-1")
			err = extLogin()
			if status.Code(err) == codes.Unavailable {
				time.Sleep(corrosion.SessionCutoffSkewMargin + time.Second)
				err = extLogin()
			}
			if err != nil {
				t.Fatalf("the reinstated external admin's directory login: %v", err)
			}
			if rep, _ := corrosion.AdminLoginState(ctx, s.db); !rep.Loggable {
				t.Errorf("the reinstated external admin does not count as able to log in: %+v", rep)
			}
		})
	}
}

// I1a: the reset-admin RPC resets the account --user names, and says which.
func TestI1a_ResetAdminRPCResetsTheNamedAdmin(t *testing.T) {
	s := resetAdminFixture(t)
	seedUser(t, s, "oldops", "admin", "old-pw")
	ctx, err := authedCtx(t, s, "test-host", tcpAddr("127.0.0.1"), "")
	if err != nil {
		t.Fatal(err)
	}
	hash := mustHash(t, "0123456789abcdef-the-new-secret")
	resp, err := s.ResetAdminPassword(ctx, &pb.ResetAdminPasswordRequest{PasswordHash: hash, Username: "oldops"})
	if err != nil || resp.GetUsername() != "oldops" {
		t.Fatalf("ResetAdminPassword --user oldops: %+v %v", resp, err)
	}
	if u, _ := corrosion.GetUser(context.Background(), s.db, "oldops"); u == nil || u.PasswordHash != hash {
		t.Fatalf("oldops was not reset: %+v", u)
	}
	if u, _ := corrosion.GetUser(context.Background(), s.db, "admin"); u != nil && u.PasswordHash == hash {
		t.Fatal("--user oldops reset admin")
	}
}
