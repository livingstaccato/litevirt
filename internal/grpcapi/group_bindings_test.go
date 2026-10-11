package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/auth/oidctest"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// groupServer is oidcServer with the permission engine wired and olga signed
// in at the IdP as a member of groups.
func groupServer(t *testing.T, groups ...string) (*Server, *oidctest.Provider) {
	t.Helper()
	s, idp := oidcServer(t)
	if err := auth.SeedBuiltinRoles(context.Background(), s.db); err != nil {
		t.Fatal(err)
	}
	e := auth.NewEngine(s.db)
	if err := e.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.SetAuthEngine(e)
	idp.SignIn(&oidctest.User{Subject: "sub-olga", PreferredUsername: "olga", Groups: groups})
	return s, idp
}

func grantGroup(t *testing.T, s *Server, role, principal, path string) string {
	t.Helper()
	r, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{Role: role, Principal: principal, Path: path, Propagate: true})
	if err != nil {
		t.Fatalf("GrantRole %s %s %s: %v", role, principal, path, err)
	}
	return r.Binding.Id
}

// oidcSession runs a full OIDC login and returns the authenticated context of
// its session, as the interceptor builds it.
func oidcSession(t *testing.T, s *Server, idp *oidctest.Provider) (string, context.Context) {
	t.Helper()
	code, state, binding := oidcCallback(t, s, idp)
	r, err := s.Login(context.Background(), &pb.LoginRequest{Realm: "oidc:corp", OidcCode: code, OidcState: state, OidcBinding: binding})
	if err != nil || r.Token == "" {
		t.Fatalf("OIDC login: %+v %v", r, err)
	}
	ctx, err := s.authenticate(bearerCtx(r.Token))
	if err != nil {
		t.Fatalf("authenticate the session: %v", err)
	}
	return r.Token, ctx
}

func TestPrincipalsForCaller_GroupsOnlyForExternalRealms(t *testing.T) {
	got := principalsForCaller("olga", "viewer", "oidc:corp", "ops", "", "ops")
	want := []string{"user:olga@oidc:corp", "group:viewer@oidc:corp", "group:oidc:corp/ops"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("principals %v, want %v", got, want)
	}
	// A directory group and a legacy role of one name are different
	// principals (review I1), and so are same-named groups of two realms
	// (review M7).
	if g := principalsForCaller("olga", "viewer", "oidc:corp", "admin"); slices.Contains(g, "group:admin@oidc:corp") {
		t.Fatalf("an IdP group named admin became the legacy admins' principal: %v", g)
	}
	if a, b := principalsForCaller("o", "", "ldap:corp", "ops"), principalsForCaller("o", "", "oidc:corp", "ops"); a[1] == b[1] {
		t.Fatalf("group ops of two realms is one principal: %v %v", a, b)
	}
	// A realm whose name contains '/' could spell another realm's group
	// principal (oidc:corp's "contractors/x" = oidc:corp/contractors's "x"):
	// its groups are ignored (re-review m1).
	if g := principalsForCaller("o", "", "oidc:corp/contractors", "x"); len(g) != 1 {
		t.Fatalf("a realm named with '/' took directory groups: %v", g)
	}
	if got := principalsForCaller("bob", "admin", "local", "ops"); len(got) != 2 {
		t.Fatalf("a local session took directory groups: %v", got)
	}
}

// TestGroupBinding_GrantsThroughTheVerifiedGroup: a binding on the IdP group
// grants its role to a session whose verified groups claim names it, at the
// binding's path only; the login audits which binding granted what.
func TestGroupBinding_GrantsThroughTheVerifiedGroup(t *testing.T) {
	s, idp := groupServer(t, "lv-operators")
	id := grantGroup(t, s, "Operator", "group:oidc:corp/lv-operators", "/projects/acme")
	_, ctx := oidcSession(t, s, idp)
	if g := callerGroups(ctx); len(g) != 1 || g[0] != "lv-operators" {
		t.Fatalf("session groups %v", g)
	}
	if err := s.RequirePerm(ctx, "/projects/acme/vms/x", "vm.start", "admin"); err != nil {
		t.Fatalf("the group's Operator binding did not apply: %v", err)
	}
	wantCode(t, "outside the binding's path", s.RequirePerm(ctx, "/projects/other/vms/x", "vm.start", "admin"), codes.PermissionDenied)

	row := lastAuditRow(t, s, "auth.group_bindings")
	if !row.found || row.result != "ok" || row.target != "olga" ||
		!strings.Contains(row.detail, "group:oidc:corp/lv-operators grants Operator at /projects/acme") ||
		!strings.Contains(row.detail, id) {
		t.Fatalf("group binding audit %+v, want the group, role, path and binding id %s", row, id)
	}
}

// TestGroupBinding_UnionWithUserBindings: user and group bindings both apply.
func TestGroupBinding_UnionWithUserBindings(t *testing.T) {
	s, idp := groupServer(t, "lv-operators", "lv-auditors")
	grantGroup(t, s, "Viewer", "user:olga@oidc:corp", "/")
	grantGroup(t, s, "Operator", "group:oidc:corp/lv-operators", "/projects/acme")
	_, ctx := oidcSession(t, s, idp)
	if err := s.RequirePerm(ctx, "/projects/other", "vm.read", "admin"); err != nil {
		t.Fatalf("the user's own Viewer binding: %v", err)
	}
	if err := s.RequirePerm(ctx, "/projects/acme/vms/x", "vm.start", "admin"); err != nil {
		t.Fatalf("the group's Operator binding: %v", err)
	}
	row := lastAuditRow(t, s, "auth.group_bindings")
	if !strings.Contains(row.detail, "groups=2") || !strings.Contains(row.detail, "1 groups hold no binding") ||
		strings.Contains(row.detail, "lv-auditors") {
		t.Fatalf("audit %q: want the count, the granting group in full and the rest as a count and hash", row.detail)
	}
}

// TestGroupBinding_ARemovedGroupStopsAtTheNextLogin: groups are the session's
// snapshot. When the IdP drops the user from the group, the next login's
// session no longer holds the grant; the earlier session keeps its snapshot
// until it ends (documented), and ending it ends the grant.
func TestGroupBinding_ARemovedGroupStopsAtTheNextLogin(t *testing.T) {
	s, idp := groupServer(t, "lv-operators")
	grantGroup(t, s, "Operator", "group:oidc:corp/lv-operators", "/projects/acme")
	oldTok, oldCtx := oidcSession(t, s, idp)

	idp.SignIn(&oidctest.User{Subject: "sub-olga", PreferredUsername: "olga", Groups: []string{"lv-viewers"}})
	_, newCtx := oidcSession(t, s, idp)
	wantCode(t, "a session minted after the group was removed", s.RequirePerm(newCtx, "/projects/acme/vms/x", "vm.start", "admin"), codes.PermissionDenied)
	if err := s.RequirePerm(oldCtx, "/projects/acme/vms/x", "vm.start", "admin"); err != nil {
		t.Fatalf("the earlier session's snapshot: %v", err)
	}
	if _, err := s.RevokeSession(adminCtx(), &pb.RevokeSessionRequest{Id: strings.TrimPrefix(oldTok, SessionTokenPrefix)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.authenticate(bearerCtx(oldTok)); err == nil {
		t.Fatal("a revoked session still authenticates")
	}
}

// TestGroupBinding_NotRecordedWithoutTheReleaseFeature: before login_policy
// opens, a login records no groups (as before the release): no group grant,
// and the audit says why.
func TestGroupBinding_NotRecordedWithoutTheReleaseFeature(t *testing.T) {
	s, idp := groupServer(t, "lv-operators")
	grantGroup(t, s, "Operator", "group:oidc:corp/lv-operators", "/projects/acme")
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: false})
	_, ctx := oidcSession(t, s, idp)
	if g := callerGroups(ctx); len(g) != 0 {
		t.Fatalf("groups %v recorded without the feature", g)
	}
	wantCode(t, "a group grant without the feature", s.RequirePerm(ctx, "/projects/acme/vms/x", "vm.start", "admin"), codes.PermissionDenied)
	if row := lastAuditRow(t, s, "auth.group_bindings"); row.result != "skipped" || !strings.Contains(row.detail, "not recorded") {
		t.Fatalf("audit %+v, want a skipped row saying the groups were not recorded", row)
	}
}

// TestGroupBinding_UnreadableGroupsRefuse: a session whose groups cannot be
// read is refused rather than authorized without them (dropping a group can
// widen a caller back to its legacy role).
func TestGroupBinding_UnreadableGroupsRefuse(t *testing.T) {
	s, idp := groupServer(t, "lv-operators")
	tok, _ := oidcSession(t, s, idp)
	if err := s.db.Execute(context.Background(), `UPDATE session_groups SET groups_json = 'not json' WHERE session_id = ?`,
		strings.TrimPrefix(tok, SessionTokenPrefix)); err != nil {
		t.Fatal(err)
	}
	_, err := s.authenticate(bearerCtx(tok))
	wantCode(t, "unreadable session groups", err, codes.Unavailable)
}

// TestGroupBinding_CallerSeesTheirGroupBindings: a non-admin lists the
// bindings that apply to them through a group, and may filter to one of
// their groups, but not to someone else's.
func TestGroupBinding_CallerSeesTheirGroupBindings(t *testing.T) {
	s, idp := groupServer(t, "lv-operators")
	id := grantGroup(t, s, "Operator", "group:oidc:corp/lv-operators", "/projects/acme")
	grantGroup(t, s, "Admin", "group:oidc:corp/lv-admins", "/")
	_, ctx := oidcSession(t, s, idp)
	r, err := s.ListRoleBindings(ctx, &pb.ListRoleBindingsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Bindings) != 1 || r.Bindings[0].Id != id {
		t.Fatalf("bindings %v, want only the caller's group binding %s", r.Bindings, id)
	}
	if _, err := s.ListRoleBindings(ctx, &pb.ListRoleBindingsRequest{Principal: "group:oidc:corp/lv-operators"}); err != nil {
		t.Fatalf("filter to the caller's own group: %v", err)
	}
	_, err = s.ListRoleBindings(ctx, &pb.ListRoleBindingsRequest{Principal: "group:oidc:corp/lv-admins"})
	wantCode(t, "filter to a group the caller is not in", err, codes.PermissionDenied)
}

func TestSessionGroups_LocalLoginsCarryNone(t *testing.T) {
	s, _ := groupServer(t)
	seedUser(t, s, "bob", "viewer", "bob-pw")
	r := login(t, s, "bob", "bob-pw")
	if rows, _ := s.db.Query(context.Background(), `SELECT session_id FROM session_groups`); len(rows) != 0 {
		t.Fatalf("a local login recorded groups: %v", rows)
	}
	ctx, err := s.authenticate(bearerCtx(r.Token))
	if err != nil || len(callerGroups(ctx)) != 0 {
		t.Fatalf("local session groups %v %v", callerGroups(ctx), err)
	}
	_ = corrosion.MaxSessionGroups
}

// TestGroupBinding_AForwardedSessionKeepsItsGroups: a session relayed by a
// peer (forwarded identity) is authorized with the same groups on the owner.
func TestGroupBinding_AForwardedSessionKeepsItsGroups(t *testing.T) {
	s, idp := groupServer(t, "lv-operators")
	grantGroup(t, s, "Operator", "group:oidc:corp/lv-operators", "/projects/acme")
	s.SetForwardedIdentity(true)
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "peer-1", Address: "10.0.0.9", State: "active"}); err != nil {
		t.Fatal(err)
	}
	tok, _ := oidcSession(t, s, idp)
	fctx, err := s.authenticate(withFwdBearer(mtlsPeerCtx("peer-1", tcpAddr("10.0.0.9"), ""), "Bearer "+tok))
	if err != nil {
		t.Fatalf("forwarded session: %v", err)
	}
	if g := callerGroups(fctx); len(g) != 1 || g[0] != "lv-operators" {
		t.Fatalf("forwarded session groups %v", g)
	}
	if err := s.RequirePerm(fctx, "/projects/acme/vms/x", "vm.start", "admin"); err != nil {
		t.Fatalf("the group binding through a forwarded session: %v", err)
	}
}

// TestGroupBinding_AnIdPGroupNamedLikeALegacyRoleGainsNothing (review I1): a
// user who creates and joins an IdP group "admin" does not take on a binding
// made for the realm's legacy admins (group:admin@<realm>).
func TestGroupBinding_AnIdPGroupNamedLikeALegacyRoleGainsNothing(t *testing.T) {
	s, idp := groupServer(t, "admin")
	grantGroup(t, s, "Admin", "group:admin@oidc:corp", "/")
	_, ctx := oidcSession(t, s, idp)
	wantCode(t, "an IdP group named admin", s.RequirePerm(ctx, "/projects/acme/vms/x", "vm.start", "admin"), codes.PermissionDenied)
}

// TestGroupBinding_LDAPGroupsAreKeyedByDN (review I2, M7): an LDAP login's
// groups are full DNs; a binding on the managed group's DN applies, and a
// same-named group in another OU is a different principal.
func TestGroupBinding_LDAPGroupsAreKeyedByDN(t *testing.T) {
	s, _ := groupServer(t)
	managed := "cn=lv-operators,ou=groups,dc=corp,dc=example"
	ldap := groupRealm{name: "ldap:corp", subject: "lena"}
	s.realmRegistry.Register(&ldap)
	grantGroup(t, s, "Operator", "group:ldap:corp/"+managed, "/projects/acme")
	login := func(groups ...string) context.Context {
		ldap.groups = groups
		r, err := s.Login(context.Background(), &pb.LoginRequest{Realm: "ldap:corp", Username: "lena", Password: "pw"})
		if err != nil || r.Token == "" {
			t.Fatalf("LDAP login: %+v %v", r, err)
		}
		ctx, err := s.authenticate(bearerCtx(r.Token))
		if err != nil {
			t.Fatal(err)
		}
		return ctx
	}
	if err := s.RequirePerm(login(managed), "/projects/acme/vms/x", "vm.start", "admin"); err != nil {
		t.Fatalf("the managed group's binding: %v", err)
	}
	wantCode(t, "a same-named group in another OU",
		s.RequirePerm(login("cn=lv-operators,ou=helpdesk,dc=corp,dc=example"), "/projects/acme/vms/x", "vm.start", "admin"),
		codes.PermissionDenied)
}

// groupRealm authenticates any password as subject with the given groups.
type groupRealm struct {
	name, subject string
	groups        []string
}

func (g *groupRealm) Name() string { return g.name }
func (g *groupRealm) Authenticate(_ context.Context, c auth.Credentials) (*auth.Principal, error) {
	if c.Password == "" {
		return nil, auth.ErrInvalidCredentials
	}
	return &auth.Principal{Subject: g.subject, Realm: g.name, Groups: g.groups}, nil
}
func (*groupRealm) SyncGroups(context.Context) error { return nil }

// TestGroupBinding_NeverMintedWithoutItsGroupsOnceOpen (review M1): once
// login_policy is open on this node, a login whose groups cannot be recorded
// (the gate does not pass for this write) is refused rather than minted
// without them, since such a session falls back to its legacy role.
func TestGroupBinding_NeverMintedWithoutItsGroupsOnceOpen(t *testing.T) {
	s, idp := groupServer(t, "lv-operators")
	if err := corrosion.RecordReleaseFeatureUse(context.Background(), s.db, capabilities.ReleaseToken,
		string(capabilities.FeatureLoginPolicy), "node-a", true); err != nil {
		t.Fatal(err)
	}
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, err: errors.New("gate refused")})
	code, state, binding := oidcCallback(t, s, idp)
	r, err := s.Login(context.Background(), &pb.LoginRequest{Realm: "oidc:corp", OidcCode: code, OidcState: state, OidcBinding: binding})
	wantCode(t, "a login whose groups cannot be recorded", err, codes.Unavailable)
	if r != nil && r.Token != "" {
		t.Fatal("a session was minted without its groups")
	}
	if rows, _ := s.db.Query(context.Background(), `SELECT id FROM sessions WHERE username = 'olga'`); len(rows) != 0 {
		t.Fatalf("session rows %v", rows)
	}
}

// TestSessionGroups_RealmMismatchRefuses (review M2): a groups row for another
// realm than its session's is an error, and the request is refused.
func TestSessionGroups_RealmMismatchRefuses(t *testing.T) {
	s, idp := groupServer(t, "lv-operators")
	tok, _ := oidcSession(t, s, idp)
	if err := s.db.Execute(context.Background(), `UPDATE session_groups SET realm = 'oidc:other' WHERE session_id = ?`,
		strings.TrimPrefix(tok, SessionTokenPrefix)); err != nil {
		t.Fatal(err)
	}
	_, err := s.authenticate(bearerCtx(tok))
	wantCode(t, "groups recorded for another realm", err, codes.Unavailable)
}

// TestGroupBinding_AuditDetailIsBounded (review M4): one login's audit row
// stays small however many groups the IdP sends; the groups that hold no
// binding are a count and a hash.
func TestGroupBinding_AuditDetailIsBounded(t *testing.T) {
	var many []string
	for i := 0; i < corrosion.MaxSessionGroups; i++ {
		many = append(many, fmt.Sprintf("%0200d", i))
	}
	s, idp := groupServer(t, many...)
	for i := 0; i < 40; i++ {
		grantGroup(t, s, "Viewer", "group:oidc:corp/"+many[i], "/projects/p")
	}
	oidcSession(t, s, idp)
	row := lastAuditRow(t, s, "auth.group_bindings")
	if !row.found || len(row.detail) > maxGroupAuditDetail || !strings.Contains(row.detail, fmt.Sprintf("groups=%d", corrosion.MaxSessionGroups)) {
		t.Fatalf("audit detail of %d bytes (cap %d): %.200s", len(row.detail), maxGroupAuditDetail, row.detail)
	}
}

// TestGrantRole_LDAPGroupDNIsCanonicalized (re-review m3): an LDAP group
// binding names the DN as sessions carry it, whatever case and spacing the
// operator typed; a value that is not a DN is refused rather than stored as a
// binding that matches nothing.
func TestGrantRole_LDAPGroupDNIsCanonicalized(t *testing.T) {
	s, _ := groupServer(t)
	r, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{Role: "Viewer", Path: "/",
		Principal: "group:ldap:corp/CN=Ops, OU=Groups,DC=Corp,DC=Example"})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Binding.Principal; got != "group:ldap:corp/cn=ops,ou=groups,dc=corp,dc=example" {
		t.Fatalf("stored principal %q", got)
	}
	_, err = s.GrantRole(adminCtx(), &pb.GrantRoleRequest{Role: "Viewer", Path: "/", Principal: "group:ldap:corp/lv-admins"})
	wantCode(t, "an LDAP group named by a bare cn", err, codes.InvalidArgument)
}

// TestGroupBinding_UnreadableFeatureStateFailsClosed (re-review m6): when
// whether login_policy is open cannot be read and the gate does not pass, a
// login with groups is refused, not minted without them.
func TestGroupBinding_UnreadableFeatureStateFailsClosed(t *testing.T) {
	s, idp := groupServer(t, "lv-operators")
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, err: errors.New("gate refused")})
	s.loginPolicyStateRead = func(context.Context) (bool, error) { return false, errors.New("replica read failed") }
	code, state, binding := oidcCallback(t, s, idp)
	_, err := s.Login(context.Background(), &pb.LoginRequest{Realm: "oidc:corp", OidcCode: code, OidcState: state, OidcBinding: binding})
	wantCode(t, "a login whose feature state is unreadable", err, codes.Unavailable)
}
