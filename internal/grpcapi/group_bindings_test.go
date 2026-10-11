package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/auth/oidctest"
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
	code, state := oidcCallback(t, s, idp)
	r, err := s.Login(context.Background(), &pb.LoginRequest{Realm: "oidc:corp", OidcCode: code, OidcState: state})
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
	want := []string{"user:olga@oidc:corp", "group:viewer@oidc:corp", "group:ops@oidc:corp"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("principals %v, want %v", got, want)
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
	id := grantGroup(t, s, "Operator", "group:lv-operators@oidc:corp", "/projects/acme")
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
		!strings.Contains(row.detail, "group:lv-operators@oidc:corp grants Operator at /projects/acme") ||
		!strings.Contains(row.detail, id) {
		t.Fatalf("group binding audit %+v, want the group, role, path and binding id %s", row, id)
	}
}

// TestGroupBinding_UnionWithUserBindings: user and group bindings both apply.
func TestGroupBinding_UnionWithUserBindings(t *testing.T) {
	s, idp := groupServer(t, "lv-operators", "lv-auditors")
	grantGroup(t, s, "Viewer", "user:olga@oidc:corp", "/")
	grantGroup(t, s, "Operator", "group:lv-operators@oidc:corp", "/projects/acme")
	_, ctx := oidcSession(t, s, idp)
	if err := s.RequirePerm(ctx, "/projects/other", "vm.read", "admin"); err != nil {
		t.Fatalf("the user's own Viewer binding: %v", err)
	}
	if err := s.RequirePerm(ctx, "/projects/acme/vms/x", "vm.start", "admin"); err != nil {
		t.Fatalf("the group's Operator binding: %v", err)
	}
	row := lastAuditRow(t, s, "auth.group_bindings")
	if !strings.Contains(row.detail, "lv-auditors") {
		t.Fatalf("audit %q does not name every verified group", row.detail)
	}
}

// TestGroupBinding_ARemovedGroupStopsAtTheNextLogin: groups are the session's
// snapshot. When the IdP drops the user from the group, the next login's
// session no longer holds the grant; the earlier session keeps its snapshot
// until it ends (documented), and ending it ends the grant.
func TestGroupBinding_ARemovedGroupStopsAtTheNextLogin(t *testing.T) {
	s, idp := groupServer(t, "lv-operators")
	grantGroup(t, s, "Operator", "group:lv-operators@oidc:corp", "/projects/acme")
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
	grantGroup(t, s, "Operator", "group:lv-operators@oidc:corp", "/projects/acme")
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
	id := grantGroup(t, s, "Operator", "group:lv-operators@oidc:corp", "/projects/acme")
	grantGroup(t, s, "Admin", "group:lv-admins@oidc:corp", "/")
	_, ctx := oidcSession(t, s, idp)
	r, err := s.ListRoleBindings(ctx, &pb.ListRoleBindingsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Bindings) != 1 || r.Bindings[0].Id != id {
		t.Fatalf("bindings %v, want only the caller's group binding %s", r.Bindings, id)
	}
	if _, err := s.ListRoleBindings(ctx, &pb.ListRoleBindingsRequest{Principal: "group:lv-operators@oidc:corp"}); err != nil {
		t.Fatalf("filter to the caller's own group: %v", err)
	}
	_, err = s.ListRoleBindings(ctx, &pb.ListRoleBindingsRequest{Principal: "group:lv-admins@oidc:corp"})
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
	grantGroup(t, s, "Operator", "group:lv-operators@oidc:corp", "/projects/acme")
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
