package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func latchedProjectClient(t *testing.T) *Client {
	t.Helper()
	c := newProjectTestClient(t)
	c.SetProjectIncarnationGate(func() bool { return true })
	return c
}

func projectIncarnationOf(t *testing.T, c *Client, name string) string {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT incarnation FROM projects WHERE name = ?`, name)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read %s's incarnation: rows=%d err=%v", name, len(rows), err)
	}
	return rows[0].String("incarnation")
}

// Every birth of a name writes a fresh 128-bit incarnation with the row: a
// first create (marked a first birth), a revival, and a create over another
// spelling's tombstone. A delete keeps it. With the gate closed nothing is
// written: the previous release's statements.
//
// Mutations: the revive written with the previous statement — red (the
// incarnation does not change); every birth marked a first birth — red.
func TestProjectIncarnation_EveryBirthWritesAFreshIncarnation(t *testing.T) {
	ctx := context.Background()
	c := latchedProjectClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	first := projectIncarnationOf(t, c, "/acme")
	if len(first) != 33 || !strings.HasPrefix(first, projectFirstBirth) {
		t.Fatalf("first create's incarnation = %q, want a first birth and 128 bits", first)
	}
	if got, _ := GetProject(ctx, c, "/acme"); got == nil || got.Incarnation != first {
		t.Fatalf("GetProject: %+v, want incarnation %q", got, first)
	}
	if err := DeleteProject(ctx, c, "/acme"); err != nil {
		t.Fatal(err)
	}
	if got := projectIncarnationOf(t, c, "/acme"); got != first {
		t.Fatalf("a delete changed the incarnation: %q -> %q", first, got)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	revived := projectIncarnationOf(t, c, "/acme")
	if revived == first || len(revived) != 33 || !strings.HasPrefix(revived, projectRebirth) {
		t.Fatalf("revival's incarnation = %q (first %q), want a fresh rebirth", revived, first)
	}
	if err := DeleteProject(ctx, c, "/acme"); err != nil {
		t.Fatal(err)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	if sib := projectIncarnationOf(t, c, "acme"); !strings.HasPrefix(sib, projectRebirth) || sib == revived {
		t.Fatalf("a create over another spelling's tombstone = %q, want a fresh rebirth", sib)
	}

	off := newProjectTestClient(t)
	if err := InsertProject(ctx, off, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteProject(ctx, off, "/acme"); err != nil {
		t.Fatal(err)
	}
	if err := InsertProject(ctx, off, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	if got := projectIncarnationOf(t, off, "/acme"); got != "" {
		t.Fatalf("gate closed: incarnation %q written", got)
	}
}

// The read rule, case by case.
//
// Mutations: an untagged binding granting whatever the incarnation — red;
// a none tag granting on a first birth (review L2) — red; a binding under a
// deleted project held — red.
func TestProjectBindingHeld_Rules(t *testing.T) {
	st := func(live, dead []string) map[string]*projectState {
		return map[string]*projectState{"/p": {live: live, dead: dead, deadAt: make([]string, len(dead))}}
	}
	first, re, old := projectFirstBirth+"1", projectRebirth+"2", projectRebirth+"0"
	for _, tc := range []struct {
		name   string
		id     string
		path   string
		states map[string]*projectState
		held   bool
	}{
		{"untagged on a pre-latch project", "b", "/projects/p", st([]string{""}, nil), false},
		{"untagged on a project born after the latch", "b", "/projects/p", st([]string{re}, nil), true},
		{"untagged on a first birth after the latch", "b", "/projects/p/vms/x", st([]string{first}, nil), true},
		{"pre-tagged on a pre-latch project", "b~p:pre", "/projects/p", st([]string{""}, nil), false},
		{"pre-tagged after a re-create", "b~p:pre", "/projects/p", st([]string{re}, nil), true},
		{"tagged with its incarnation", "b~p:" + re, "/projects/p/containers/c", st([]string{re}, nil), false},
		{"tagged with an older incarnation", "b~p:" + old, "/projects/p", st([]string{re}, nil), true},
		{"a pre-grant on a first birth", "b~p:none", "/projects/p", st([]string{first}, nil), true},
		{"a pre-grant on a pre-latch project", "b~p:none", "/projects/p", st([]string{""}, nil), false},
		{"a pre-grant on a rebirth", "b~p:none", "/projects/p", st([]string{re}, []string{first}), true},
		{"under a deleted project", "b~p:" + old, "/projects/p", st(nil, []string{re}), false},
		{"under no project row", "b~p:" + old, "/projects/p", map[string]*projectState{}, false},
		{"outside /projects", "b~p:" + old, "/", st([]string{re}, nil), false},
		{"a sub-project's own binding", "b", "/projects/p/team", st([]string{re}, nil), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := projectBindingHeld(RoleBindingRecord{ID: tc.id, Path: tc.path}, tc.states); got != tc.held {
				t.Fatalf("held = %v, want %v", got, tc.held)
			}
		})
	}
}

// A grant tagged with the incarnation a lagging node held reaches the node
// after the re-create (here written as the replicator would apply it): it is
// held, listed as such, and the principal stays bound. A grant made for the
// new project grants.
func TestProjectIncarnation_AnOlderProjectsGrantIsHeld(t *testing.T) {
	ctx := context.Background()
	c := latchedProjectClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	staleID, err := ProjectBindingID(ctx, c, "/projects/p", "stale")
	if err != nil {
		t.Fatal(err)
	}
	if err := DeleteProject(ctx, c, "/p"); err != nil {
		t.Fatal(err)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Execute(ctx, roleBindingInsertSQL, staleID, "/projects/p", "Operator", "user:bob@local", 1, c.NowTS()); err != nil {
		t.Fatal(err)
	}
	freshID, err := ProjectBindingID(ctx, c, "/projects/p", "fresh")
	if err != nil {
		t.Fatal(err)
	}
	if err := InsertRoleBinding(ctx, c, RoleBindingRecord{ID: freshID, Path: "/projects/p", Role: "Operator", Principal: "user:carol@local", Propagate: true}); err != nil {
		t.Fatal(err)
	}
	bs, err := ListRoleBindings(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	held := map[string]bool{}
	for _, b := range bs {
		held[b.ID] = b.Held
	}
	if !held[staleID] || held[freshID] || len(held) != 2 {
		t.Fatalf("held = %v, want only %s held", held, staleID)
	}
	if b, _ := GetRoleBinding(ctx, c, staleID); b == nil || !b.Held || b.Role != "Operator" {
		t.Fatalf("GetRoleBinding(%s) = %+v, want it held, role kept", staleID, b)
	}
	if bs, _ := ListBindingsForPrincipal(ctx, c, "user:bob@local"); len(bs) != 1 || !bs[0].Held {
		t.Fatalf("ListBindingsForPrincipal = %+v, want bob's binding held", bs)
	}
}

// settleProjectName retires only on a change of incarnation, and then only
// the bindings tagged with an incarnation the name no longer holds: each
// becomes NoAccess, stamped just after its own clock. Untagged and
// none-tagged bindings, and other projects' bindings, are left alone.
//
// Mutations: retirement on every projects write (the before/after compare
// dropped) — red at the late grant; untagged bindings retired too — red; a
// fresh NowTS stamp instead of just-after — red.
func TestProjectIncarnation_RetiresOnlyOnAnIncarnationChange(t *testing.T) {
	ctx := context.Background()
	c := latchedProjectClient(t)
	for _, p := range []string{"/p", "/q"} {
		if err := InsertProject(ctx, c, ProjectRecord{Name: p}); err != nil {
			t.Fatal(err)
		}
	}
	inc := projectIncarnationOf(t, c, "/p")
	seed := []struct{ id, path string }{
		{"own~p:" + inc, "/projects/p"},
		{"untagged", "/projects/p"},
		{"pregrant~p:none", "/projects/p/vms/x"},
		{"other~p:" + projectIncarnationOf(t, c, "/q"), "/projects/q"},
	}
	for _, s := range seed {
		if err := c.Execute(ctx, roleBindingInsertSQL, s.id, s.path, "Operator", "user:bob@local", 1, c.NowTS()); err != nil {
			t.Fatal(err)
		}
	}
	roleOf := func() map[string]string {
		bs, err := ListRoleBindings(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, b := range bs {
			out[b.ID] = b.Role + "@" + b.UpdatedAt
		}
		return out
	}
	settle := func(newInc string) {
		t.Helper()
		tx, err := c.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		before, err := projectIncarnationHeld(ctx, tx, "/p")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`UPDATE projects SET incarnation = ? WHERE name = ?`, newInc, "/p"); err != nil {
			t.Fatal(err)
		}
		if err := settleProjectName(ctx, tx, "/p", before); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	was := roleOf()
	settle(inc)
	if got := roleOf(); len(got) != len(was) || got["own~p:"+inc] != was["own~p:"+inc] {
		t.Fatalf("same incarnation: %v, want nothing retired (%v)", got, was)
	}
	next := newProjectIncarnation(false)
	settle(next)
	got := roleOf()
	at, _ := justAfterTS(strings.SplitN(was["own~p:"+inc], "@", 2)[1])
	if got["own~p:"+inc] != SentinelRole+"@"+at {
		t.Fatalf("the older incarnation's grant = %q, want NoAccess at %s", got["own~p:"+inc], at)
	}
	for _, id := range []string{"untagged", "pregrant~p:none", "other~p:" + projectIncarnationOf(t, c, "/q")} {
		if got[id] != was[id] {
			t.Errorf("%s: %q, want it untouched (%q)", id, got[id], was[id])
		}
	}
	// A grant of the older incarnation that arrives after the change is held
	// (projectBindingHeld); a later write of the same incarnation retires
	// nothing.
	if err := c.Execute(ctx, roleBindingInsertSQL, "late~p:"+inc, "/projects/p", "Operator", "user:bob@local", 1, c.NowTS()); err != nil {
		t.Fatal(err)
	}
	settle(next)
	if b, _ := GetRoleBinding(ctx, c, "late~p:"+inc); b == nil || b.Role != "Operator" || !b.Held {
		t.Fatalf("a late grant of the older incarnation after a same-incarnation write: %+v, want it held and untouched", b)
	}
}

// A grant or quota prepared for an incarnation the project no longer holds
// when it is written is refused (ErrProjectChanged), and nothing is written.
//
// Mutations: insertProjectBinding's in-transaction tag check always true —
// red; the quota written unguarded — red.
func TestProjectIncarnation_AWriteTheProjectMovedUnderIsRefused(t *testing.T) {
	ctx := context.Background()
	c := latchedProjectClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	id, err := ProjectBindingID(ctx, c, "/projects/p", "late")
	if err != nil {
		t.Fatal(err)
	}
	if err := DeleteProject(ctx, c, "/p"); err != nil {
		t.Fatal(err)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	err = InsertRoleBinding(ctx, c, RoleBindingRecord{ID: id, Path: "/projects/p", Role: "Operator", Principal: "user:bob@local"})
	if !errors.Is(err, ErrProjectChanged) {
		t.Fatalf("grant for the old project: err=%v, want ErrProjectChanged", err)
	}
	if b, _ := GetRoleBinding(ctx, c, id); b != nil {
		t.Fatalf("the refused grant was written: %+v", b)
	}

	fired := false
	projectWriteInterleaveHook = func() {
		if fired {
			return
		}
		fired = true
		if err := DeleteProject(ctx, c, "/p"); err != nil {
			t.Error(err)
		}
		if err := InsertProject(ctx, c, ProjectRecord{Name: "/p"}); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { projectWriteInterleaveHook = nil })
	err = UpsertProjectQuota(ctx, c, ProjectQuotaRecord{ProjectName: "/p", VCPULimit: 8})
	if !errors.Is(err, ErrProjectChanged) {
		t.Fatalf("quota for the old project: err=%v, want ErrProjectChanged", err)
	}
	if q, _ := GetProjectQuota(ctx, c, "/p"); q != nil && q.VCPULimit == 8 {
		t.Fatalf("the refused quota was written: %+v", q)
	}
	if err := UpsertProjectQuota(ctx, c, ProjectQuotaRecord{ProjectName: "/p", VCPULimit: 8}); err != nil {
		t.Fatalf("a quota for the project as it stands: %v", err)
	}
}

// Writes carry the guard a receiver checks. A quota carries project_live and
// names its incarnation. A grant carries no project guard, and a grant to a
// local account keeps user_incarnation_v1's (user_live), so a receiver that
// has not reached the account holds and replays it (review M1). A NoAccess
// binding carries user_tighten. With the gate closed nothing is tagged.
//
// Mutations: a grant given a project guard (replacing the user stamp) — red;
// noAccessBindingInsert left out of statementTightensHere (review L4) — red.
func TestProjectIncarnation_WritesCarryTheirGuard(t *testing.T) {
	ctx := context.Background()
	c := latchedProjectClient(t)
	c.SetUserIncarnationGate(func() bool { return true })
	if err := InsertUser(ctx, c, "bob", "viewer", "h"); err != nil {
		t.Fatal(err)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	inc := projectIncarnationOf(t, c, "/p")
	grant, _ := ProjectBindingID(ctx, c, "/projects/p", "g")
	sentinel, _ := ProjectBindingID(ctx, c, "/projects/p", "s")
	if err := InsertRoleBinding(ctx, c, RoleBindingRecord{ID: grant, Path: "/projects/p", Role: "Operator", Principal: "user:bob@local"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertRoleBinding(ctx, c, RoleBindingRecord{ID: sentinel, Path: "/projects/p", Role: SentinelRole, Principal: "user:bob@local"}); err != nil {
		t.Fatal(err)
	}
	if err := UpsertProjectQuota(ctx, c, ProjectQuotaRecord{ProjectName: "/p", VCPULimit: 4}); err != nil {
		t.Fatal(err)
	}
	guards := loggedGuards(t, c)
	userInc := ""
	if rows, _ := c.Query(ctx, `SELECT created_at FROM users WHERE username = 'bob'`); len(rows) == 1 {
		userInc = rows[0].String("created_at")
	}
	want := map[string]string{
		grant:    userIncarnationGuardV1 + " " + userGuardLive + " bob " + userInc,
		sentinel: userIncarnationGuardV1 + " " + userGuardTighten + " bob " + userInc,
		"/p":     projectIncarnationGuardV1 + " " + projectGuardLive + " /p " + inc,
	}
	for k, w := range want {
		if guards[k] != w {
			t.Errorf("%s: guard %q, want %q", k, guards[k], w)
		}
	}

	off := newProjectTestClient(t)
	if err := InsertProject(ctx, off, ProjectRecord{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	if id, _ := ProjectBindingID(ctx, off, "/projects/p", "g"); id != "g" {
		t.Fatalf("gate closed: id %q tagged", id)
	}
}

// loggedGuards reads c's mutation log: for each role binding insert (by id)
// and quota upsert (by project) its guard as "protocol kind resource
// incarnation", or "" for none. A quota also checks its incarnation column.
func loggedGuards(t *testing.T, c *Client) map[string]string {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT stmts FROM mutation_log ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rows {
		var stmts []Statement
		if err := json.Unmarshal([]byte(r.String("stmts")), &stmts); err != nil {
			t.Fatal(err)
		}
		for _, s := range stmts {
			sh, _, err := parseResolved(s.SQL)
			if err != nil {
				continue
			}
			key := ""
			switch stmtFingerprint(sh) {
			case fpRoleBindingInsert:
				key = coerceString(s.Params[0])
			case fpProjectQuotaUpsertIncarn:
				key = coerceString(s.Params[0])
				if s.Guard != nil && coerceString(s.Params[7]) != s.Guard.Incarnation {
					t.Errorf("quota %s written for %q under a guard for %q", key, coerceString(s.Params[7]), s.Guard.Incarnation)
				}
			default:
				continue
			}
			if s.Guard == nil {
				out[key] = ""
				continue
			}
			g := s.Guard
			out[key] = g.Protocol + " " + g.ResourceKind + " " + g.ResourceID + " " + g.Incarnation
		}
	}
	return out
}

// A receiver's verdict on each guard kind, in its own transaction.
//
// Mutations: project_deleted matching a live project, or ignoring a live
// spelling (review L4, m05) — red; project_live ignoring the incarnation —
// red.
func TestProjectGuard_ReceiverVerdicts(t *testing.T) {
	ctx := context.Background()
	c := latchedProjectClient(t)
	c.SetUserIncarnationGate(func() bool { return true })
	if err := InsertUser(ctx, c, "bob", "viewer", "h"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/live", "/gone", "acme"} {
		if err := InsertProject(ctx, c, ProjectRecord{Name: p}); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"/gone", "acme"} {
		if err := DeleteProject(ctx, c, p); err != nil {
			t.Fatal(err)
		}
	}
	acmeDead := projectIncarnationOf(t, c, "acme")
	// Another spelling of acme, live, beside the tombstone.
	if err := c.Execute(ctx, projectsInsertIncarnationSQL, "/acme", "", "", nowRFC3339(), c.NowTS(), newProjectIncarnation(false)); err != nil {
		t.Fatal(err)
	}
	live, gone := projectIncarnationOf(t, c, "/live"), projectIncarnationOf(t, c, "/gone")
	g := func(kind, proj, inc string) *MutationGuard {
		return &MutationGuard{Protocol: projectIncarnationGuardV1, ResourceKind: kind, ResourceID: proj, Incarnation: inc}
	}
	for _, tc := range []struct {
		name  string
		guard *MutationGuard
		want  bool
	}{
		{"a quota for the live incarnation", g(projectGuardLive, "/live", live), true},
		{"a quota for another incarnation", g(projectGuardLive, "/live", "r0"), false},
		{"a quota for a deleted project", g(projectGuardLive, "/gone", gone), false},
		{"a retirement of the tombstone held", g(projectGuardDeleted, "/gone", gone), true},
		{"a retirement of another tombstone", g(projectGuardDeleted, "/gone", "r0"), false},
		{"a retirement of a live project", g(projectGuardDeleted, "/live", live), false},
		{"a retirement of a tombstone beside a live spelling", g(projectGuardDeleted, "/acme", acmeDead), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := c.db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			got, err := c.mutationGuardMatches(ctx, tx, tc.guard)
			if err != nil || got != tc.want {
				t.Fatalf("matches = %v (err %v), want %v", got, err, tc.want)
			}
		})
	}
}

// An entry is refused unless every project guard binds the statement it is
// on: the project and the incarnation, and nothing mixed in. A grant takes no
// project guard.
//
// Mutation: validateProjectIncarnationEntry returning nil — red.
func TestValidateProjectIncarnationEntry(t *testing.T) {
	pg := func(kind, proj, inc string) *MutationGuard {
		return &MutationGuard{Protocol: projectIncarnationGuardV1, ResourceKind: kind, ResourceID: proj, Incarnation: inc}
	}
	quota := func(name, inc string, g *MutationGuard) Statement {
		return Statement{SQL: projectQuotaUpsertIncarnationSQL, Params: []interface{}{name, 1, 0, 0, 0, 0, 0, inc, "ts"}, Guard: g}
	}
	ok := quota("/p", "r1", pg(projectGuardLive, "/p", "r1"))
	for _, tc := range []struct {
		name  string
		stmts []Statement
		valid bool
	}{
		{"a quota it binds", []Statement{ok}, true},
		{"a quota of another spelling", []Statement{quota("p", "r1", pg(projectGuardLive, "/p", "r1"))}, true},
		{"a quota of another project", []Statement{quota("/q", "r1", pg(projectGuardLive, "/p", "r1"))}, false},
		{"a quota for another incarnation", []Statement{quota("/p", "r2", pg(projectGuardLive, "/p", "r1"))}, false},
		{"a quota with a retirement's kind", []Statement{quota("/p", "r1", pg(projectGuardDeleted, "/p", "r1"))}, false},
		{"a quota naming an account", []Statement{func() Statement {
			s := quota("/p", "r1", pg(projectGuardLive, "/p", "r1"))
			s.Guard.TargetResourceID = "bob"
			return s
		}()}, false},
		{"a grant", []Statement{{SQL: roleBindingInsertSQL, Params: []interface{}{"x~p:r1", "/projects/p", "Operator", "group:ops", 1, "ts"},
			Guard: pg(projectGuardLive, "/p", "r1")}}, false},
		{"a retirement it binds", []Statement{{SQL: retireProjectAuthoritySQL, Params: []interface{}{"d", "ts", "p"}, Guard: pg(projectGuardDeleted, "/p", "")}}, true},
		{"a statement it does not bind", []Statement{{SQL: roleBindingDeleteSQL, Params: []interface{}{"d", "ts", "x"}, Guard: pg(projectGuardLive, "/p", "r1")}}, false},
		{"mixed protocols", []Statement{ok, {SQL: roleBindingDeleteSQL, Params: []interface{}{"d", "ts", "x"},
			Guard: &MutationGuard{Protocol: userIncarnationGuardV1, ResourceKind: userGuardLive, ResourceID: "bob", Incarnation: "t"}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateGuardedMutationEntry(tc.stmts)
			if (err == nil) != tc.valid {
				t.Fatalf("err = %v, want valid=%v", err, tc.valid)
			}
		})
	}
}

// Review m1: a local account whose authority comes through its legacy role's
// group (group:admin@local at "/") loses a project binding to a delete and
// is NOT given a NoAccess binding of its own: the group's binding keeps it
// bound as it keeps the group's other members, and a later revoke of that
// binding returns them all to the legacy role together. An account without
// such a group binding still gets one.
//
// Mutation: legacyGroupStable always false — red.
func TestDeleteProject_GroupHeldAuthorityNeedsNoPersonalSentinel(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	for _, u := range []struct{ name, role string }{{"alice", "admin"}, {"bob", "viewer"}} {
		if err := InsertUser(ctx, c, u.name, u.role, "h"); err != nil {
			t.Fatal(err)
		}
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	for _, b := range []RoleBindingRecord{
		{ID: "admins", Path: "/", Role: "Admin", Principal: "group:admin@local", Propagate: true},
		{ID: "alice-p", Path: "/projects/p", Role: "Operator", Principal: "user:alice@local", Propagate: true},
		{ID: "bob-p", Path: "/projects/p", Role: "Operator", Principal: "user:bob@local", Propagate: true},
	} {
		if err := InsertRoleBinding(ctx, c, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := DeleteProject(ctx, c, "/p"); err != nil {
		t.Fatal(err)
	}
	for who, want := range map[string]int{"user:alice@local": 0, "user:bob@local": 1} {
		bs, err := ListBindingsForPrincipal(ctx, c, who)
		if err != nil {
			t.Fatal(err)
		}
		if len(bs) != want {
			t.Errorf("%s holds %d bindings after the delete (%+v), want %d", who, len(bs), bs, want)
		}
	}
}

// Once user_incarnation_v1 has latched, deleting (or re-creating) a project
// that two local accounts are bound in leaves each a NoAccess binding in one
// entry. That only tightens, so it is not refused as a multi-account grant.
//
// Red on 1f052cf68: "a write that grants or loosens more than one account in
// one entry". Mutation: noAccessBindingInsert always false — red.
func TestDeleteProject_TwoAccountsAfterTheUserLatch(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	c.SetUserIncarnationGate(func() bool { return true })
	for _, u := range []string{"alice", "bob"} {
		if err := InsertUser(ctx, c, u, "viewer", "h"); err != nil {
			t.Fatal(err)
		}
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"alice", "bob"} {
		if err := InsertRoleBinding(ctx, c, RoleBindingRecord{ID: "b-" + u, Path: "/projects/p", Role: "Operator", Principal: "user:" + u + "@local", Propagate: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := DeleteProject(ctx, c, "/p"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	for _, u := range []string{"alice", "bob"} {
		bs, _ := ListBindingsForPrincipal(ctx, c, "user:"+u+"@local")
		if len(bs) != 1 || bs[0].Role != SentinelRole {
			t.Errorf("%s: %+v, want one NoAccess binding", u, bs)
		}
	}
}

// The guard kinds are a wire contract: a receiver refuses a kind it does not
// know.
func TestProjectGuardKinds_AreTheKnownOnes(t *testing.T) {
	if projectIncarnationGuardV1 != "project_incarnation_v1" || projectGuardLive != "project_live" ||
		projectGuardDeleted != "project_deleted" {
		t.Fatal("a project guard's protocol or kind changed: receivers of the previous build refuse it")
	}
	c := latchedProjectClient(t)
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := c.mutationGuardMatches(context.Background(), tx, &MutationGuard{
		Protocol: projectIncarnationGuardV1, ResourceKind: "project", ResourceID: "/p"}); err == nil {
		t.Fatal("an unknown project guard kind was accepted")
	}
}
