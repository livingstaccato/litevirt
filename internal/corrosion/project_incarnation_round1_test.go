package corrosion

import (
	"context"
	"strings"
	"testing"
)

// Review L2: a first birth carries over the pre-grants its creator holds
// (each tombstoned and granted again, tagged with the new incarnation), and a
// pre-grant it did not hold, arriving afterwards, is held: nothing ties it to
// this project.
//
// Mutations: no pre-grant carried — red at "carried"; a none tag granting on
// a first birth — red at "late".
func TestProjectIncarnation_AFirstBirthCarriesItsCreatorsPreGrants(t *testing.T) {
	ctx := context.Background()
	c := latchedProjectClient(t)
	pre, err := ProjectBindingID(ctx, c, "/projects/new", "pre")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(pre, projectBindingTagSep+projectTagNone) {
		t.Fatalf("pre-grant id %q, want it tagged none", pre)
	}
	for _, b := range []RoleBindingRecord{
		{ID: pre, Path: "/projects/new", Role: "Operator", Principal: "user:alice@local", Propagate: true},
		{ID: "legacy", Path: "/projects/new/vms/x", Role: "Viewer", Principal: "group:ops"},
		{ID: "elsewhere", Path: "/projects/other", Role: "Viewer", Principal: "group:ops"},
	} {
		if err := InsertRoleBinding(ctx, c, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/new"}); err != nil {
		t.Fatal(err)
	}
	inc := projectIncarnationOf(t, c, "/new")
	bs, err := ListRoleBindings(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]RoleBindingRecord{}
	for _, b := range bs {
		got[b.Principal+" "+b.Path] = b
	}
	for _, k := range []string{"user:alice@local /projects/new", "group:ops /projects/new/vms/x"} {
		b, ok := got[k]
		if !ok || b.Held || !strings.HasSuffix(b.ID, projectBindingTagSep+inc) {
			t.Errorf("carried %s: %+v (present %v), want it granting, tagged %s", k, b, ok, inc)
		}
	}
	if b := got["group:ops /projects/other"]; b.ID != "elsewhere" {
		t.Errorf("another project's binding was touched: %+v", b)
	}
	if b, _ := GetRoleBinding(ctx, c, pre); b != nil {
		t.Errorf("the original pre-grant is still live: %+v", b)
	}

	// A pre-grant from a host that saw no row, arriving after the create.
	if err := c.Execute(ctx, roleBindingInsertSQL, "late~p:none", "/projects/new", "Admin", "user:mallory@local", 1, c.NowTS()); err != nil {
		t.Fatal(err)
	}
	if b, _ := GetRoleBinding(ctx, c, "late~p:none"); b == nil || !b.Held {
		t.Fatalf("late pre-grant: %+v, want it held", b)
	}
}

// Review L1: before its own latch, a node writes the incarnation forms for a
// project that already carries an incarnation: its revive is a new
// incarnation, and its grant is tagged. Only a latched writer makes an
// incarnation, so every replica already decodes the forms.
//
// Mutations: projectFormsFor reading the gate only — red (the quota);
// ProjectBindingID reading the gate only — red (the grant).
func TestProjectIncarnation_AnUnlatchedNodeKeepsACarriedIncarnationGoing(t *testing.T) {
	ctx := context.Background()
	c := latchedProjectClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	first := projectIncarnationOf(t, c, "/p")
	if err := DeleteProject(ctx, c, "/p"); err != nil {
		t.Fatal(err)
	}
	c.SetProjectIncarnationGate(func() bool { return false })
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	if inc := projectIncarnationOf(t, c, "/p"); inc == first || !strings.HasPrefix(inc, projectRebirth) {
		t.Fatalf("an unlatched revive of a project born latched: incarnation %q (was %q), want a new one", inc, first)
	}
	id, err := ProjectBindingID(ctx, c, "/projects/p", "g")
	if err != nil || !strings.HasSuffix(id, projectBindingTagSep+projectIncarnationOf(t, c, "/p")) {
		t.Fatalf("an unlatched grant on a project that carries an incarnation: id %q (err %v), want it tagged", id, err)
	}
	// So is its quota: it names the incarnation, and is enforced.
	if err := UpsertProjectQuota(ctx, c, ProjectQuotaRecord{ProjectName: "/p", VCPULimit: 3}); err != nil {
		t.Fatal(err)
	}
	if rows, _ := c.Query(ctx, `SELECT incarnation FROM project_quotas WHERE project_name = '/p'`); len(rows) != 1 ||
		rows[0].String("incarnation") != projectIncarnationOf(t, c, "/p") {
		t.Fatalf("an unlatched quota on a project that carries an incarnation: %+v, want it named", rows)
	}
	// A project born before any latch stays in the previous form.
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/old"}); err != nil {
		t.Fatal(err)
	}
	if id, _ := ProjectBindingID(ctx, c, "/projects/old", "g"); id != "g" {
		t.Fatalf("unlatched grant on a pre-latch project: id %q, want it untagged", id)
	}
}

// Review L3: while every incarnation is ”, a node's dump leaves the column
// out, so a previous-release node still takes its projects and quota rows;
// once one is set, the column is sent.
//
// Mutation: withoutUnsetIncarnation returning the table as it is — red.
func TestProjectIncarnation_TheDumpLeavesOutAnUnsetIncarnation(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	if err := UpsertProjectQuota(ctx, c, ProjectQuotaRecord{ProjectName: "/p", VCPULimit: 2}); err != nil {
		t.Fatal(err)
	}
	has := func(table string) bool {
		st, ok := c.dumpTable(table)
		if !ok {
			t.Fatalf("dump %s", table)
		}
		return indexOf(st.Columns, "incarnation") >= 0
	}
	if has("projects") || has("project_quotas") {
		t.Fatal("an unset incarnation column is in the dump")
	}
	c.SetProjectIncarnationGate(func() bool { return true })
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/q"}); err != nil {
		t.Fatal(err)
	}
	if err := UpsertProjectQuota(ctx, c, ProjectQuotaRecord{ProjectName: "/q", VCPULimit: 2}); err != nil {
		t.Fatal(err)
	}
	if !has("projects") || !has("project_quotas") {
		t.Fatal("a set incarnation column is missing from the dump")
	}
}

// Review M2: a quota set for another incarnation of a project is not
// enforced on it; a node that takes a new incarnation drops such rows; and
// anti-entropy takes the project's own quota over another's whatever the
// clocks, and never another's over its own or over none.
//
// Mutations: GetProjectQuota enforcing any row — red at "read";
// dropOtherIncarnationQuotas a no-op — red at "settle"; projectQuotaDecision
// normal — red at "anti-entropy".
func TestProjectIncarnation_AQuotaBelongsToItsIncarnation(t *testing.T) {
	ctx := context.Background()
	c := latchedProjectClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	old := projectIncarnationOf(t, c, "/p")
	if err := UpsertProjectQuota(ctx, c, ProjectQuotaRecord{ProjectName: "/p", VCPULimit: 10}); err != nil {
		t.Fatal(err)
	}
	if q, _ := GetProjectQuota(ctx, c, "/p"); q == nil || q.VCPULimit != 10 {
		t.Fatalf("own quota: %+v, want vcpu 10", q)
	}
	// read: a row of another incarnation, as a lagging node's arrives.
	stale := func(limit int) {
		t.Helper()
		if err := c.Execute(ctx, projectQuotaUpsertIncarnationSQL, "/p", limit, 0, 0, 0, 0, 0, "r0", c.NowTS()); err != nil {
			t.Fatal(err)
		}
	}
	stale(100)
	if q, _ := GetProjectQuota(ctx, c, "/p"); q != nil {
		t.Fatalf("read: another incarnation's quota is enforced: %+v", q)
	}
	// settle: a new incarnation drops the quota rows of others.
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE projects SET incarnation = ? WHERE name = '/p'`, "r0"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE project_quotas SET incarnation = ? WHERE project_name = '/p'`, old); err != nil {
		t.Fatal(err)
	}
	if err := settleProjectName(ctx, tx, "/p", old); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if rows, _ := c.Query(ctx, `SELECT 1 FROM project_quotas WHERE project_name = '/p'`); len(rows) != 0 {
		t.Fatal("settle: the old incarnation's quota row is still there")
	}

	// anti-entropy, with the project at r0.
	decide := func(inc string) mergeAuthorityDecision {
		t.Helper()
		tx, err := c.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		table := syncTable{Name: "project_quotas", Columns: []string{"project_name", "vcpu_limit", "incarnation", "updated_at"}}
		d, err := projectQuotaDecision(tx, table, []interface{}{"/p", 1, inc, "ts"})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := decide(old); d != mergeAuthorityKeepLocal {
		t.Errorf("anti-entropy: another incarnation's quota over none: %v, want keep local", d)
	}
	if d := decide("r0"); d != mergeAuthorityNormal {
		t.Errorf("anti-entropy: the project's own quota over none: %v, want normal", d)
	}
	stale(5) // a row of r0 is the project's own now
	if err := c.Execute(ctx, `UPDATE project_quotas SET incarnation = ? WHERE project_name = '/p'`, old); err != nil {
		t.Fatal(err)
	}
	if d := decide("r0"); d != mergeAuthorityApplyIncoming {
		t.Errorf("anti-entropy: the project's own quota over another's: %v, want apply incoming", d)
	}
	if d := decide(old); d != mergeAuthorityKeepLocal {
		t.Errorf("anti-entropy: another's quota: %v, want keep local", d)
	}
}
