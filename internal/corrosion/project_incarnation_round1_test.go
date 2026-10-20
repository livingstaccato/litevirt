package corrosion

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Review L2: a first birth carries over the pre-grants its creator holds
// (each tombstoned and granted again, tagged with the new incarnation), and a
// pre-grant it did not hold, arriving afterwards, is held: nothing ties it to
// this project.
//
// Mutations: no pre-grant carried — red at "carried"; a none tag granting on
// a first birth — red at "late"; untagged bindings carried too (round 2,
// L1) — red at "untagged".
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
	if b, ok := got["user:alice@local /projects/new"]; !ok || b.Held || !strings.HasSuffix(b.ID, projectBindingTagSep+inc) {
		t.Errorf("carried pre-grant: %+v (present %v), want it granting, tagged %s", b, ok, inc)
	}
	// An untagged binding may be an earlier lifetime's, from before the
	// latch: it is not carried, and is held (review round 2, L1).
	if b := got["group:ops /projects/new/vms/x"]; b.ID != "legacy" || !b.Held {
		t.Errorf("untagged binding: %+v, want it left as it is, held", b)
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
// Mutations: upsertProjectQuota reading the gate only — red (the quota);
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
	// So is its quota: it is keyed by the incarnation, and is enforced.
	if err := UpsertProjectQuota(ctx, c, ProjectQuotaRecord{ProjectName: "/p", VCPULimit: 3}); err != nil {
		t.Fatal(err)
	}
	if rows, _ := c.Query(ctx, `SELECT 1 FROM project_quotas WHERE project_name = ?`, projectQuotaKey("/p", projectIncarnationOf(t, c, "/p"))); len(rows) != 1 {
		t.Fatal("an unlatched quota on a project that carries an incarnation is not keyed by it")
	}
	if q, _ := GetProjectQuota(ctx, c, "/p"); q == nil || q.VCPULimit != 3 {
		t.Fatalf("an unlatched quota on a project that carries an incarnation: %+v, want vcpu 3", q)
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
	if has("projects") {
		t.Fatal("an unset incarnation column is in the dump")
	}
	c.SetProjectIncarnationGate(func() bool { return true })
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/q"}); err != nil {
		t.Fatal(err)
	}
	if err := UpsertProjectQuota(ctx, c, ProjectQuotaRecord{ProjectName: "/q", VCPULimit: 2}); err != nil {
		t.Fatal(err)
	}
	if !has("projects") {
		t.Fatal("a set incarnation column is missing from the dump")
	}
}

// A quota is keyed by the incarnation it was set for (rounds 1 and 2,
// review M2 and R2-B): a project reads only its own incarnation's row, so a
// quota set for another, at any clock, by the WAL or anti-entropy, neither
// displaces nor overrides it; and the new incarnation's own row, written
// before the project reaches it, is read once it does (R2-A).
//
// Mutations: GetProjectQuota reading the bare name — red; a quota written
// under the bare name — red.
func TestProjectIncarnation_AQuotaBelongsToItsIncarnation(t *testing.T) {
	ctx := context.Background()
	c := latchedProjectClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	inc := projectIncarnationOf(t, c, "/p")
	if err := UpsertProjectQuota(ctx, c, ProjectQuotaRecord{ProjectName: "/p", VCPULimit: 10}); err != nil {
		t.Fatal(err)
	}
	put := func(key string, limit int) {
		t.Helper()
		if err := c.Execute(ctx, projectQuotaUpsertSQL, key, limit, 0, 0, 0, 0, 0, c.NowTS()); err != nil {
			t.Fatal(err)
		}
	}
	// Later quotas of other incarnations, and of the previous form.
	put(projectQuotaKey("/p", "r0"), 100)
	put("/p", 200)
	if q, _ := GetProjectQuota(ctx, c, "/p"); q == nil || q.VCPULimit != 10 || q.ProjectName != "/p" {
		t.Fatalf("another incarnation's quota displaced the project's own: %+v, want /p at vcpu 10", q)
	}
	// The next incarnation's own quota, here before the project reaches it.
	next := newProjectIncarnation(false)
	put(projectQuotaKey("/p", next), 7)
	if q, _ := GetProjectQuota(ctx, c, "/p"); q == nil || q.VCPULimit != 10 {
		t.Fatalf("an incarnation not reached yet: %+v, want vcpu 10", q)
	}
	if err := c.Execute(ctx, `UPDATE projects SET incarnation = ? WHERE name = '/p'`, next); err != nil {
		t.Fatal(err)
	}
	if q, _ := GetProjectQuota(ctx, c, "/p"); q == nil || q.VCPULimit != 7 {
		t.Fatalf("the new incarnation's own quota: %+v, want vcpu 7", q)
	}
	_ = inc
	// A deleted project's quota is refused once the forms apply.
	if err := DeleteProject(ctx, c, "/p"); err != nil {
		t.Fatal(err)
	}
	if err := UpsertProjectQuota(ctx, c, ProjectQuotaRecord{ProjectName: "/p", VCPULimit: 9}); !errors.Is(err, ErrNoLiveProject) {
		t.Fatalf("a quota for a deleted project: err=%v, want ErrNoLiveProject", err)
	}
}

// Review round 2, L2: a dump without the incarnation column comes from a node
// that never held a birth made after the latch, so its projects row never
// displaces a local one that carries an incarnation, whatever its clock.
//
// Mutation: projectsDumpDecision always normal — red.
func TestProjectIncarnation_AColumnlessDumpKeepsALocalIncarnation(t *testing.T) {
	c := latchedProjectClient(t)
	if err := InsertProject(context.Background(), c, ProjectRecord{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertProject(context.Background(), c, ProjectRecord{Name: "/old"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Execute(context.Background(), `UPDATE projects SET incarnation = '' WHERE name = '/old'`); err != nil {
		t.Fatal(err)
	}
	decide := func(table syncTable, name string) mergeAuthorityDecision {
		t.Helper()
		tx, err := c.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		row := make([]interface{}, len(table.Columns))
		row[0] = name
		d, err := projectsDumpDecision(tx, table, row)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	without := syncTable{Name: "projects", Columns: []string{"name", "display", "updated_at"}}
	with := syncTable{Name: "projects", Columns: []string{"name", "display", "updated_at", "incarnation"}}
	if d := decide(without, "/p"); d != mergeAuthorityKeepLocal {
		t.Errorf("a column-less row over one that carries an incarnation: %v, want keep local", d)
	}
	if d := decide(without, "/old"); d != mergeAuthorityNormal {
		t.Errorf("a column-less row over a pre-latch one: %v, want normal", d)
	}
	if d := decide(without, "/none"); d != mergeAuthorityNormal {
		t.Errorf("a column-less row with no local row: %v, want normal", d)
	}
	if d := decide(with, "/p"); d != mergeAuthorityNormal {
		t.Errorf("a row with the column: %v, want normal", d)
	}
}
