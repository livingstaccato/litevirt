package corrosion

import (
	"context"
	"strings"
	"testing"
)

// A deleted project's name must be usable again. DeleteProject tombstones the
// row, which keeps its primary key, so a plain INSERT collided with it.
func TestProject_NameReusableAfterDelete(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme", Display: "first"}); err != nil {
		t.Fatal(err)
	}
	first, _ := GetProject(ctx, c, "/acme")
	if err := DeleteProject(ctx, c, "/acme"); err != nil {
		t.Fatal(err)
	}
	if got, _ := GetProject(ctx, c, "/acme"); got != nil {
		t.Fatalf("deleted project still resolves: %+v", got)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme", Display: "first"}); err != nil {
		t.Fatalf("re-create after delete: %v", err)
	}
	got, _ := GetProject(ctx, c, "/acme")
	if got == nil || got.Display != "first" {
		t.Fatalf("re-created project = %+v, want live", got)
	}
	_ = first
	all, _ := ListProjects(ctx, c)
	n := 0
	for _, p := range all {
		if p.Name == "/acme" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("ListProjects shows /acme %d times, want 1", n)
	}
	// A LIVE project is still not creatable twice.
	err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate create of a live project: err=%v, want already exists", err)
	}
}

// Everything that grants authority over a project NAME dies with the project: a
// new project under an old name starts with no operators, no admission holder
// and no limits of the old one's choosing.
func TestProject_RecreatedNameInheritsNoGrants(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	for _, b := range []RoleBindingRecord{
		{ID: "b-root", Path: "/projects/acme", Role: "Admin", Principal: "user:alice", Propagate: true},
		{ID: "b-vm", Path: "/projects/acme/vms/web", Role: "Operator", Principal: "user:bob"},
		{ID: "b-sib", Path: "/projects/acme2", Role: "Admin", Principal: "user:carol", Propagate: true},
		{ID: "b-other", Path: "/projects/_default", Role: "Viewer", Principal: "user:dave"},
	} {
		if err := InsertRoleBinding(ctx, c, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := UpsertProjectQuota(ctx, c, ProjectQuotaRecord{ProjectName: "/acme", VCPULimit: 500}); err != nil {
		t.Fatal(err)
	}
	if _, err := ClaimInitialProjectAuthority(ctx, c, "/acme", "node-1"); err != nil {
		t.Fatal(err)
	}

	if err := DeleteProject(ctx, c, "/acme"); err != nil {
		t.Fatal(err)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}

	live := map[string]bool{}
	bs, _ := ListRoleBindings(ctx, c)
	for _, b := range bs {
		live[b.ID] = true
	}
	if live["b-root"] || live["b-vm"] {
		t.Fatalf("re-created project inherited role bindings: %v", live)
	}
	if !live["b-sib"] || !live["b-other"] {
		t.Fatalf("grants of other projects were retired too: %v", live)
	}
	if q, _ := GetProjectQuota(ctx, c, "/acme"); q != nil && q.VCPULimit != 0 {
		t.Fatalf("re-created project inherited quota %+v", q)
	}
	if _, ok, _ := CurrentProjectAuthority(ctx, c, "/acme"); ok {
		t.Fatal("re-created project inherited a live admission authority")
	}
}

// A tombstone written by a build that did not retire grants on delete (or by a
// replica that has not yet seen the retirement) still revives clean.
func TestProject_RecreateRetiresGrantsLeftByAnOlderDelete(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/old"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertRoleBinding(ctx, c, RoleBindingRecord{ID: "b1", Path: "/projects/old", Role: "Admin", Principal: "user:alice", Propagate: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := ClaimInitialProjectAuthority(ctx, c, "/old", "node-1"); err != nil {
		t.Fatal(err)
	}
	// What a previous release's DeleteProject did: tombstone, nothing else.
	if err := c.Execute(ctx, `UPDATE projects SET deleted_at = ?, updated_at = ? WHERE name = ?`,
		nowRFC3339(), c.NowTS(), "/old"); err != nil {
		t.Fatal(err)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/old"}); err != nil {
		t.Fatal(err)
	}
	if bs, _ := ListRoleBindings(ctx, c); len(bs) != 0 {
		t.Fatalf("inherited bindings: %+v", bs)
	}
	if _, ok, _ := CurrentProjectAuthority(ctx, c, "/old"); ok {
		t.Fatal("inherited admission authority")
	}
}

// Creating a project that never existed leaves grants alone: only a revival
// retires them.
func TestProject_FirstCreateKeepsPreGrantedBindings(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertRoleBinding(ctx, c, RoleBindingRecord{ID: "pre", Path: "/projects/new", Role: "Admin", Principal: "user:alice", Propagate: true}); err != nil {
		t.Fatal(err)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/new"}); err != nil {
		t.Fatal(err)
	}
	if bs, _ := ListRoleBindings(ctx, c); len(bs) != 1 {
		t.Fatalf("pre-granted binding lost on first create: %+v", bs)
	}
}

// The revive keeps the tombstoned row's display and parent, so a request that
// asks for different ones is refused rather than silently given stale values.
func TestProject_RecreateRefusesADifferingDisplayOrParent(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	for _, p := range []ProjectRecord{{Name: "/a"}, {Name: "/b"}, {Name: "/a/x", Display: "X", ParentName: "/a"}} {
		if err := InsertProject(ctx, c, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := DeleteProject(ctx, c, "/a/x"); err != nil {
		t.Fatal(err)
	}
	err := InsertProject(ctx, c, ProjectRecord{Name: "/a/x", Display: "Y", ParentName: "/a"})
	if err == nil || !strings.Contains(err.Error(), `"X"`) {
		t.Fatalf("differing display: err=%v, want a refusal naming the old display", err)
	}
	err = InsertProject(ctx, c, ProjectRecord{Name: "/a/x", ParentName: "/b"})
	if err == nil || !strings.Contains(err.Error(), "parent") {
		t.Fatalf("differing parent: err=%v, want a refusal", err)
	}
	if got, _ := GetProject(ctx, c, "/a/x"); got != nil {
		t.Fatalf("a refused re-create revived the project: %+v", got)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/a/x", ParentName: "/a"}); err != nil {
		t.Fatalf("re-create with no display: %v", err)
	}
	if got, _ := GetProject(ctx, c, "/a/x"); got == nil || got.Display != "X" {
		t.Fatalf("re-created = %+v, want old display X", got)
	}
}
