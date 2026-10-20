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
	for _, b := range liveBindings(t, c) {
		if b.Role != SentinelRole {
			t.Fatalf("inherited binding: %+v", b)
		}
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

func liveBindings(t *testing.T, c *Client) []RoleBindingRecord {
	t.Helper()
	bs, err := ListRoleBindings(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	return bs
}

// Retirement happens AT DELETE, not only when the name is next created: between
// the two, stale grants must not sit live under a path nobody owns.
func TestDeleteProject_RetiresGrantsImmediately(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertRoleBinding(ctx, c, RoleBindingRecord{ID: "b1", Path: "/projects/acme/vms/web", Role: "Operator", Principal: "user:bob@local"}); err != nil {
		t.Fatal(err)
	}
	if err := UpsertProjectQuota(ctx, c, ProjectQuotaRecord{ProjectName: "/acme", VCPULimit: 7}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteProject(ctx, c, "/acme"); err != nil {
		t.Fatal(err)
	}
	for _, b := range liveBindings(t, c) {
		if b.ID == "b1" {
			t.Fatal("a deleted project's role binding is still live")
		}
	}
	if q, _ := GetProjectQuota(ctx, c, "/acme"); q != nil && q.VCPULimit != 0 {
		t.Fatalf("a deleted project's quota is still %+v", q)
	}
}

// H1: a principal whose only bindings were in the project must not be left with
// none, or RequirePerm falls back to its legacy role, cluster-wide.
func TestDeleteProject_NeverLeavesAPrincipalUnbound(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	for _, b := range []RoleBindingRecord{
		{ID: "only", Path: "/projects/acme", Role: "Operator", Principal: "user:bob@local", Propagate: true},
		{ID: "two", Path: "/projects/acme/vms/x", Role: "Operator", Principal: "user:bob@local"},
		{ID: "also", Path: "/projects/acme", Role: "Viewer", Principal: "user:eve@local", Propagate: true},
		{ID: "elsewhere", Path: "/projects/beta", Role: "Viewer", Principal: "user:eve@local", Propagate: true},
	} {
		if err := InsertRoleBinding(ctx, c, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := DeleteProject(ctx, c, "/acme"); err != nil {
		t.Fatal(err)
	}
	perPrincipal := map[string][]RoleBindingRecord{}
	for _, b := range liveBindings(t, c) {
		perPrincipal[b.Principal] = append(perPrincipal[b.Principal], b)
	}
	bob := perPrincipal["user:bob@local"]
	if len(bob) != 1 || bob[0].Role != SentinelRole || bob[0].Path != "/" {
		t.Fatalf("bob (bound only in the deleted project) has %+v, want exactly one NoAccess sentinel at /", bob)
	}
	if eve := perPrincipal["user:eve@local"]; len(eve) != 1 || eve[0].ID != "elsewhere" {
		t.Fatalf("eve (bound elsewhere too) has %+v, want only her /projects/beta binding", eve)
	}
	// A re-create must not remove the sentinel (it is outside the project's root).
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, b := range liveBindings(t, c) {
		if b.Principal == "user:bob@local" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("after re-create bob has %d live bindings, want his sentinel", n)
	}
}

// H2: resources that carry the project name and resolve under its RBAC root
// would be inherited by a project of the same name, so delete refuses.
func TestDeleteProject_RefusesWhileProjectOwnedResourcesExist(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		make  func(c *Client) error
		wants string
	}{
		{"network", func(c *Client) error {
			return UpsertNetwork(ctx, c, NetworkRecord{Name: "acme-net", Type: "bridge", Config: "{}", Project: "acme"})
		}, "lv network rm acme-net"},
		{"pool", func(c *Client) error {
			return UpsertStoragePool(ctx, c, StoragePoolRecord{HostName: "h1", Name: "acme-pool", Driver: "dir", Project: "/acme", State: "active"})
		}, "lv pool delete acme-pool"},
		{"backup schedule", func(c *Client) error {
			return UpsertBackupSchedule(ctx, c, BackupScheduleRecord{VMName: "@project:/acme", Repo: "r1", Scope: "project", ProjectName: "/acme", Cron: "0 2 * * *", Enabled: true})
		}, "lv backup schedule"},
		{"notification route", func(c *Client) error {
			return InsertNotificationRoute(ctx, c, NotificationRoute{ID: "route1", EventPattern: "*", Project: "/acme", TargetID: "t", Enabled: true})
		}, "lv notify route rm route1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newProjectTestClient(t)
			if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
				t.Fatal(err)
			}
			if err := tc.make(c); err != nil {
				t.Fatal(err)
			}
			err := DeleteProject(ctx, c, "/acme")
			if err == nil || !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("DeleteProject = %v, want a refusal naming %q", err, tc.wants)
			}
			if got, _ := GetProject(ctx, c, "/acme"); got == nil {
				t.Fatal("a refused delete tombstoned the project")
			}
		})
	}
}

// The same resources, left by a delete from an older build, block the re-create.
func TestProject_RecreateRefusedWhileAnOlderDeleteLeftOwnedResources(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	if err := UpsertNetwork(ctx, c, NetworkRecord{Name: "acme-net", Type: "bridge", Config: "{}", Project: "/acme"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Execute(ctx, `UPDATE projects SET deleted_at = ?, updated_at = ? WHERE name = ?`, nowRFC3339(), c.NowTS(), "/acme"); err != nil {
		t.Fatal(err)
	}
	err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"})
	if err == nil || !strings.Contains(err.Error(), "lv network rm acme-net") {
		t.Fatalf("re-create = %v, want a refusal naming the network", err)
	}
	if got, _ := GetProject(ctx, c, "/acme"); got != nil {
		t.Fatal("a refused re-create revived the project")
	}
}

// L3: deleting a project that is not live changes nothing.
func TestDeleteProject_OfAMissingProjectRevokesNothing(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertRoleBinding(ctx, c, RoleBindingRecord{ID: "pre", Path: "/projects/future", Role: "Admin", Principal: "user:alice@local", Propagate: true}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteProject(ctx, c, "/future"); err == nil {
		t.Fatal("deleting a project that does not exist succeeded")
	}
	if len(liveBindings(t, c)) != 1 {
		t.Fatal("deleting a missing project retired a pre-grant")
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/gone"}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteProject(ctx, c, "/gone"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteProject(ctx, c, "/gone"); err == nil {
		t.Fatal("deleting an already-deleted project succeeded")
	}
}

// L2: a re-create of a LIVE project fails without having revoked anything.
func TestProject_DuplicateCreateRevokesNothing(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertRoleBinding(ctx, c, RoleBindingRecord{ID: "b", Path: "/projects/acme", Role: "Admin", Principal: "user:alice@local", Propagate: true}); err != nil {
		t.Fatal(err)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err == nil {
		t.Fatal("duplicate create succeeded")
	}
	if len(liveBindings(t, c)) != 1 {
		t.Fatal("a failed duplicate create retired a live project's binding")
	}
}

// M2: another spelling of a deleted name shares its RBAC root.
func TestProject_OtherSpellingOfADeletedNameInheritsNothing(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertRoleBinding(ctx, c, RoleBindingRecord{ID: "b", Path: "/projects/acme", Role: "Admin", Principal: "user:alice@local", Propagate: true}); err != nil {
		t.Fatal(err)
	}
	// An older build's delete: tombstone only.
	if err := c.Execute(ctx, `UPDATE projects SET deleted_at = ?, updated_at = ? WHERE name = ?`, nowRFC3339(), c.NowTS(), "/acme"); err != nil {
		t.Fatal(err)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	for _, b := range liveBindings(t, c) {
		if b.ID == "b" {
			t.Fatal("a project created under another spelling inherited the old binding")
		}
	}
}
