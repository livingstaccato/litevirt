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
	// eve keeps her /projects/beta binding AND is left a sentinel: "keeps a
	// binding elsewhere" cannot be decided from a snapshot (see
	// TestFleet_ConcurrentProjectDeletesNeverUnbindAUser).
	eveKept, eveSentinel := false, false
	for _, b := range perPrincipal["user:eve@local"] {
		eveKept = eveKept || b.ID == "elsewhere"
		eveSentinel = eveSentinel || (b.Role == SentinelRole && b.Path == "/")
	}
	if !eveKept || !eveSentinel || len(perPrincipal["user:eve@local"]) != 2 {
		t.Fatalf("eve has %+v, want her /projects/beta binding and one sentinel", perPrincipal["user:eve@local"])
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

// I3: a create that loses the race must not have revoked the winner's state.
// The hook is the pause between R reading the tombstone and its transaction.
func TestProject_LosingRecreateRevokesNothingOfTheWinner(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteProject(ctx, c, "/acme"); err != nil {
		t.Fatal(err)
	}
	fired := false
	projectLifecycleInterleaveHook = func() {
		if fired {
			return
		}
		fired = true
		projectLifecycleInterleaveHook = nil
		// W: wins, then the operator installs the new incarnation's state.
		if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
			t.Errorf("winner: %v", err)
			return
		}
		if err := InsertRoleBinding(ctx, c, RoleBindingRecord{ID: "new", Path: "/projects/acme", Role: "Admin", Principal: "user:carol@local", Propagate: true}); err != nil {
			t.Error(err)
		}
		if err := UpsertProjectQuota(ctx, c, ProjectQuotaRecord{ProjectName: "/acme", VCPULimit: 11}); err != nil {
			t.Error(err)
		}
		if ok, err := ClaimInitialProjectAuthority(ctx, c, "/acme", "node-2"); err != nil || !ok {
			t.Errorf("claim: ok=%v err=%v", ok, err)
		}
	}
	t.Cleanup(func() { projectLifecycleInterleaveHook = nil })
	err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("the losing create: err=%v, want already exists", err)
	}
	live := false
	for _, b := range liveBindings(t, c) {
		live = live || b.ID == "new"
	}
	if !live {
		t.Fatal("the losing create retired the winner's role binding")
	}
	if q, _ := GetProjectQuota(ctx, c, "/acme"); q == nil || q.VCPULimit != 11 {
		t.Fatalf("the losing create reset the winner's quota: %+v", q)
	}
	if a, ok, _ := CurrentProjectAuthority(ctx, c, "/acme"); !ok || a.Holder != "node-2" {
		t.Fatalf("the losing create retired the winner's authority epoch: %+v ok=%v", a, ok)
	}
}

// I3: the orphan reaper's scan and its retirement are not atomic; a re-create in
// between must keep its new epoch.
func TestReconcileOrphanedProjectAuthority_KeepsARecreatedProjectsEpoch(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := ClaimInitialProjectAuthority(ctx, c, "/acme", "node-1"); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	// An older build's delete: tombstone only, authority left live.
	if err := c.Execute(ctx, `UPDATE projects SET deleted_at = ?, updated_at = ? WHERE name = ?`, nowRFC3339(), c.NowTS(), "/acme"); err != nil {
		t.Fatal(err)
	}
	fired := false
	projectLifecycleInterleaveHook = func() {
		if fired {
			return
		}
		fired = true
		projectLifecycleInterleaveHook = nil
		if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
			t.Errorf("recreate: %v", err)
			return
		}
		if ok, err := ClaimInitialProjectAuthority(ctx, c, "/acme", "node-2"); err != nil || !ok {
			t.Errorf("claim: ok=%v err=%v", ok, err)
		}
	}
	t.Cleanup(func() { projectLifecycleInterleaveHook = nil })
	if _, err := ReconcileOrphanedProjectAuthority(ctx, c); err != nil {
		t.Fatal(err)
	}
	if a, ok, _ := CurrentProjectAuthority(ctx, c, "/acme"); !ok || a.Holder != "node-2" || a.Epoch != 2 {
		t.Fatalf("the reaper retired the re-created project's epoch: %+v ok=%v", a, ok)
	}
}

// I4: "/" and "/_default" canonicalise to RBAC roots that are not the row's own.
// A row that already exists under such a name (nothing creates one now) must
// delete without touching anyone else's grants.
func TestDeleteProject_UnsafeNamesRetireNoPrefixGrants(t *testing.T) {
	for _, name := range []string{"/", "//", "/_default"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			c := newProjectTestClient(t)
			if err := InsertProject(ctx, c, ProjectRecord{Name: name}); err != nil {
				t.Fatal(err)
			}
			for _, b := range []RoleBindingRecord{
				{ID: "other", Path: "/projects/beta/vms/x", Role: "Operator", Principal: "user:bob@local"},
				{ID: "dflt", Path: "/projects/_default/vms/y", Role: "Operator", Principal: "user:carol@local", Propagate: true},
				{ID: "dflt-root", Path: "/projects/_default", Role: "Viewer", Principal: "user:dave@local", Propagate: true},
			} {
				if err := InsertRoleBinding(ctx, c, b); err != nil {
					t.Fatal(err)
				}
			}
			if err := DeleteProject(ctx, c, name); err != nil {
				t.Fatalf("delete %q: %v", name, err)
			}
			got := map[string]bool{}
			for _, b := range liveBindings(t, c) {
				got[b.ID] = true
			}
			for _, id := range []string{"other", "dflt", "dflt-root"} {
				if !got[id] {
					t.Fatalf("deleting project %q retired the unrelated grant %q", name, id)
				}
			}
		})
	}
}

// R1: an existing row whose name the validator refuses (an older build made it)
// must delete without retiring a live parent project's resource grants.
func TestDeleteProject_LegacyReservedSegmentRowKeepsParentGrants(t *testing.T) {
	for _, seg := range []string{"vms", "containers", "networks", "storage_pools", "security_groups", "stacks"} {
		t.Run(seg, func(t *testing.T) {
			ctx := context.Background()
			c := newProjectTestClient(t)
			child := "/acme/" + seg
			for _, p := range []ProjectRecord{{Name: "/acme"}, {Name: child, ParentName: "/acme"}} {
				if err := InsertProject(ctx, c, p); err != nil {
					t.Fatal(err)
				}
			}
			if err := InsertRoleBinding(ctx, c, RoleBindingRecord{ID: "res", Path: "/projects/acme/" + seg + "/x", Role: "Operator", Principal: "user:bob@local"}); err != nil {
				t.Fatal(err)
			}
			if err := DeleteProject(ctx, c, child); err != nil {
				t.Fatal(err)
			}
			for _, b := range liveBindings(t, c) {
				if b.ID == "res" {
					return
				}
			}
			t.Fatalf("deleting legacy row %s retired live project /acme's grant on /projects/acme/%s/x", child, seg)
		})
	}
}

// R2: a delete decided while no other spelling was live must not retire the
// fresh grants of a sibling spelling revived before its transaction.
func TestDeleteProject_DoesNotRetireARevivedSpellingsFreshGrant(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteProject(ctx, c, "/acme"); err != nil {
		t.Fatal(err)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	fired := false
	projectSpellingsReadHook = func() {
		if fired {
			return
		}
		fired = true
		projectSpellingsReadHook = nil
		if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
			t.Errorf("revive sibling: %v", err)
			return
		}
		if err := InsertRoleBinding(ctx, c, RoleBindingRecord{ID: "fresh", Path: "/projects/acme", Role: "Operator", Principal: "user:carol@local", Propagate: true}); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { projectSpellingsReadHook = nil })
	if err := DeleteProject(ctx, c, "acme"); err == nil {
		t.Fatal("the delete went through although a sibling spelling was revived under it")
	}
	for _, b := range liveBindings(t, c) {
		if b.ID == "fresh" {
			return
		}
	}
	t.Fatal("the delete of one spelling retired a grant of the live sibling spelling /acme")
}

// R3: a principal holding a grant outside /projects/ (root scope, group-held)
// gets no sentinel: it would turn a later revoke of that grant into a lockout.
func TestDeleteProject_NoSentinelForAPrincipalWithRootScopeAuthority(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	for _, b := range []RoleBindingRecord{
		{ID: "root-admin", Path: "/", Role: "Admin", Principal: "group:admin@local", Propagate: true},
		{ID: "p-admin", Path: "/projects/p", Role: "Admin", Principal: "group:admin@local", Propagate: true},
	} {
		if err := InsertRoleBinding(ctx, c, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := DeleteProject(ctx, c, "/p"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteRoleBinding(ctx, c, "root-admin"); err != nil {
		t.Fatal(err)
	}
	for _, b := range liveBindings(t, c) {
		if b.Principal == "group:admin@local" {
			t.Fatalf("group:admin@local is still bound after its root grant was revoked: %+v "+
				"(every legacy admin would be bound to NoAccess only)", b)
		}
	}
}

// M8: one sentinel per principal, however many projects it loses.
func TestDeleteProject_OneSentinelPerPrincipal(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	for _, n := range []string{"/p", "/q", "/r"} {
		if err := InsertProject(ctx, c, ProjectRecord{Name: n}); err != nil {
			t.Fatal(err)
		}
		if err := InsertRoleBinding(ctx, c, RoleBindingRecord{ID: "u" + n, Path: "/projects" + n, Role: "Operator", Principal: "user:u@local"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"/p", "/q", "/r"} {
		if err := DeleteProject(ctx, c, n); err != nil {
			t.Fatal(err)
		}
	}
	sentinels := 0
	for _, b := range liveBindings(t, c) {
		if b.Principal == "user:u@local" {
			if b.Role != SentinelRole {
				t.Fatalf("a granting binding survived: %+v", b)
			}
			sentinels++
		}
	}
	if sentinels != 1 {
		t.Fatalf("u has %d sentinels after losing three projects, want 1", sentinels)
	}
}

// M6: a delete decided on a snapshot must lose to a delete-and-re-create that
// happened since, instead of tombstoning the new project and its fresh grant.
func TestDeleteProject_LosesToAConcurrentDeleteAndRecreate(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	fired := false
	projectLifecycleInterleaveHook = func() {
		if fired {
			return
		}
		fired = true
		projectLifecycleInterleaveHook = nil
		if err := DeleteProject(ctx, c, "/acme"); err != nil {
			t.Errorf("W delete: %v", err)
			return
		}
		if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
			t.Errorf("W recreate: %v", err)
			return
		}
		if err := InsertRoleBinding(ctx, c, RoleBindingRecord{ID: "fresh", Path: "/projects/acme", Role: "Admin", Principal: "user:carol@local", Propagate: true}); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { projectLifecycleInterleaveHook = nil })
	if err := DeleteProject(ctx, c, "/acme"); err == nil {
		t.Fatal("the stale delete succeeded")
	}
	if got, _ := GetProject(ctx, c, "/acme"); got == nil {
		t.Fatal("the stale delete tombstoned the re-created project")
	}
	found := false
	for _, b := range liveBindings(t, c) {
		found = found || b.ID == "fresh"
	}
	if !found {
		t.Fatal("the stale delete retired the re-created project's fresh grant")
	}
}

// M7: revive, then delete, then a stale revive: the guard pins the tombstone it
// read (updated_at), not merely "some tombstone".
func TestProject_StaleReviveLosesAfterReviveAndDelete(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteProject(ctx, c, "/acme"); err != nil {
		t.Fatal(err)
	}
	fired := false
	projectLifecycleInterleaveHook = func() {
		if fired {
			return
		}
		fired = true
		projectLifecycleInterleaveHook = nil
		if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
			t.Errorf("W revive: %v", err)
			return
		}
		if err := DeleteProject(ctx, c, "/acme"); err != nil {
			t.Errorf("W delete: %v", err)
		}
	}
	t.Cleanup(func() { projectLifecycleInterleaveHook = nil })
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err == nil {
		t.Fatal("the stale revive succeeded over a later tombstone")
	}
	if got, _ := GetProject(ctx, c, "/acme"); got != nil {
		t.Fatalf("the stale revive brought back a project deleted after it read: %+v", got)
	}
}
