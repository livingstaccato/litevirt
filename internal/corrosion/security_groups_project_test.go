package corrosion

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

func sgProjectsDB(t *testing.T) *Client {
	t.Helper()
	db := NewTestClientT(t)
	if err := InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return db
}

// loggedSGStatements is every replicated statement on security_groups.
func loggedSGStatements(t *testing.T, db *Client) []string {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT stmts FROM mutation_log`)
	if err != nil {
		t.Fatalf("read mutation_log: %v", err)
	}
	var out []string
	for _, r := range rows {
		if s := r.String("stmts"); strings.Contains(s, "security_groups") {
			out = append(out, s)
		}
	}
	return out
}

// A project group is a statement shape a previous-release peer cannot decode,
// so it is written only through the release feature sg_projects: without that
// feature's grant it is refused with nothing logged for replication, and the
// global writer never takes it.
func TestInsertProjectSecurityGroup_NeedsTheFeaturesGrant(t *testing.T) {
	ctx := context.Background()
	db := sgProjectsDB(t)
	row := SecurityGroup{ID: "sg-p", Name: "web", Project: "acme"}

	if err := InsertProjectSecurityGroup(ctx, db, capabilities.FeatureGrant{}, row); err == nil {
		t.Fatal("a project group was written with no grant")
	}
	if err := InsertProjectSecurityGroup(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureFirewallLog), row); err == nil {
		t.Fatal("a project group was written with another feature's grant")
	}
	if err := InsertSecurityGroup(ctx, db, row); err == nil {
		t.Fatal("the global writer wrote a project group, bypassing the release feature")
	}
	if got, _ := GetSecurityGroup(ctx, db, "sg-p"); got != nil {
		t.Fatalf("a refused project group was stored: %+v", got)
	}
	if stmts := loggedSGStatements(t, db); len(stmts) != 0 {
		t.Fatalf("a refused project group reached the replication log: %v", stmts)
	}
}

// A global group keeps the previous release's statement shape, never names
// the column and needs no feature: a previous-release peer applies it.
func TestInsertSecurityGroup_AGlobalGroupKeepsThePreviousShape(t *testing.T) {
	ctx := context.Background()
	db := sgProjectsDB(t)

	if err := InsertSecurityGroup(ctx, db, SecurityGroup{ID: "sg-g", Name: "base"}); err != nil {
		t.Fatalf("global group: %v", err)
	}
	stmts := loggedSGStatements(t, db)
	if len(stmts) != 1 {
		t.Fatalf("logged %d security_groups statements, want 1: %v", len(stmts), stmts)
	}
	if strings.Contains(stmts[0], "project") {
		t.Fatalf("a global group's insert names the project column, which a previous-release peer cannot decode:\n%s", stmts[0])
	}
	got, err := GetSecurityGroup(ctx, db, "sg-g")
	if err != nil || got == nil || got.Project != "" {
		t.Fatalf("global group read back as %+v (%v), want project ''", got, err)
	}
}

// With the grant, the project is stored and read back by every reader.
func TestInsertProjectSecurityGroup_StoresTheProject(t *testing.T) {
	ctx := context.Background()
	db := sgProjectsDB(t)

	if err := InsertProjectSecurityGroup(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureSGProjects),
		SecurityGroup{ID: "sg-p", Name: "web", Project: "acme"}); err != nil {
		t.Fatalf("project group with the grant: %v", err)
	}
	if got, err := GetSecurityGroup(ctx, db, "sg-p"); err != nil || got == nil || got.Project != "acme" {
		t.Fatalf("GetSecurityGroup = %+v (%v), want project acme", got, err)
	}
	all, err := ListSecurityGroups(ctx, db, "")
	if err != nil || len(all) != 1 || all[0].Project != "acme" {
		t.Fatalf("ListSecurityGroups = %+v (%v), want one group of project acme", all, err)
	}
	stmts := loggedSGStatements(t, db)
	if len(stmts) != 1 || !strings.Contains(stmts[0], "project") {
		t.Fatalf("the project group's insert does not carry the project: %v", stmts)
	}
}

// A project that still owns a security group is not deleted: a later project
// of the same name would inherit the group and its rules.
func TestDeleteProject_RefusesWhileItOwnsSecurityGroups(t *testing.T) {
	ctx := context.Background()
	db := sgProjectsDB(t)
	if err := InsertProject(ctx, db, ProjectRecord{Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertProjectSecurityGroup(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureSGProjects),
		SecurityGroup{ID: "sg-p", Name: "web", Project: "acme"}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteProject(ctx, db, "acme"); err == nil || !strings.Contains(err.Error(), "security groups") {
		t.Fatalf("DeleteProject with a live group: %v, want a refusal naming security groups", err)
	}
	if err := DeleteSecurityGroup(ctx, db, "sg-p"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteProject(ctx, db, "acme"); err != nil {
		t.Fatalf("DeleteProject once the group is gone: %v", err)
	}
}

// An existing group migrates as global: the column is added with ” and no
// row is rewritten.
func TestSecurityGroupsProjectColumn_ExistingRowsAreGlobal(t *testing.T) {
	ctx := context.Background()
	db := sgProjectsDB(t)
	if err := db.execLocal(ctx, `INSERT INTO security_groups (id, name, stack_name, created_at, updated_at)
		VALUES ('sg-old', 'legacy', '', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	got, err := GetSecurityGroup(ctx, db, "sg-old")
	if err != nil || got == nil || got.Project != "" {
		t.Fatalf("pre-existing group = %+v (%v), want global (project '')", got, err)
	}
}
