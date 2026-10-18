package corrosion

import (
	"context"
	"errors"
	"strings"
	"testing"
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
// so it is refused, with nothing logged for replication, until sg_projects_v1
// has latched. The gate fails closed when it was never wired.
func TestInsertSecurityGroup_AProjectGroupWaitsForTheLatch(t *testing.T) {
	ctx := context.Background()
	db := sgProjectsDB(t)

	err := InsertSecurityGroup(ctx, db, SecurityGroup{ID: "sg-p", Name: "web", Project: "acme"})
	if !errors.Is(err, ErrSGProjectsNotLatched) {
		t.Fatalf("project group with the gate unwired: %v, want ErrSGProjectsNotLatched", err)
	}
	db.SetSGProjectsGate(func() bool { return false })
	err = InsertSecurityGroup(ctx, db, SecurityGroup{ID: "sg-p", Name: "web", Project: "acme"})
	if !errors.Is(err, ErrSGProjectsNotLatched) {
		t.Fatalf("project group with the gate closed: %v, want ErrSGProjectsNotLatched", err)
	}
	if got, _ := GetSecurityGroup(ctx, db, "sg-p"); got != nil {
		t.Fatalf("a refused project group was stored: %+v", got)
	}
	if stmts := loggedSGStatements(t, db); len(stmts) != 0 {
		t.Fatalf("a refused project group reached the replication log: %v", stmts)
	}
}

// A global group keeps the previous release's statement shape, never names
// the column and is never gated: a previous-release peer applies it.
func TestInsertSecurityGroup_AGlobalGroupKeepsThePreviousShape(t *testing.T) {
	ctx := context.Background()
	db := sgProjectsDB(t)

	if err := InsertSecurityGroup(ctx, db, SecurityGroup{ID: "sg-g", Name: "base"}); err != nil {
		t.Fatalf("global group with the gate unwired: %v", err)
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

// Once latched, the project is stored and read back by every reader.
func TestInsertSecurityGroup_AProjectGroupAfterTheLatch(t *testing.T) {
	ctx := context.Background()
	db := sgProjectsDB(t)
	db.SetSGProjectsGate(func() bool { return true })

	if err := InsertSecurityGroup(ctx, db, SecurityGroup{ID: "sg-p", Name: "web", Project: "acme"}); err != nil {
		t.Fatalf("project group after the latch: %v", err)
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
