package corrosion

import (
	"context"
	"strings"
	"testing"
)

// A severed test client commits nothing, by any path — a replicated write, a
// raw statement on its pool — while another client of the same shared
// database (another node's) writes as before; once restored it writes
// again.
//
// Mutation: refuse returns 0 — the severed writes land, and the landed
// count reports their rows, red.
func TestSeverWritesForTests_RefusesOnlyTheSeveredClient(t *testing.T) {
	ctx := context.Background()
	suffix := strings.ReplaceAll(t.Name(), "/", "_")
	a, err := NewSharedTestClient(suffix, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	b, err := NewSharedTestClient(suffix, "node-b")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	if err := InitSchema(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DB().ExecContext(ctx, `CREATE TABLE sever_probe (k TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	// The replicated write path works before the sever, so its failure
	// below is the sever's.
	if err := a.Execute(ctx, `INSERT INTO sever_probe (k) VALUES ('before')`); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DB().ExecContext(ctx, `DELETE FROM sever_probe`); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		t.Helper()
		var n int
		if err := b.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM sever_probe`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	restore := a.SeverWritesForTests()
	if _, err := a.DB().ExecContext(ctx, `INSERT INTO sever_probe (k) VALUES ('raw')`); err == nil {
		t.Error("a raw write on the severed client succeeded")
	}
	if err := a.Execute(ctx, `INSERT INTO sever_probe (k) VALUES ('replicated')`); err == nil {
		t.Error("a replicated write on the severed client succeeded")
	}
	if n := count(); n != 0 {
		t.Errorf("%d rows written through the severed client", n)
	}
	// Reads still answer.
	if _, err := a.Query(ctx, `SELECT k FROM sever_probe`); err != nil {
		t.Errorf("a read on the severed client: %v", err)
	}
	if _, err := b.DB().ExecContext(ctx, `INSERT INTO sever_probe (k) VALUES ('other')`); err != nil {
		t.Errorf("another client's write while a is severed: %v", err)
	}
	refused, landed := restore()
	if refused < 2 {
		t.Errorf("the sever refused %d commits, want at least 2", refused)
	}
	if landed != 0 {
		t.Errorf("%d rows reached the database through the severed client", landed)
	}
	if _, err := a.DB().ExecContext(ctx, `INSERT INTO sever_probe (k) VALUES ('after')`); err != nil {
		t.Errorf("a write after restore: %v", err)
	}
	if n := count(); n != 2 {
		t.Errorf("%d rows, want 2 (the other client's and the one after restore)", n)
	}
}
