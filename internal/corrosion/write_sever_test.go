package corrosion

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A severed test client commits nothing, by any path — a replicated write, a
// raw statement on its pool — while another client of the same shared
// database (another node's) writes as before; once restored it writes
// again.
//
// Mutation: refuse returns 0 — the severed writes land, and the landed
// count reports their rows, red.
func TestFenceWritesForTests_RefusesOnlyTheSeveredClient(t *testing.T) {
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

	fence := a.FenceWritesForTests()
	<-fence.Held()
	fence.Kill()
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
	refused, landed := fence.Lift()
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

// A call of the client's admitted before the fence runs to its end and the
// fence is held only then; a later call waits at the client's lock until the
// kill, and its commit is then refused.
//
// Mutation: the fence does not take the client's lock — the later write
// runs while fenced, before the kill, red.
func TestFenceWritesForTests_HoldsLaterCallsUntilTheKill(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DB().ExecContext(ctx, `CREATE TABLE fence_probe (k TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	fence := c.FenceWritesForTests()
	select {
	case <-fence.Held():
	case <-time.After(10 * time.Second):
		t.Fatal("the fence did not take an idle client's lock")
	}
	ran := make(chan error, 1)
	go func() { ran <- c.Execute(ctx, `INSERT INTO fence_probe (k) VALUES ('late')`) }()
	select {
	case err := <-ran:
		t.Fatalf("a write on the fenced client ran before the kill (%v)", err)
	case <-time.After(200 * time.Millisecond):
	}
	fence.Kill()
	if err := <-ran; err == nil {
		t.Error("the held write was not refused once killed")
	}
	if _, landed := fence.Lift(); landed != 0 {
		t.Errorf("%d rows landed", landed)
	}
}
