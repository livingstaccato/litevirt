package corrosion

import (
	"context"
	"strings"
	"testing"
)

// A deploy's record and firewall intent are one replicated entry, intent
// first, so a receiver, which applies an entry in one transaction, never
// holds the new record without the intent written with it.
//
// Mutation: write them as two Executes — two entries, red.
func TestUpsertStackWithFirewallIntent_IsOneEntry(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.SetClusterPolicyGate(func() bool { return true })
	var before int64
	if err := c.db.QueryRow(`SELECT COALESCE(MAX(seq), 0) FROM mutation_log`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := UpsertStackWithFirewallIntent(ctx, c, StackRecord{Name: "s", ComposeYAML: "name: s\n", State: "active"}, true, true, "n"); err != nil {
		t.Fatal(err)
	}
	rows, err := c.Query(ctx, `SELECT stmts FROM mutation_log WHERE seq > ?`, before)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("the record and the intent are %d entries, want one", len(rows))
	}
	stmts := rows[0].String("stmts")
	i, r := strings.Index(stmts, "stack_firewall/s"), strings.Index(stmts, "INSERT INTO stacks")
	if i < 0 || r < 0 || i > r {
		t.Errorf("the entry does not carry the intent, then the record: %s", stmts)
	}
}
