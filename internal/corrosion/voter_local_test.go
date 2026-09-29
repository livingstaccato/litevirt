package corrosion

import (
	"context"
	"strings"
	"testing"
)

func localTestMutationLogCount(t *testing.T, c *Client) int {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT COUNT(*) AS n FROM mutation_log`)
	if err != nil {
		t.Fatalf("count mutation_log: %v", err)
	}
	return rows[0].Int("n")
}

// TestExecuteLocal_NeverWritesMutationLog: the claim tables must not be relayed.
// A promise a peer could replay is a promise a peer could write.
//
// Mutation: route ExecuteLocal through executeBatchInternal — the count moves.
func TestExecuteLocal_NeverWritesMutationLog(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	before := localTestMutationLogCount(t, c)
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO local_voter_adoption (generation, imported_from, adopted_at)
			VALUES (?, ?, ?)`, 7, "", "now")
		return err
	})
	if err != nil {
		t.Fatalf("ExecuteLocal: %v", err)
	}
	if after := localTestMutationLogCount(t, c); after != before {
		t.Fatalf("ExecuteLocal wrote %d mutation_log row(s); it must write none", after-before)
	}
	rows, err := c.Query(ctx, `SELECT generation FROM local_voter_adoption`)
	if err != nil || len(rows) != 1 || rows[0].Int("generation") != 7 {
		t.Fatalf("the local write did not land: %+v %v", rows, err)
	}
}

// TestExecuteLocal_RefusesReplicatedTable: "local" is a property the client
// checks, not a convention. A write to a replicated table through the
// non-relaying path would diverge replicas silently.
//
// Mutation: drop the table check in LocalTx.Exec — the write succeeds.
func TestExecuteLocal_RefusesReplicatedTable(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`INSERT INTO voter_configs (generation, members_json, members_hash, change, certificate, created_by, created_at, updated_at) VALUES (1,'[]','','genesis','','x','t','t')`,
		`UPDATE hosts SET state = 'fenced' WHERE name = 'x'`,
		`DELETE FROM runtime_action_proofs WHERE id = 'x'`,
		`INSERT OR REPLACE INTO host_fence_credentials (host_name, ipmi_pass, updated_at) VALUES ('x','y','t')`,
	} {
		err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
			_, err := tx.Exec(ctx, stmt)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "replicated") {
			t.Errorf("ExecuteLocal accepted a write to a replicated table:\n  %s\n  err=%v", stmt, err)
		}
	}
}

// TestVoterIncarnation_MintedOnceAndSurvivesReopen: the incarnation is the
// identity of THIS state.db's claim state. It survives a restart and changes
// when the database is recreated (§3.11).
//
// Mutation: mint the incarnation on every InitSchema (INSERT OR REPLACE) — the
// reopened database reports a different one.
func TestVoterIncarnation_MintedOnceAndSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	open := func() *Client {
		c, err := NewLocalClient(dir, "node-a")
		if err != nil {
			t.Fatal(err)
		}
		if err := InitSchema(ctx, c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := open()
	first, err := c.VoterIncarnation(ctx)
	if err != nil || first == "" {
		t.Fatalf("incarnation after first init: %q %v", first, err)
	}
	c.Close()

	c = open()
	again, err := c.VoterIncarnation(ctx)
	c.Close()
	if err != nil || again != first {
		t.Fatalf("incarnation changed across a restart: %q -> %q (%v)", first, again, err)
	}

	other := open2(t, t.TempDir())
	fresh, err := other.VoterIncarnation(ctx)
	if err != nil || fresh == "" || fresh == first {
		t.Fatalf("a fresh state.db must mint a fresh incarnation, got %q (first %q, err %v)", fresh, first, err)
	}
}

func open2(t *testing.T, dir string) *Client {
	t.Helper()
	c, err := NewLocalClient(dir, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestSynchronousFull_OnDiskDSN: a voter must not reply before its promise is
// on disk, so state.db is opened with synchronous=FULL rather than trusting the
// driver's compiled default (§3.7).
//
// modernc.org/sqlite's compiled default is already FULL on a WAL database, so
// the level check alone cannot tell the pragma from the default — the DSN check
// is what pins it.
//
// Mutation: drop the pragma from sqliteDSN — the DSN assertion goes red.
func TestSynchronousFull_OnDiskDSN(t *testing.T) {
	if dsn := sqliteDSN("/x/state.db"); !strings.Contains(dsn, "_pragma=synchronous(full)") {
		t.Fatalf("state.db DSN does not set synchronous(full): %s", dsn)
	}
	c := open2(t, t.TempDir())
	lvl, err := c.SynchronousLevel(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if lvl < SynchronousFull {
		t.Fatalf("state.db opened with synchronous=%d; claims need >= %d (FULL)", lvl, SynchronousFull)
	}
}

// TestNodeLocalClaimTablesAreNotReplicated: the tables ExecuteLocal may write
// are in no sync path.
func TestNodeLocalClaimTablesAreNotReplicated(t *testing.T) {
	for table := range nodeLocalClaimTables {
		if IsReplicatedTable(table) {
			t.Errorf("%s is writable through ExecuteLocal but is replicated", table)
		}
	}
	if !IsReplicatedTable("voter_configs") {
		t.Error("voter_configs must be replicated")
	}
}
