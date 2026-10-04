package corrosion

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// TestConnPool_ConcurrentReadersKeepTheirConnections: a burst of concurrent
// readers must find its connections in the pool the next time, not open them
// again. database/sql keeps only two idle connections by default, so every
// burst wider than two closed the rest on release and reopened them on the
// next burst — and a fresh SQLite connection runs the DSN's PRAGMAs and
// parses the whole schema before its first statement. Readers do that while
// holding c.mu's read side, so a writer queued behind them waits for every
// reopen. Under -race a reopen cost ~300 ms, a fleet node reopened ~37 a
// second, and a recovery-claim voter's promise waited past the proposer's
// 3 s call timeout to begin its local transaction
// (TestFleet_PartitionSettle_DualRunSettlesToTheCertifiedCopy timing out).
//
// Mutation: drop the pool sizing in openHookedDB — the second burst finds
// two idle connections, opens six, and closes six on release.
func TestConnPool_ConcurrentReadersKeepTheirConnections(t *testing.T) {
	const width = 8 // concurrent readers a busy node has at once, well inside the pool
	for _, tc := range []struct {
		name string
		open func(t *testing.T) *Client
	}{
		{"in-memory test client", func(t *testing.T) *Client { return NewTestClientT(t) }},
		{"production DSN", func(t *testing.T) *Client {
			c, err := NewLocalClient(t.TempDir(), "node-a")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Close() })
			return c
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := tc.open(t)
			if err := InitSchema(ctx, c); err != nil {
				t.Fatal(err)
			}
			burst := func() {
				conns := make([]*sql.Conn, 0, width)
				for i := 0; i < width; i++ {
					conn, err := c.db.Conn(ctx)
					if err != nil {
						t.Fatal(err)
					}
					var n int
					if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM hosts`).Scan(&n); err != nil {
						t.Fatal(err)
					}
					conns = append(conns, conn)
				}
				for _, conn := range conns {
					_ = conn.Close() // back to the pool
				}
			}
			for round := 0; round < 5; round++ {
				burst()
			}
			st := c.db.Stats()
			if st.MaxIdleClosed != 0 || st.OpenConnections < width {
				t.Fatalf("a burst of %d readers churned the pool: %d connections closed for want of an idle slot, %d open after the bursts",
					width, st.MaxIdleClosed, st.OpenConnections)
			}
		})
	}
}

// TestTestClient_SurvivesThePoolReapingEveryIdleConnection: a test client's
// in-memory database must outlive the pool's idle reaping. A shared-cache
// in-memory database exists only while some connection to it is open, and
// the pool closes a connection nobody has used for maxConnIdleTime (2 min).
// A test that sat idle that long — TestRunSupersededGC_TombstonesOldResolvedHealthConditions
// sleeps 121 s waiting out runSupersededGC's first delay — lost every
// connection, the database with them, and its next query opened a fresh,
// empty one: "no such table: health_conditions". The test client therefore
// pins a connection of its own for as long as it is open.
//
// The idle time is shortened here so the reaping happens in a second rather
// than two minutes; OpenConnections reaching zero proves the pool really did
// close everything it held, so the query afterwards is not vacuous.
//
// Mutation: drop the keeper connection from openTestDB — the query fails
// with "no such table".
func TestTestClient_SurvivesThePoolReapingEveryIdleConnection(t *testing.T) {
	for _, tc := range []struct {
		name string
		open func(t *testing.T) *Client
	}{
		{"NewTestClientT", func(t *testing.T) *Client { return NewTestClientT(t) }},
		{"NewSharedTestClient", func(t *testing.T) *Client {
			c, err := NewSharedTestClient(t.Name(), "node-a")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Close() })
			return c
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := tc.open(t)
			if err := InitSchema(ctx, c); err != nil {
				t.Fatalf("InitSchema: %v", err)
			}
			c.db.SetConnMaxIdleTime(100 * time.Millisecond)
			deadline := time.Now().Add(10 * time.Second)
			for c.db.Stats().OpenConnections > 0 {
				if time.Now().After(deadline) {
					t.Fatalf("pool still holds %d connections; the idle reaping never ran", c.db.Stats().OpenConnections)
				}
				time.Sleep(50 * time.Millisecond)
			}
			if _, err := ListHealthConditions(ctx, c, true); err != nil {
				t.Fatalf("query after the pool closed its idle connections: %v", err)
			}
		})
	}
}

// TestTestClient_CloseReleasesTheDatabase: the keeper that holds a test
// client's database open must not outlive the client. modernc's sqlite
// allocates outside the Go heap, so a database kept alive past Close is the
// unseen ~2 MB per test that once grew the grpcapi test binary to 4.4 GB.
//
// Mutation: drop the memKeeper Close from Client.Close — a fresh handle on
// the same DSN still finds the schema.
func TestTestClient_CloseReleasesTheDatabase(t *testing.T) {
	ctx := context.Background()
	c, err := NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	dsn := c.dsn
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	probe, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	var n int
	if err := probe.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master`).Scan(&n); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if n != 0 {
		t.Fatalf("a fresh handle on a closed test client's DSN finds %d schema objects; the database outlived Close", n)
	}
}
