package corrosion

import (
	"context"
	"database/sql"
	"testing"
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
