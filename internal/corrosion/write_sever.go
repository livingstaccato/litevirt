package corrosion

import "sync/atomic"

// writeSever is a test client's write switch: while on, SQLite rolls back
// every transaction one of the client's connections commits (its commit
// hook), so nothing the client writes reaches the database, however it
// writes (Execute, a raw DB() statement, a guarded batch, a local-only
// table). It also counts, apart from that decision, the rows each commit
// carried into the database while on: zero unless the refusal is broken.
type writeSever struct {
	on      atomic.Bool
	refused atomic.Int64
	landed  atomic.Int64
}

// severConn is one connection's view of its client's sever: the rows its
// open transaction has changed so far (pre-update hook).
type severConn struct {
	s    *writeSever
	rows atomic.Int64
}

func (s *writeSever) conn() *severConn { return &severConn{s: s} }

// staged counts one row change of the open transaction.
func (c *severConn) staged() { c.rows.Add(1) }

// commit is the connection's commit hook: non-zero turns the commit into a
// rollback.
func (c *severConn) commit() int32 {
	rows := c.rows.Swap(0)
	if !c.s.on.Load() {
		return 0
	}
	if refuse := c.s.refuse(); refuse != 0 {
		return refuse
	}
	c.s.landed.Add(rows)
	return 0
}

// rollback is the connection's rollback hook: the open transaction's rows
// are gone.
func (c *severConn) rollback() { c.rows.Store(0) }

// refuse is the sever's decision on a commit while on.
func (s *writeSever) refuse() int32 {
	s.refused.Add(1)
	return 1
}

// SeverWritesForTests refuses everything this client commits until restore:
// a scenario's killed process, whose connection the database no longer
// hears. The caller gets an error and no row changes. It severs this client
// only; another client of the same shared test database (another node's)
// writes as before. restore reports how many commits it refused, and how
// many rows nonetheless reached the database while severed.
//
// Test clients only (NewTestClient, NewSharedTestClient); it panics on any
// other.
func (c *Client) SeverWritesForTests() (restore func() (refused, landed int64)) {
	s := c.writeSever
	if s == nil {
		panic("corrosion: SeverWritesForTests on a client that is not a test client")
	}
	s.refused.Store(0)
	s.landed.Store(0)
	s.on.Store(true)
	return func() (int64, int64) {
		s.on.Store(false)
		return s.refused.Load(), s.landed.Load()
	}
}
