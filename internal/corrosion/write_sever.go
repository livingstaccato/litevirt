package corrosion

import "sync/atomic"

// writeSever is a test client's write switch: while on, SQLite rolls back
// every transaction one of the client's connections commits (its commit
// hook), so nothing the client writes reaches the database, however it
// writes (Execute, a raw DB() statement, a guarded batch).
type writeSever struct {
	on      atomic.Bool
	refused atomic.Int64
}

// commit is the connections' commit hook: non-zero turns the commit into a
// rollback.
func (s *writeSever) commit() int32 {
	if !s.on.Load() {
		return 0
	}
	s.refused.Add(1)
	return 1
}

// SeverWritesForTests refuses everything this client commits until restore:
// a scenario's killed process, whose connection the database no longer
// hears. The caller gets an error and no row changes. It severs this client
// only; another client of the same shared test database (another node's)
// writes as before. restore reports how many commits it refused.
//
// Test clients only (NewTestClient, NewSharedTestClient); it panics on any
// other.
func (c *Client) SeverWritesForTests() (restore func() (refused int64)) {
	s := c.writeSever
	if s == nil {
		panic("corrosion: SeverWritesForTests on a client that is not a test client")
	}
	s.refused.Store(0)
	s.on.Store(true)
	return func() int64 {
		s.on.Store(false)
		return s.refused.Load()
	}
}
