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

// WriteFence is a test client's database cut off from a scenario's killed
// process: the commits of the client's connections are refused, and the
// client's own calls are held at its lock.
type WriteFence struct {
	c      *Client
	held   chan struct{} // closed once the fence holds the client's lock
	killed atomic.Bool
}

// FenceWritesForTests fences this client: from now on every commit of its
// connections is refused (the caller gets an error, no row changes), and the
// fence takes the client's lock, so that a call of the client's admitted
// before the fence runs to its end while a later one waits at the lock,
// asking the database nothing. Held reports when the lock is taken. It
// fences this client only; another client of the same shared test database
// (another node's) is untouched. A raw read through DB() still answers.
//
// Test clients only (NewTestClient, NewSharedTestClient); it panics on any
// other.
func (c *Client) FenceWritesForTests() *WriteFence {
	s := c.writeSever
	if s == nil {
		panic("corrosion: FenceWritesForTests on a client that is not a test client")
	}
	s.refused.Store(0)
	s.landed.Store(0)
	s.on.Store(true)
	w := &WriteFence{c: c, held: make(chan struct{})}
	go func() {
		c.mu.Lock()
		close(w.held)
	}()
	return w
}

// Held is closed once the client's lock is held: every call admitted before
// the fence has returned.
func (w *WriteFence) Held() <-chan struct{} { return w.held }

// Kill lets the held calls, and every later one, go on to a database that
// refuses all they commit. Only once Held.
func (w *WriteFence) Kill() {
	<-w.held
	if w.killed.CompareAndSwap(false, true) {
		w.c.mu.Unlock()
	}
}

// Lift ends the refusal, for the client of the process that replaces the
// dead one, once nothing of the dead one is left: it reports how many
// commits were refused, and how many rows nonetheless reached the database
// while fenced.
func (w *WriteFence) Lift() (refused, landed int64) {
	w.Kill()
	s := w.c.writeSever
	s.on.Store(false)
	return s.refused.Load(), s.landed.Load()
}
