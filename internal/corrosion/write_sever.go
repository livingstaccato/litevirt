package corrosion

import (
	"sync"
	"sync/atomic"
)

// writeSever is a test client's write switch (FenceWritesForTests). Fenced,
// the client's own calls wait at its lock and nothing is refused; once the
// fence holds the lock, a commit that still reaches the database got past
// the lock (a raw DB() write) and is counted. Dead, SQLite rolls back every
// commit of the client's connections (their commit hook), however it was
// written. It also counts, apart from that decision, the rows each commit
// carried into the database while dead: zero unless the refusal is broken.
type writeSever struct {
	state       atomic.Int32 // severOff, severFenced, severHeld or severDead
	refused     atomic.Int64
	landed      atomic.Int64
	pastTheLock atomic.Int64
}

const (
	severOff int32 = iota
	severFenced
	severHeld
	severDead
)

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
	switch c.s.state.Load() {
	case severHeld:
		c.s.pastTheLock.Add(1)
		return 0
	case severDead:
		if refuse := c.s.refuse(); refuse != 0 {
			return refuse
		}
		c.s.landed.Add(rows)
	}
	return 0
}

// rollback is the connection's rollback hook: the open transaction's rows
// are gone.
func (c *severConn) rollback() { c.rows.Store(0) }

// refuse is the sever's decision on a commit of a dead client.
func (s *writeSever) refuse() int32 {
	s.refused.Add(1)
	return 1
}

// WriteFence is a test client cut off from the database for a scenario's
// killed process.
type WriteFence struct {
	c    *Client
	held chan struct{} // closed once the fence holds the client's lock
	once sync.Once
}

// FenceWritesForTests fences this client: the fence takes the client's
// lock, so a call of the client's admitted before the fence runs to its end,
// commits included, and a later one waits at the lock, asking the database
// nothing and learning nothing. Nothing is refused until Kill. Held reports
// when the lock is taken. It fences this client only; another client of the
// same shared test database (another node's) is untouched. A raw read
// through DB() still answers; a raw write is counted (PastTheLock).
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
	s.pastTheLock.Store(0)
	s.state.Store(severFenced)
	w := &WriteFence{c: c, held: make(chan struct{})}
	go func() {
		c.mu.Lock()
		s.state.CompareAndSwap(severFenced, severHeld)
		close(w.held)
	}()
	return w
}

// Held is closed once the client's lock is held: every call admitted before
// the fence has returned.
func (w *WriteFence) Held() <-chan struct{} { return w.held }

// PastTheLock is how many commits reached the database through this client's
// connections while the fence held its lock: writes that bypassed the
// client (raw DB() statements).
func (w *WriteFence) PastTheLock() int64 { return w.c.writeSever.pastTheLock.Load() }

// Kill refuses every commit of the client's connections from now on, and
// lets the held calls, and every later one, go on to that refusal once the
// fence holds the lock (at once when it does).
func (w *WriteFence) Kill() {
	w.c.writeSever.state.Store(severDead)
	select {
	case <-w.held:
		w.release()
	default:
		go w.release()
	}
}

// release gives the client's lock back once the fence holds it.
func (w *WriteFence) release() {
	<-w.held
	w.once.Do(func() { w.c.mu.Unlock() })
}

// Lift ends the refusal, for the client of the process that replaces the
// dead one, once nothing of the dead one is left: it reports how many
// commits were refused, and how many rows nonetheless reached the database
// while dead.
func (w *WriteFence) Lift() (refused, landed int64) {
	w.release()
	s := w.c.writeSever
	s.state.Store(severOff)
	return s.refused.Load(), s.landed.Load()
}
