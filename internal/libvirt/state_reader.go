package libvirt

import (
	"errors"
	"fmt"
	"sync"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// libvirtd serves at most max_client_requests (default 5) requests of one
// client connection at a time; past that it stops reading the connection, and
// every later request on it waits, whatever domain it names, until one of
// those returns. A call naming a domain whose start waits on storage that
// does not answer does not return (the start holds the domain's lock), and
// neither does one that lists every domain. The daemon's background loops make
// such calls on its one connection, so on a host where libvirt hangs on one
// domain a handful of them fill it, and libvirt answers nothing more on it,
// for any domain, while another connection is answered at once (lab 2,
// 03fe9868 B2: `lv ls` read a healthy VM unknown; `virsh domstate` of it
// answered in 23 ms).
//
// A StateReader asks for domain states on connections of its own. A
// connection one of whose calls has been unanswered for stallAfter takes no
// new call: the next call dials a fresh connection, and the stalled one is
// closed once its calls have returned. So a domain libvirt does not answer
// for holds a connection of its own, not every read after it.
const (
	// defaultStateStallAfter is how long a call goes unanswered before its
	// connection takes no new call. libvirt answers a state call in
	// milliseconds.
	defaultStateStallAfter = time.Second
	// maxStalledStateConns caps the stalled connections kept open. Past it,
	// calls go on the current connection although it is stalled; the caller
	// bounds its wait as before.
	maxStalledStateConns = 16
)

// StateConn is one connection's domain-state calls.
type StateConn interface {
	DomainState(name string) (string, error)
	DomainStateReason(name string) (DomainStatus, error)
	Close() error
}

// ErrStateConnUnavailable is a StateReader that could not dial a connection
// of its own: the caller may ask on its usual connection instead.
var ErrStateConnUnavailable = errors.New("no state-read connection to libvirtd")

var errStateReaderClosed = errors.New("state reader closed")

type readConn struct {
	conn   StateConn
	calls  map[uint64]time.Time // outstanding call → when asked
	broken bool                 // a call answered with a transport error
}

// oldestCall is when the longest-outstanding call on c was asked (zero if
// none is).
func (c *readConn) oldestCall() time.Time {
	var t time.Time
	for _, at := range c.calls {
		if t.IsZero() || at.Before(t) {
			t = at
		}
	}
	return t
}

// StateReader reads domain states on connections of its own (see above).
type StateReader struct {
	dial       func() (StateConn, error)
	stallAfter time.Duration

	mu      sync.Mutex
	cur     *readConn
	retired map[*readConn]struct{} // stalled or broken, closed once drained
	dialing chan struct{}          // closed when the dial in progress ends
	seq     uint64
	dials   int
	closed  bool
}

// NewStateReader is a StateReader whose connections dial makes. stallAfter
// <= 0 is defaultStateStallAfter.
func NewStateReader(dial func() (StateConn, error), stallAfter time.Duration) *StateReader {
	if stallAfter <= 0 {
		stallAfter = defaultStateStallAfter
	}
	return &StateReader{dial: dial, stallAfter: stallAfter, retired: map[*readConn]struct{}{}}
}

// DomainState is Client.DomainState, asked on the reader's connection.
func (r *StateReader) DomainState(name string) (string, error) {
	st := "unknown"
	err := r.do(func(c StateConn) error {
		var e error
		st, e = c.DomainState(name)
		return e
	})
	return st, err
}

// DomainStateReason is Client.DomainStateReason, asked on the reader's
// connection.
func (r *StateReader) DomainStateReason(name string) (DomainStatus, error) {
	st := DomainStatus{State: "unknown", Reason: "unknown"}
	err := r.do(func(c StateConn) error {
		var e error
		st, e = c.DomainStateReason(name)
		return e
	})
	return st, err
}

// Dials is how many connections the reader has dialled.
func (r *StateReader) Dials() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dials
}

// Open is how many of the reader's connections are open: the current one and
// the stalled ones not yet drained.
func (r *StateReader) Open() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(r.retired)
	if r.cur != nil {
		n++
	}
	return n
}

// Close closes every connection of the reader; a call after it fails.
func (r *StateReader) Close() error {
	r.mu.Lock()
	r.closed = true
	conns := make([]*readConn, 0, len(r.retired)+1)
	if r.cur != nil {
		conns = append(conns, r.cur)
		r.cur = nil
	}
	for c := range r.retired {
		conns = append(conns, c)
		delete(r.retired, c)
	}
	r.mu.Unlock()
	var first error
	for _, c := range conns {
		if err := c.conn.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (r *StateReader) do(call func(StateConn) error) error {
	c, id, err := r.acquire()
	if err != nil {
		return err
	}
	cerr := call(c.conn)
	r.release(c, id, cerr)
	return cerr
}

// acquire picks the connection a call goes on and records the call on it.
func (r *StateReader) acquire() (*readConn, uint64, error) {
	r.mu.Lock()
	for {
		if r.closed {
			r.mu.Unlock()
			return nil, 0, errStateReaderClosed
		}
		if c := r.cur; c != nil {
			stalled := false
			if t := c.oldestCall(); !t.IsZero() && time.Since(t) >= r.stallAfter {
				stalled = true
			}
			if !c.broken && (!stalled || len(r.retired) >= maxStalledStateConns) {
				r.seq++
				id := r.seq
				c.calls[id] = time.Now()
				r.mu.Unlock()
				return c, id, nil
			}
			// Retire it: it takes no new call, and is closed once drained.
			r.cur = nil
			r.retired[c] = struct{}{}
			if len(c.calls) == 0 {
				delete(r.retired, c)
				go c.conn.Close() //nolint:errcheck // best effort
			}
		}
		if r.dialing != nil {
			ch := r.dialing
			r.mu.Unlock()
			<-ch
			r.mu.Lock()
			continue
		}
		ch := make(chan struct{})
		r.dialing = ch
		r.dials++
		r.mu.Unlock()
		conn, err := r.dial()
		r.mu.Lock()
		r.dialing = nil
		close(ch)
		if err != nil {
			r.mu.Unlock()
			return nil, 0, fmt.Errorf("%w: %w", ErrStateConnUnavailable, err)
		}
		if r.closed {
			r.mu.Unlock()
			conn.Close() //nolint:errcheck // best effort
			return nil, 0, errStateReaderClosed
		}
		r.cur = &readConn{conn: conn, calls: map[uint64]time.Time{}}
	}
}

// release records that the call id on c has returned with err.
func (r *StateReader) release(c *readConn, id uint64, err error) {
	r.mu.Lock()
	delete(c.calls, id)
	if err != nil && isTransportError(err) {
		c.broken = true
	}
	closeIt := false
	if _, ok := r.retired[c]; ok && len(c.calls) == 0 {
		delete(r.retired, c)
		closeIt = true
	}
	r.mu.Unlock()
	if closeIt {
		c.conn.Close() //nolint:errcheck // best effort
	}
}

// isTransportError reports whether err is not an answer of libvirt's own (a
// golibvirt.Error), i.e. the connection may be gone.
func isTransportError(err error) bool {
	var lerr golibvirt.Error
	return !errors.As(err, &lerr)
}

// virtStateConn is a StateConn on a connection of its own to libvirtd.
type virtStateConn struct{ virt *golibvirt.Libvirt }

func (c virtStateConn) DomainState(name string) (string, error) {
	return domainState(c.virt, name)
}

func (c virtStateConn) DomainStateReason(name string) (DomainStatus, error) {
	return domainStateReason(c.virt, name)
}

func (c virtStateConn) Close() error { return c.virt.Disconnect() }

// StateReader is the client's reader of domain states on connections of its
// own (see above), made on first use and closed by Close.
func (c *Client) StateReader() *StateReader {
	c.stateReaderMu.Lock()
	defer c.stateReaderMu.Unlock()
	if c.stateReader == nil {
		c.stateReader = NewStateReader(func() (StateConn, error) {
			v, err := dialLibvirt()
			if err != nil {
				return nil, err
			}
			return virtStateConn{virt: v}, nil
		}, 0)
	}
	return c.stateReader
}
