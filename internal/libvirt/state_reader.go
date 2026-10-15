package libvirt

import (
	"errors"
	"fmt"
	"net"
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
// connection takes no new call once one of its calls has been unanswered for
// stallAfter, or once it has MaxStateConnCalls calls outstanding, before
// libvirtd's limit fills it: the next call dials a fresh connection, and the
// retired one is closed once its calls have returned. So a domain libvirt does
// not answer for holds a connection of its own, not every read after it.
//
// A call that did land on a connection libvirtd stopped reading stays
// outstanding until a hung call on that connection returns; the caller's
// bound (grpcapi's latch) reads that domain unknown for as long.
const (
	// defaultStateStallAfter is how long a call goes unanswered before its
	// connection takes no new call. libvirt answers a state call in
	// milliseconds.
	defaultStateStallAfter = time.Second
	// MaxStateConnCalls is how many calls a connection takes at once: one
	// under libvirtd's default max_client_requests, so a connection is
	// retired before libvirtd stops reading it.
	MaxStateConnCalls = 4
	// MaxStalledStateConns caps the retired connections kept open while they
	// have calls. Past it, calls go on the current connection although it is
	// stalled or busy; the caller bounds its wait as before. It is small
	// because each call libvirt does not answer holds one of libvirtd's
	// workers (max_workers 20, shared with every client): the reader holds at
	// most about MaxStalledStateConns plus one connection's worth of them.
	MaxStalledStateConns = 4
	// stateDialTimeout bounds a reader connection's dial and handshake, so a
	// libvirtd that does not answer a handshake costs the caller a fallback
	// to its usual connection, not every read.
	stateDialTimeout = 2 * time.Second
	// stateCloseTimeout bounds how long Close waits for its connections to
	// close; a connection libvirtd stopped reading never answers the close.
	stateCloseTimeout = time.Second
)

// readOnlySocket is libvirtd's read-only socket: a state read needs nothing
// more (the lab's 23 ms `virsh -r domstate` used it).
const readOnlySocket = "/var/run/libvirt/libvirt-sock-ro"

// StateConn is one connection's read calls: the domain states, and the other
// reads a caller makes of a domain while libvirt may hang on another (the
// domain list, whether a domain is active, its VNC port and console
// password). Every one but ConsolePassword is allowed on a read-only
// connection; ConsolePassword reads the domain's secure XML, which libvirt
// refuses one (a reader for it dials the read-write socket,
// Client.SecureStateReader).
type StateConn interface {
	DomainState(name string) (string, error)
	DomainStateReason(name string) (DomainStatus, error)
	DomainIsActive(name string) (bool, error)
	ListDomains() ([]string, error)
	VNCPort(name string) (int, error)
	ConsolePassword(name, kind string) (string, error)
	DumpXML(name string) (string, error)
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
	retired map[*readConn]struct{} // stalled, busy or broken; closed once drained
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

// DomainIsActive is Client.DomainIsActive, asked on the reader's connection.
func (r *StateReader) DomainIsActive(name string) (bool, error) {
	var active bool
	err := r.do(func(c StateConn) error {
		var e error
		active, e = c.DomainIsActive(name)
		return e
	})
	return active, err
}

// ListDomains is Client.ListDomains, asked on the reader's connection.
// libvirt answers it only once it can look at every domain, so a domain it
// hangs on holds it too.
func (r *StateReader) ListDomains() ([]string, error) {
	var names []string
	err := r.do(func(c StateConn) error {
		var e error
		names, e = c.ListDomains()
		return e
	})
	return names, err
}

// VNCPort is Client.GetVMVNCPort, asked on the reader's connection.
func (r *StateReader) VNCPort(name string) (int, error) {
	port := -1
	err := r.do(func(c StateConn) error {
		var e error
		port, e = c.VNCPort(name)
		return e
	})
	return port, err
}

// ConsolePassword is Client.ConsolePassword, asked on the reader's
// connection, which must be a read-write one (Client.SecureStateReader).
func (r *StateReader) ConsolePassword(name, kind string) (string, error) {
	var pw string
	err := r.do(func(c StateConn) error {
		var e error
		pw, e = c.ConsolePassword(name, kind)
		return e
	})
	return pw, err
}

// DumpXML is Client.DumpXML (the live XML, without secrets), asked on the
// reader's connection.
func (r *StateReader) DumpXML(name string) (string, error) {
	var x string
	err := r.do(func(c StateConn) error {
		var e error
		x, e = c.DumpXML(name)
		return e
	})
	return x, err
}

// Dials is how many connections the reader has dialled.
func (r *StateReader) Dials() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dials
}

// Open is how many of the reader's connections are open: the current one and
// the retired ones not yet drained.
func (r *StateReader) Open() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(r.retired)
	if r.cur != nil {
		n++
	}
	return n
}

// InFlight is how many calls the reader has outstanding, on every connection.
func (r *StateReader) InFlight() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	if r.cur != nil {
		n += len(r.cur.calls)
	}
	for c := range r.retired {
		n += len(c.calls)
	}
	return n
}

// Close closes every connection of the reader; a call after it fails. It
// waits at most stateCloseTimeout: a connection libvirtd stopped reading never
// answers its close, and Close must not hold up the daemon's shutdown.
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
	done := make(chan error, len(conns))
	for _, c := range conns {
		go func() { done <- c.conn.Close() }()
	}
	timer := time.NewTimer(stateCloseTimeout)
	defer timer.Stop()
	var first error
	for range conns {
		select {
		case err := <-done:
			if err != nil && first == nil {
				first = err
			}
		case <-timer.C:
			return errors.New("state reader: a connection did not close in time")
		}
	}
	return first
}

// do makes call on a connection of the reader. A transport error (the
// connection is gone, as after libvirtd restarts) retires the connection, and
// the call is made once more on a fresh one.
func (r *StateReader) do(call func(StateConn) error) error {
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		c, id, aerr := r.acquire()
		if aerr != nil {
			return aerr
		}
		err = call(c.conn)
		r.release(c, id, err)
		if err == nil || !isTransportError(err) {
			return err
		}
	}
	return err
}

// takes reports whether c takes a new call now.
func (r *StateReader) takes(c *readConn) bool {
	if c.broken {
		return false
	}
	busy := len(c.calls) >= MaxStateConnCalls
	if t := c.oldestCall(); !t.IsZero() && time.Since(t) >= r.stallAfter {
		busy = true
	}
	return !busy || len(r.retired) >= MaxStalledStateConns
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
			if r.takes(c) {
				r.seq++
				id := r.seq
				c.calls[id] = time.Now()
				r.mu.Unlock()
				return c, id, nil
			}
			// Retire it: it takes no new call, and is closed once drained.
			r.cur = nil
			if len(c.calls) == 0 {
				go c.conn.Close() //nolint:errcheck // best effort
			} else {
				r.retired[c] = struct{}{}
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
			go conn.Close() //nolint:errcheck // best effort
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
		if r.cur == c {
			r.cur = nil
			r.retired[c] = struct{}{}
		}
	}
	closeIt := false
	if _, ok := r.retired[c]; ok && len(c.calls) == 0 {
		delete(r.retired, c)
		closeIt = true
	}
	r.mu.Unlock()
	if closeIt {
		go c.conn.Close() //nolint:errcheck // best effort
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

func (c virtStateConn) DomainIsActive(name string) (bool, error) {
	return domainIsActive(c.virt, name)
}

func (c virtStateConn) ListDomains() ([]string, error) { return listDomains(c.virt) }

func (c virtStateConn) VNCPort(name string) (int, error) { return vncPort(c.virt, name) }

func (c virtStateConn) ConsolePassword(name, kind string) (string, error) {
	return consolePassword(c.virt, name, kind)
}

func (c virtStateConn) DumpXML(name string) (string, error) { return dumpXML(c.virt, name) }

func (c virtStateConn) Close() error { return c.virt.Disconnect() }

// closedStateReader is a reader whose every call fails: what a client hands
// out once it is closed, so nothing dials a connection Close will not close.
func closedStateReader() *StateReader {
	r := NewStateReader(func() (StateConn, error) { return nil, errStateReaderClosed }, 0)
	r.Close() //nolint:errcheck // it has no connection
	return r
}

// dialLibvirtBounded is dialLibvirt on socket, with the dial and the
// handshake bounded by timeout. go-libvirt puts no deadline on the handshake,
// and a read deadline would not end it (its reader retries a timeout), so the
// socket is closed when the time is up, which fails the handshake.
func dialLibvirtBounded(socket string, timeout time.Duration) (*golibvirt.Libvirt, error) {
	conn, err := net.DialTimeout("unix", socket, timeout)
	if err != nil {
		return nil, fmt.Errorf("connect to libvirtd: %w", err)
	}
	timer := time.AfterFunc(timeout, func() { conn.Close() }) //nolint:errcheck // ends the handshake
	virt := golibvirt.New(conn)
	err = virt.Connect()
	if !timer.Stop() {
		conn.Close() //nolint:errcheck // already closed by the timer
		return nil, fmt.Errorf("libvirt handshake: no answer in %s", timeout)
	}
	if err != nil {
		conn.Close() //nolint:errcheck // best effort
		return nil, fmt.Errorf("libvirt handshake: %w", err)
	}
	return virt, nil
}

// StateReader is the client's reader of domain states on connections of its
// own (see above), made on first use and closed by Close. It dials libvirtd's
// read-only socket, and the read-write one where that is missing.
func (c *Client) StateReader() *StateReader {
	c.stateReaderMu.Lock()
	defer c.stateReaderMu.Unlock()
	if c.closed {
		return closedStateReader()
	}
	if c.stateReader == nil {
		c.stateReader = NewStateReader(func() (StateConn, error) {
			v, err := dialLibvirtBounded(readOnlySocket, stateDialTimeout)
			if err != nil {
				var rerr error
				if v, rerr = dialLibvirtBounded(defaultSocket, stateDialTimeout); rerr != nil {
					return nil, fmt.Errorf("%w; %w", err, rerr)
				}
			}
			return virtStateConn{virt: v}, nil
		}, 0)
	}
	return c.stateReader
}

// SecureStateReader is StateReader on the read-write socket only, for the
// reads libvirt refuses a read-only connection: a console's password, read
// from the domain's secure XML (ConsolePassword). Made on first use and
// closed by Close.
func (c *Client) SecureStateReader() *StateReader {
	c.stateReaderMu.Lock()
	defer c.stateReaderMu.Unlock()
	if c.closed {
		return closedStateReader()
	}
	if c.secureReader == nil {
		c.secureReader = NewStateReader(func() (StateConn, error) {
			v, err := dialLibvirtBounded(defaultSocket, stateDialTimeout)
			if err != nil {
				return nil, err
			}
			return virtStateConn{virt: v}, nil
		}, 0)
	}
	return c.secureReader
}
