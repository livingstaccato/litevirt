package libvirtfake

import (
	"errors"
	"sync"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"

	"github.com/litevirt/litevirt/internal/libvirt"
)

// The connection model of the state calls (DomainState, DomainStateReason).
//
// Real libvirtd does two things this models:
//
//   - it serves at most max_client_requests (default 5) requests of one
//     client connection at a time; past that it stops reading the
//     connection, so a later request on it waits for one of those to return,
//     whatever domain it names, while another connection is answered at once;
//   - a start that waits on storage that does not answer holds its domain's
//     lock, and a call naming that domain waits with it.
//
// Lab 2 (03fe9868, check B2) is the two together: the daemon's background
// loops made calls naming the hung domain on the daemon's one connection,
// they filled it, and `lv ls` read a healthy VM on the same host as unknown
// while `virsh domstate` of it answered in 23 ms.
//
// HangDomain makes the state calls naming a domain wait; SetConnRequests
// caps the state calls in flight on each connection (0, the default: no
// cap). The Fake's own methods are one connection, the daemon's; a
// StateReader dials connections of its own, each with its own cap.
//
// Closing a connection is a request on it, as go-libvirt's Disconnect sends
// ConnectClose first: it waits for a slot like any call, so a full
// connection does not close. A call in flight on a connection closed under
// it fails, as go-libvirt fails it with ErrInterrupted, once libvirt
// answers. SetStateDial makes a StateReader's dials fail or wait.
//
// Besides the two state calls, the reads a caller makes of a domain while
// libvirt may hang on another are modelled, on the Fake's connection and a
// reader's alike: DomainExists, DomainIsActive, the VNC port, the console
// password and the domain list, which waits on every hung domain (libvirt
// looks at each domain to list it; lab 2's `virsh list --all` timed out
// with one hung). A reader's connections are read-only ones, which libvirt
// refuses the console password (its secure XML); SecureStateReader's are
// read-write. Every other method answers at once, as before; libvirtd's
// worker pool is not modelled.
type connModel struct {
	mu       sync.Mutex
	requests int                      // the per-connection cap; 0 = none
	hung     map[string]chan struct{} // domain → closed when released
	hungCall map[string]chan struct{} // call kind + "\x00" + domain → closed when released
	main     *fakeConn
	reader   *libvirt.StateReader
	all      []*fakeConn // every connection made, to wake on a new cap
	dialHook func() error
	mainN    int            // state calls made on the main connection
	mainFor  map[string]int // modelled calls on the main connection, by domain ("" = the list)
	secure   *libvirt.StateReader
}

// errConnClosed is a call on a connection already closed.
var errConnClosed = errors.New("libvirtfake: connection closed")

// fakeConn is one client connection to the fake libvirtd.
type fakeConn struct {
	f        *Fake
	mu       sync.Mutex
	cond     *sync.Cond
	inFlight int
	closed   bool
	readOnly bool // a read-only connection (libvirt-sock-ro)
}

func (f *Fake) newFakeConn(readOnly bool) *fakeConn {
	c := &fakeConn{f: f, readOnly: readOnly}
	c.cond = sync.NewCond(&c.mu)
	f.conns.mu.Lock()
	f.conns.all = append(f.conns.all, c)
	f.conns.mu.Unlock()
	return c
}

func (f *Fake) mainConn() *fakeConn {
	f.conns.mu.Lock()
	defer f.conns.mu.Unlock()
	if f.conns.main == nil {
		c := &fakeConn{f: f}
		c.cond = sync.NewCond(&c.mu)
		f.conns.all = append(f.conns.all, c)
		f.conns.main = c
	}
	return f.conns.main
}

// SetConnRequests sets libvirtd's per-connection cap on requests in flight
// (max_client_requests) for the state calls; 0 removes it.
func (f *Fake) SetConnRequests(n int) {
	f.conns.mu.Lock()
	f.conns.requests = n
	all := append([]*fakeConn(nil), f.conns.all...)
	f.conns.mu.Unlock()
	// Wake calls waiting on the old cap.
	for _, c := range all {
		c.mu.Lock()
		c.cond.Broadcast()
		c.mu.Unlock()
	}
}

// SetStateDial sets a hook each StateReader dial runs first: an error fails
// the dial, and the hook may block. nil removes it.
func (f *Fake) SetStateDial(hook func() error) {
	f.conns.mu.Lock()
	f.conns.dialHook = hook
	f.conns.mu.Unlock()
}

// MainConnCallsFor is how many modelled calls naming the domain name were
// made on the Fake's own connection ("" counts the domain lists).
func (f *Fake) MainConnCallsFor(name string) int {
	f.conns.mu.Lock()
	defer f.conns.mu.Unlock()
	return f.conns.mainFor[name]
}

// MainConnCalls is how many state calls were made on the Fake's own
// connection.
func (f *Fake) MainConnCalls() int {
	f.conns.mu.Lock()
	defer f.conns.mu.Unlock()
	return f.conns.mainN
}

func (f *Fake) connRequests() int {
	f.conns.mu.Lock()
	defer f.conns.mu.Unlock()
	return f.conns.requests
}

// HangDomain makes every state call naming name wait, as a call naming a
// domain whose start waits on storage does, until release is called. A call
// that waits holds its connection's slot (see SetConnRequests).
func (f *Fake) HangDomain(name string) (release func()) {
	ch := make(chan struct{})
	f.conns.mu.Lock()
	if f.conns.hung == nil {
		f.conns.hung = map[string]chan struct{}{}
	}
	f.conns.hung[name] = ch
	f.conns.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			f.conns.mu.Lock()
			if f.conns.hung[name] == ch {
				delete(f.conns.hung, name)
			}
			f.conns.mu.Unlock()
			close(ch)
		})
	}
}

func (f *Fake) waitHung(name string) {
	f.conns.mu.Lock()
	ch := f.conns.hung[name]
	f.conns.mu.Unlock()
	if ch != nil {
		<-ch
	}
}

// HangCall is HangDomain for the calls of one kind only, naming name:
// CallVNCPort or CallConsolePassword. The domain's other calls answer.
func (f *Fake) HangCall(kind, name string) (release func()) {
	key := kind + "\x00" + name
	ch := make(chan struct{})
	f.conns.mu.Lock()
	if f.conns.hungCall == nil {
		f.conns.hungCall = map[string]chan struct{}{}
	}
	f.conns.hungCall[key] = ch
	f.conns.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			f.conns.mu.Lock()
			if f.conns.hungCall[key] == ch {
				delete(f.conns.hungCall, key)
			}
			f.conns.mu.Unlock()
			close(ch)
		})
	}
}

// The call kinds HangCall takes.
const (
	CallVNCPort         = "vnc-port"
	CallConsolePassword = "console-password"
)

func (f *Fake) waitHungCall(kind, name string) {
	if kind == "" {
		return
	}
	f.conns.mu.Lock()
	ch := f.conns.hungCall[kind+"\x00"+name]
	f.conns.mu.Unlock()
	if ch != nil {
		<-ch
	}
}

// waitAllHung waits until no domain is hung, as a domain list does.
func (f *Fake) waitAllHung() {
	for {
		f.conns.mu.Lock()
		var ch chan struct{}
		for _, c := range f.conns.hung {
			ch = c
			break
		}
		f.conns.mu.Unlock()
		if ch == nil {
			return
		}
		<-ch
	}
}

// ConnInFlight is how many state calls are in flight on the Fake's own
// connection.
func (f *Fake) ConnInFlight() int {
	c := f.mainConn()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inFlight
}

// call makes one state call on c: it waits for a slot under the cap, then
// for its domain to be released, then calls fn. It returns errConnClosed,
// without calling fn, on a connection already closed.
func (c *fakeConn) call(name string, fn func()) error {
	return c.callAs(true, "", name, fn)
}

// callAs is call; state says it is a state call (MainConnCalls counts
// those), and kind names the call for HangCall ("" for none). A name of ""
// waits on every hung domain (the domain list).
func (c *fakeConn) callAs(state bool, kind, name string, fn func()) error {
	if c == c.f.mainConn() {
		c.f.conns.mu.Lock()
		if state {
			c.f.conns.mainN++
		}
		if c.f.conns.mainFor == nil {
			c.f.conns.mainFor = map[string]int{}
		}
		c.f.conns.mainFor[name]++
		c.f.conns.mu.Unlock()
	}
	if !c.takeSlot() {
		return errConnClosed
	}
	defer c.freeSlot()
	if name == "" {
		c.f.waitAllHung()
	} else {
		c.f.waitHung(name)
		c.f.waitHungCall(kind, name)
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return errConnClosed
	}
	fn()
	return nil
}

// takeSlot waits for a slot under the cap; false on a closed connection.
func (c *fakeConn) takeSlot() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if c.closed {
			return false
		}
		if lim := c.f.connRequests(); lim <= 0 || c.inFlight < lim {
			c.inFlight++
			return true
		}
		c.cond.Wait()
	}
}

func (c *fakeConn) freeSlot() {
	c.mu.Lock()
	c.inFlight--
	c.cond.Broadcast()
	c.mu.Unlock()
}

// StateReader is the Fake's libvirt.StateReader (the real one), whose
// connections are fake connections of their own (see above).
func (f *Fake) StateReader() *libvirt.StateReader {
	f.conns.mu.Lock()
	defer f.conns.mu.Unlock()
	if f.conns.reader == nil {
		f.conns.reader = f.newStateReaderLocked(0)
	}
	return f.conns.reader
}

// NewStateReader is a libvirt.StateReader on fresh fake connections, with
// its own stallAfter, for a test of the reader itself.
func (f *Fake) NewStateReader(stallAfter time.Duration) *libvirt.StateReader {
	f.conns.mu.Lock()
	defer f.conns.mu.Unlock()
	return f.newStateReaderLocked(stallAfter)
}

// SecureStateReader is the Fake's libvirt.SecureStateReader: the real
// StateReader on read-write fake connections of its own.
func (f *Fake) SecureStateReader() *libvirt.StateReader {
	f.conns.mu.Lock()
	defer f.conns.mu.Unlock()
	if f.conns.secure == nil {
		f.conns.secure = f.newReaderLocked(0, false)
	}
	return f.conns.secure
}

func (f *Fake) newStateReaderLocked(stallAfter time.Duration) *libvirt.StateReader {
	return f.newReaderLocked(stallAfter, true)
}

func (f *Fake) newReaderLocked(stallAfter time.Duration, readOnly bool) *libvirt.StateReader {
	return libvirt.NewStateReader(func() (libvirt.StateConn, error) {
		f.conns.mu.Lock()
		hook := f.conns.dialHook
		f.conns.mu.Unlock()
		if hook != nil {
			if err := hook(); err != nil {
				return nil, err
			}
		}
		return f.newFakeConn(readOnly), nil
	}, stallAfter)
}

// DomainState is the Fake's DomainState on c.
func (c *fakeConn) DomainState(name string) (string, error) {
	var st string
	var err error
	if cerr := c.call(name, func() { st, err = c.f.domainState(name) }); cerr != nil {
		return "unknown", cerr
	}
	return st, err
}

// DomainStateReason is the Fake's DomainStateReason on c.
func (c *fakeConn) DomainStateReason(name string) (libvirt.DomainStatus, error) {
	var st libvirt.DomainStatus
	var err error
	if cerr := c.call(name, func() { st, err = c.f.domainStateReason(name) }); cerr != nil {
		return libvirt.DomainStatus{State: "unknown", Reason: "unknown"}, cerr
	}
	return st, err
}

// DomainIsActive is the Fake's DomainIsActive on c.
func (c *fakeConn) DomainIsActive(name string) (bool, error) {
	var active bool
	var err error
	if cerr := c.callAs(false, "", name, func() { active, err = c.f.domainIsActive(name) }); cerr != nil {
		return false, cerr
	}
	return active, err
}

// ListDomains is the Fake's ListDomains on c.
func (c *fakeConn) ListDomains() ([]string, error) {
	var names []string
	var err error
	if cerr := c.callAs(false, "", "", func() { names, err = c.f.listDomains() }); cerr != nil {
		return nil, cerr
	}
	return names, err
}

// VNCPort is the Fake's GetVMVNCPort on c.
func (c *fakeConn) VNCPort(name string) (int, error) {
	port := -1
	var err error
	if cerr := c.callAs(false, CallVNCPort, name, func() { port, err = c.f.vncPort(name) }); cerr != nil {
		return -1, cerr
	}
	return port, err
}

// ConsolePassword is the Fake's ConsolePassword on c. libvirt refuses it a
// read-only connection: it reads the secure XML.
func (c *fakeConn) ConsolePassword(name, kind string) (string, error) {
	if c.readOnly {
		return "", golibvirt.Error{Code: uint32(golibvirt.ErrOperationDenied),
			Message: "libvirtfake: virDomainGetXMLDesc with secure flag is not allowed on a read-only connection"}
	}
	var pw string
	var err error
	if cerr := c.callAs(false, CallConsolePassword, name, func() { pw, err = c.f.consolePassword(name, kind) }); cerr != nil {
		return "", cerr
	}
	return pw, err
}

// Close closes c. Like go-libvirt's Disconnect it is a request first, so it
// waits for a slot, and on a full connection does not return until a call
// on it does. A later call fails, and so does a call in flight, once libvirt
// answers it.
func (c *fakeConn) Close() error {
	if !c.takeSlot() {
		return nil // already closed
	}
	c.mu.Lock()
	c.closed = true
	c.inFlight--
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}
