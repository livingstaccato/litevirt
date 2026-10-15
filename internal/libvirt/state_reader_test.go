package libvirt_test

import (
	"errors"
	"testing"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"

	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// stateReaderFake is a fake libvirtd that runs every domain named; a test
// caps the requests it answers per connection (max_client_requests) and
// hangs domains (libvirtfake/conn_model.go).
func stateReaderFake(t *testing.T, names ...string) *libvirtfake.Fake {
	t.Helper()
	f := libvirtfake.New()
	for _, n := range names {
		if err := f.DefineDomain("<domain><name>" + n + "</name></domain>"); err != nil {
			t.Fatal(err)
		}
		if err := f.StartDomain(n); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func readWithin(t *testing.T, d time.Duration, read func() (string, error)) (string, error, bool) {
	t.Helper()
	type answer struct {
		st  string
		err error
	}
	ch := make(chan answer, 1)
	go func() {
		st, err := read()
		ch <- answer{st, err}
	}()
	select {
	case a := <-ch:
		return a.st, a.err, true
	case <-time.After(d):
		return "", nil, false
	}
}

func waitInFlight(t *testing.T, r *libvirt.StateReader, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for r.InFlight() != n {
		if time.Now().After(deadline) {
			t.Fatalf("reader calls in flight: %d, want %d", r.InFlight(), n)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func hang(t *testing.T, f *libvirtfake.Fake, names ...string) (releaseAll func()) {
	t.Helper()
	var rs []func()
	for _, n := range names {
		rs = append(rs, f.HangDomain(n))
	}
	releaseAll = func() {
		for _, r := range rs {
			r()
		}
	}
	t.Cleanup(releaseAll)
	return releaseAll
}

// A connection one of whose calls has been unanswered for stallAfter takes no
// new call: the next one goes on a fresh connection, and the stalled one is
// closed once its call has returned.
//
// Mutation: the stall check dropped: ok goes on the first connection, dials
// stays 1: red.
func TestStateReader_AStalledConnectionTakesNoNewCall(t *testing.T) {
	f := stateReaderFake(t, "ok", "h1")
	f.SetConnRequests(5)
	releaseAll := hang(t, f, "h1")
	const stall = 100 * time.Millisecond
	r := f.NewStateReader(stall)
	t.Cleanup(func() { _ = r.Close() })

	go func() { _, _ = r.DomainState("h1") }()
	waitInFlight(t, r, 1)
	time.Sleep(2 * stall)

	st, err, answered := readWithin(t, 2*time.Second, func() (string, error) { return r.DomainState("ok") })
	if !answered || err != nil || st != "running" {
		t.Fatalf("ok: answered=%v %q %v, want running", answered, st, err)
	}
	if d := r.Dials(); d != 2 {
		t.Fatalf("dials: %d, want 2 (the stalled connection retired)", d)
	}
	if o := r.Open(); o != 2 {
		t.Fatalf("open connections while the stalled one has a call: %d, want 2", o)
	}
	for i := 0; i < 3; i++ {
		if st, err := r.DomainState("ok"); err != nil || st != "running" {
			t.Fatalf("ok again: %q %v", st, err)
		}
	}
	if d := r.Dials(); d != 2 {
		t.Fatalf("dials after more reads: %d, want 2", d)
	}

	releaseAll()
	deadline := time.Now().Add(5 * time.Second)
	for r.Open() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("open connections after the stalled one drained: %d, want 1", r.Open())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Five calls libvirt does not answer, asked together before any has stalled,
// would fill one connection, and libvirtd would read nothing more on it. A
// connection takes at most MaxStateConnCalls (one under libvirtd's cap), so
// they spread over two, and a read of a domain libvirt answers for answers.
//
// Mutation: no cap on a connection's calls: all five on the first, ok waits
// behind them: red.
func TestStateReader_ABusyConnectionTakesNoNewCall(t *testing.T) {
	hung := []string{"h1", "h2", "h3", "h4", "h5"}
	f := stateReaderFake(t, append([]string{"ok"}, hung...)...)
	f.SetConnRequests(5)
	hang(t, f, hung...)
	r := f.NewStateReader(time.Hour)
	t.Cleanup(func() { _ = r.Close() })
	for _, n := range hung {
		go func() { _, _ = r.DomainState(n) }()
	}
	waitInFlight(t, r, len(hung))

	st, err, answered := readWithin(t, 2*time.Second, func() (string, error) { return r.DomainState("ok") })
	if !answered {
		t.Fatal("the read of ok did not answer: it went on a connection libvirtd stopped reading")
	}
	if err != nil || st != "running" {
		t.Fatalf("ok: %q %v, want running", st, err)
	}
}

// A call that has not stalled, on a connection not busy, does not retire its
// connection: the reader does not dial a connection per concurrent call.
//
// Mutation: a connection retired at any outstanding call: dials > 1: red.
func TestStateReader_AConnectionIsKeptWhileItsCallsAnswer(t *testing.T) {
	f := stateReaderFake(t, "a", "b")
	hang(t, f, "a")
	r := f.NewStateReader(time.Hour)
	t.Cleanup(func() { _ = r.Close() })
	go func() { _, _ = r.DomainState("a") }()
	waitInFlight(t, r, 1)
	for i := 0; i < 3; i++ {
		if st, err := r.DomainState("b"); err != nil || st != "running" {
			t.Fatalf("b: %q %v", st, err)
		}
	}
	if d := r.Dials(); d != 1 {
		t.Fatalf("dials: %d, want 1", d)
	}
}

// Past MaxStalledStateConns retired connections with calls, the reader dials
// no more: further calls go on the current connection, and the caller's bound
// applies. Each call libvirt does not answer holds one of libvirtd's workers,
// shared with every client, so the reader must not hold many.
//
// Mutation: the cap dropped: one more dial: red.
func TestStateReader_RetiredConnectionsAreCapped(t *testing.T) {
	f := stateReaderFake(t, "h")
	hang(t, f, "h")
	r := f.NewStateReader(time.Hour)
	t.Cleanup(func() { _ = r.Close() })
	// Enough calls to fill MaxStalledStateConns+1 connections, and three more.
	n := libvirt.MaxStateConnCalls*(libvirt.MaxStalledStateConns+1) + 3
	for i := 0; i < n; i++ {
		go func() { _, _ = r.DomainState("h") }()
	}
	waitInFlight(t, r, n)
	if d, want := r.Dials(), libvirt.MaxStalledStateConns+1; d != want {
		t.Fatalf("dials: %d, want %d", d, want)
	}
}

// A call that fails with an error other than libvirt's own (the connection is
// gone, as after libvirtd restarts) retires its connection, and is made once
// more on a fresh one, so the read answers.
//
// Mutation: no retry: the read fails: red. No retire: dials stays 1: red.
func TestStateReader_ATransportErrorIsRetriedOnAFreshConnection(t *testing.T) {
	f := stateReaderFake(t, "a")
	calls := 0
	f.FailDomainState = func(string) error {
		calls++
		if calls == 1 {
			return errors.New("libvirtfake: connection reset by peer")
		}
		return nil
	}
	r := f.NewStateReader(time.Hour)
	t.Cleanup(func() { _ = r.Close() })
	if st, err := r.DomainState("a"); err != nil || st != "running" {
		t.Fatalf("a: %q %v, want running on the retry", st, err)
	}
	if d := r.Dials(); d != 2 {
		t.Fatalf("dials: %d, want 2", d)
	}
	if o := r.Open(); o != 1 {
		t.Fatalf("open: %d, want 1", o)
	}
}

// libvirt's own error (no such domain) is an answer: the connection is kept
// and the call is not made again.
//
// Mutation: every error a transport error: two calls, two dials: red.
func TestStateReader_LibvirtsOwnErrorKeepsTheConnection(t *testing.T) {
	f := stateReaderFake(t, "a")
	calls := 0
	f.FailDomainState = func(string) error {
		calls++
		return golibvirt.Error{Code: uint32(golibvirt.ErrNoDomain), Message: "no domain"}
	}
	r := f.NewStateReader(time.Hour)
	t.Cleanup(func() { _ = r.Close() })
	if _, err := r.DomainState("a"); err == nil {
		t.Fatal("want libvirt's error")
	}
	if calls != 1 {
		t.Fatalf("libvirt asked %d times, want 1", calls)
	}
	if d := r.Dials(); d != 1 {
		t.Fatalf("dials: %d, want 1", d)
	}
}

// Close does not wait on a connection libvirtd stopped reading: its close is
// a request too and is never read. The daemon's shutdown closes the reader
// before the rest, and must go on.
//
// Mutation: Close waiting for every connection to close: it does not return:
// red.
func TestStateReader_CloseDoesNotWaitOnAFullConnection(t *testing.T) {
	hung := []string{"h1", "h2", "h3", "h4"}
	f := stateReaderFake(t, hung...)
	f.SetConnRequests(libvirt.MaxStateConnCalls) // the calls fill the connection
	hang(t, f, hung...)
	r := f.NewStateReader(time.Hour)
	for _, n := range hung {
		go func() { _, _ = r.DomainState(n) }()
	}
	waitInFlight(t, r, len(hung))
	done := make(chan struct{})
	go func() {
		_ = r.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return while a connection was full")
	}
	if _, err := r.DomainState("h1"); err == nil {
		t.Fatal("a read after Close answered")
	}
}

// A reader whose dial fails says so with ErrStateConnUnavailable, so the
// caller can ask on its usual connection.
func TestStateReader_ADialFailureIsErrStateConnUnavailable(t *testing.T) {
	r := libvirt.NewStateReader(func() (libvirt.StateConn, error) {
		return nil, errors.New("dial unix /var/run/libvirt/libvirt-sock: connect: no such file or directory")
	}, 0)
	if _, err := r.DomainState("a"); !errors.Is(err, libvirt.ErrStateConnUnavailable) {
		t.Fatalf("err %v, want ErrStateConnUnavailable", err)
	}
}
