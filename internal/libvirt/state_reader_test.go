package libvirt_test

import (
	"errors"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// stateReaderFake is a fake libvirtd that answers at most five requests of
// one connection at a time (max_client_requests) and runs every domain
// named; hung names domains whose state calls do not answer until the test
// ends (libvirtfake/conn_model.go).
func stateReaderFake(t *testing.T, names ...string) *libvirtfake.Fake {
	t.Helper()
	f := libvirtfake.New()
	f.SetConnRequests(5)
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

// A connection whose calls libvirt does not answer fills up, and libvirtd
// reads nothing more on it; a reader whose connection has had a call
// unanswered for stallAfter puts the next call on a fresh connection, so a
// domain libvirt answers for is answered whatever is stuck on the old one.
// The stalled connection is closed once its calls have returned.
//
// Mutation: the stall check dropped (every call on the first connection):
// the read of ok does not answer: red.
func TestStateReader_AStalledConnectionTakesNoNewCall(t *testing.T) {
	hung := []string{"h1", "h2", "h3", "h4", "h5"}
	f := stateReaderFake(t, append([]string{"ok"}, hung...)...)
	var releases []func()
	for _, n := range hung {
		releases = append(releases, f.HangDomain(n))
	}
	releaseAll := func() {
		for _, r := range releases {
			r()
		}
	}
	t.Cleanup(releaseAll)
	const stall = 50 * time.Millisecond
	r := f.NewStateReader(stall)
	t.Cleanup(func() { _ = r.Close() })

	// Five calls libvirt does not answer, all asked before any has stalled:
	// they share, and fill, the first connection.
	for _, n := range hung {
		go func() { _, _ = r.DomainState(n) }()
	}
	time.Sleep(4 * stall)
	if d := r.Dials(); d != 1 {
		t.Fatalf("dials after the hung calls: %d, want 1", d)
	}

	st, err, answered := readWithin(t, 2*time.Second, func() (string, error) { return r.DomainState("ok") })
	if !answered {
		t.Fatal("the read of ok did not answer: it was put on the full connection")
	}
	if err != nil || st != "running" {
		t.Fatalf("ok: %q %v, want running", st, err)
	}
	if d := r.Dials(); d != 2 {
		t.Fatalf("dials: %d, want 2 (the stalled connection retired)", d)
	}
	if o := r.Open(); o != 2 {
		t.Fatalf("open connections while the stalled one has calls: %d, want 2", o)
	}

	// Further reads stay on the fresh connection.
	for i := 0; i < 3; i++ {
		if st, err := r.DomainState("ok"); err != nil || st != "running" {
			t.Fatalf("ok again: %q %v", st, err)
		}
	}
	if d := r.Dials(); d != 2 {
		t.Fatalf("dials after more reads: %d, want 2", d)
	}

	// Once libvirt answers, the stalled connection drains and is closed.
	releaseAll()
	deadline := time.Now().Add(5 * time.Second)
	for r.Open() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("open connections after the stalled one drained: %d, want 1", r.Open())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A call that has not been unanswered for stallAfter does not retire its
// connection: the reader does not dial a connection per concurrent call.
//
// Mutation: a connection retired at any outstanding call: dials > 1: red.
func TestStateReader_AConnectionIsKeptWhileItsCallsAnswer(t *testing.T) {
	f := stateReaderFake(t, "a", "b")
	release := f.HangDomain("a")
	t.Cleanup(release)
	r := f.NewStateReader(time.Hour)
	t.Cleanup(func() { _ = r.Close() })
	go func() { _, _ = r.DomainState("a") }()
	time.Sleep(20 * time.Millisecond)
	for i := 0; i < 3; i++ {
		if st, err := r.DomainState("b"); err != nil || st != "running" {
			t.Fatalf("b: %q %v", st, err)
		}
	}
	if d := r.Dials(); d != 1 {
		t.Fatalf("dials: %d, want 1", d)
	}
}

// A call that fails with an error other than libvirt's own (the connection
// may be gone) retires its connection: the next call dials afresh. libvirt's
// own error (no such domain) does not.
//
// Mutation: no error retires: dials stays 1: red.
func TestStateReader_ATransportErrorRetiresTheConnection(t *testing.T) {
	f := stateReaderFake(t, "a")
	fail := true
	f.FailDomainState = func(string) error {
		if fail {
			return errors.New("connection reset by peer")
		}
		return nil
	}
	r := f.NewStateReader(time.Hour)
	t.Cleanup(func() { _ = r.Close() })
	if _, err := r.DomainState("a"); err == nil {
		t.Fatal("want the injected error")
	}
	fail = false
	if st, err := r.DomainState("a"); err != nil || st != "running" {
		t.Fatalf("a: %q %v", st, err)
	}
	if d := r.Dials(); d != 2 {
		t.Fatalf("dials: %d, want 2", d)
	}
	if o := r.Open(); o != 1 {
		t.Fatalf("open: %d, want 1", o)
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
