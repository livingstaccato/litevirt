package grpcapi

import (
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// lsunknown review I-1 (cancelled-starts): the sweep asked whether a
// cancelled start's domain is active on the daemon's connection. Bounded, so
// it never held the sweep, but with libvirt hung on another domain and the
// connection full, it never got an answer either, and a domain libvirt
// started after the restart ran on under a row stopped by its operator for
// as long as the other domain hung. The read is asked on a reader
// connection now, so the sweep sees web running and undoes the start. (The
// fake does not model the destroy on the daemon's connection: this pins the
// read only.)
//
// Mutation: the read asked on s.virt again: it is not answered and the
// domain runs on: red.
func TestCancelledStart_TheSweepReadsOffAFullDaemonConnection(t *testing.T) {
	st := newStuckStart(t)
	st.s.liveStateWait = 200 * time.Millisecond
	st.restarted(t, "stopped", "operator-stop")
	f := st.s.virt.(*libvirtfake.Fake)
	if err := f.DefineDomain("<domain><name>st</name></domain>"); err != nil {
		t.Fatal(err)
	}
	f.SetConnRequests(5)
	release := f.HangDomain("st")
	t.Cleanup(release)
	for i := 0; i < 5; i++ {
		go func() { _, _ = f.DomainState("st") }()
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.ConnInFlight() < 5 {
		if time.Now().After(deadline) {
			t.Fatalf("the daemon's connection has %d calls in flight, want 5", f.ConnInFlight())
		}
		time.Sleep(5 * time.Millisecond)
	}

	st.sweepWithin(t, 5*time.Second, "a sweep with the daemon's connection full")
	f.SetConnRequests(0) // so the test can read the domain
	if st.domainActive(t) {
		t.Fatal("the cancelled start's domain still runs: the sweep's read was not answered")
	}
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 0 {
		t.Fatalf("the record outlived the destroy: %+v", recs)
	}
}
