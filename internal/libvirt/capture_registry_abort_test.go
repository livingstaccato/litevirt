package libvirt

import (
	"sync/atomic"
	"testing"
	"time"
)

// libvirt never answers the abort of a capture's job (its job lock held by a
// stuck call, or the connection wedged), and the pauser holds the captured VM
// again on every pass. At most one abort per capture is outstanding: a later
// Hold observes the one in flight instead of
// issuing another RPC that would tie up one more libvirtd worker.
//
// Mutation: a fresh "abort idle" slot per Hold (the old per-call limit) —
// one more outstanding abort per Hold; red.
func TestCaptureRegistry_AnUnansweredAbortIsNotReissued(t *testing.T) {
	reg := NewCaptureRegistry()
	release := make(chan struct{})
	var outstanding, most, calls atomic.Int32
	e, err := reg.begin("vm", func() error {
		calls.Add(1)
		n := outstanding.Add(1)
		for m := most.Load(); n > m && !most.CompareAndSwap(m, n); m = most.Load() {
		}
		<-release
		outstanding.Add(-1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { close(release); reg.end("vm", e) }()

	for i := 0; i < 5; i++ { // five pause passes
		if captured, settled := reg.Hold("vm", 30*time.Millisecond); !captured || settled {
			t.Fatalf("pass %d: Hold = captured %v, settled %v; want an unsettled hold of a capture", i, captured, settled)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if m := most.Load(); m != 1 {
		t.Fatalf("%d aborts of one capture were outstanding at once (of %d issued); want 1", m, calls.Load())
	}
}
