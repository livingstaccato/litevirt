package corrosion

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A local write has to wake EVERY per-peer push loop, not one of them.
//
// notifyReplicator used to send one value into a capacity-1 channel that every
// per-peer goroutine selected on. A send wakes exactly one receiver, so on a
// cluster with N peers a committed write reached one peer promptly and the
// other N-1 waited for their 10s periodic tick. That is the whole
// write-to-peer latency budget, spent on a channel idiom rather than on
// anything about the network, and it gets worse as the cluster grows.
//
// The symptom is invisible from either end: the push succeeds when it finally
// runs, the backlog drains, and no gauge records that the entries sat for ten
// seconds first.
func TestNotifyReplicator_WakesEveryWaiter(t *testing.T) {
	c := mustTestClient(t)

	const waiters = 4
	var woke atomic.Int32
	var ready sync.WaitGroup
	var done sync.WaitGroup
	ready.Add(waiters)
	done.Add(waiters)

	for range waiters {
		go func() {
			// Read the channel the way the push loop does: fresh each time
			// round, so a broadcast implementation can hand out a new one.
			ch := c.ReplicatorNotify()
			ready.Done()
			select {
			case <-ch:
				woke.Add(1)
			case <-time.After(3 * time.Second):
			}
			done.Done()
		}()
	}
	ready.Wait()
	// Every waiter is parked on the channel before the notify fires.
	time.Sleep(50 * time.Millisecond)

	c.notifyReplicator()
	done.Wait()

	if got := woke.Load(); got != waiters {
		t.Fatalf("%d of %d push loops woke on a local write; the rest wait out their 10s "+
			"periodic tick, so write-to-peer latency is ~10s for all but one peer",
			got, waiters)
	}
}

// Notifying with nobody listening must not block or panic, because
// notifyReplicator is called from commit paths that hold the client lock.
func TestNotifyReplicator_IsSafeWithNoWaiters(t *testing.T) {
	c := mustTestClient(t)
	done := make(chan struct{})
	go func() {
		c.notifyReplicator()
		c.notifyReplicator()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("notifyReplicator blocked with no waiters; it is called from commit paths")
	}
}

// A waiter that arrives after a notify must park for the NEXT one rather than
// seeing a permanently-ready channel — otherwise a broadcast implementation
// that forgets to replace the channel spins every push loop at full tilt.
func TestNotifyReplicator_DoesNotLatchReady(t *testing.T) {
	c := mustTestClient(t)
	c.notifyReplicator()

	ch := c.ReplicatorNotify()
	select {
	case <-ch:
		t.Fatal("the notify channel stayed ready after a broadcast; every push loop would " +
			"spin instead of waiting, burning CPU and hammering peers")
	case <-time.After(200 * time.Millisecond):
	}
}
