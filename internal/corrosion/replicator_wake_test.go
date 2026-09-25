package corrosion

import (
	"context"
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

// A write that commits while a push loop is between its read of mutation_log
// and its wait must still wake that loop.
//
// The broadcast closes the current channel and installs a fresh one. A loop
// that fetched the channel only when it reached its select waited on the FRESH
// one, so a notify fired in between closed a channel nobody held: the entry sat
// for the full 10 s idle interval. The capacity-1 send it replaced kept that
// wakeup in its buffer, so this was a regression the broadcast introduced.
func TestReplicateToPeer_AWriteDuringThePushIsNotLost(t *testing.T) {
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})

	calls := make(chan time.Time, 8)
	var first atomic.Bool
	r.afterReplicateOnceForTests = func() {
		if first.CompareAndSwap(false, true) {
			c.notifyReplicator() // a local write lands after the read, before the wait
		}
		calls <- time.Now()
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go r.replicateToPeer(ctx, "peer-b")

	start := <-calls
	select {
	case again := <-calls:
		if d := again.Sub(start); d > 2*time.Second {
			t.Fatalf("the loop re-ran %v after the write; the wakeup was lost", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not re-run within 5s of a write that landed during its push: the wakeup was lost and it is waiting out the 10s idle interval")
	}
}
