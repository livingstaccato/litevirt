package health

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// A long operation on one container — a backup, a migrate, a snapshot holds
// its lock for the whole run — must not stall the sweep for every other one.
// With "a" locked by an operation, "b" crashing is still restarted in the same
// sweep, and "a" is left alone until a later one.
func TestContainerCheck_BusyContainerDoesNotStallTheSweep(t *testing.T) {
	db := testLogicDB(t)
	rt := newFakeCtRuntime()
	rt.states["a"] = lxc.StateStopped // would be restarted if the sweep reached it
	rt.states["b"] = lxc.StateStopped // crashed
	for _, n := range []string{"a", "b"} {
		insertCt(t, db, corrosion.ContainerRecord{
			HostName: "node1", Name: n, State: "running",
			RestartPolicy: ctPolicyJSON(t, "always", 0, "0s", ""),
		})
	}

	var locksMu sync.Mutex
	locks := map[string]*sync.Mutex{}
	lockOf := func(name string) *sync.Mutex {
		locksMu.Lock()
		defer locksMu.Unlock()
		if locks[name] == nil {
			locks[name] = &sync.Mutex{}
		}
		return locks[name]
	}
	lockOf("a").Lock() // a backup of "a" is running
	released := false
	release := func() {
		if !released {
			released = true
			lockOf("a").Unlock()
		}
	}
	t.Cleanup(release)

	c := NewContainerChecker("node1", db, rt)
	c.SetContainerLock(func(name string) (func(), bool) {
		mu := lockOf(name)
		if !mu.TryLock() {
			return nil, false
		}
		return mu.Unlock, true
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.SweepOnce(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		release()
		<-done
		t.Fatal("the sweep blocked on a container another operation holds; every other container waited on it")
	}
	if n := rt.startCount("b"); n != 1 {
		t.Fatalf("b was started %d times in the sweep, want 1: a busy container stalled the rest", n)
	}
	if n := rt.startCount("a"); n != 0 {
		t.Fatalf("a was started %d times while an operation held its lock, want 0", n)
	}

	// The operation finishes: the next sweep reconciles "a".
	release()
	c.SweepOnce(context.Background())
	if n := rt.startCount("a"); n != 1 {
		t.Fatalf("a was started %d times by the sweep after its operation finished, want 1", n)
	}
}
