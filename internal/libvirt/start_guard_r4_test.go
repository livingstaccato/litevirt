package libvirt

import (
	"testing"
	"time"
)

// TestStartGuard_OnlyGuardedStartsWait (re-review m3): the wait for the
// firewall's start guard after a host boots is for a guarded VM's start. A
// VM with no NIC guard starts as it did before guards, without waiting; one
// whose guard could not be read waits like a guarded one.
func TestStartGuard_OnlyGuardedStartsWait(t *testing.T) {
	c := &Client{}
	c.RequireStartGuard(time.Minute, func(name string) bool { return name != "plain" })
	got := make(chan error, 1)
	go func() {
		_, err := c.guard("plain")
		got <- err
	}()
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("an unguarded start was refused: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an unguarded start waited for the firewall's start guard")
	}

	held := make(chan error, 1)
	go func() {
		_, err := c.guard("web")
		held <- err
	}()
	select {
	case err := <-held:
		t.Fatalf("a guarded start ran before any guard was set: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	c.SetStartGuard(StartGuard{})
	select {
	case err := <-held:
		if err != nil {
			t.Fatalf("the held guarded start: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the held guarded start never resumed once the guard was set")
	}
}
