package daemon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Round 2 m-7: the daemon's firewall-logging wiring. The loader's Logging
// answers through the gate, so with the probe passed it is available only
// while the listener holds the group; the listener's bind report reaches both
// the gate and the condition; a change runs a pass, and a second one shortly
// after, so a pass that loaded before the change cannot leave the old plan
// applied (m-1 window 3); Stop turns logging off and runs one pass at once
// (window 1), but only when lines may have been rendered.
//
// Mutations: Logging from the probe alone — red; OnBind skips the gate —
// red; no follow-up pass — red; Stop runs no pass — red.
func TestFirewallLogging_Wiring(t *testing.T) {
	var mu sync.Mutex
	passes := 0
	var reported []error
	f := newFirewallLogging(context.Background(), 27, nil,
		func(context.Context) error { mu.Lock(); passes++; mu.Unlock(); return nil },
		func(err error) { mu.Lock(); reported = append(reported, err); mu.Unlock() })
	f.followUp = 10 * time.Millisecond
	count := func() int { mu.Lock(); defer mu.Unlock(); return passes }
	if ok, g := f.Logging(); ok || g != 27 {
		t.Fatalf("before any bind: %v %d, want unavailable", ok, g)
	}
	f.OnBind(nil)
	if ok, _ := f.Logging(); !ok {
		t.Fatal("bound, but the loader is told logging is unavailable")
	}
	deadline := time.Now().Add(5 * time.Second)
	for count() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if n := count(); n != 2 {
		t.Errorf("passes after the bind = %d, want 2 (one now, one follow-up)", n)
	}
	f.OnBind(errors.New("socket closed"))
	if ok, _ := f.Logging(); ok {
		t.Error("the bind was lost, but logging is still available")
	}
	mu.Lock()
	if len(reported) != 2 || reported[0] != nil || reported[1] == nil {
		t.Errorf("condition reports = %v, want bound then lost", reported)
	}
	mu.Unlock()
	f.OnBind(nil)
	for count() < 6 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	before := count()
	f.Stop(context.Background())
	if ok, _ := f.Logging(); ok {
		t.Error("logging available after Stop")
	}
	if count() != before+1 {
		t.Errorf("Stop ran %d pass(es), want one, synchronously", count()-before)
	}

	refused := newFirewallLogging(context.Background(), 27, errors.New("nft refused"),
		func(context.Context) error { t.Error("a pass ran for a host whose probe was refused"); return nil }, func(error) {})
	refused.OnBind(nil)
	if ok, _ := refused.Logging(); ok {
		t.Error("a refused probe still made logging available")
	}
	refused.Stop(context.Background())
}
