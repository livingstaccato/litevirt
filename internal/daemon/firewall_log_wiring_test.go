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

// Codex cand36 review I1: a listener that held the group, had its lines
// applied, and then lost the group has its loss-triggered passes scheduled on
// the run context. When SIGTERM cancels that context before they apply, the
// lines stay; Stop, with a fresh context, must still run its removal pass,
// because the lines may be in the kernel whatever the bind says now. A host
// that never held the group keeps no pass at stop (control).
//
// Mutation: Stop runs its pass only while the gate is bound — no pass: red.
func TestFirewallLogging_StopAfterALostBindStillRemovesTheLines(t *testing.T) {
	runCtx, cancelRun := context.WithCancel(context.Background())
	var mu sync.Mutex
	var fresh, cancelled int
	f := newFirewallLogging(runCtx, 27, nil, func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		if ctx.Err() != nil {
			cancelled++ // the loader fails on a cancelled context: nothing is removed
			return ctx.Err()
		}
		fresh++
		return nil
	}, func(error) {})
	f.followUp = time.Hour // only the immediate loss pass, on the run context
	f.OnBind(nil)
	if ok, _ := f.Logging(); !ok { // a loader is told logging is on: the lines are applied
		t.Fatal("bound, but logging unavailable")
	}
	cancelRun()                           // SIGTERM, before the loss pass runs
	f.OnBind(errors.New("socket closed")) // the listener loses the group
	time.Sleep(50 * time.Millisecond)     // the loss pass runs on the cancelled context
	mu.Lock()
	before := fresh
	mu.Unlock()
	f.Stop(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if fresh != before+1 {
		t.Errorf("Stop after a lost bind ran %d removal pass(es) on a live context, want 1", fresh-before)
	}

	never := newFirewallLogging(context.Background(), 27, nil,
		func(context.Context) error {
			t.Error("a pass at stop for a host that never held the group")
			return nil
		}, func(error) {})
	never.OnBind(errors.New("operation not permitted"))
	never.Stop(context.Background())
}
