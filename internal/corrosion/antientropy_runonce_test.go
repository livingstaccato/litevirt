package corrosion

import (
	"context"
	"testing"
	"time"
)

// TestAntiEntropyRunOnce_Debounce: RunOnce runs a pass, then no-ops within the cooldown or
// while a pass is in progress — so `lv cluster converge --all` in a loop can't hammer a node.
// A test client has no peers, and a pass that finds none starts no cooldown (it exchanged
// nothing — see runGuarded), so the pass that must start one is stubbed as having had peers.
func TestAntiEntropyRunOnce_Debounce(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	defer c.Close()
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	ae := NewAntiEntropy(c, "", time.Minute)
	ctx := context.Background()

	if !ae.runGuarded(func() bool { return true }, passOperator) {
		t.Fatal("first operator pass should run")
	}
	if ae.RunOnce(ctx) {
		t.Fatal("RunOnce within cooldown should debounce")
	}

	ae.mu.Lock()
	ae.lastRan = time.Now().Add(-2 * antiEntropyCooldown)
	ae.mu.Unlock()
	if !ae.RunOnce(ctx) {
		t.Fatal("RunOnce after the cooldown should run")
	}

	ae.mu.Lock()
	ae.lastRan = time.Now().Add(-2 * antiEntropyCooldown) // past cooldown, so inProgress alone must gate
	ae.inProgress = true
	ae.mu.Unlock()
	if ae.RunOnce(ctx) {
		t.Fatal("RunOnce while a pass is in progress should debounce")
	}
}
