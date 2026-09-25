package grpcapi

import (
	"testing"
	"time"
)

// The budget a progress stream is judged against must measure STALL, not
// elapsed wall clock.
//
// runRestoreLiveUntil used to give up 5s after it started, whatever the stream
// was doing. That budget belongs to work the test does not control -- a chunked
// restore plus a VM start -- so under `go test ./...` on a loaded machine it
// expired while the restore was still emitting frames. The observed failure was
// exactly that, and it named the evidence itself:
//
//	born_running_test.go:195: never reached phase STARTED; frames=4
//
// Four frames had arrived. Nothing was wrong; the machine was busy. Three
// unrelated branches were reported as broken by it in one sync run.
func TestPhaseWaiter_ProgressDefersTheDeadline(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	w := newPhaseWaiter(time.Second, start.Add(time.Hour))

	// A frame every 900ms, for well past the old flat budget. The stream is
	// slow, not stuck, and must never be given up on.
	now := start
	for i := 1; i <= 20; i++ {
		now = now.Add(900 * time.Millisecond)
		if giveUp, why := w.observe(i, now); giveUp {
			t.Fatalf("gave up on a stream still producing frames after %s (%s); "+
				"a slow machine is not a stalled restore", now.Sub(start), why)
		}
	}
}

// The other half: a stream that stops producing must still fail, and reasonably
// promptly. A waiter that never gives up is not a fix, it is a hang.
func TestPhaseWaiter_StallGivesUp(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	w := newPhaseWaiter(time.Second, start.Add(time.Hour))

	if giveUp, _ := w.observe(3, start.Add(500*time.Millisecond)); giveUp {
		t.Fatal("gave up inside the quiet window")
	}
	// Same frame count, past the quiet window.
	giveUp, why := w.observe(3, start.Add(2*time.Second))
	if !giveUp {
		t.Fatal("a stream that stopped producing must be given up on, or the test hangs " +
			"until the package timeout and reports nothing useful")
	}
	if why == "" {
		t.Error("the refusal must say what it observed; 'it timed out' is what sent me " +
			"looking at three innocent branches")
	}
}

// The hard stop keeps the waiter inside the test binary's own deadline, so a
// stalled stream cannot consume the package budget and take every later test
// down with it.
func TestPhaseWaiter_HardStopWins(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	w := newPhaseWaiter(time.Hour, start.Add(2*time.Second))

	// Progress every second: the quiet window is nowhere near expiring, but the
	// hard stop is.
	if giveUp, _ := w.observe(1, start.Add(time.Second)); giveUp {
		t.Fatal("gave up before the hard stop")
	}
	if giveUp, _ := w.observe(2, start.Add(3*time.Second)); !giveUp {
		t.Fatal("the hard stop must win over a still-open quiet window")
	}
}
