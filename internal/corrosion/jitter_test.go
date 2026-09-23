package corrosion

import (
	"testing"
	"time"
)

// Periodic replication work is spread, not synchronised.
//
// Every per-peer push loop is started in the same instant and idled on exactly
// 10 s, so they woke together forever; every node's anti-entropy ticker, started
// at cluster boot, fired together too — each node pulling digests from every
// other at the same moment, an O(N²) burst on a fixed beat. Jitter breaks the
// lockstep without changing the average rate.
func TestJittered_StaysInBoundsAndVaries(t *testing.T) {
	const d = 10 * time.Second
	const frac = 0.2
	lo, hi := time.Duration(float64(d)*(1-frac)), time.Duration(float64(d)*(1+frac))

	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		got := jittered(d, frac)
		if got < lo || got > hi {
			t.Fatalf("jittered(%v, %v) = %v, outside [%v, %v]", d, frac, got, lo, hi)
		}
		seen[got] = true
	}
	if len(seen) < 10 {
		t.Errorf("200 draws produced only %d distinct values — this is not spreading anything", len(seen))
	}
}

// Jitter must not bias the rate. Two hundred draws averaging far from d would
// quietly change how often every loop runs.
func TestJittered_IsCentredOnTheInterval(t *testing.T) {
	const d = 10 * time.Second
	var sum time.Duration
	const n = 2000
	for i := 0; i < n; i++ {
		sum += jittered(d, 0.2)
	}
	mean := sum / n
	if mean < 9500*time.Millisecond || mean > 10500*time.Millisecond {
		t.Errorf("mean of %d draws = %v, want ~%v", n, mean, d)
	}
}

// A zero or negative fraction is no jitter, and a non-positive interval is left
// alone rather than turned into a negative sleep.
func TestJittered_DegenerateInputs(t *testing.T) {
	if got := jittered(10*time.Second, 0); got != 10*time.Second {
		t.Errorf("frac 0 gave %v, want the interval unchanged", got)
	}
	if got := jittered(0, 0.2); got != 0 {
		t.Errorf("interval 0 gave %v, want 0", got)
	}
}
