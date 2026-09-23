package corrosion

import (
	"math/rand"
	"time"
)

// Idle intervals for the periodic replication loops. Named so the jitter
// applied to them is visible at the declaration rather than buried in a select.
const (
	// pushIdleInterval is how long a per-peer push loop waits with nothing to
	// send before re-checking for deferred writes.
	pushIdleInterval = 10 * time.Second
	// loopJitter is the ±fraction every periodic replication timer is spread by.
	loopJitter = 0.2
)

// jittered returns d spread uniformly by up to ±frac of itself.
//
// Every per-peer push loop is started in the same instant and idled on exactly
// pushIdleInterval, so they woke together for the life of the process. Every
// node's anti-entropy ticker, started at cluster boot, fired together as well:
// each node pulling digests from every other at the same moment, an O(N²)
// burst on a fixed beat. Spreading each wait breaks the lockstep; the draw is
// symmetric, so the average rate is unchanged.
//
// A non-positive d or frac returns d unchanged, so a caller can never be handed
// a negative sleep.
func jittered(d time.Duration, frac float64) time.Duration {
	if d <= 0 || frac <= 0 {
		return d
	}
	spread := float64(d) * frac
	return d + time.Duration((rand.Float64()*2-1)*spread)
}
