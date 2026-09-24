package health

import (
	"context"
	"time"
)

// Test-only seams for the external health_test package, which needs the
// failover coordinator and so cannot live inside package health.

// SetClockForTest replaces the checker's local clock.
func (c *Checker) SetClockForTest(fn func() time.Time) { c.clock = fn }

// ProbeAllForTest runs one probe cycle, exactly as one tick of Start would.
func (c *Checker) ProbeAllForTest(ctx context.Context) bool { return c.checkAllPeers(ctx) }

// BeatForTest is one beat of the liveness heartbeat Start runs, at the
// checker's current clock.
func BeatForTest(c *Checker) { c.beat(c.now()) }
