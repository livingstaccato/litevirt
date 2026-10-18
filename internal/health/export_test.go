package health

import (
	"context"
)

// Test-only seams for the external health_test package, which needs the
// failover coordinator and so cannot live inside package health.

// ProbeAllForTest runs one probe cycle, exactly as one tick of Start would.
func (c *Checker) ProbeAllForTest(ctx context.Context) bool { return c.checkAllPeers(ctx) }

// BeatForTest is one beat of the liveness heartbeat Start runs, at the
// checker's current clock.
func BeatForTest(c *Checker) { c.beat(c.now()) }

// SetVoterSetForTest replaces the voter set the probe plan reads (nil restores
// corrosion.VoterSet). It does not touch QuorumProof or the coordinator.
func (c *Checker) SetVoterSetForTest(fn func(context.Context) (map[string]bool, error)) {
	c.voterSet = fn
}
