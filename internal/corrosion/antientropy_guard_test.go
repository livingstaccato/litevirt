package corrosion

import (
	"context"
	"testing"
)

// The trigger guard's two exceptions to the cooldown (fix round 1 of
// fix/post-restart-friction):
//   - a pass that found no peer exchanged nothing, so it starts no cooldown;
//   - the operator's RunOnce is not held back by a cooldown the loop's own
//     catch-up pass started, so `lv cluster converge` works on a stuck node.
//
// Everything else is debounced exactly as before.
func TestRunGuarded_CooldownExceptions(t *testing.T) {
	ctx := context.Background()
	contacted := func() bool { return true }
	noPeers := func() bool { return false }
	newAE := func() *AntiEntropy { return NewAntiEntropy(newPruneTestClient(t), t.TempDir(), 0) }

	t.Run("operator after a catch-up pass is not debounced", func(t *testing.T) {
		ae := newAE()
		if !ae.runGuarded(contacted, passCatchUp) {
			t.Fatal("first catch-up pass did not run")
		}
		if !ae.RunOnce(ctx) {
			t.Fatal("RunOnce right after the loop's catch-up pass was debounced; the operator's lever is gone on a stuck node")
		}
	})
	t.Run("operator after a scheduled pass is debounced", func(t *testing.T) {
		ae := newAE()
		if !ae.runGuarded(contacted, passScheduled) {
			t.Fatal("scheduled pass did not run")
		}
		if ae.RunOnce(ctx) {
			t.Fatal("RunOnce inside the cooldown of a scheduled pass ran; the hammer guard is gone")
		}
	})
	t.Run("the loop after a catch-up pass is debounced", func(t *testing.T) {
		ae := newAE()
		ae.runGuarded(contacted, passCatchUp)
		if ae.runGuarded(contacted, passCatchUp) {
			t.Fatal("a second catch-up pass inside the cooldown ran; passes must stay a cooldown apart")
		}
	})
	t.Run("a pass with no peers starts no cooldown", func(t *testing.T) {
		ae := newAE()
		if !ae.runGuarded(noPeers, passCatchUp) {
			t.Fatal("the no-peer pass did not run")
		}
		if !ae.runGuarded(contacted, passCatchUp) {
			t.Fatal("a pass right after one that found no peers was debounced; peers that come back wait out a cooldown for nothing")
		}
	})
}
