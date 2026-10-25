package failover

import (
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The rc10 lab's N2: a trust setting changed while a recovery is held on a
// confirmed SSH power-off left ha.recovery.unproven_fence saying what the
// setting was when the fence was judged ("may instead set
// --trust-ssh-poweroff" after it was set). The coordinator does not re-judge
// a host it has handled, so the settle sweep re-reads the host's setting and
// rewrites the remedy (sshTrustNote). The hold does not change: trust is never
// retroactive, and the VM stays where it is until fence-confirm.
//
// Mutations: no re-raise in the settle sweep (the note it was raised with
// stays) — red; the hold text not refreshed with the note — red.
func TestUnprovenFence_TheTrustNoteFollowsTheHostsSetting(t *testing.T) {
	t.Run("trust set during the hold", func(t *testing.T) {
		db, ctx := seedDownHost(t, "ssh", nil)
		c := newTestCoordinator("coordinator", db)
		c.SetFencer(confirmedSSH("managed"))
		c.run(ctx)
		if _, ev, open := unprovenCond(t, db); !open || !strings.Contains(ev.Remedy, "may instead set") {
			t.Fatalf("setup: no condition offering the opt-in (open %v, remedy %q)", open, ev.Remedy)
		}
		for k, v := range trustSSH {
			if err := corrosion.SetHostLabel(ctx, db, "down", k, v); err != nil {
				t.Fatal(err)
			}
		}
		c.run(ctx)
		c.run(ctx)
		if got := vmHost(t, db, ctx); got != "down" {
			t.Fatalf("trust set during the hold recovered the VM to %q: trust is never retroactive", got)
		}
		_, ev, open := unprovenCond(t, db)
		if !open {
			t.Fatal("the condition resolved while the recovery is still held")
		}
		if !strings.Contains(ev.Remedy, "trusts a confirmed SSH power-off now") || strings.Contains(ev.Remedy, "may instead set") {
			t.Errorf("remedy does not follow the trust set during the hold: %q", ev.Remedy)
		}
		if !strings.Contains(ev.Remedy, "`lv host fence-confirm down`") {
			t.Errorf("remedy lost the way out: %q", ev.Remedy)
		}
		// The stall alert's hold text follows it too (review m3).
		if hold := c.holdReason["down"]; !strings.Contains(hold, "trusts a confirmed SSH power-off now") || strings.Contains(hold, "may instead set") {
			t.Errorf("the hold the stall alert names does not follow the trust set during the hold: %q", hold)
		}
	})
}
