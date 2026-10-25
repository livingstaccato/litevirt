package failover

import (
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The rc9 lab's F1b (A2): an operator confirmation from an earlier outage
// does not stand for this one, and this outage's SSH power-off, which the
// remote shell confirmed, is not proof on a host that does not trust one.
// The stall alert gave only the stale confirmation as its reason, so it never
// said the fence itself was the hold, nor named the trust opt-in: the
// confirmation check returned before the "not proof" branch was reached.
// The alert's reason must lead with the hold's actual reason, name the
// trust opt-in, and still name the confirmation it refused.
//
// Mutation: return straight after a stale confirmedOffNow, as before — the
// reason is the stale confirmation alone, red.
func TestStallReason_AStaleConfirmationDoesNotHideAnUntrustedSSHPowerOff(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	liveMembership(t, db)
	fenceRowAt(t, db, "confirm-old", "manual", "manual-confirmed", time.Now().Add(-time.Minute))
	time.Sleep(1100 * time.Millisecond)
	if err := corrosion.UpdateHostStartup(ctx, db, "down", "active", "", 0, 0, 0, false); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	runStart := time.Now()
	for _, o := range []string{"coordinator", "alive"} {
		failingSince(t, db, o, runStart, runStart)
	}
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(confirmedSSH("managed"))
	now := time.Now()
	c.Now = func() time.Time { return now }
	var reasons []string
	c.OnRecoveryStalled = func(host, _, reason string, _ int, _ time.Time) {
		if host == "down" {
			reasons = append(reasons, reason)
		}
	}

	c.run(ctx)
	// Past the stall threshold, and through a repeat: every cycle judges the
	// confirmation again, and the alert repeats.
	for _, step := range []time.Duration{recoveryStallAfter + time.Second, recoveryStallRepeat} {
		now = now.Add(step)
		holdLeaseThrough(t, db, ctx, now)
		c.run(ctx)
	}

	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM moved to %q on an untrusted SSH power-off and a stale confirmation", got)
	}
	if len(reasons) < 2 {
		t.Fatalf("stall alerts %q, want the first and its repeat", reasons)
	}
	reason := reasons[len(reasons)-1]
	if !strings.HasPrefix(reason, "the SSH fence's remote shell confirmed the power-off, which is not proof the host is off") {
		t.Errorf("stall reason does not lead with the untrusted SSH power-off: %q", reason)
	}
	for _, want := range []string{"--trust-ssh-poweroff", "lv host fence-confirm down", "confirm-old"} {
		if !strings.Contains(reason, want) {
			t.Errorf("stall reason does not name %q: %q", want, reason)
		}
	}
}

// The same hold, and an operator confirmation written after the fence that
// does not stand either: no observer has watched the host stay down since
// it. The confirmation-resume check judges it on every cycle; its note is
// appended to the hold, which still leads with the untrusted SSH power-off,
// rather than replacing it.
//
// Mutation: noteConfirmationStale sets the hold to its note alone — red.
func TestStallReason_AConfirmationAfterTheHoldIsAppendedToIt(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	liveMembership(t, db)
	runStart := time.Now()
	for _, o := range []string{"coordinator", "alive"} {
		failingSince(t, db, o, runStart, runStart)
	}
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(confirmedSSH("managed"))
	now := time.Now()
	c.Now = func() time.Time { return now }
	var reasons []string
	c.OnRecoveryStalled = func(host, _, reason string, _ int, _ time.Time) {
		if host == "down" {
			reasons = append(reasons, reason)
		}
	}
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("setup: VM moved to %q on an untrusted SSH power-off", got)
	}

	time.Sleep(1100 * time.Millisecond)
	fenceRowAt(t, db, "confirm-new", "manual", "manual-confirmed", time.Now())
	now = now.Add(recoveryStallAfter + time.Second)
	holdLeaseThrough(t, db, ctx, now)
	for _, o := range []string{"coordinator", "alive"} {
		failingSince(t, db, o, runStart, now) // still failing it: a fence candidate
	}
	c.run(ctx)

	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM moved to %q on a confirmation that does not stand", got)
	}
	if len(reasons) == 0 {
		t.Fatal("no stall alert for the held host")
	}
	reason := reasons[len(reasons)-1]
	if !strings.HasPrefix(reason, "the SSH fence's remote shell confirmed the power-off, which is not proof the host is off") {
		t.Errorf("stall reason does not lead with the untrusted SSH power-off: %q", reason)
	}
	for _, want := range []string{"--trust-ssh-poweroff", "confirm-new"} {
		if !strings.Contains(reason, want) {
			t.Errorf("stall reason does not name %q: %q", want, reason)
		}
	}
}
