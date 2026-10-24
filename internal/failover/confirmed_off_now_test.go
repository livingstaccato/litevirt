package failover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// Re-review 4 (R4-C1): recoverFenced's three confirmation gates accept an
// operator confirmation only while it stands for the outage in progress
// (confirmedOffNow). manualFenceConfirmed alone accepts any confirmation
// under five minutes old, and recoverFenced records the host 'offline' before
// its gates, which ends the life fenceRowCutoff would otherwise exclude an
// earlier life's confirmation by. A host recorded fenced boots 'active'
// (hostboot.go), so a confirmation of the outage before a reboot was spent on
// a fence of the next one while the host ran its workloads.

// The reviewer's probe: confirmed a minute ago, then the host booted
// (UpdateHostStartup 'active'), and every observer's failing run began after
// the boot. A manual fence now must not move the VM on the old confirmation;
// the hold names the remedy, and confirming again moves it.
//
// Mutation: manualFenceConfirmed in place of confirmedOffNow at the manual
// gate — the VM moves on the old confirmation.
func TestConfirmedOffNow_AConfirmationFromBeforeTheHostRebootedIsNotSpent(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
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
	c.SetFencer(manualFencer())

	c.run(ctx)
	c.run(ctx)

	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM moved to %q on a confirmation from before the host's reboot", got)
	}
	hold := c.holdReason["down"]
	if !strings.Contains(hold, "confirm-old") || !strings.Contains(hold, "lv host fence-confirm down") {
		t.Fatalf("hold %q does not name the refused confirmation and the remedy", hold)
	}

	// The remedy: the operator confirms again, after the runs began.
	again := runStart.Add(6 * time.Second)
	c.Now = func() time.Time { return time.Now().Add(7 * time.Second) }
	if err := corrosion.UpdateHostState(ctx, db, "down", "fenced"); err != nil {
		t.Fatal(err)
	}
	fenceRowAt(t, db, "confirm-again", "manual", "manual-confirmed", again)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM still on %q after the operator confirmed again (hold %q)", got, c.holdReason["down"])
	}
}

// The life check alone: the host booted within fenceSkewMargin of the
// confirmation, so the observers' runs begun at the boot are not "begun
// after" it, and v4's unbroken run spans it — confirmationStands accepts it.
// It was still written before the host last turned active, and the life is
// read before recoverFenced records the host 'offline'.
//
// Mutation: read fenceRowCutoff after markHostState, or drop the life check
// from confirmedOffNow — the VM moves.
func TestConfirmedOffNow_TheLifeIsReadBeforeTheHostIsRecordedOffline(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	liveMembership(t, db)
	fenceRowAt(t, db, "confirm-old", "manual", "manual-confirmed", time.Now())
	failingSince(t, db, "v4", time.Now().Add(-2*time.Minute), time.Now())
	time.Sleep(1100 * time.Millisecond)
	if err := corrosion.UpdateHostStartup(ctx, db, "down", "active", "", 0, 0, 0, false); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	for _, o := range []string{"coordinator", "alive"} {
		failingSince(t, db, o, time.Now(), time.Now())
	}
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(manualFencer())

	c.run(ctx)

	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM moved to %q on a confirmation from before the host last turned active", got)
	}
	if hold := c.holdReason["down"]; !strings.Contains(hold, "before the host last turned active") {
		t.Fatalf("hold %q does not say why the confirmation was refused", hold)
	}
}

// The safe-fence and fence_requires_confirmation gates apply
// confirmationStands to a confirmation OLDER than the fence they judge, which
// a successor reaches by resuming from a recorded unverified fence: the host
// is 'offline', so there is no life to cut the confirmation off by, and the
// fence itself stands (every observer's run spans it). The confirmation, a
// minute old, is inside manualFenceConfirmed's window; when every observer's
// failing run began after it, the host answered (or rebooted) since it, and
// nothing moves. The control, runs spanning the confirmation too, moves the
// VM through the same gate.
//
// (The manual gate is reached only by a live fence of an 'active' host,
// where the life check refuses such a confirmation first; the probe above
// covers it.)
//
// Mutation: drop the stands check at one gate (confirmedOffNow ->
// manualFenceConfirmed there) — that gate's "restarted" subtest goes red.
func TestConfirmedOffNow_AResumedGateRequiresTheConfirmationToStand(t *testing.T) {
	gates := []struct {
		name     string
		strategy string
		labels   map[string]string
		method   string
		safe     bool
	}{
		{"fence_requires_confirmation", "ssh", requireConfirmation, "ssh", false},
		// A best-effort fence counts only as a self-pause, so the resumed
		// row is one; its pause wait is zero here, to isolate the gate.
		{"best-effort under safe-fence", "best-effort", nil, "best-effort-ssh", true},
	}
	for _, g := range gates {
		for _, tc := range []struct {
			name     string
			runStart time.Duration // relative to the confirmation
			want     string
		}{
			{"runs span the confirmation", -time.Minute, "alive"},
			{"runs restarted since the confirmation", 30 * time.Second, "down"},
		} {
			t.Run(g.name+"/"+tc.name, func(t *testing.T) {
				db, ctx := seedDownHost(t, g.strategy, g.labels)
				confirmedAt := time.Now().Add(-time.Minute)
				fenceRowAt(t, db, "confirm-1", "manual", "manual-confirmed", confirmedAt)
				if g.method == "best-effort-ssh" {
					fenceRowDetailAt(t, db, "fence-2", g.method, "fenced", corrosion.FencePauseReliance+"stub",
						time.Now().Add(-20*time.Second))
				} else {
					fenceRowAt(t, db, "fence-2", g.method, "fenced", time.Now().Add(-20*time.Second))
				}
				if err := corrosion.UpdateHostState(ctx, db, "down", "offline"); err != nil {
					t.Fatal(err)
				}
				// v4's unbroken run spans the confirmation either way, so the
				// refusal is on the runs begun since it.
				failingSince(t, db, "v4", confirmedAt.Add(-time.Minute), time.Now())
				for _, o := range []string{"coordinator", "alive"} {
					failingSince(t, db, o, confirmedAt.Add(tc.runStart), time.Now())
				}
				c := newTestCoordinator("coordinator", db)
				c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
					t.Error("the successor fenced a host recorded off by an unverified fence")
					return fence.Result{}
				})
				if g.safe {
					c.Gate = gateEnforcing(capabilities.SafeFenceDefaultV1)
					c.SafeFenceEnforce = true
					c.PauseWaitFor = func(int) time.Duration { return 0 }
				}

				c.run(ctx)

				if got := vmHost(t, db, ctx); got != tc.want {
					t.Fatalf("VM on %q, want %q (hold %q)", got, tc.want, c.holdReason["down"])
				}
				if tc.want == "alive" {
					return
				}
				hold := c.holdReason["down"]
				if !strings.Contains(hold, "confirm-1 does not stand") || !strings.Contains(hold, "lv host fence-confirm down") {
					t.Fatalf("hold %q does not name the refused confirmation and the remedy", hold)
				}
				// R4-m1: a run begun since is not asserted to be an answer.
				if !strings.Contains(hold, "or its own daemon restarted") {
					t.Fatalf("hold %q does not say the observer may have restarted", hold)
				}
			})
		}
	}
}

// Re-review 4 (R4-m2): a self-pause record a restarted coordinator declines
// (it has no probe answer from the host, so it does not rely on the pause)
// is re-judged every cycle; why it does not rely is logged once, not every
// poll. A reason that changes is logged again.
//
// Mutation: log in relyOnPartitionPause unconditionally — one line per cycle.
func TestRelyOnPartitionPause_ANotRelyingReasonIsLoggedOncePerChange(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	c.run(ctx)
	if _, ok := c.pauseWaits["down"]; !ok {
		t.Fatal("setup: the self-pause fence started no wait")
	}
	t0 := time.Now()
	failingSince(t, db, "v4", t0.Add(-time.Hour), t0.Add(time.Minute))
	for _, o := range []string{"coordinator", "alive"} {
		failingSince(t, db, o, t0.Add(30*time.Second), t0.Add(time.Minute))
	}
	if err := db.Execute(ctx, `DELETE FROM leader_election`); err != nil {
		t.Fatal(err)
	}
	succ := newTestCoordinator("alive", db)
	succ.SetFencer(fencerReturning("best-effort-ssh", true))
	succ.Mono = mono.Now
	succ.Now = func() time.Time { return time.Now().Add(time.Minute) }
	succ.PartitionPauseEnforced = func(context.Context) bool { return true }
	word := false
	succ.PeerPausesOnLoss = func(string) bool { return word }

	buf := captureSlog(t)
	for i := 0; i < 5; i++ {
		succ.run(ctx)
	}
	const noWord = "did not say it pauses on losing the majority"
	if n := strings.Count(buf.String(), noWord); n != 1 {
		t.Fatalf("logged %d times over 5 cycles, want once:\n%s", n, buf.String())
	}
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("the declined record moved the VM to %q", got)
	}
	if !strings.Contains(succ.holdReason["down"], "no longer stands") {
		t.Fatalf("the declined record is not the host's hold: %q", succ.holdReason["down"])
	}

	// Relied on once, then not: the reason is new again.
	word = true
	if !succ.relyOnPartitionPause(ctx, &corrosion.HostRecord{Name: "down"}) {
		t.Fatal("setup: the pause is not relied on with the host's word")
	}
	word = false
	succ.relyOnPartitionPause(ctx, &corrosion.HostRecord{Name: "down"})
	if n := strings.Count(buf.String(), noWord); n != 2 {
		t.Fatalf("logged %d times after the reliance changed twice, want 2", n)
	}
}
