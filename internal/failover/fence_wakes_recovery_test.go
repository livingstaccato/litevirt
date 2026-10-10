package failover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/fence"
)

// ageFenceRows moves every fencing_log row of 'down' back by d, as if the
// coordinator's fence had run d ago.
func ageFenceRows(t *testing.T, db *corrosion.Client, ctx context.Context, d time.Duration) {
	t.Helper()
	rows, err := db.Query(ctx, `SELECT id, timestamp FROM fencing_log WHERE host_name = 'down'`)
	if err != nil {
		t.Fatalf("read fencing_log: %v", err)
	}
	for _, r := range rows {
		ts, perr := time.Parse(time.RFC3339, r.String("timestamp"))
		if perr != nil {
			t.Fatalf("fencing_log timestamp %q: %v", r.String("timestamp"), perr)
		}
		if err := db.Execute(ctx, `UPDATE fencing_log SET timestamp = ? WHERE id = ?`,
			ts.Add(-d).UTC().Format(time.RFC3339), r.String("id")); err != nil {
			t.Fatalf("age fencing_log row: %v", err)
		}
	}
}

// operatorFences does what a successful `lv host fence down --confirmed` does
// over SSH: 'offline' and an ssh/fenced row.
func operatorFences(t *testing.T, db *corrosion.Client, ctx context.Context) {
	t.Helper()
	if err := corrosion.RecordFenceWithState(ctx, db, corrosion.FenceLogRecord{
		ID: "operator-ssh-down", HostName: "down", Method: "ssh", Result: fence.LogFenced, Detail: "operator fence",
	}, "offline"); err != nil {
		t.Fatalf("RecordFenceWithState: %v", err)
	}
}

// countingFencer returns a fencer that reports results in order (the last one
// repeats) and counts the fences it runs.
func countingFencer(n *int, results ...fence.Result) Fencer {
	return func(context.Context, fence.HostConfig) fence.Result {
		r := results[len(results)-1]
		if *n < len(results) {
			r = results[*n]
		}
		*n++
		return r
	}
}

var (
	sshFailedFence = fence.Result{Method: "ssh", Success: false, Detail: "ssh: no identity"}
	sshFence       = fence.Result{Method: "ssh", Success: true, Detail: "poweroff sent"}
)

// Lab drill S5: the lease-holding coordinator's own fence of a down host
// fails, and an operator then fences the host successfully. The coordinator
// recovers the host's workloads on its next cycle, from the operator's
// record, without fencing it again and without a restart — and only once.
//
// On main the failed fence cached the host as handled, so no later cycle
// reached the resume path, and the workloads waited for a coordinator
// restart (6 min 13 s in the drill).
//
// Mutation M1 (adopt): drop the newer-recorded-fence check from the cached
// branch of run (fenceAuthorityChanged answers false) — the VM stays on 'down'.
func TestFenceWake_OperatorFenceAfterOwnFailedFenceRecoversNextCycle(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	lengthenStreak(t, db, ctx, 2*time.Minute)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(countingFencer(&fences, sshFailedFence))

	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("precondition: a failed fence moved the VM to %q", got)
	}
	if got := hostState(t, db, ctx); got != "offline" {
		t.Fatalf("precondition: the failed fence left 'down' %q, want offline", got)
	}

	// The operator's fence lands after the failed one, inside the retry
	// backoff, so nothing but the operator's record can move the VM.
	ageFenceRows(t, db, ctx, 10*time.Second)
	operatorFences(t, db, ctx)

	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM still on %q one cycle after an operator fence of its host succeeded", got)
	}
	c.run(ctx)
	c.run(ctx)
	if fences != 1 {
		t.Errorf("the coordinator ran %d fences, want 1: it adopts the operator's fence, never repeats it", fences)
	}
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM on %q after further cycles, want it left on alive", got)
	}
	// Mutation M22: keep the hold reason when recovery runs — the stale
	// "fence failed" survives the recovery.
	if r, ok := c.holdReason["down"]; ok {
		t.Errorf("hold reason %q survived the recovery that ran", r)
	}
}

// A coordinator whose own fence failed does not park the host: it fences it
// again once the retry backoff has passed, and recovers on success. It does
// not fence it again inside the backoff.
//
// Mutation M2 (retry): fenceRetryDue answers false — the second fence never
// runs and the VM stays on 'down'.
// Mutation M3 (backoff): fenceRetryDue ignores the delay — the immediate
// second cycle fences again.
func TestFenceWake_OwnFailedFenceIsRetriedOnSchedule(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(countingFencer(&fences, sshFailedFence, sshFence))

	c.run(ctx)
	c.run(ctx)
	if fences != 1 {
		t.Fatalf("the coordinator ran %d fences inside the retry backoff, want 1", fences)
	}
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("precondition: a failed fence moved the VM to %q", got)
	}

	ageFenceRows(t, db, ctx, fenceRetryBase+time.Second)
	c.lastFenceAt = nil // the first fence ran fenceRetryBase ago on this clock too
	c.run(ctx)
	if fences != 2 {
		t.Fatalf("the coordinator ran %d fences once the backoff had passed, want 2", fences)
	}
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM still on %q after the retried fence succeeded", got)
	}
}

// A retry repeats the method that failed, never the host's strategy now: a
// host switched to best-effort since its IPMI fence failed must not have its
// workloads moved on a failed best-effort fence, which proceeds anyway.
//
// Mutation M9: fence the retry with the host's current strategy — the
// best-effort retry "succeeds" by proceeding and the VM moves.
func TestFenceWake_RetryRepeatsTheFailedMethod(t *testing.T) {
	db, ctx := seedDownHost(t, "ipmi", nil)
	c := newTestCoordinator("coordinator", db)
	var strategies []string
	c.SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
		strategies = append(strategies, h.FenceStrategy)
		return fence.Result{Method: "ipmi", Success: false, Detail: "BMC unreachable"}
	})
	c.run(ctx)
	if err := db.Execute(ctx, `UPDATE hosts SET fence_strategy = 'best-effort' WHERE name = 'down'`); err != nil {
		t.Fatalf("switch strategy: %v", err)
	}
	ageFenceRows(t, db, ctx, fenceRetryBase+time.Second)
	c.lastFenceAt = nil // the first fence ran fenceRetryBase ago on this clock too
	c.run(ctx)
	if len(strategies) != 2 || strategies[1] != "ipmi" {
		t.Fatalf("fence strategies = %v, want the retry to repeat ipmi", strategies)
	}
	if got := vmHost(t, db, ctx); got != "down" {
		t.Errorf("VM moved to %q on a failed retry", got)
	}
}

// The retry backoff doubles from fenceRetryBase to fenceRetryMax.
//
// Mutation M4: drop the cap — the sixth delay is 16 minutes.
func TestFenceWake_RetryBackoffDoublesToItsCap(t *testing.T) {
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i, w := range want {
		if got := fenceRetryDelay(i + 1); got != w {
			t.Errorf("fenceRetryDelay(%d) = %v, want %v", i+1, got, w)
		}
	}
	if got := fenceRetryDelay(64); got != fenceRetryMax {
		t.Errorf("fenceRetryDelay(64) = %v, want the cap %v", got, fenceRetryMax)
	}
}

// A manual fence is never retried: it cannot succeed, and its recovery waits
// for `lv host fence-confirm`, which the confirmation path owns. Nor is a
// watchdog fence of a peer: fence.Execute refuses it for any host but the
// caller, so it can only fail.
//
// Mutation M5: let fenceRetryDue accept a manual attempt — a second manual
// fence runs.
// Mutation M17: let retryableFenceMethod accept watchdog — a second watchdog
// fence runs.
func TestFenceWake_ManualAndWatchdogFencesAreNotRetried(t *testing.T) {
	for _, tc := range []struct {
		strategy string
		result   fence.Result
	}{
		{"manual", fence.Result{Method: "manual", Detail: "operator must confirm", Success: false}},
		{"watchdog", fence.Result{Method: "watchdog", Detail: "watchdog fence only for the local node", Success: false}},
	} {
		t.Run(tc.strategy, func(t *testing.T) {
			db, ctx := seedDownHost(t, tc.strategy, nil)
			c := newTestCoordinator("coordinator", db)
			fences := 0
			c.SetFencer(countingFencer(&fences, tc.result))
			c.run(ctx)
			ageFenceRows(t, db, ctx, 10*time.Minute)
			c.lastFenceAt = nil
			c.run(ctx)
			if fences != 1 {
				t.Errorf("the coordinator ran %d %s fences, want 1", fences, tc.strategy)
			}
		})
	}
}

type stallAlert struct {
	host, coordinator, reason string
	pending                   int
}

// A fenced/offline host whose recoverable workloads are still on it
// recoveryStallAfter after its fence record raises one alert, naming the host,
// the coordinator and why it is not proceeding, as an event and through
// OnRecoveryStalled; it repeats no more often than recoveryStallRepeat.
//
// Mutation M6: drop the recoveryStallAfter wait — the first cycle alerts.
// Mutation M7: drop the repeat bound — every cycle alerts.
func TestFenceWake_StalledRecoveryAlertsOnceThenAtABoundedInterval(t *testing.T) {
	db, ctx := seedDownHost(t, "ipmi", nil)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "ipmi", Success: false, Detail: "BMC unreachable"}
	})
	now := time.Now()
	c.Now = func() time.Time { return now }
	var alerts []stallAlert
	c.OnRecoveryStalled = func(host, coordinator, reason string, pending int, _ time.Time) {
		alerts = append(alerts, stallAlert{host, coordinator, reason, pending})
	}
	bus := events.NewBus()
	evs, cancel := bus.Subscribe()
	defer cancel()
	c.Events = bus

	c.run(ctx)
	if len(alerts) != 0 {
		t.Fatalf("alerted %v on the cycle that fenced, want nothing before %v", alerts, recoveryStallAfter)
	}
	now = now.Add(recoveryStallAfter + time.Second)
	c.run(ctx)
	if len(alerts) != 1 {
		t.Fatalf("alerts = %v once the recovery had stalled %v, want exactly one", alerts, recoveryStallAfter)
	}
	a := alerts[0]
	if a.host != "down" || a.coordinator != "coordinator" || a.pending != 1 || !strings.Contains(a.reason, "fence failed") {
		t.Errorf("alert = %+v, want host down, coordinator coordinator, 1 pending, a reason naming the failed fence", a)
	}
	select {
	case e := <-evs:
		if e.Action != EventRecoveryStalled || e.Target != "down" || !strings.Contains(e.Detail, "coordinator") {
			t.Errorf("event = %+v, want %s for down naming the coordinator", e, EventRecoveryStalled)
		}
	default:
		t.Error("no event published for the stalled recovery")
	}

	now = now.Add(time.Minute)
	c.run(ctx)
	if len(alerts) != 1 {
		t.Fatalf("alerted again %v after the first; the repeat is bounded by %v", alerts[1:], recoveryStallRepeat)
	}
	now = now.Add(recoveryStallRepeat)
	c.run(ctx)
	if len(alerts) != 2 {
		t.Errorf("alerts = %d after %v more, want the repeat", len(alerts), recoveryStallRepeat)
	}
}

// A host whose workloads all moved raises no stall alert, however long ago
// its fence was.
//
// Mutation M8: count every fenced/offline host as stalled — this alerts.
func TestFenceWake_RecoveredHostDoesNotAlert(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(fencerReturning("ssh", true))
	now := time.Now()
	c.Now = func() time.Time { return now }
	alerts := 0
	c.OnRecoveryStalled = func(string, string, string, int, time.Time) { alerts++ }

	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("precondition: the VM was not recovered (on %q)", got)
	}
	now = now.Add(recoveryStallAfter + recoveryStallRepeat)
	c.run(ctx)
	if alerts != 0 {
		t.Errorf("%d stall alert(s) for a host with nothing left on it", alerts)
	}
}

// thirdVoter adds a third voter observing 'down' as failing, so one observer
// can see the host answer while a quorum (2 of 3) still counts it down.
func thirdVoter(t *testing.T, db *corrosion.Client, ctx context.Context) {
	t.Helper()
	ensureVoter(t, db, "third")
	if err := db.Execute(ctx,
		`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES ('third', 'down', 'suspect', ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
		offlineThreshold); err != nil {
		t.Fatalf("insert health: %v", err)
	}
}

// aliveAnswers records that the observer 'alive' has just seen 'down' answer.
func aliveAnswers(t *testing.T, db *corrosion.Client, ctx context.Context) {
	t.Helper()
	if err := db.Execute(ctx,
		`UPDATE host_health SET status = 'healthy', consecutive_failures = 0,
		 updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE observer = 'alive' AND target = 'down'`); err != nil {
		t.Fatalf("alive answers: %v", err)
	}
}

// A host anyone has seen answer since the fence attempt that failed is not
// fenced again, though a quorum's rows still count it down: a partition that
// heals between attempts must not have its host powered off as it returns.
//
// Mutation M15: retryStillDown answers true — the retry runs.
func TestFenceWake_HostThatAnsweredSinceTheFailureIsNotRetried(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	thirdVoter(t, db, ctx)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(countingFencer(&fences, sshFailedFence, sshFence))
	c.run(ctx)
	if fences != 1 {
		t.Fatalf("fixture: %d fences, want the one failed fence", fences)
	}
	ageFenceRows(t, db, ctx, fenceRetryBase+time.Second)
	c.lastFenceAt = nil
	aliveAnswers(t, db, ctx)

	c.run(ctx)
	if fences != 1 {
		t.Errorf("the coordinator fenced a host an observer saw answer after the failed attempt (%d fences)", fences)
	}
	if got := vmHost(t, db, ctx); got != "down" {
		t.Errorf("VM moved to %q", got)
	}
}

// A retry runs the host's CURRENT strategy when it is ipmi or ssh: an
// operator who fixes a failed SSH fence by configuring IPMI has the next
// retry use it.
//
// Mutation M16: retryStrategy always repeats the failed method — the retry
// runs ssh.
func TestFenceWake_RetryHonoursAFixedStrategy(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	c := newTestCoordinator("coordinator", db)
	var strategies []string
	c.SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
		strategies = append(strategies, h.FenceStrategy)
		if h.FenceStrategy == "ipmi" {
			return fence.Result{Method: "ipmi", Success: true, Detail: "verified off"}
		}
		return sshFailedFence
	})
	c.run(ctx)
	if err := db.Execute(ctx, `UPDATE hosts SET fence_strategy = 'ipmi' WHERE name = 'down'`); err != nil {
		t.Fatalf("switch strategy: %v", err)
	}
	ageFenceRows(t, db, ctx, fenceRetryBase+time.Second)
	c.lastFenceAt = nil
	c.run(ctx)
	if len(strategies) != 2 || strategies[1] != "ipmi" {
		t.Fatalf("fence strategies = %v, want the retry to run the operator's ipmi", strategies)
	}
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM still on %q after the IPMI retry succeeded", got)
	}
}

// The fence gates hold a due retry back exactly as they hold a first fence.
//
// Mutation M12: drop the LocalStall gate — local-stall retries.
// Mutation M13: drop the QuorumRegain gate — quorum-regain retries.
// Mutation M14: drop the recentlyFenced gate — recently-fenced retries.
func TestFenceWake_FenceGatesHoldARetryBack(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, *corrosion.Client, context.Context, *Coordinator)
	}{
		{"local-stall", func(_ *testing.T, _ *corrosion.Client, _ context.Context, c *Coordinator) {
			c.LocalStall = func() bool { return true }
		}},
		{"quorum-regain", func(_ *testing.T, _ *corrosion.Client, _ context.Context, c *Coordinator) {
			c.QuorumRegain = func(context.Context, string) bool { return true }
		}},
		{"recently-fenced", func(t *testing.T, db *corrosion.Client, ctx context.Context, _ *Coordinator) {
			// A success four minutes ago, older than the failure: the newest
			// attempt still failed, so the retry is due, but a fence is recent.
			if err := db.Execute(ctx,
				`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES ('older-ok', 'down', 'ssh', 'fenced', ?, 'earlier')`,
				time.Now().Add(-4*time.Minute).UTC().Format(time.RFC3339)); err != nil {
				t.Fatalf("seed older success: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, ctx := seedDownHost(t, "ssh", nil)
			c := newTestCoordinator("coordinator", db)
			fences := 0
			c.SetFencer(countingFencer(&fences, sshFailedFence, sshFence))
			c.run(ctx)
			ageFenceRows(t, db, ctx, fenceRetryBase+time.Second)
			c.lastFenceAt = nil
			tc.setup(t, db, ctx, c)
			c.run(ctx)
			if fences != 1 {
				t.Errorf("a due retry ran under the %s gate (%d fences)", tc.name, fences)
			}
		})
	}
}

// An adopted fence goes through resumeActionFor like a successor's: an
// operator's SSH fence of a host an observer has seen answer since does not
// stand, and the leader recovers nothing from it.
//
// Mutation M11: treat a declined resume as resumeFromRecord — the VM moves.
func TestFenceWake_AnAdoptedFenceThatDoesNotStandIsDeclined(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	thirdVoter(t, db, ctx)
	lengthenStreak(t, db, ctx, 2*time.Minute)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(countingFencer(&fences, sshFailedFence))
	c.run(ctx)
	ageFenceRows(t, db, ctx, 10*time.Second)
	operatorFences(t, db, ctx)
	aliveAnswers(t, db, ctx)

	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Errorf("VM moved to %q on an operator fence an observer saw the host answer after", got)
	}
}

// Losing the lease drops the stall clock, the last alert and the hold
// reasons: the node that takes the lease back alerts from its own view.
//
// Mutation M18: keep the stall state across a step-down — the regained
// leader stays silent inside the repeat window.
func TestFenceWake_StepDownResetsTheStallClock(t *testing.T) {
	db, ctx := seedDownHost(t, "ipmi", nil)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "ipmi", Success: false, Detail: "BMC unreachable"}
	})
	now := time.Now()
	c.Now = func() time.Time { return now }
	alerts := 0
	c.OnRecoveryStalled = func(string, string, string, int, time.Time) { alerts++ }

	c.run(ctx)
	now = now.Add(recoveryStallAfter + time.Second)
	c.run(ctx)
	if alerts != 1 {
		t.Fatalf("fixture: %d alerts, want 1", alerts)
	}

	// Another node holds the lease: this one steps down.
	if err := db.Execute(ctx, `UPDATE leader_election SET holder = 'other', expires_at = ? WHERE key = 'failover'`,
		now.Add(time.Minute).UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("hand the lease over: %v", err)
	}
	c.run(ctx)
	if c.stallSince != nil || c.stallAlerted != nil || c.holdReason != nil {
		t.Errorf("stall state survived the step-down: since=%v alerted=%v reasons=%v", c.stallSince, c.stallAlerted, c.holdReason)
	}

	// Its lease runs out; this node leads again, inside the repeat window.
	now = now.Add(2 * time.Minute)
	c.run(ctx)
	if alerts != 2 {
		t.Errorf("alerts = %d after regaining the lease; the new tenure alerts from its own view", alerts)
	}
}

// A failed retry does not repeat the host.fenced notification until its
// backoff has reached the cap, and then at most once per retryNotifyEvery.
//
// Mutation M19: fenceNotifies always true — every failed retry notifies.
func TestFenceWake_FailedRetriesNotifySparingly(t *testing.T) {
	c := NewCoordinator("coordinator", nil)
	now := time.Now()
	c.Now = func() time.Time { return now }
	failed := fence.Result{Method: "ipmi", Success: false}
	if !c.fenceNotifies("down", failed) {
		t.Error("a first fence that failed must notify")
	}
	notified := 0
	for n := 1; n <= 8; n++ {
		c.retrying = &fenceRetry{Failures: n}
		if c.fenceNotifies("down", failed) {
			notified++
		}
		now = now.Add(fenceRetryDelay(n))
	}
	// Failures 2..4 are under the cap; the 5th reaches it and notifies; the
	// rest fall inside the hour.
	if notified != 1 {
		t.Errorf("%d of 8 failed retries notified, want 1", notified)
	}
	now = now.Add(retryNotifyEvery)
	if !c.fenceNotifies("down", failed) {
		t.Error("a failed retry at the cap an hour later must notify again")
	}
	c.retrying = &fenceRetry{Failures: 1}
	if !c.fenceNotifies("down", fence.Result{Method: "ipmi", Success: true}) {
		t.Error("a retry that succeeded must notify")
	}
}

// The stall alert names what holds the recovery NOW, not the refusal before
// it: after the operator's fence is adopted, a recovery that cannot place the
// VM is reported as that, not as the leader's earlier failed fence.
//
// Mutation M24: drop the placement hold reason — the alert does not say why
// the recovery that ran left the VM.
func TestFenceWake_StallReasonIsWhatHoldsTheRecoveryNow(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	lengthenStreak(t, db, ctx, 2*time.Minute)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(countingFencer(new(int), sshFailedFence))
	now := time.Now()
	c.Now = func() time.Time { return now }
	var reasons []string
	c.OnRecoveryStalled = func(_, _, reason string, _ int, _ time.Time) { reasons = append(reasons, reason) }

	c.run(ctx)
	if !strings.Contains(c.holdReason["down"], "fence failed") {
		t.Fatalf("fixture: hold reason %q, want the failed fence", c.holdReason["down"])
	}
	// Nowhere to put the VM: the only other workload host is in maintenance
	// (the coordinator itself is a witness, which places nothing).
	if err := corrosion.UpdateHostState(ctx, db, "alive", "maintenance"); err != nil {
		t.Fatalf("UpdateHostState: %v", err)
	}
	ageFenceRows(t, db, ctx, 10*time.Second)
	operatorFences(t, db, ctx)
	c.run(ctx)
	now = now.Add(recoveryStallAfter + time.Second)
	c.run(ctx)
	if len(reasons) != 1 || !strings.Contains(reasons[0], "no eligible host") || strings.Contains(reasons[0], "fence failed") {
		t.Errorf("stall reasons = %q, want the recovery's own (no eligible host), not the stale failed fence", reasons)
	}
}

// A retried fence does not erase what an earlier recovery by this
// coordinator recorded: VMs moved, so the host waits for `lv host undrain`.
//
// Mutation M23: seed fenceRelocated false on every commit — the retry resets
// it, and recoverHosts could return the host to service on its own.
func TestFenceWake_ARetryKeepsVMsMoved(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	c := newTestCoordinator("coordinator", db)
	// Both fences fail, so no recovery runs that could set it true again.
	fences := 0
	c.SetFencer(countingFencer(&fences, sshFailedFence))
	c.fenceRelocated["down"] = true // an earlier recovery of this outage moved VMs

	c.run(ctx)
	ageFenceRows(t, db, ctx, fenceRetryBase+time.Second)
	c.lastFenceAt = nil
	c.run(ctx)
	if fences != 2 {
		t.Fatalf("fixture: %d fences, want the failed fence and its retry", fences)
	}
	if !c.fenceRelocated["down"] {
		t.Error("a fence of the host reset fenceRelocated: the record that VMs moved is gone")
	}
}
