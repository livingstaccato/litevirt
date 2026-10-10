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
// for `lv host fence-confirm`, which the confirmation path owns.
//
// Mutation M5: let fenceRetryDue accept a manual attempt — a second manual
// fence runs.
func TestFenceWake_ManualFenceIsNotRetried(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(func(ctx context.Context, h fence.HostConfig) fence.Result {
		fences++
		return manualFencer()(ctx, h)
	})
	c.run(ctx)
	ageFenceRows(t, db, ctx, 10*time.Minute)
	c.run(ctx)
	if fences != 1 {
		t.Errorf("the coordinator ran %d manual fences, want 1", fences)
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
