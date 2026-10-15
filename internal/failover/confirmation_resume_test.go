package failover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
)

// operatorConfirms does exactly what `lv host fence-confirm` does
// (FenceHost with confirm_manual_only): mark the host fenced and write a
// manual-confirmed row. It runs no fence.
func operatorConfirms(t *testing.T, db *corrosion.Client, ctx context.Context, host string) {
	t.Helper()
	if err := corrosion.UpdateHostState(ctx, db, host, "fenced"); err != nil {
		t.Fatalf("UpdateHostState: %v", err)
	}
	if err := corrosion.InsertFenceLog(ctx, db, corrosion.FenceLogRecord{
		ID: "operator-" + host, HostName: host, Method: "manual", Result: "manual-confirmed",
		Detail: "operator confirmation via FenceHost(confirm_manual_only)",
	}); err != nil {
		t.Fatalf("InsertFenceLog: %v", err)
	}
}

// poweredOff is the operator powering down off before confirming it: an
// observer that saw it answer (a bridge) now fails it, its run begun 10 s ago.
// A confirmation is spent only while nobody has seen the host answer since it
// (confirmationStands), so a bridge still answering would refuse it.
func poweredOff(t *testing.T, db *corrosion.Client, observer string) {
	t.Helper()
	now := time.Now()
	if err := db.Execute(context.Background(),
		`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES (?, 'down', 'suspect', ?, ?, ?)`, observer, offlineThreshold,
		now.Add(-10*time.Second).UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

// A manual-fence host's workloads move once an operator confirms it is off.
//
// This is the flow the manual strategy has always documented — the coordinator
// fences, refuses to reschedule without a confirmation, the operator powers the
// host off and runs `lv host fence-confirm` — and it never worked. The refusal
// marked the host handled for the outage, nothing ever looked at it again, and
// the confirmation landed on a host no code path would revisit. The VM stayed
// assigned to a powered-off machine.
func TestConfirmationResume_ManualHostRecoversAfterConfirmation(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(manualFencer())

	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("precondition: the unconfirmed manual fence moved the VM to %q", got)
	}

	operatorConfirms(t, db, ctx, "down")
	c.run(ctx)

	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM still on %q after the operator confirmed the host off — the confirmation stranded it", got)
	}
}

// The same holds across a daemon restart between the refusal and the
// confirmation: the evidence is in fencing_log, not in the process that refused.
func TestConfirmationResume_SurvivesARestart(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	first := newTestCoordinator("coordinator", db)
	first.SetFencer(manualFencer())
	first.run(ctx)

	operatorConfirms(t, db, ctx, "down")
	restarted := newTestCoordinator("coordinator", db)
	restarted.SetFencer(manualFencer())
	restarted.run(ctx)

	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM still on %q after a restart and a confirmation", got)
	}
}

// The per-host "requires a verified fence" label now has a way through: an SSH
// fence is refused, the operator confirms, the workloads move.
func TestConfirmationResume_UnlocksTheFenceRequiresConfirmationLabel(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", requireConfirmation)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(fencerReturning("ssh", true))
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("precondition: the label did not hold the VM (on %q)", got)
	}

	operatorConfirms(t, db, ctx, "down")
	c.run(ctx)

	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM still on %q after confirming a label-held host", got)
	}
}

// A confirmation of a host the cluster never fenced resumes nothing.
//
// This is the objection that withdrew the earlier stranded-workload sweep
// (397c39f4): fence-confirm has no precondition and runs no fence, so a
// mistyped hostname would forge the whole admission proof. The resume
// therefore demands the cluster's own fence attempt as well, and a confirmation
// alone is not one.
//
// A confirmation written before any fence of this outage — the order a forced
// voter reconfiguration requires — therefore does not resume anything. It puts
// the host back on the fence path (confirmationFencesAfresh), and what happens
// next is the fresh fence's business: here an IPMI fence that fails, so nothing
// moves, exactly as for a host nobody confirmed.
func TestConfirmationResume_AConfirmationAloneIsNotEnough(t *testing.T) {
	db, ctx := seedDownHost(t, "ipmi", nil)
	lengthenStreak(t, db, ctx, 2*time.Minute)
	confirmAgo(t, db, ctx, 30*time.Second) // before any fence: no attempt row exists
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fences++
		return fence.Result{Method: "ipmi", Detail: "BMC unreachable", Success: false}
	})

	c.run(ctx)
	c.run(ctx)

	if fences != 1 {
		t.Errorf("the coordinator ran %d fences of a host confirmed during this outage, want 1 fresh fence", fences)
	}
	if got := vmHost(t, db, ctx); got != "down" {
		t.Errorf("VM moved to %q on a confirmation of a host whose own fence failed", got)
	}
}

// The positive half of the above: a manual-strategy host confirmed during this
// outage, before anything fenced it, is fenced afresh — the cluster's own
// attempt — and the manual fence's gate accepts that same recent confirmation.
func TestConfirmationResume_AConfirmationBeforeAnyFenceFencesAfresh(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	lengthenStreak(t, db, ctx, 2*time.Minute)
	confirmAgo(t, db, ctx, 30*time.Second)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(func(ctx context.Context, h fence.HostConfig) fence.Result {
		fences++
		return manualFencer()(ctx, h)
	})

	c.run(ctx)
	c.run(ctx)

	if fences != 1 {
		t.Errorf("the coordinator ran %d fences, want exactly 1 fresh fence", fences)
	}
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM still on %q after a confirmation of this outage and a fresh fence", got)
	}
}

// A confirmation older than the outage — the host answered after it, and its
// failing run began later — fences nothing and moves nothing.
func TestConfirmationResume_AConfirmationBeforeTheOutageFencesNothing(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil) // a run of five probes: eight seconds
	confirmAgo(t, db, ctx, 10*time.Minute)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(func(ctx context.Context, h fence.HostConfig) fence.Result {
		fences++
		return manualFencer()(ctx, h)
	})

	c.run(ctx)
	c.run(ctx)

	if fences != 0 {
		t.Errorf("the coordinator fenced on a confirmation from before the outage (%d fences)", fences)
	}
	if got := vmHost(t, db, ctx); got != "down" {
		t.Errorf("VM moved to %q on a confirmation from before the outage", got)
	}
}

// confirmAgo is `lv host fence-confirm down` run ago: the host marked fenced
// and a manual-confirmed row stamped then.
func confirmAgo(t *testing.T, db *corrosion.Client, ctx context.Context, ago time.Duration) {
	t.Helper()
	if err := corrosion.UpdateHostState(ctx, db, "down", "fenced"); err != nil {
		t.Fatalf("UpdateHostState: %v", err)
	}
	seedFenceRow(t, db, ctx, "operator-down", "manual-confirmed", ago)
}

// lengthenStreak makes every observer's failing run of 'down' span d.
func lengthenStreak(t *testing.T, db *corrosion.Client, ctx context.Context, d time.Duration) {
	t.Helper()
	if err := db.Execute(ctx, `UPDATE host_health SET consecutive_failures = ? WHERE target = 'down'`,
		int(d/health.ProbeInterval)+offlineThreshold); err != nil {
		t.Fatalf("lengthen streak: %v", err)
	}
}

// A confirmation from BEFORE the latest fence does not count: it attests to an
// earlier outage, not this one.
func TestConfirmationResume_AStaleConfirmationDoesNotCount(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if err := db.Execute(ctx,
		`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		"old-confirm", "down", "manual", "manual-confirmed", old, "last week's outage"); err != nil {
		t.Fatalf("seed old confirmation: %v", err)
	}
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(manualFencer())

	c.run(ctx) // fences now; the confirmation is older than this attempt
	c.run(ctx)

	if got := vmHost(t, db, ctx); got != "down" {
		t.Errorf("VM moved to %q on a confirmation older than the fence it would authorise", got)
	}
}

// The host must still be down NOW. A host that has come back is not a
// candidate, and resuming its recovery would start a second copy of VMs it is
// running.
func TestConfirmationResume_AHostThatCameBackIsNotResumed(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(manualFencer())
	c.run(ctx)

	operatorConfirms(t, db, ctx, "down")
	for _, o := range []string{"coordinator", "alive"} {
		ensureVoter(t, db, o)
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'down', 'healthy', 0, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`, o); err != nil {
			t.Fatalf("mark healthy: %v", err)
		}
	}
	c.run(ctx)

	if got := vmHost(t, db, ctx); got != "down" {
		t.Errorf("VM moved to %q although the host is answering again", got)
	}
}

// A host the operator has since put into maintenance is operator intent, and is
// never recovered automatically — not even with a fence attempt and a newer
// confirmation on record. Maintenance means "I am handling this machine".
func TestConfirmationResume_MaintenanceIsNeverResumed(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(manualFencer())
	c.run(ctx)
	operatorConfirms(t, db, ctx, "down")
	if err := corrosion.UpdateHostState(ctx, db, "down", "maintenance"); err != nil {
		t.Fatalf("UpdateHostState: %v", err)
	}

	c.run(ctx)
	c.run(ctx)

	if got := vmHost(t, db, ctx); got != "down" {
		t.Errorf("VM moved to %q off a host in maintenance", got)
	}
}

// switchableGate is an enforced split-brain gate whose decision the test flips.
type switchableGate struct {
	fakeFailoverGate
	open *bool
}

func (g switchableGate) DecisionGate(context.Context) health.GateResult {
	if *g.open {
		return health.GateResult{OK: true}
	}
	return health.GateResult{OK: false, Reason: health.ReasonNoQuorum}
}

// A resume is a runtime-ownership decision, and takes the decide-site gate like
// every other one: a CRDT lease can be held on both sides of a partition, so a
// minority coordinator holding one must not resume a recovery on a confirmation.
//
// The property that makes the resume-site gate necessary rather than redundant
// is the SECOND half. recoverWorkloads has late gates of its own that would also
// refuse — but by then the confirmation has been spent, so when quorum came back
// nothing would ever retry. Refusing before the confirmation is consumed is what
// lets the resume happen once the coordinator can decide again.
func TestConfirmationResume_TakesTheDecisionGateAndRetriesAfterIt(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	open := true
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(manualFencer())
	c.Gate = switchableGate{fakeFailoverGate: fakeFailoverGate{supports: map[string]bool{"alive": true}}, open: &open}
	c.run(ctx)

	operatorConfirms(t, db, ctx, "down")
	open = false // this coordinator has lost quorum
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM moved to %q by a coordinator without quorum", got)
	}

	open = true // quorum is back
	c.run(ctx)

	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM still on %q after quorum returned — the refused resume spent the confirmation", got)
	}
}

// One confirmation resumes one recovery. The coordinator polls every couple of
// seconds and a fenced host stays a quorum-down candidate for as long as it is
// off, so without this every cycle would log another "resuming" and count
// another confirmation_resumed — a metric that climbs forever over one outage
// says something happened that did not.
func TestConfirmationResume_OncePerConfirmation(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	fm := newFakeMetrics()
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(manualFencer())
	c.Metrics = fm
	c.run(ctx)

	operatorConfirms(t, db, ctx, "down")
	for i := 0; i < 4; i++ {
		c.run(ctx)
	}

	if got := fm.attempts[foKey(PhaseRecovery, ResultOK, ErrConfirmationResumed)]; got != 1 {
		t.Errorf("confirmation_resumed counted %d times over four cycles, want exactly 1", got)
	}
}

// Only the failover leader resumes a recovery on a confirmation, and a
// coordinator that is not the leader neither acts on it nor spends it.
//
// Every coordinator in the cluster sees the same fencing_log and the same
// quorum-down host, so without the lease each of them would resume the same
// recovery on the same confirmation — correctness would rest on whichever
// reschedule replicated first. The "not spent" half matters as much: a
// non-leader that recorded the confirmation as used would, on becoming leader,
// never resume it.
func TestConfirmationResume_OnlyTheLeaderResumes(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	leader := newTestCoordinator("coordinator", db)
	leader.SetFencer(manualFencer())
	leader.run(ctx) // takes the lease, fences, refuses for want of a confirmation

	operatorConfirms(t, db, ctx, "down")

	fm := newFakeMetrics()
	peer := newTestCoordinator("peer", db)
	peer.SetFencer(manualFencer())
	peer.Metrics = fm
	peer.run(ctx)
	peer.run(ctx)

	if got := vmHost(t, db, ctx); got != "down" {
		t.Errorf("VM moved to %q by a coordinator that does not hold the failover lease", got)
	}
	if got := fm.attempts[foKey(PhaseRecovery, ResultOK, ErrConfirmationResumed)]; got != 0 {
		t.Errorf("non-leader counted confirmation_resumed %d times, want 0", got)
	}
	if id, spent := peer.confirmResumed["down"]; spent {
		t.Errorf("non-leader recorded confirmation %q as spent", id)
	}

	leader.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM still on %q after the leader ran with the confirmation on record", got)
	}
}

// A confirmation the old leader never acted on is resumed by the next one.
//
// The refusing coordinator's lease lapses before it sees the confirmation (it
// died, or was partitioned away); the coordinator that takes the lease over
// must still find and resume the recovery, from fencing_log alone.
func TestConfirmationResume_TheNextLeaderResumesAfterHandover(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	old := newTestCoordinator("coordinator", db)
	old.SetFencer(manualFencer())
	old.run(ctx)

	operatorConfirms(t, db, ctx, "down")

	next := newTestCoordinator("peer", db)
	next.SetFencer(manualFencer())
	next.run(ctx) // the old lease is still live: stands down
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM moved to %q while another coordinator held the lease", got)
	}

	// The old leader is gone; its lease runs out. (Expired in the row rather
	// than by advancing next's clock, which would also age out the health rows
	// that make the host a candidate at all.)
	if err := db.Execute(ctx, `UPDATE leader_election SET expires_at = ? WHERE key = 'failover'`,
		time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("expire lease: %v", err)
	}
	next.run(ctx)

	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM still on %q after the lease changed hands — the new leader did not resume the confirmation", got)
	}
}

// A fence attempt and a confirmation from an EARLIER outage do not move the
// workloads in this one.
//
// The attempt is two days old and the confirmation one; the host is terminal
// and quorum-down now, and nothing fenced it for this outage. "The newest
// confirmation is at or after the newest attempt" is true of those two rows, and
// it is no evidence at all about the machine as it stands: whatever that fence
// did, it did two days ago. Resuming here reschedules the VMs of a host nobody
// has powered off, past every gate the fence path would apply.
func TestConfirmationResume_AnEarlierOutagesConfirmationDoesNotCount(t *testing.T) {
	for _, state := range []string{"fenced", "offline"} {
		t.Run(state, func(t *testing.T) {
			db, ctx := seedDownHost(t, "manual", nil)
			if err := corrosion.UpdateHostState(ctx, db, "down", state); err != nil {
				t.Fatalf("UpdateHostState: %v", err)
			}
			seedFenceRow(t, db, ctx, "old-attempt", "partial", 48*time.Hour)
			seedFenceRow(t, db, ctx, "old-confirm", "manual-confirmed", 24*time.Hour)
			c := newTestCoordinator("coordinator", db)
			c.SetFencer(manualFencer())

			c.run(ctx)
			c.run(ctx)

			if got := vmHost(t, db, ctx); got != "down" {
				t.Errorf("VM moved to %q on a fence attempt and a confirmation from an earlier outage", got)
			}
		})
	}
}

// The same holds for a FRESH confirmation of an old attempt: `lv host
// fence-confirm` runs no fence, so an operator confirming today does not turn
// a fence from two days ago into one for this outage. The confirmation is of
// this outage, so the coordinator fences afresh, and the recovery rests on THAT
// attempt: an IPMI fence that fails moves nothing.
func TestConfirmationResume_AFreshConfirmationOfAnOldAttemptDoesNotCount(t *testing.T) {
	db, ctx := seedDownHost(t, "ipmi", nil)
	lengthenStreak(t, db, ctx, 2*time.Minute)
	seedFenceRow(t, db, ctx, "old-attempt", "partial", 48*time.Hour)
	confirmAgo(t, db, ctx, 30*time.Second)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fences++
		return fence.Result{Method: "ipmi", Detail: "BMC unreachable", Success: false}
	})

	c.run(ctx)
	c.run(ctx)

	if fences != 1 {
		t.Errorf("the coordinator ran %d fences, want 1 fresh fence for this outage", fences)
	}
	if got := vmHost(t, db, ctx); got != "down" {
		t.Errorf("VM moved to %q on today's confirmation of a two-day-old fence attempt", got)
	}
}

// An operator who takes longer than recentFenceWindow to walk to the rack is
// still honoured, because the observers have watched the host down without a
// break since the attempt: the attempt is this outage's, however old it is.
func TestConfirmationResume_ASlowConfirmationOfThisOutageStillCounts(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	// Twenty minutes of unbroken failed probes from both observers.
	streak := int((20 * time.Minute) / health.ProbeInterval)
	if err := db.Execute(ctx, `UPDATE host_health SET consecutive_failures = ? WHERE target = 'down'`, streak); err != nil {
		t.Fatalf("lengthen streak: %v", err)
	}
	if err := corrosion.UpdateHostState(ctx, db, "down", "offline"); err != nil {
		t.Fatalf("UpdateHostState: %v", err)
	}
	seedFenceRow(t, db, ctx, "attempt", "partial", 15*time.Minute)
	operatorConfirms(t, db, ctx, "down")
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(manualFencer())

	c.run(ctx)

	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM still on %q after a confirmation of this outage's fence, fifteen minutes on", got)
	}
}

func seedFenceRow(t *testing.T, db *corrosion.Client, ctx context.Context, id, result string, age time.Duration) {
	t.Helper()
	if err := db.Execute(ctx,
		`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		id, "down", "manual", result, time.Now().Add(-age).UTC().Format(time.RFC3339), "seeded"); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}

// confirmedLastOutage seeds down's first outage, as a coordinator that took
// the lease since (or restarted) finds it: the cluster's fence attempt and an
// operator's confirmation of it, attemptAge and confirmAge ago. v4's path to
// down never healed, so its failing run reaches back an hour; coordinator and
// alive saw down answer after the confirmation, and fail it again in the
// outage in progress, their runs begun 30 s ago.
func confirmedLastOutage(t *testing.T, attemptAge, confirmAge time.Duration) (*corrosion.Client, context.Context) {
	t.Helper()
	db, ctx := seedDownHost(t, "manual", nil)
	now := time.Now()
	ensureVoter(t, db, "v4")
	failingSince(t, db, "v4", now.Add(-time.Hour), now)
	for _, o := range []string{"coordinator", "alive"} {
		failingSince(t, db, o, now.Add(-30*time.Second), now)
	}
	seedFenceRow(t, db, ctx, "outage1-attempt", "partial", attemptAge)
	confirmAgo(t, db, ctx, confirmAge)
	return db, ctx
}

// Re-review 2 (R2-C1): a confirmation of an earlier outage is not spent in
// the next one. The attempt reads as this outage's — inside
// recentFenceWindow, or on v4's unbroken run — and the confirmation is newer
// than it, but coordinator and alive saw down answer after the confirmation:
// their failing runs began after it. A coordinator that has not spent the
// confirmation (the lease moved, or it restarted) must not resume on it;
// down is running whatever it ran before. The refusal is the host's hold,
// with the remedy.
//
// Mutation: drop the check that the confirmation still stands from
// confirmationResume — the VM moves in both subtests.
func TestConfirmationResume_AConfirmationSomeoneSawTheHostAnswerSinceIsNotResumed(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		attemptAge, confirmAge time.Duration
	}{
		{"attempt inside the fence window", 3 * time.Minute, 2 * time.Minute},
		{"attempt on one observer's spanning run", 20 * time.Minute, 15 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, ctx := confirmedLastOutage(t, tc.attemptAge, tc.confirmAge)
			c := newTestCoordinator("coordinator", db)
			c.SetFencer(manualFencer())

			c.run(ctx)
			c.run(ctx)

			if got := vmHost(t, db, ctx); got != "down" {
				t.Fatalf("VM moved to %q on a confirmation the observers saw down answer after", got)
			}
			hold := c.holdReason["down"]
			if !strings.Contains(hold, "lv host fence-confirm down") || !strings.Contains(hold, "alive") {
				t.Errorf("the refusal is not the host's hold with the remedy and the observers that saw it answer: %q", hold)
			}
		})
	}
}

// The remedy works: confirming again in the outage in progress resumes the
// recovery, although the attempt is the earlier outage's — the new
// confirmation is the operator's word that down is off now, and nobody has
// seen it answer since.
//
// Mutation: judge the confirmation's standing at the attempt instead of at
// the confirmation — coordinator's and alive's runs began after the attempt,
// so the fresh confirmation is refused too and the VM never moves.
func TestConfirmationResume_ConfirmingAgainInThisOutageResumes(t *testing.T) {
	db, ctx := confirmedLastOutage(t, 20*time.Minute, 15*time.Minute)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(manualFencer())
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("setup: VM moved to %q on the earlier outage's confirmation", got)
	}

	seedFenceRow(t, db, ctx, "operator-again", "manual-confirmed", 0)
	c.run(ctx)

	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM still on %q after the operator confirmed down off again in this outage", got)
	}
}

// This node's own healthy probe of the host since the confirmation is an
// answer since it too, read on this node's clock.
//
// Mutation: drop the LastContact check from confirmationResume — the VM
// moves although this node reached down after the confirmation.
func TestConfirmationResume_AProbeAnswerSinceTheConfirmationIsNotResumed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		contact time.Duration // before now
		want    string
	}{
		{"probed healthy before the confirmation", 2 * time.Minute, "alive"},
		{"probed healthy since the confirmation", 0, "down"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, ctx := seedDownHost(t, "manual", nil)
			now := time.Now()
			for _, o := range []string{"coordinator", "alive"} {
				failingSince(t, db, o, now.Add(-5*time.Minute), now)
			}
			seedFenceRow(t, db, ctx, "attempt", "partial", time.Minute)
			confirmAgo(t, db, ctx, 30*time.Second)
			c := newTestCoordinator("coordinator", db)
			c.SetFencer(manualFencer())
			contact := now.Add(-tc.contact)
			c.LastContact = func(string) (time.Time, bool) { return contact, true }

			c.run(ctx)

			if got := vmHost(t, db, ctx); got != tc.want {
				t.Fatalf("VM on %q, want %q", got, tc.want)
			}
			if tc.want == "down" && !strings.Contains(c.holdReason["down"], "lv host fence-confirm down") {
				t.Errorf("the refusal is not the host's hold with the remedy: %q", c.holdReason["down"])
			}
		})
	}
}

// The same rule holds where a confirmation fences afresh: a confirmation
// written before any fence of the earlier outage, which ended before the
// coordinator fenced, does not fence down in the next outage on v4's
// spanning run — the manual fence it would start accepts that same recent
// confirmation, and the VM would move beside down's copy. Confirming again
// fences afresh and recovers.
//
// Mutation: judge the confirmation by observerStreakSpans alone in
// confirmationFencesAfresh — the coordinator fences and the VM moves.
func TestConfirmationFencesAfresh_AConfirmationSomeoneSawTheHostAnswerSinceFencesNothing(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	now := time.Now()
	ensureVoter(t, db, "v4")
	failingSince(t, db, "v4", now.Add(-time.Hour), now)
	for _, o := range []string{"coordinator", "alive"} {
		failingSince(t, db, o, now.Add(-30*time.Second), now)
	}
	confirmAgo(t, db, ctx, 2*time.Minute) // no fence attempt on record
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(func(ctx context.Context, h fence.HostConfig) fence.Result {
		fences++
		return manualFencer()(ctx, h)
	})

	c.run(ctx)
	c.run(ctx)

	if fences != 0 || vmHost(t, db, ctx) != "down" {
		t.Fatalf("%d fences and the VM on %q, on a confirmation the observers saw down answer after", fences, vmHost(t, db, ctx))
	}
	if hold := c.holdReason["down"]; !strings.Contains(hold, "lv host fence-confirm down") {
		t.Errorf("the refusal is not the host's hold with the remedy: %q", hold)
	}

	seedFenceRow(t, db, ctx, "operator-again", "manual-confirmed", 0)
	c.run(ctx)
	c.run(ctx)

	if fences != 1 || vmHost(t, db, ctx) != "alive" {
		t.Errorf("%d fences and the VM on %q after confirming again; want one fresh fence and the VM recovered", fences, vmHost(t, db, ctx))
	}
}
