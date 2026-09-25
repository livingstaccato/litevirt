package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
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
func TestConfirmationResume_AConfirmationAloneIsNotEnough(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	operatorConfirms(t, db, ctx, "down") // before any fence: no attempt row exists
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(manualFencer())

	c.run(ctx)
	c.run(ctx)

	if got := vmHost(t, db, ctx); got != "down" {
		t.Errorf("VM moved to %q on a confirmation of a host the cluster never fenced", got)
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
