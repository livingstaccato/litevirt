package failover

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// monoClock is a settable monotonic clock for the pause deadline.
type monoClock struct {
	mu  sync.Mutex
	now time.Time
}

func (m *monoClock) Now() time.Time { m.mu.Lock(); defer m.mu.Unlock(); return m.now }
func (m *monoClock) Advance(d time.Duration) {
	m.mu.Lock()
	m.now = m.now.Add(d)
	m.mu.Unlock()
}

// pauseCoordinator is seedDownHost with a best-effort fence that cannot reach
// the host (method best-effort-ssh, assurance assumed), and the reliance
// predicate as given.
func pauseCoordinator(t *testing.T, latched bool) (*Coordinator, *corrosion.Client, context.Context, *monoClock) {
	t.Helper()
	db, ctx := seedDownHost(t, "best-effort", nil)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(fencerReturning("best-effort-ssh", true))
	mono := &monoClock{now: time.Unix(1_900_000_000, 0)}
	c.Mono = mono.Now
	c.PartitionPauseEnforced = func(context.Context) bool { return latched }
	return c, db, ctx, mono
}

func newestFence(t *testing.T, db *corrosion.Client, ctx context.Context, host string) (method, result string) {
	t.Helper()
	rows, err := db.Query(ctx, `SELECT method, result FROM fencing_log WHERE host_name = ? ORDER BY timestamp DESC, rowid DESC LIMIT 1`, host)
	if err != nil || len(rows) == 0 {
		t.Fatalf("no fencing_log row for %s: %v", host, err)
	}
	return rows[0].String("method"), rows[0].String("result")
}

// Unlatched, nothing changes: an assumed best-effort fence recovers at once
// and is recorded as assumed. G2 of docs/design/partition-pause.md.
//
// Mutation: rely on the pause regardless of the predicate — the VM does not
// move on the first cycle and this goes red.
func TestPartitionPause_UnlatchedRecoversAtOnceAsAssumed(t *testing.T) {
	c, db, ctx, _ := pauseCoordinator(t, false)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM on %q after an assumed fence with partition_pause_v1 unlatched; want it recovered at once, as today", got)
	}
	m, r := newestFence(t, db, ctx, "down")
	if a := corrosion.FenceAssurance(m, r); a != corrosion.FenceAssumed {
		t.Fatalf("fence recorded as %s/%s (assurance %s), want assumed", m, r, a)
	}
}

// Latched, the coordinator records self_paused and starts nothing until the
// wait has passed on its monotonic clock — then recovers.
//
// Mutations: drop the deadline gate in recoverFenced — the VM moves on the
// first cycle; drop asSelfPause — the fence is recorded assumed; compare the
// deadline against the WALL clock (c.now) instead of Mono — the VM never moves
// (the wall clock does not advance here) and the last check goes red.
func TestPartitionPause_LatchedWaitsOutThePauseThenRecovers(t *testing.T) {
	c, db, ctx, mono := pauseCoordinator(t, true)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM moved to %q at the fence decision; the minority may not have paused yet", got)
	}
	m, r := newestFence(t, db, ctx, "down")
	if a := corrosion.FenceAssurance(m, r); a != corrosion.FenceSelfPaused {
		t.Fatalf("fence recorded as %s/%s (assurance %s), want %s", m, r, a, corrosion.FenceSelfPaused)
	}
	wait, _ := c.partitionPauseWait(ctx)
	if wait != health.PartitionPauseWaitFor(2) {
		t.Fatalf("wait = %v for a 3-host cluster, want W(2) = %v", wait, health.PartitionPauseWaitFor(2))
	}
	mono.Advance(wait - time.Second)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM moved to %q a second before the deadline", got)
	}
	mono.Advance(2 * time.Second)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM on %q after the deadline passed; want it recovered", got)
	}
}

// A successor coordinator — or this one restarted — holds no wait in memory.
// It resumes from the self-pause fence record and waits afresh, anchored at
// its own first sight, which is later than the original decision and so safe.
//
// Mutation: treat a resumed self-pause fence as already waited — the VM moves
// on the successor's first cycle and this goes red.
func TestPartitionPause_ASuccessorWaitsAfresh(t *testing.T) {
	c, db, ctx, mono := pauseCoordinator(t, true)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("setup: VM moved to %q", got)
	}
	// Expire the first coordinator's lease so the successor can take it.
	if err := db.Execute(ctx, `DELETE FROM leader_election`); err != nil {
		t.Fatal(err)
	}
	succ := newTestCoordinator("alive", db)
	succ.SetFencer(fencerReturning("best-effort-ssh", true))
	succ.Mono = mono.Now
	succ.PartitionPauseEnforced = func(context.Context) bool { return true }
	mono.Advance(health.PartitionPauseWaitFor(2) - time.Second)
	succ.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("the successor recovered at once (%q) on a self-pause record it never waited for", got)
	}
	mono.Advance(health.PartitionPauseWaitFor(2) + time.Second)
	succ.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM on %q after the successor's own wait passed", got)
	}
}

// A host that answered after the fence is not recovered at the deadline: it is
// back, and it resumes itself.
//
// Mutation: drop the fenceStillStands re-check in retryPauseWait — the VM moves
// and this goes red.
func TestPartitionPause_AHostThatAnsweredIsNotRecovered(t *testing.T) {
	c, db, ctx, mono := pauseCoordinator(t, true)
	c.run(ctx)
	// An observer (not a voter, so the fence quorum still stands) saw the host
	// answer after the fence.
	if err := db.Execute(ctx,
		`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES ('bystander', 'down', 'healthy', 0, NULL, ?)`, c.now().Add(time.Second).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	mono.Advance(health.PartitionPauseWaitFor(2) + time.Second)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM recovered to %q although an observer saw the host answer after the fence", got)
	}
}

// An open partition_pause_failed for the host means its pause cannot be relied
// on: the coordinator records assumed and behaves as without partition pause.
//
// Mutation: ignore the condition in relyOnPartitionPause — the fence is
// recorded self_paused and this goes red.
func TestPartitionPause_AFailedPauseIsNotReliedOn(t *testing.T) {
	c, db, ctx, _ := pauseCoordinator(t, true)
	if err := corrosion.UpsertHealthCondition(ctx, db, corrosion.HealthCondition{
		Evaluator: corrosion.PartitionPauseEvaluator, Code: corrosion.CondPartitionPauseFailed,
		SubjectKind: "host", SubjectID: "down", Lifecycle: corrosion.ConditionConfirmed,
		Severity: corrosion.SeverityCritical, FirstSeen: "2026-10-02T00:00:00Z", LastSeen: "2026-10-02T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	c.run(ctx)
	m, r := newestFence(t, db, ctx, "down")
	if a := corrosion.FenceAssurance(m, r); a != corrosion.FenceAssumed {
		t.Fatalf("fence recorded %s although the host reported its pause failed", a)
	}
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM on %q; with no pause to rely on, recovery runs as today", got)
	}
}

// A verified fence never waits.
//
// Mutation: rewrite every successful fence as self-pause — this goes red.
func TestPartitionPause_AVerifiedFenceDoesNotWait(t *testing.T) {
	db, ctx := seedDownHost(t, "ipmi", nil)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(fencerReturning("ipmi", true))
	c.PartitionPauseEnforced = func(context.Context) bool { return true }
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM on %q after a verified fence; nothing to wait for", got)
	}
}

// The wait scales with the hosts the minority may probe (§4.4).
//
// Mutation: compute the wait from a constant one-batch size — the 20-host
// case goes red.
func TestPartitionPause_WaitScalesWithClusterSize(t *testing.T) {
	c, db, ctx, _ := pauseCoordinator(t, true)
	for i := 0; i < 17; i++ {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: fmt.Sprintf("extra-%02d", i),
			Address: "10.0.1.1", GRPCPort: 7443, State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	// 20 hosts: 19 probe targets, two batches.
	wait, targets := c.partitionPauseWait(ctx)
	if targets != 19 || wait != health.PartitionPauseWaitFor(19) || wait <= health.PartitionPauseWait {
		t.Fatalf("wait = %v for %d targets, want W(19) = %v (more than one batch's %v)",
			wait, targets, health.PartitionPauseWaitFor(19), health.PartitionPauseWait)
	}
}

// partition_one_way: raised when a quorum fails the host while the host's own
// rows, written after those failure streaks began, mark a majority healthy;
// NOT raised on a symmetric split, where the host's last healthy rows predate
// the streaks.
//
// Mutations: drop the "after the streak began" test — the symmetric case
// raises and goes red; drop the condition write — the one-way case goes red.
func TestPartitionPause_OneWayIsMadeVisible(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset time.Duration // when "down" wrote its healthy rows, relative to now
		want   bool
	}{
		{"one-way", 0, true},
		{"symmetric", -time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, db, ctx, _ := pauseCoordinator(t, true)
			ensureVoter(t, db, "down")
			at := c.now().Add(tc.offset).UTC().Format(time.RFC3339Nano)
			for _, peer := range []string{"coordinator", "alive"} {
				if err := db.Execute(ctx,
					`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
					 VALUES ('down', ?, 'healthy', 0, NULL, ?)`, peer, at); err != nil {
					t.Fatal(err)
				}
			}
			c.run(ctx)
			row, ok, err := corrosion.GetHealthCondition(ctx, db, corrosion.PartitionPauseEvaluator,
				corrosion.CondPartitionOneWay, "host", "down")
			if err != nil {
				t.Fatal(err)
			}
			raised := ok && row.Lifecycle != corrosion.ConditionResolved
			if raised != tc.want {
				t.Fatalf("partition_one_way raised = %v, want %v (%+v)", raised, tc.want, row)
			}
		})
	}
}

// A coordinator that regained the voter majority moments ago decides no new
// fence: the failure rows it holds were written during its own cut.
//
// Mutation: drop the QuorumRegain check in run — the host is fenced and this
// goes red.
func TestPartitionPause_ARegainedCoordinatorDefersNewFences(t *testing.T) {
	c, db, ctx, _ := pauseCoordinator(t, true)
	regained := true
	c.QuorumRegain = func() bool { return regained }
	c.run(ctx)
	rows, err := db.Query(ctx, `SELECT 1 AS one FROM fencing_log WHERE host_name = 'down'`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatal("a coordinator inside its quorum-regain grace fenced a host")
	}
	regained = false
	c.run(ctx)
	if rows, _ := db.Query(ctx, `SELECT 1 AS one FROM fencing_log WHERE host_name = 'down'`); len(rows) == 0 {
		t.Fatal("the fence was not decided once the grace had passed")
	}
}
