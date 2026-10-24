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

// A self-pause recovers a best-effort host only while its partition pause is
// relied on. When reliance lapses during the wait or on a successor, nothing
// else proves the host off, so the VM is held with the way out; it is never
// recovered on the best-effort fence alone (review B-1, adopted from the
// reviewer's probes).

func pauseFailedCondition(t *testing.T, db *corrosion.Client, ctx context.Context) {
	t.Helper()
	if err := corrosion.UpsertHealthCondition(ctx, db, corrosion.HealthCondition{
		Evaluator: corrosion.PartitionPauseEvaluator, Code: corrosion.CondPartitionPauseFailed,
		SubjectKind: "host", SubjectID: "down", Lifecycle: corrosion.ConditionConfirmed,
		Severity: corrosion.SeverityCritical, FirstSeen: "2026-10-02T00:00:00Z", LastSeen: "2026-10-02T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
}

// Relied on at the fence; the host's partition_pause_failed arrives during the
// wait. At the deadline the pause is not relied on, and the deadline refuses.
//
// Mutation: fall back to quietFallback when the pause is not relied on at the
// deadline (selfPauseStillStands, the code before) — the VM moves, red.
func TestPauseLapse_PauseFailedDuringTheWaitIsHeld(t *testing.T) {
	c, db, ctx, mono := pauseCoordinator(t, true)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("setup: moved to %q", got)
	}
	pauseFailedCondition(t, db, ctx)
	mono.Advance(health.PartitionPauseWaitFor(2) + 2*time.Second)
	c.run(ctx)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM recovered to %q though the host reported its pause FAILED and nothing proves it off", got)
	}
	if hold := c.holdReason["down"]; !strings.Contains(hold, "no longer relied on") || !strings.Contains(hold, "fence-confirm") ||
		!strings.Contains(hold, "ipmi or redfish") {
		t.Fatalf("hold %q does not say why and name the way out", hold)
	}
}

// A successor whose own flag is off, or that holds no probe answer from the
// host, does not rely on the pause, and holds the self-pause record.
//
// Mutation: as above, and drop the resume decline and the recoverFenced
// re-check — the VM moves, red.
func TestPauseLapse_ASuccessorThatDoesNotRelyIsHeld(t *testing.T) {
	for _, tc := range []struct {
		name       string
		flag, word bool
	}{{"flag-off", false, true}, {"no-word", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			c, db, ctx, mono := pauseCoordinator(t, true)
			c.run(ctx)
			if err := db.Execute(ctx, `DELETE FROM leader_election`); err != nil {
				t.Fatal(err)
			}
			succ := newTestCoordinator("alive", db)
			succ.SetFencer(dialledFencer())
			succ.Mono = mono.Now
			flag, word := tc.flag, tc.word
			succ.PartitionPauseEnforced = func(context.Context) bool { return flag }
			succ.PeerPausesOnLoss = func(string) bool { return word }
			succ.run(ctx)
			mono.Advance(health.PartitionPauseWaitFor(2) + 2*time.Second)
			succ.run(ctx)
			succ.run(ctx)
			if got := vmHost(t, db, ctx); got != "down" {
				t.Fatalf("successor recovered to %q without relying on the pause", got)
			}
		})
	}
}

// The resume decision itself: a self-pause record whose pause is not relied
// on is declined, with the way out, never resumed from.
//
// Mutation: drop the not-relied decline from resumeActionForIn — red.
func TestPauseLapse_ResumeDeclinesASelfPauseNotReliedOn(t *testing.T) {
	db, ctx := seedDownHost(t, "best-effort", nil)
	c := newTestCoordinator("coordinator", db)
	c.PartitionPauseEnforced = func(context.Context) bool { return false }
	h, err := corrosion.GetHost(ctx, db, "down")
	if err != nil || h == nil {
		t.Fatal(err)
	}
	rec := fenceRecord{ID: "sp", Method: "best-effort-ssh", Result: "fenced", Detail: corrosion.FencePauseReliance + "SSH failed"}
	act, why := c.resumeActionFor(ctx, h, rec, time.Now().Add(-10*time.Second))
	if act != resumeDecline || !strings.Contains(why, "no longer relied on") {
		t.Fatalf("resume of a self-pause not relied on = (%v, %q), want declined", act, why)
	}
}

// recoverFenced re-checks reliance before it starts a pause wait: a self-pause
// result whose pause is not relied on any more starts none and holds.
//
// Mutation: drop the re-check in recoverFenced — a wait starts, red.
func TestPauseLapse_RecoverFencedStartsNoWaitWithoutReliance(t *testing.T) {
	db, ctx := seedDownHost(t, "best-effort", nil)
	c := newTestCoordinator("coordinator", db)
	c.PartitionPauseEnforced = func(context.Context) bool { return false }
	h, err := corrosion.GetHost(ctx, db, "down")
	if err != nil || h == nil {
		t.Fatal(err)
	}
	fr := fence.Result{Method: "best-effort-ssh", Success: true, Detail: corrosion.FencePauseReliance + "SSH failed"}
	c.recoverFenced(ctx, h, fr, "best-effort", false)
	if _, ok := c.pauseWaits["down"]; ok {
		t.Fatal("a pause wait started on a self-pause not relied on")
	}
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM recovered to %q", got)
	}
	if hold := c.holdReason["down"]; !strings.Contains(hold, "no longer relied on") {
		t.Fatalf("hold %q does not say the pause is not relied on", hold)
	}
}
