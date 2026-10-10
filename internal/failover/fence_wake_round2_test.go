package failover

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// An operator who fixes a host whose watchdog fence of a peer failed — it
// always does — by configuring IPMI has the next retry run IPMI, as the docs
// promise. The retry is gated on the strategy it would RUN, not on the
// method that failed.
//
// Mutation M25: gate fenceRetryDue on the failed method again — no retry.
func TestFenceWake_SwitchingAWatchdogHostToIPMIIsRetried(t *testing.T) {
	db, ctx := seedDownHost(t, "watchdog", nil)
	c := newTestCoordinator("coordinator", db)
	var strategies []string
	c.SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
		strategies = append(strategies, h.FenceStrategy)
		if h.FenceStrategy == "ipmi" {
			return fence.Result{Method: "ipmi", Success: true, Detail: "verified off"}
		}
		return fence.Result{Method: "watchdog", Success: false, Detail: "watchdog fence only for the local node"}
	})
	c.run(ctx)
	if err := db.Execute(ctx, `UPDATE hosts SET fence_strategy = 'ipmi' WHERE name = 'down'`); err != nil {
		t.Fatalf("switch strategy: %v", err)
	}
	ageFenceRows(t, db, ctx, fenceRetryBase+time.Second)
	c.lastFenceAt = nil
	c.run(ctx)
	if len(strategies) != 2 || strategies[1] != "ipmi" {
		t.Fatalf("fence strategies = %v, want the operator's ipmi retried after the failed watchdog fence", strategies)
	}
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM still on %q after the IPMI retry succeeded", got)
	}
}

// captureSlog sends the default logger to a buffer, at Debug, for the test.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// A retry refused because the host answered is logged at Warn once, on the
// transition, and at Debug on the cycles after, while it stays refused for
// the same reason; it is still refused every cycle.
//
// Mutation M26: always Warn — one Warn line per cycle.
func TestFenceWake_ARefusedRetryWarnsOnTheTransitionOnly(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	thirdVoter(t, db, ctx)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(countingFencer(&fences, sshFailedFence, sshFence))
	c.run(ctx)
	ageFenceRows(t, db, ctx, fenceRetryBase+time.Second)
	c.lastFenceAt = nil
	aliveAnswers(t, db, ctx)

	logs := captureSlog(t)
	for i := 0; i < 3; i++ {
		c.run(ctx)
	}
	if fences != 1 {
		t.Fatalf("a refused retry ran (%d fences)", fences)
	}
	const msg = "not retrying the fence of a host that answered"
	var warn, debug int
	for _, line := range strings.Split(logs.String(), "\n") {
		if !strings.Contains(line, msg) {
			continue
		}
		switch {
		case strings.Contains(line, "level=WARN"):
			warn++
		case strings.Contains(line, "level=DEBUG"):
			debug++
		}
	}
	if warn != 1 || debug != 2 {
		t.Errorf("refusal logged %d Warn and %d Debug lines over 3 cycles, want 1 and 2", warn, debug)
	}
}

// A claim refusal and a lost claim each name themselves as what holds the
// host's recovery, for the stall alert.
//
// Mutation M27: drop noteClaimRefused's hold reason.
// Mutation M28: drop noteClaimLost's hold reason.
func TestFenceWake_ClaimRefusalAndLossNameTheirHold(t *testing.T) {
	c := NewCoordinator("coordinator", nil)
	c.noteClaimRefused(context.Background(), ActionReschedule, "vm", "web", "down", errors.New("2 of 3 voters refused"))
	if r := c.holdReason["down"]; !strings.Contains(r, "vm web") || !strings.Contains(r, "claim") {
		t.Errorf("hold reason after a refused claim = %q, want it to name vm web and the claim", r)
	}
	c.noteClaimLost(ActionReschedule, "vm", "db", "down", corrosion.ActionProof{
		ID: "p1", Action: "promote", DestHost: "alive", Coordinator: "other",
	})
	if r := c.holdReason["down"]; !strings.Contains(r, "vm db") || !strings.Contains(r, "other") {
		t.Errorf("hold reason after a lost claim = %q, want it to name vm db and the deciding coordinator", r)
	}
}

// A container held back by an active ownership condition names that as the
// host's hold.
//
// Mutation M29: drop the container dispute's hold reason.
func TestFenceWake_ContainerOwnershipDisputeNamesItsHold(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	for _, h := range []corrosion.HostRecord{
		{Name: "dead", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "offline"},
		{Name: "live", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CPUTotal: 8, MemTotal: 8192},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatal(err)
		}
	}
	runsContainers(t, db, "live")
	if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
		HostName: "dead", Name: "web", State: "running", Image: "alpine:3.19",
		CPULimit: 1, MemMiB: 128, Project: "p1", OnHostFailure: "image-recreate",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if err := db.Execute(ctx,
		`INSERT INTO health_conditions (evaluator, code, subject_kind, subject_id, lifecycle, created_at, updated_at)
		 VALUES ('dual_run', 'ct_dual_run', 'container', 'web', 'confirmed', ?, ?)`, now, now); err != nil {
		t.Fatalf("seed condition: %v", err)
	}
	c := newTestCoordinator("coord", db)
	c.relocateContainers(ctx, &corrosion.HostRecord{Name: "dead"}, []corrosion.HostRecord{{Name: "live", State: "active"}})
	if r := c.holdReason["dead"]; !strings.Contains(r, "ct web") || !strings.Contains(r, "ownership") {
		t.Errorf("hold reason = %q, want it to name ct web and its ownership condition", r)
	}
}

// retryStillDown fails closed: an unreadable host_health refuses the retry.
//
// Mutation M30: answeredSince reports "still down" on a read error.
func TestFenceWake_UnreadableHealthRefusesTheRetry(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	c := newTestCoordinator("coordinator", db)
	if err := db.Execute(ctx, `DROP TABLE host_health`); err != nil {
		t.Fatalf("drop host_health: %v", err)
	}
	why, down := c.retryStillDown(ctx, "down", time.Now().Add(-time.Minute))
	if down {
		t.Error("retryStillDown allowed a retry with host_health unreadable")
	}
	if !strings.Contains(why, "unreadable") {
		t.Errorf("reason = %q, want it to say host_health is unreadable", why)
	}
}
