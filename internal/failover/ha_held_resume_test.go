package failover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// fenceRowAgo seeds a fencing_log row of 'down' with the given method and
// result, stamped age ago.
func fenceRowAgo(t *testing.T, db *corrosion.Client, id, method, result string, age time.Duration) {
	t.Helper()
	if err := db.Execute(context.Background(),
		`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES (?, 'down', ?, ?, ?, 'seeded')`,
		id, method, result, time.Now().Add(-age).UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}

// heldOn is a coordinator that handled 'down' this outage and holds its
// recovery for an HA disarm, as recoverWorkloads leaves it.
func heldOn(db *corrosion.Client) *Coordinator {
	c := newTestCoordinator("coordinator", db)
	c.fenced["down"] = true
	c.noteHAHeldRecovery("down")
	return c
}

// Merge review finding 1: an owed claim retry judged to belong to an outage
// that is over drops the host for the fence path to decide afresh. The HA
// held mark of the same recovery goes with it: left behind, the next cycle
// resumes the held recovery on the old fence before the fence path runs,
// past the probe answer the retry was judged on.
//
// Mutation: keep the held mark in claimRetryOutageOver's drop — the held
// recovery resumes on the old fence and the VM moves.
func TestHADisarm_AClaimRetryOutageOverDropsTheHeldMark(t *testing.T) {
	db, ctx := seedDownHost(t, "best-effort", nil)
	if err := corrosion.UpdateHostState(ctx, db, "down", "fenced"); err != nil {
		t.Fatal(err)
	}
	lengthenStreak(t, db, ctx, 5*time.Minute)
	fenceRowAgo(t, db, "ssh-1", "best-effort-ssh", "fenced", time.Minute)
	c := heldOn(db)
	mono := time.Now()
	c.retryClaimsFor("down")
	c.noteRecoveryAt("down", time.Now().Add(-time.Minute), mono.Add(-time.Minute))
	// This node has probed down healthy since the recovery's moment.
	c.LastContact = func(string) (time.Time, bool) { return mono, true }
	if !c.claimRetryOutageOver(ctx, "down") {
		t.Fatal("setup: the host could not be judged")
	}
	if c.claimRetry["down"] || c.fenced["down"] {
		t.Fatal("setup: the owed retry was not judged an outage that is over")
	}
	if c.ha.heldRecovery["down"] {
		t.Fatal("the outage was judged over, but the HA held mark of its recovery was kept")
	}
	c.resumeHAHeldRecovery(ctx, "down", 2)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("the held recovery resumed on the old fence after its outage was judged over: VM on %q", got)
	}
}

// Merge review finding 2: a held recovery with no recorded successful fence
// (here a manual fence an operator confirmed) resumes only while nobody has
// seen the host answer since the fence attempt — including this node's own
// probe, which no host_health row may show. Refused, the hold names the
// confirmation and the remedy, and confirming again recovers.
//
// Mutation: drop the contactedSince check — the VM moves on the old attempt.
func TestHADisarm_HeldRecoveryNotResumedAfterThisNodeProbedTheHostHealthy(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	lengthenStreak(t, db, ctx, 10*time.Minute)
	fenceRowAgo(t, db, "manual-1", "manual", "partial", 3*time.Minute)
	confirmAgo(t, db, ctx, 2*time.Minute)
	c := heldOn(db)
	c.SetFencer(manualFencer())
	contact := time.Now().Add(-time.Minute)
	c.LastContact = func(string) (time.Time, bool) { return contact, true }
	if !c.resumeHAHeldRecovery(ctx, "down", 2) {
		t.Fatal("the held recovery was not handled")
	}
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM moved to %q although this node probed the host healthy after the fence attempt", got)
	}
	if c.ha.heldRecovery["down"] {
		t.Fatal("a refusal judged on readable rows kept the held mark")
	}
	hold := c.holdReason["down"]
	for _, want := range []string{"operator-down", "lv host fence-confirm down' again"} {
		if !strings.Contains(hold, want) {
			t.Fatalf("hold %q does not name %q", hold, want)
		}
	}
	// The operator confirms again, after the answer: the recovery resumes.
	fenceRowAgo(t, db, "operator-down-2", "manual", "manual-confirmed", 0)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("after a fresh confirmation the VM is on %q, want alive (hold %q)", got, c.holdReason["down"])
	}
}

// The same branch without this node's probe: the rows and the probe agree the
// host stayed down, and the held recovery resumes. The control for the test
// above.
func TestHADisarm_HeldRecoveryOnAConfirmationResumesWhileItStands(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	lengthenStreak(t, db, ctx, 10*time.Minute)
	fenceRowAgo(t, db, "manual-1", "manual", "partial", 3*time.Minute)
	confirmAgo(t, db, ctx, 2*time.Minute)
	c := heldOn(db)
	c.LastContact = func(string) (time.Time, bool) { return time.Now().Add(-time.Hour), true }
	c.resumeHAHeldRecovery(ctx, "down", 2)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM on %q, want the held recovery resumed (hold %q)", got, c.holdReason["down"])
	}
}

// Merge review finding 2: the branch keeps fenceStillStandsIn. An observer
// that saw the host answer after the attempt refuses the resume, naming the
// remedy.
//
// Mutation: drop the fenceStillStandsIn check — the VM moves.
func TestHADisarm_HeldRecoveryWithoutARecordedFenceNotResumedAfterAnAnswer(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	lengthenStreak(t, db, ctx, 10*time.Minute)
	fenceRowAgo(t, db, "manual-1", "manual", "partial", 3*time.Minute)
	confirmAgo(t, db, ctx, 2*time.Minute)
	if err := db.Execute(ctx, `INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES ('outsider', 'down', 'unready', 1, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`); err != nil {
		t.Fatal(err)
	}
	c := heldOn(db)
	c.resumeHAHeldRecovery(ctx, "down", 2)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM moved to %q although an observer saw the host answer after the attempt", got)
	}
	if hold := c.holdReason["down"]; !strings.Contains(hold, "fence-confirm down' again") {
		t.Fatalf("hold %q names no remedy", hold)
	}
}

// Merge review findings 2 and 3: a host that is neither fenced nor offline
// (an upgrade's reboot, maintenance) never resumes a held recovery through
// the no-recorded-fence branch, whatever fence it has on record: it keeps the
// mark and says why, as an owed claim retry does.
//
// Mutation: drop the state check — the VM moves to alive.
func TestHADisarm_HeldRecoveryOfAHostNeitherFencedNorOfflineIsHeld(t *testing.T) {
	for _, state := range []string{"upgrading", "maintenance", "active"} {
		t.Run(state, func(t *testing.T) {
			db, ctx := seedDownHost(t, "best-effort", nil)
			lengthenStreak(t, db, ctx, 10*time.Minute)
			fenceRowAgo(t, db, "ssh-1", "best-effort-ssh", "fenced", 2*time.Minute)
			if err := corrosion.UpdateHostState(ctx, db, "down", state); err != nil {
				t.Fatal(err)
			}
			c := heldOn(db)
			if !c.resumeHAHeldRecovery(ctx, "down", 2) {
				t.Fatal("the held recovery was not handled")
			}
			if got := vmHost(t, db, ctx); got != "down" {
				t.Fatalf("a %s host's held recovery resumed: VM on %q", state, got)
			}
			if !c.ha.heldRecovery["down"] {
				t.Fatal("the held mark was dropped; it must be judged again once the host is fenced or offline")
			}
			if hold := c.holdReason["down"]; !strings.Contains(hold, state) {
				t.Fatalf("hold %q does not name the state", hold)
			}
		})
	}
}
