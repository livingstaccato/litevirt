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

func refenceCondition(t *testing.T, db *corrosion.Client, host string) (bool, string) {
	t.Helper()
	row, ok, err := corrosion.GetHealthCondition(context.Background(), db, RefenceEvaluator, CondRefenceFailed, "host", host)
	if err != nil {
		t.Fatal(err)
	}
	return ok && row.Lifecycle != corrosion.ConditionResolved, row.Evidence
}

// agedFenceFixture is handoffFixture moved on past recentFenceWindow, with the
// observers still failing "bad": the successor's resume decision is a re-fence
// with the recorded (verified) method.
func agedFenceFixture(t *testing.T) (*corrosion.Client, *Coordinator, *time.Time) {
	t.Helper()
	db, _, second, now := handoffFixture(t)
	*now = now.Add(recentFenceWindow + leaseDuration + time.Second)
	if err := db.Execute(context.Background(), `UPDATE host_health SET updated_at = ?, consecutive_failures = ?`,
		now.Format(time.RFC3339), int((recentFenceWindow+leaseDuration+time.Minute)/health.ProbeInterval)); err != nil {
		t.Fatalf("refresh health: %v", err)
	}
	return db, second, now
}

// TestRefence_FailureRaisesACondition: a successor that re-fences a host
// whose verified fence is aged, and fails, recovers nothing and leaves the
// host for an operator (refence). Until now that was a log line and a metric
// on whichever node held the lease; refence_failed is the cluster-wide record
// of it, naming the host and the command that resumes it. It resolves once a
// later fence of the host succeeds or an operator confirms it off.
//
// Mutations, each red: no raise on the failed re-fence — not raised; resolve
// on any newer fencing_log row, the failed attempt's own included — resolved
// before the confirmation; never resolve — still raised after it.
func TestRefence_FailureRaisesACondition(t *testing.T) {
	ctx := context.Background()
	db, second, now := agedFenceFixture(t)
	second.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "ipmi", Detail: "BMC unreachable", Success: false}
	})
	second.RunOnce(ctx)
	if leaseHolder(t, db) != "good" {
		t.Fatalf("fixture: the successor does not hold the lease")
	}
	if vm, _ := corrosion.GetVM(ctx, db, "vm1"); vm == nil || vm.HostName != "bad" {
		t.Fatalf("fixture: a failed re-fence moved vm1: %+v", vm)
	}
	raised, ev := refenceCondition(t, db, "bad")
	if !raised || !strings.Contains(ev, "fence-confirm bad") || !strings.Contains(ev, "BMC unreachable") {
		t.Fatalf("refence_failed is not raised for bad naming the next step: raised=%v %q", raised, ev)
	}

	// Another cycle with nothing new: still raised.
	*now = now.Add(time.Second)
	second.RunOnce(ctx)
	if raised, _ := refenceCondition(t, db, "bad"); !raised {
		t.Fatal("refence_failed resolved with nothing newer than the failed re-fence")
	}

	// The operator confirms bad off (`lv host fence-confirm bad`), after the
	// failure.
	later := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if err := db.Execute(ctx, `INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
		VALUES ('confirm-1', 'bad', 'manual', 'manual-confirmed', ?, 'operator confirmed manual fence')`, later); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Second)
	second.RunOnce(ctx)
	if raised, ev := refenceCondition(t, db, "bad"); raised {
		t.Fatalf("refence_failed is still raised after bad was confirmed off: %q", ev)
	}
}

// TestRefence_SuccessRaisesNothing: a re-fence that succeeds recovers as
// before and raises nothing.
func TestRefence_SuccessRaisesNothing(t *testing.T) {
	ctx := context.Background()
	db, second, _ := agedFenceFixture(t)
	fenced := 0
	second.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fenced++
		return fence.Result{Method: "ipmi", Detail: "powered off", Success: true}
	})
	second.RunOnce(ctx)
	if fenced != 1 {
		t.Fatalf("fixture: the successor fenced bad %d times, want one re-fence", fenced)
	}
	if raised, ev := refenceCondition(t, db, "bad"); raised {
		t.Fatalf("refence_failed raised for a re-fence that succeeded: %q", ev)
	}
}
