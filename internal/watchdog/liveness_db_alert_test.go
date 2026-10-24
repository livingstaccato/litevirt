package watchdog

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// alertLog records the alerts a gate raised.
type alertLog struct {
	mu     sync.Mutex
	alerts []DBProbeAlert
}

func (l *alertLog) add(a DBProbeAlert) {
	l.mu.Lock()
	l.alerts = append(l.alerts, a)
	l.mu.Unlock()
}

func (l *alertLog) snapshot() (failing, recovered []DBProbeAlert) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, a := range l.alerts {
		if a.Recovered {
			recovered = append(recovered, a)
		} else {
			failing = append(failing, a)
		}
	}
	return failing, recovered
}

// Probes failing past a third of the threshold raise the alert once, with the
// error and the time left to the fence, then at most every quarter of the
// threshold; the first success after it raises one recovered. A run of
// failures shorter than a third of the threshold raises nothing.
//
// Mutations: never raise, and the first case goes red; raise on every failure
// (drop the a.stale/3 check), and both go red.
func TestDBProbeAlerts_RaisesPastAThirdOfTheThresholdAtABoundedRate(t *testing.T) {
	const s = time.Second
	busy := errors.New("query: database is locked (5) (SQLITE_BUSY)")

	t.Run("keeps failing", func(t *testing.T) {
		a := dbProbeAlerts{stale: 120 * s}
		var at []time.Duration
		var raised []DBProbeAlert
		for now := 15 * s; now <= 120*s; now += 15 * s {
			if al, ok := a.observe(busy, now); ok {
				at, raised = append(at, now), append(raised, al)
			}
		}
		// First failure at 15 s: 40 s of failing is reached at 60 s, and
		// repeats are 30 s apart.
		if want := []time.Duration{60 * s, 90 * s, 120 * s}; len(at) != len(want) || at[0] != want[0] || at[1] != want[1] || at[2] != want[2] {
			t.Fatalf("alerts raised at %v, want %v", at, want)
		}
		first := raised[0]
		if first.Recovered || first.Err != busy.Error() || first.Failing != 45*s || first.FenceIn != 60*s {
			t.Fatalf("first alert = %+v, want the error, 45s failing, 60s to the fence", first)
		}
		if d := first.Detail(); !strings.Contains(d, busy.Error()) || !strings.Contains(d, "45s") || !strings.Contains(d, "self-fences in 1m0s") {
			t.Fatalf("detail %q does not name the error, the time failing and the time to the fence", d)
		}
		al, ok := a.observe(nil, 135*s)
		if !ok || !al.Recovered {
			t.Fatalf("the first success after the alert raised %+v, %v; want one recovered", al, ok)
		}
		if al, ok := a.observe(nil, 150*s); ok {
			t.Fatalf("a second success raised %+v", al)
		}
	})

	t.Run("fails briefly", func(t *testing.T) {
		a := dbProbeAlerts{stale: 120 * s}
		for i, step := range []struct {
			err error
			now time.Duration
		}{{busy, 15 * s}, {busy, 30 * s}, {nil, 45 * s}, {busy, 60 * s}, {busy, 75 * s}, {nil, 90 * s}} {
			if al, ok := a.observe(step.err, step.now); ok {
				t.Fatalf("step %d: failures shorter than a third of the threshold raised %+v", i, al)
			}
		}
	})
}

// Through a running heartbeat: an active gate whose probes keep failing
// raises the alert at a bounded rate and fences; one whose probes recover
// before the fence raises one recovered and keeps petting; brief failures
// raise nothing; and a gate that is not active (an unverified device) raises
// nothing however long its probes fail.
//
// Mutations: never call the callback in raise, and the first two cases go
// red; raise on every failure, and the first and third go red.
func TestHeartbeat_LivenessGateAlertsWhileDBProbesFail(t *testing.T) {
	busy := errors.New("query: database is locked (5) (SQLITE_BUSY)")
	// run runs a gate with a 600 ms threshold (alert at 200 ms, repeats
	// 150 ms apart) whose probe fails until failFor has passed (forever when
	// 0), and returns the alerts raised within window and the probe count.
	run := func(t *testing.T, verified bool, failFor, window time.Duration) (*Controller, *alertLog, uint64, string) {
		t.Helper()
		if verified {
			verifiedDevice(t)
		}
		var log alertLog
		var probes atomic.Uint64
		dev := fakeWatchdog(t, "")
		start := time.Now()
		ctrl := runGate(t, dev, func(c *Controller) {
			c.SetLivenessStale(600 * time.Millisecond)
			c.SetDBProbeAlert(log.add)
			c.SetDBProbe(func(context.Context) error {
				probes.Add(1)
				if failFor == 0 || time.Since(start) < failFor {
					return busy
				}
				return nil
			})
		})
		time.Sleep(window)
		return ctrl, &log, probes.Load(), dev
	}

	t.Run("keeps failing", func(t *testing.T) {
		ctrl, log, probes, _ := run(t, true, 0, 900*time.Millisecond)
		failing, recovered := log.snapshot()
		if len(failing) == 0 {
			t.Fatalf("%d failing probes raised no alert", probes)
		}
		if len(failing) > 5 || uint64(len(failing))*5 > probes {
			t.Fatalf("%d alerts for %d failing probes: not rate-limited", len(failing), probes)
		}
		if f := failing[0]; f.Err != busy.Error() || f.FenceIn <= 0 || f.Failing < 200*time.Millisecond {
			t.Fatalf("first alert = %+v, want the error, a positive time to the fence, at least 200ms failing", f)
		}
		if len(recovered) != 0 {
			t.Fatalf("probes that never succeeded raised recovered: %+v", recovered)
		}
		if !ctrl.Fenced() {
			t.Fatal("the gate did not self-fence")
		}
	})

	t.Run("recovers before the fence", func(t *testing.T) {
		ctrl, log, _, dev := run(t, true, 400*time.Millisecond, 700*time.Millisecond)
		failing, recovered := log.snapshot()
		if len(failing) == 0 || len(recovered) != 1 {
			t.Fatalf("%d failing alerts and %d recovered; want at least one and exactly one", len(failing), len(recovered))
		}
		if ctrl.Fenced() || !grows(t, dev, 60*time.Millisecond) {
			t.Fatal("probes that recovered inside the threshold did not keep the watchdog petted")
		}
	})

	t.Run("fails briefly", func(t *testing.T) {
		_, log, _, _ := run(t, true, 100*time.Millisecond, 500*time.Millisecond)
		if failing, recovered := log.snapshot(); len(failing)+len(recovered) != 0 {
			t.Fatalf("failures shorter than a third of the threshold raised %+v %+v", failing, recovered)
		}
	})

	t.Run("gate inactive", func(t *testing.T) {
		ctrl, log, _, _ := run(t, false, 0, 500*time.Millisecond)
		if ctrl.Armed() {
			t.Fatal("the unverified device armed the gate; the case needs an inactive one")
		}
		if failing, recovered := log.snapshot(); len(failing)+len(recovered) != 0 {
			t.Fatalf("an inactive gate raised %+v %+v", failing, recovered)
		}
	})
}
