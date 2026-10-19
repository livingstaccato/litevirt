package firewall

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// lastRunner records the last ruleset each table received.
type lastRunner struct {
	mu   sync.Mutex
	last []string
}

func (r *lastRunner) Apply(_ context.Context, ruleset string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last = append(r.last, ruleset)
	return "", nil
}

func (r *lastRunner) Flush(context.Context) (string, error) { return "", nil }

// nicTable is the last per-NIC table applied.
func (r *lastRunner) nicTable() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.last) - 1; i >= 0; i-- {
		if strings.Contains(r.last[i], "table bridge "+NICTableName) {
			return r.last[i]
		}
	}
	return ""
}

// Codex cand36 review I2: a pass that loaded its plan while logging was on,
// and is descheduled before applying it, must not apply that plan after the
// stop pass has applied one without log lines: once Stop's pass has applied,
// no log line may come back. The seam is the loader itself, held right after
// it read the gate (logging on) until the stop pass has had its chance; the
// run context stays live, as on a re-exec, so cancellation cannot mask it.
//
// Mutation: Apply does not ask the gate again under its lock (the stale plan
// applies last, log lines and all) — red.
func TestReconciler_StaleLoggingPlanCannotFollowTheStopPass(t *testing.T) {
	gate := NewLogGate(27, nil, nil)
	gate.OnBind(nil)
	loaded := make(chan struct{})
	release := make(chan struct{})
	var first sync.Once
	loader := func(ctx context.Context) (Plan, error) {
		p := goldenLogPlan(NICModeEnforce)
		on, grp := gate.Logging()
		p.LogPolicy.Available, p.LogPolicy.Group = on, grp
		if on {
			p.logRecheck = gate.Logging // as CorrosionPlanLoader sets it (TestLoader_LoggingPlanCarriesItsRecheck)
		}
		held := false
		first.Do(func() { held = true })
		if held {
			close(loaded)
			<-release // descheduled with a logging-enabled plan in hand
		}
		return p, nil
	}
	run := &lastRunner{}
	r := NewReconciler(loader, NewApplier(run), time.Hour)
	ctx := context.Background()

	stale := make(chan error, 1)
	go func() { stale <- r.Reconcile(ctx) }()
	<-loaded

	// The stop pass: logging off for good, then one pass.
	if !gate.Stop() {
		t.Fatal("the gate says no line may have been rendered")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- r.Reconcile(ctx) }()
	select {
	case err := <-stopped:
		// Without the pass lock the stop pass applies at once; let the stale
		// pass apply after it, as the scheduler may.
		if err != nil {
			t.Fatal(err)
		}
		close(release)
		if err := <-stale; err != nil {
			t.Fatal(err)
		}
	case <-time.After(200 * time.Millisecond):
		// The stop pass waits for the stale one: release it, then the stop
		// pass applies last.
		close(release)
		if err := <-stale; err != nil {
			t.Fatal(err)
		}
		if err := <-stopped; err != nil {
			t.Fatal(err)
		}
	}
	nic := run.nicTable()
	if nic == "" {
		t.Fatal("no per-NIC table was applied")
	}
	if strings.Contains(nic, " log group ") {
		t.Errorf("a log line is in force after the stop pass applied a plan without them:\n%s", nic)
	}
	if !strings.Contains(nic, "chain nic_in_") {
		t.Error("the per-NIC rules were removed along with the log lines")
	}
}

// The loader hands Apply its logging decision to ask again, so the recheck in
// TestReconciler_StaleLoggingPlanCannotFollowTheStopPass is the production
// path's, not the test loader's alone.
//
// Mutation: the loader does not set the recheck — red.
func TestLoader_LoggingPlanCarriesItsRecheck(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	g := NewLogGate(27, nil, nil)
	g.OnBind(nil)
	p, err := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{Logging: g.Logging})(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !p.LogPolicy.Available || p.logRecheck == nil {
		t.Fatalf("a logging plan: available %v, recheck set %v; want both", p.LogPolicy.Available, p.logRecheck != nil)
	}
	g.Stop()
	if on, _ := p.logRecheck(); on {
		t.Error("the recheck still says logging is on after the gate stopped")
	}
}
