package daemon

import (
	"context"
	"log"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hostboot"
	"github.com/litevirt/litevirt/internal/metrics"
)

// The prior boot really raises the condition and leaves its awaiting note.
// Removing cleanup from the active fallback boot leaves that same row open,
// both before and after the next daemon answers its own Ping.
func TestActiveFallbackBootResolvesPersistedUnconfirmed(t *testing.T) {
	d, db, ctx := upgradingHost(t)
	metrics.SetUpgradingUnconfirmed(false)
	if err := corrosion.UpdateHostState(ctx, db, "h", "active"); err != nil {
		t.Fatal(err)
	}
	var checks bootChecks
	bctx, cancel := context.WithCancel(ctx)
	d.selfPinger = checks.pinger(&gatedPinger{open: make(chan struct{})})
	t.Cleanup(func() { cancel(); checks.wait(t) })
	d.writeBootState(bctx, 0, 0, 0, false)
	waitLifecycle(t, "the prior boot's real open condition", func() bool {
		r, ok := unconfirmedRow(t, ctx, db)
		return ok && r.Lifecycle == corrosion.ConditionConfirmed
	})
	prior, _ := unconfirmedRow(t, ctx, db)
	if hostState(t, ctx, db) != "upgrading" || unconfirmedGauge(t) != 1 {
		t.Fatal("prior boot did not remain upgrading with its diagnostic metric")
	}
	note, err := os.ReadFile(hostboot.AwaitingPath(d.cfg.DataDir))
	if err != nil {
		t.Fatal(err)
	}
	cancel() // that daemon dies without answering Ping
	checks.wait(t)
	if row, ok := unconfirmedRow(t, ctx, db); !ok || row.Lifecycle != prior.Lifecycle || row.Evidence != prior.Evidence || row.FirstSeen != prior.FirstSeen {
		t.Fatalf("canceling the prior boot changed its persisted condition: %+v ok=%v", row, ok)
	}
	// A fresh Daemon shares only the real database and local marker directory.
	serving := make(chan struct{})
	next := &Daemon{cfg: d.cfg, db: db, selfPinger: checks.pinger(&gatedPinger{open: serving})}
	nctx, ncancel := context.WithCancel(ctx)
	t.Cleanup(func() { ncancel(); checks.wait(t) })
	next.writeBootState(nctx, 0, 0, 0, false)
	if got := hostState(t, ctx, db); got != "active" {
		t.Fatalf("fallback boot recorded %q, want active", got)
	}
	if got, err := os.ReadFile(hostboot.AwaitingPath(d.cfg.DataDir)); err != nil || string(got) != string(note) {
		t.Fatalf("fallback lost the prior awaiting note before Ping: %q (%v)", got, err)
	}
	// The documented policy resolves a non-upgrading host even before Ping.
	if !awaitLifecycle(time.Second, func() bool {
		r, ok := unconfirmedRow(t, ctx, db)
		return ok && r.Lifecycle == corrosion.ConditionResolved && unconfirmedGauge(t) == 0
	}) {
		t.Error("prior persisted condition did not resolve for the active fallback before Ping")
	}
	close(serving)
	checks.wait(t)
	if _, err := os.Stat(hostboot.AwaitingPath(d.cfg.DataDir)); !os.IsNotExist(err) {
		t.Fatalf("successful own Ping left the awaiting note: %v", err)
	}
	row, ok := unconfirmedRow(t, ctx, db)
	if !ok || row.Lifecycle != corrosion.ConditionResolved || row.FirstSeen != prior.FirstSeen || row.Evidence != prior.Evidence || unconfirmedGauge(t) != 0 {
		t.Fatalf("prior persisted condition after serving = %+v ok=%v gauge=%v, want the same row resolved", row, ok, unconfirmedGauge(t))
	}
}

// Reject only the actual resolution upsert, after a real upgrading->active
// confirmation succeeds. Removing the resolution retry leaves the real row
// confirmed after the trigger is removed, without another daemon boot.
func TestConfirmActiveRetriesRealConditionResolution(t *testing.T) {
	testConditionResolution(t, false)
}

// A failed resolution must not keep shutdown waiting through the retry backoff.
func TestShutdownEndsConditionResolutionBackoff(t *testing.T) {
	testConditionResolution(t, true)
}

func testConditionResolution(t *testing.T, shutdown bool) {
	t.Helper()
	d, db, ctx := upgradingHost(t)
	since, ok, err := corrosion.HostStateSince(ctx, db, "h")
	if err != nil || !ok {
		t.Fatalf("HostStateSince: %v %v", ok, err)
	}
	if err := hostboot.RaiseUpgradingUnconfirmed(ctx, db, "h", "prior own Ping did not answer", since, time.Now()); err != nil {
		t.Fatal(err)
	}
	metrics.SetUpgradingUnconfirmed(true)
	// This trigger cannot reject host confirmation, ordinary reads, or raises.
	const refusal = "injected transient resolution error"
	if _, err := db.DB().ExecContext(ctx, `CREATE TRIGGER refuse_boot_resolution BEFORE INSERT ON health_conditions
		WHEN NEW.evaluator = 'host_boot' AND NEW.code = 'upgrading_unconfirmed' AND NEW.lifecycle = 'resolved'
		BEGIN SELECT RAISE(ABORT, 'injected transient resolution error'); END`); err != nil {
		t.Fatal(err)
	}
	failed := make(chan struct{}, 1)
	oldLogger := slog.Default()
	oldOutput, oldFlags := log.Writer(), log.Flags()
	slog.SetDefault(slog.New(&resolutionErrorHandler{Handler: slog.NewTextHandler(os.Stderr, nil), failed: failed, marker: refusal}))
	t.Cleanup(func() {
		slog.SetDefault(oldLogger)
		log.SetOutput(oldOutput)
		log.SetFlags(oldFlags)
	})
	confirmRetryFirst, confirmRetryMax = 10*time.Millisecond, 20*time.Millisecond
	if shutdown {
		confirmRetryFirst, confirmRetryMax = time.Hour, time.Hour
	}
	var confirmations atomic.Int32
	d.confirmServing = func(cctx context.Context) (bool, string, error) {
		confirmations.Add(1)
		return hostboot.ConfirmServing(cctx, db, "h")
	}
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { d.confirmActive(cctx, &unconfirmed{}, true); close(done) }()
	t.Cleanup(func() { cancel(); waitCheckDone(t, done) })
	select {
	case <-failed: // the actual ResolveUpgradingUnconfirmed upsert failed
	case <-time.After(3 * time.Second):
		t.Fatal("no actual condition-resolution failure was observed")
	}
	if got := hostState(t, ctx, db); got != "active" || confirmations.Load() != 1 {
		t.Fatalf("resolution failure preceded actual confirmation: state=%q confirmations=%d", got, confirmations.Load())
	}
	activeSince, ok, err := corrosion.HostStateSince(ctx, db, "h")
	if err != nil || !ok {
		t.Fatalf("active state time: %v %v", ok, err)
	}
	row, ok := unconfirmedRow(t, ctx, db)
	if !ok || row.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("refused actual resolution lost the open condition: %+v ok=%v", row, ok)
	}
	if g := unconfirmedGauge(t); g != 1 {
		t.Errorf("failed real resolution: row still confirmed but gauge=%v, want 1 until persisted resolution", g)
	}
	if shutdown {
		select {
		case <-done:
			t.Fatal("resolution cleanup returned while its real row was still unresolved, before shutdown")
		case <-time.After(20 * time.Millisecond):
			// The cleanup remains live with the hour-long backoff selected.
		}
		cancel()
		waitCheckDone(t, done)
		if row, _ := unconfirmedRow(t, ctx, db); row.Lifecycle != corrosion.ConditionConfirmed {
			t.Fatalf("shutdown fabricated a resolved row: %+v", row)
		}
	} else {
		if _, err := db.DB().ExecContext(ctx, "DROP TRIGGER refuse_boot_resolution"); err != nil {
			t.Fatal(err)
		}
		if !awaitLifecycle(time.Second, func() bool {
			r, ok := unconfirmedRow(t, ctx, db)
			return ok && r.Lifecycle == corrosion.ConditionResolved && unconfirmedGauge(t) == 0
		}) {
			r, _ := unconfirmedRow(t, ctx, db)
			t.Fatalf("transient real resolution error never recovered without restart: row=%+v gauge=%v", r, unconfirmedGauge(t))
		}
		waitCheckDone(t, done)
	}
	finalSince, ok, err := corrosion.HostStateSince(ctx, db, "h")
	if err != nil || !ok || !finalSince.Equal(activeSince) || confirmations.Load() != 1 {
		t.Fatalf("resolution retry repeated host confirmation: time=%s was=%s confirmations=%d err=%v", finalSince, activeSince, confirmations.Load(), err)
	}
}

type resolutionErrorHandler struct {
	slog.Handler
	failed chan<- struct{}
	marker string
}

func (h *resolutionErrorHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Message == "restart: could not resolve the upgrading_unconfirmed condition" {
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "error" && strings.Contains(a.Value.String(), h.marker) {
				select {
				case h.failed <- struct{}{}:
				default:
				}
			}
			return true
		})
	}
	return h.Handler.Handle(ctx, r)
}

func waitLifecycle(t *testing.T, what string, ready func() bool) {
	t.Helper()
	if !awaitLifecycle(3*time.Second, ready) {
		t.Fatalf("timed out waiting for %s", what)
	}
}

func awaitLifecycle(timeout time.Duration, ready func() bool) bool {
	for deadline := time.Now().Add(timeout); ; time.Sleep(time.Millisecond) {
		if ready() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

func waitCheckDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("serving check did not finish on resolution or cancellation")
	}
}
