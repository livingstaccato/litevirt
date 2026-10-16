package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hostboot"
	"github.com/litevirt/litevirt/internal/metrics"
)

// upgradingHost is a daemon whose host "h" is recorded 'upgrading', read from
// host_membership (so its state time is known), with the serving check's
// timings shrunk.
func upgradingHost(t *testing.T) (*Daemon, *corrosion.Client, context.Context) {
	t.Helper()
	oldPoll, oldFirst, oldMax, oldAfter, oldEvery := pingPollInterval, confirmRetryFirst, confirmRetryMax, unconfirmedAfter, unconfirmedCheckEvery
	pingPollInterval, confirmRetryFirst, confirmRetryMax, unconfirmedAfter, unconfirmedCheckEvery = time.Millisecond, time.Millisecond, 5*time.Millisecond, 0, 0
	t.Cleanup(func() {
		pingPollInterval, confirmRetryFirst, confirmRetryMax, unconfirmedAfter, unconfirmedCheckEvery = oldPoll, oldFirst, oldMax, oldAfter, oldEvery
	})
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "h", Address: "127.0.0.1", SSHUser: "root", CertSerial: "s", State: "active",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	db.SetHostMembershipGate(func() bool { return true })
	if _, err := db.SplitHostMembership(ctx); err != nil || !db.HostMembershipLive() {
		t.Fatalf("split host membership: live=%v err=%v", db.HostMembershipLive(), err)
	}
	if err := corrosion.UpdateHostState(ctx, db, "h", "upgrading"); err != nil {
		t.Fatal(err)
	}
	return &Daemon{cfg: &Config{HostName: "h", DataDir: t.TempDir()}, db: db}, db, ctx
}

func unconfirmedRow(t *testing.T, ctx context.Context, db *corrosion.Client) (corrosion.HealthCondition, bool) {
	t.Helper()
	row, ok, err := corrosion.GetHealthCondition(ctx, db, hostboot.BootEvaluator, hostboot.CondUpgradingUnconfirmed, "host", "h")
	if err != nil {
		t.Fatal(err)
	}
	return row, ok
}

func hostState(t *testing.T, ctx context.Context, db *corrosion.Client) string {
	t.Helper()
	h, err := corrosion.GetHost(ctx, db, "h")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %v", err)
	}
	return h.State
}

// A serving daemon whose write recording the host active fails retries it
// until it lands. Past the upgrading window it raises upgrading_unconfirmed
// about itself, naming the cause and the remedy, and sets the metric; the
// write landing resolves both.
//
// Mutations: return after the first failed attempt (the check before this
// change) — the host stays 'upgrading'; drop noteUnconfirmed from the retry
// loop — no condition is raised; drop clearUnconfirmed from the success path
// — the condition stays open; write the condition on every attempt — it is
// written more than once.
func TestConfirmActiveRetriesAndShowsAnUnconfirmedHost(t *testing.T) {
	d, db, ctx := upgradingHost(t)
	var attempts atomic.Int32
	release := make(chan struct{})
	d.confirmServing = func(ctx context.Context) (bool, string, error) {
		attempts.Add(1)
		select {
		case <-release:
			return hostboot.ConfirmServing(ctx, db, "h")
		default:
			return false, "upgrading", errors.New("write refused")
		}
	}
	done := make(chan struct{})
	go func() { d.confirmActive(ctx, &unconfirmed{}, true); close(done) }()

	deadline := time.Now().Add(3 * time.Second)
	for {
		row, ok := unconfirmedRow(t, ctx, db)
		if ok && row.Lifecycle == corrosion.ConditionConfirmed && attempts.Load() >= 5 {
			var ev struct{ Cause, Remedy string }
			if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil ||
				!strings.Contains(ev.Cause, "write refused") || !strings.Contains(ev.Remedy, "lv host undrain") {
				t.Fatalf("upgrading_unconfirmed evidence = %s (%v), want the cause and the remedy", row.Evidence, err)
			}
			if row.Severity != corrosion.SeverityWarning {
				t.Fatalf("severity %q, want warning", row.Severity)
			}
			// One replicated write for one unchanged cause, however many
			// attempts fail.
			if row.ObserveCount != 1 {
				t.Fatalf("upgrading_unconfirmed written %d times for one cause over %d attempts, want once",
					row.ObserveCount, attempts.Load())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no upgrading_unconfirmed after %d failed attempts (row %+v ok=%v)", attempts.Load(), row, ok)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if g := unconfirmedGauge(t); g != 1 {
		t.Fatalf("litevirt_host_upgrading_unconfirmed = %v while unconfirmed, want 1", g)
	}
	if got := hostState(t, ctx, db); got != "upgrading" {
		t.Fatalf("host %q before the write lands, want upgrading", got)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the serving check did not finish once the write could land")
	}
	if got := hostState(t, ctx, db); got != "active" {
		t.Fatalf("host %q after the write landed, want active", got)
	}
	if row, ok := unconfirmedRow(t, ctx, db); !ok || row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("upgrading_unconfirmed after the host turned active = %+v ok=%v, want resolved", row, ok)
	}
	if g := unconfirmedGauge(t); g != 0 {
		t.Fatalf("litevirt_host_upgrading_unconfirmed = %v once active, want 0", g)
	}
}

// A daemon whose own Ping never answers raises upgrading_unconfirmed past the
// upgrading window, naming its own Ping as the cause: peers that reach it do
// not fence it, so nothing else would show it.
//
// Mutation: drop noteUnconfirmed from activateOnceServing's ping loop — no
// condition is raised.
func TestOwnPingThatNeverAnswersShowsAnUnconfirmedHost(t *testing.T) {
	d, db, ctx := upgradingHost(t)
	cctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	d.activateOnceServing(cctx, &fakePinger{failN: 1 << 30}, 10*time.Millisecond)
	row, ok := unconfirmedRow(t, ctx, db)
	if !ok || row.Lifecycle != corrosion.ConditionConfirmed || !strings.Contains(row.Evidence, "own Ping") {
		t.Fatalf("upgrading_unconfirmed = %+v ok=%v, want open, naming the daemon's own Ping", row, ok)
	}
	if got := hostState(t, ctx, db); got != "upgrading" {
		t.Fatalf("host %q, want upgrading", got)
	}
}

// unconfirmedGauge reads litevirt_host_upgrading_unconfirmed from the default
// registry.
func unconfirmedGauge(t *testing.T) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "litevirt_host_upgrading_unconfirmed" && len(mf.GetMetric()) == 1 {
			return mf.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatal("litevirt_host_upgrading_unconfirmed is not registered")
	return 0
}

// Nothing is raised before the host has been 'upgrading' for the upgrading
// window, however many attempts fail.
//
// Mutation: drop the unconfirmedAfter check from noteUnconfirmed — the
// condition is raised at once.
func TestUnconfirmedWaitsForTheUpgradingWindow(t *testing.T) {
	d, db, ctx := upgradingHost(t)
	unconfirmedAfter = time.Hour
	metrics.SetUpgradingUnconfirmed(false)
	confirmRetryFirst, confirmRetryMax = 20*time.Millisecond, 20*time.Millisecond
	var attempts atomic.Int32
	d.confirmServing = func(context.Context) (bool, string, error) {
		attempts.Add(1)
		return false, "upgrading", errors.New("write refused")
	}
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { d.confirmActive(cctx, &unconfirmed{}, true); close(done) }()
	for deadline := time.Now().Add(3 * time.Second); attempts.Load() < 5; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("only %d attempts", attempts.Load())
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelling the daemon's context did not end the retry loop")
	}
	if row, ok := unconfirmedRow(t, ctx, db); ok {
		t.Fatalf("upgrading_unconfirmed raised inside the upgrading window: %+v", row)
	}
	if g := unconfirmedGauge(t); g != 0 {
		t.Fatalf("litevirt_host_upgrading_unconfirmed = %v inside the window, want 0", g)
	}
}

// A host recorded as something other than 'upgrading' ends the retry loop
// (ErrNotUpgrading), and the condition it raised is resolved.
//
// Mutation: treat ErrNotUpgrading as a failure to retry — the loop does not
// end.
func TestConfirmActiveStopsOnceTheHostIsNotUpgrading(t *testing.T) {
	d, db, ctx := upgradingHost(t)
	var attempts atomic.Int32
	d.confirmServing = func(context.Context) (bool, string, error) {
		if attempts.Add(1) <= 3 {
			return false, "upgrading", errors.New("write refused")
		}
		return false, "fenced", hostboot.ErrNotUpgrading
	}
	done := make(chan struct{})
	go func() { d.confirmActive(ctx, &unconfirmed{}, true); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("the retry loop went on after the host was recorded as something else (%d attempts)", attempts.Load())
	}
	if row, ok := unconfirmedRow(t, ctx, db); !ok || row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("upgrading_unconfirmed after ErrNotUpgrading = %+v ok=%v, want raised then resolved", row, ok)
	}
	if g := unconfirmedGauge(t); g != 0 {
		t.Fatalf("litevirt_host_upgrading_unconfirmed = %v, want 0", g)
	}
}

// A host that stops being 'upgrading' (an operator undrained it) while its
// daemon's own Ping still fails has nothing to show: the condition the ping
// loop raised is resolved and the metric cleared, without waiting for the
// Ping.
//
// Mutation: return from noteUnconfirmed without clearing when the host is not
// 'upgrading' — the condition stays open for an active host.
func TestUnconfirmedClearsWhenTheHostIsNoLongerUpgrading(t *testing.T) {
	d, db, ctx := upgradingHost(t)
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() { d.activateOnceServing(cctx, &fakePinger{failN: 1 << 30}, 10*time.Millisecond); close(done) }()
	waitRow := func(what string, cond func(corrosion.HealthCondition, bool) bool) {
		t.Helper()
		for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(5 * time.Millisecond) {
			row, ok := unconfirmedRow(t, ctx, db)
			if cond(row, ok) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s: %+v ok=%v", what, row, ok)
			}
		}
	}
	waitRow("the condition", func(r corrosion.HealthCondition, ok bool) bool {
		return ok && r.Lifecycle == corrosion.ConditionConfirmed
	})
	if err := corrosion.UpdateHostState(ctx, db, "h", "active"); err != nil { // lv host undrain
		t.Fatal(err)
	}
	waitRow("the condition to resolve", func(r corrosion.HealthCondition, ok bool) bool {
		return ok && r.Lifecycle == corrosion.ConditionResolved
	})
	if g := unconfirmedGauge(t); g != 0 {
		t.Fatalf("litevirt_host_upgrading_unconfirmed = %v for an active host, want 0", g)
	}
	cancel()
	<-done
}

// Cancelling the daemon's context (shutdown) ends the retry loop while it
// waits out its backoff, not after it.
//
// Mutation: drop the ctx.Done arm from confirmActive's backoff — the loop
// sleeps out the hour.
func TestShutdownEndsTheConfirmBackoff(t *testing.T) {
	d, _, ctx := upgradingHost(t)
	confirmRetryFirst, confirmRetryMax = time.Hour, time.Hour
	var attempts atomic.Int32
	d.confirmServing = func(context.Context) (bool, string, error) {
		attempts.Add(1)
		return false, "upgrading", errors.New("write refused")
	}
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { d.confirmActive(cctx, &unconfirmed{}, true); close(done) }()
	for deadline := time.Now().Add(3 * time.Second); attempts.Load() < 1; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no attempt")
		}
	}
	time.Sleep(20 * time.Millisecond) // into the backoff
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelling the daemon's context did not end the retry backoff")
	}
	if n := attempts.Load(); n != 1 {
		t.Fatalf("%d attempts, want 1", n)
	}
}
