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
// — the condition stays open.
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
		if ok && row.Lifecycle == corrosion.ConditionConfirmed && attempts.Load() >= 3 {
			var ev struct{ Cause, Remedy string }
			if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil ||
				!strings.Contains(ev.Cause, "write refused") || !strings.Contains(ev.Remedy, "lv host undrain") {
				t.Fatalf("upgrading_unconfirmed evidence = %s (%v), want the cause and the remedy", row.Evidence, err)
			}
			if row.Severity != corrosion.SeverityWarning {
				t.Fatalf("severity %q, want warning", row.Severity)
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
