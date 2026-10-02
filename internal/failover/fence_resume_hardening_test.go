package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
)

// TestResume_SafeFenceKeysOnTheRecordedFence: a best-effort host is fenced by
// a leader that loses the lease before recovering — its lenient SSH success is
// recorded as method "ssh" — and an operator then switches the host's fence
// strategy to ipmi. The successor resumes from the RECORDED fence, which is no
// better than it was. Under the safe-fence policy that fence needs an
// operator's confirmation, and the successor must still ask for one.
//
// The gate used to read the host's current strategy, found "ipmi", and moved
// the VM on an unconfirmed SSH power-off.
//
// Mutation: key the gate on fence.ResolveStrategy(h.FenceStrategy) again.
func TestResume_SafeFenceKeysOnTheRecordedFence(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, h := range []corrosion.HostRecord{
		{Name: "bad", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "best-effort"},
		{Name: "good", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "ipmi"},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "bad", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fenceQuorum(t, ctx, db, []string{"first", "good"}, "bad")

	first := NewCoordinator("first", db)
	first.Now = func() time.Time { return now }
	first.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		seedLease(t, db, "good", now.Add(leaseDuration))
		return fence.Result{Method: "ssh", Detail: "poweroff sent", Success: true}
	})
	first.RunOnce(ctx)
	if h, _ := corrosion.GetHost(ctx, db, "bad"); h == nil || h.State != "fenced" {
		t.Fatalf("fixture: bad is %+v after the handoff, want 'fenced'", h)
	}

	if err := db.Execute(ctx, `UPDATE hosts SET fence_strategy = 'ipmi' WHERE name = 'bad'`); err != nil {
		t.Fatalf("switch strategy: %v", err)
	}

	second := NewCoordinator("good", db)
	second.Now = first.Now
	second.Gate = gateEnforcing(capabilities.SafeFenceDefaultV1)
	second.SafeFenceEnforce = true
	fm := newFakeMetrics()
	second.Metrics = fm
	second.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		t.Error("the successor fenced a host recorded off by an unverified fence; that is never re-fenced")
		return fence.Result{}
	})
	second.RunOnce(ctx)

	if vm, err := corrosion.GetVM(ctx, db, "vm1"); err != nil || vm == nil || vm.HostName != "bad" {
		t.Errorf("vm1 moved on an unconfirmed SSH fence because the host's strategy is now ipmi (vm=%+v err=%v)", vm, err)
	}
	if got := fm.attempts[foKey(PhaseSplitBrain, ResultRefused, ErrManualUnconfirmed)]; got != 1 {
		t.Errorf("safe-fence refusals = %d, want 1 (attempts %v)", got, fm.attempts)
	}
}

// TestFenceStillStands_SkewMargin: a fence's timestamp is the leader's clock and
// an observer's row is the observer's, so the comparisons give fenceSkewMargin
// to the safe side. A failing run that began only 3s before the fence by the
// observer's clock may have begun AFTER it by the leader's, and a verdict that
// the host answered 3s before the fence may have been after it.
//
// Mutation: set fenceSkewMargin to 0 (the run arm goes red), or compare the
// answered verdict against `at` itself (the answered arm goes red).
func TestFenceStillStands_SkewMargin(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	now := at.Add(60 * time.Second)
	upd := now.Add(-time.Second) // fresh
	ts := func(t time.Time) string { return t.Format(time.RFC3339) }

	for _, tc := range []struct {
		name     string
		runStart time.Duration // relative to at
		answered time.Duration // relative to at; 0 = no answered row
		want     bool
	}{
		{name: "run-began-well-before", runStart: -7 * time.Second, want: true},
		{name: "run-began-inside-the-margin", runStart: -3 * time.Second, want: false},
		{name: "answered-inside-the-margin", runStart: -7 * time.Second, answered: -3 * time.Second, want: false},
		{name: "answered-well-before", runStart: -7 * time.Second, answered: -20 * time.Second, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestDB(t)
			n := int(upd.Sub(at.Add(tc.runStart))/health.ProbeInterval) + 1
			if err := db.Execute(ctx,
				`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
				 VALUES ('o1', 'bad', 'suspect', ?, NULL, ?)`, n, ts(upd)); err != nil {
				t.Fatal(err)
			}
			if tc.answered != 0 {
				if err := db.Execute(ctx,
					`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
					 VALUES ('o2', 'bad', 'healthy', 0, NULL, ?)`, ts(at.Add(tc.answered))); err != nil {
					t.Fatal(err)
				}
			}
			c := NewCoordinator("me", db)
			c.Now = func() time.Time { return now }
			why, got := c.fenceStillStands(ctx, "bad", at)
			if got != tc.want {
				t.Errorf("fenceStillStands = %v (%s), want %v", got, why, tc.want)
			}
		})
	}
}
