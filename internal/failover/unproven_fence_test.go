package failover

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// unprovenCond reads down's ha.recovery.unproven_fence; open is false when
// there is none or it is resolved.
func unprovenCond(t *testing.T, db *corrosion.Client) (row corrosion.HealthCondition, ev unprovenFenceEvidence, open bool) {
	t.Helper()
	row, ok, err := corrosion.GetHealthCondition(context.Background(), db, RefenceEvaluator, CondRecoveryUnprovenFence, "host", "down")
	if err != nil {
		t.Fatalf("read %s: %v", CondRecoveryUnprovenFence, err)
	}
	if !ok {
		return row, ev, false
	}
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		t.Fatalf("%s evidence %q: %v", CondRecoveryUnprovenFence, row.Evidence, err)
	}
	return row, ev, row.Lifecycle != corrosion.ConditionResolved
}

// The rc9 lab's F3: a recovery held because a confirmed SSH power-off is not
// proof (the host does not trust one) showed only in the coordinator's log,
// the stall alert and `lv doctor fence`, never in `lv health`. It raises
// ha.recovery.unproven_fence, critical, naming the host, the held workload,
// the reason and the way out — fence-confirm, and the trust opt-in, which
// does not reach back to this fence — and it resolves once the operator's
// confirmation lets the recovery go ahead.
//
// Mutation: drop raiseUnproven from holdUnproven — no condition, red. (The
// VM moving resolves it twice over, so the resolves themselves are pinned by
// the tests below.)
func TestUnprovenFence_AnUntrustedSSHPowerOffIsAHealthCondition(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(confirmedSSH("managed"))
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("setup: VM recovered to %q on an untrusted SSH power-off", got)
	}
	row, ev, open := unprovenCond(t, db)
	if !open {
		t.Fatalf("no open %s for a recovery held on an untrusted SSH power-off (hold %q)", CondRecoveryUnprovenFence, c.holdReason["down"])
	}
	if row.Severity != corrosion.SeverityCritical || len(row.Hosts) != 1 || row.Hosts[0] != "down" {
		t.Errorf("row severity %q hosts %v, want critical on down", row.Severity, row.Hosts)
	}
	if len(ev.Workloads) != 1 || ev.Workloads[0] != "vm/vm" {
		t.Errorf("workloads %v, want [vm/vm]", ev.Workloads)
	}
	if !strings.Contains(ev.Detail, "confirmed the power-off, which is not proof down is off") ||
		!strings.Contains(ev.Detail, "does not trust a confirmed SSH power-off") {
		t.Errorf("detail does not give the reason: %q", ev.Detail)
	}
	for _, want := range []string{"`lv host fence-confirm down`", "`lv host config down --trust-ssh-poweroff`",
		"never this one", "--fence-strategy ipmi|redfish"} {
		if !strings.Contains(ev.Remedy, want) {
			t.Errorf("remedy does not name %q: %q", want, ev.Remedy)
		}
	}

	operatorConfirms(t, db, ctx, "down")
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM still on %q after fence-confirm (hold %q)", got, c.holdReason["down"])
	}
	if _, _, open := unprovenCond(t, db); open {
		t.Fatalf("%s still open after the recovery went ahead", CondRecoveryUnprovenFence)
	}
}

// The other ways the hold ends resolve it too, on the cycle that sees it:
// the recovery going ahead with a workload still left on the host (no
// capacity, say), which the settle sweep alone would not resolve; and, read
// back from the replica by a coordinator that never judged the fence, a host
// with no recoverable workload left on it, or one back in service.
//
// Mutations: drop the resolve in resumeFromConfirmation — the first case stays
// open, red; drop the pending case from resolveUnprovenSettled — the other two
// stay open, red.
func TestUnprovenFence_ResolvesWhenTheHoldEnds(t *testing.T) {
	t.Run("recovery went ahead, workload left", func(t *testing.T) {
		db, ctx := seedDownHost(t, "ssh", nil)
		c := newTestCoordinator("coordinator", db)
		c.SetFencer(confirmedSSH("managed"))
		c.run(ctx)
		if _, _, open := unprovenCond(t, db); !open {
			t.Fatal("setup: no condition raised")
		}
		// Nowhere to place it: the only peer is in maintenance.
		if err := corrosion.UpdateHostState(ctx, db, "alive", "maintenance"); err != nil {
			t.Fatal(err)
		}
		operatorConfirms(t, db, ctx, "down")
		c.run(ctx)
		if got := vmHost(t, db, ctx); got != "down" {
			t.Fatalf("setup: VM placed on %q with no host to take it", got)
		}
		if _, _, open := unprovenCond(t, db); open {
			t.Fatalf("%s still open once the operator's confirmation let the recovery go ahead", CondRecoveryUnprovenFence)
		}
	})
	for _, tc := range []struct {
		name   string
		settle func(t *testing.T, db *corrosion.Client, ctx context.Context)
	}{
		{"no recoverable workload left", func(t *testing.T, db *corrosion.Client, ctx context.Context) {
			if err := db.Execute(ctx, `UPDATE vms SET host_name = 'alive' WHERE name = 'vm'`); err != nil {
				t.Fatal(err)
			}
		}},
		{"host back in service", func(t *testing.T, db *corrosion.Client, ctx context.Context) {
			if err := corrosion.UpdateHostState(ctx, db, "down", "active"); err != nil {
				t.Fatal(err)
			}
			// Healthy again: no longer a fence candidate.
			if err := db.Execute(ctx, `UPDATE host_health SET consecutive_failures = 0, status = 'healthy' WHERE target = 'down'`); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, ctx := seedDownHost(t, "ssh", nil)
			c := newTestCoordinator("coordinator", db)
			c.SetFencer(confirmedSSH("managed"))
			c.run(ctx)
			if _, _, open := unprovenCond(t, db); !open {
				t.Fatal("setup: no condition raised")
			}
			tc.settle(t, db, ctx)
			// A successor that never judged the fence reads it back.
			if err := db.Execute(ctx, `DELETE FROM leader_election`); err != nil {
				t.Fatal(err)
			}
			succ := newTestCoordinator("alive", db)
			succ.SetFencer(confirmedSSH("managed"))
			succ.run(ctx)
			if _, _, open := unprovenCond(t, db); open {
				t.Fatalf("%s still open once the hold ended (%s)", CondRecoveryUnprovenFence, tc.name)
			}
		})
	}
}

// A best-effort fence that proves nothing, on a host whose partition pause is
// not relied on, raises the condition too; its remedy has no trust opt-in,
// which only a confirmed SSH power-off would answer.
//
// Mutation: hold the best-effort refusal with noteGateHold alone — no
// condition, red.
func TestUnprovenFence_ABestEffortFenceThatProvesNothingIsAHealthCondition(t *testing.T) {
	db, ctx := seedDownHost(t, "best-effort", nil)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "best-effort-ssh", Dialled: true, Detail: "SSH failed (exit status 255) [path=managed]"}
	})
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("setup: VM recovered to %q on a best-effort fence that proves nothing", got)
	}
	_, ev, open := unprovenCond(t, db)
	if !open {
		t.Fatalf("no open %s for a best-effort hold (hold %q)", CondRecoveryUnprovenFence, c.holdReason["down"])
	}
	if !strings.Contains(ev.Detail, "best-effort fence proves nothing") || !strings.Contains(ev.Remedy, "`lv host fence-confirm down`") {
		t.Errorf("evidence does not give the reason and the way out: %+v", ev)
	}
	if strings.Contains(ev.Remedy, "trust-ssh-poweroff") {
		t.Errorf("remedy offers the SSH trust opt-in for a fence it would not count: %q", ev.Remedy)
	}
}

// Trust is never retroactive, whichever leader judges the fence: a
// successor resuming a recorded SSH power-off that was judged untrusted uses
// the recorded decision, not the label as it reads now. The VM stays held and
// the condition open after the operator sets the trust, until fence-confirm.
//
// Mutation: judge a resumed fence by trustsSSHPoweroff(h) again — the
// successor recovers the VM, red.
func TestUnprovenFence_TrustSetAfterTheFenceDoesNotReleaseItUnderASuccessor(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(confirmedSSH("managed"))
	c.run(ctx)
	if _, _, open := unprovenCond(t, db); !open {
		t.Fatal("setup: no condition raised")
	}
	for k, v := range trustSSH {
		if err := corrosion.SetHostLabel(ctx, db, "down", k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Execute(ctx, `DELETE FROM leader_election`); err != nil {
		t.Fatal(err)
	}
	succ := newTestCoordinator("alive", db)
	succ.SetFencer(confirmedSSH("managed"))
	succ.run(ctx)
	succ.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("a successor recovered the VM to %q on a fence judged untrusted, once the trust was set", got)
	}
	if _, _, open := unprovenCond(t, db); !open {
		t.Fatalf("%s resolved while the recovery is still held (hold %q)", CondRecoveryUnprovenFence, succ.holdReason["down"])
	}
	operatorConfirms(t, db, ctx, "down")
	succ.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM still on %q after fence-confirm (hold %q)", got, succ.holdReason["down"])
	}
}

// A later fence that passes the gates resolves the condition, whether or not
// a workload is placed: a failed best-effort fence holds the VM, the host is
// given an ipmi strategy, and its retry proves the power-off, with no host to
// take the VM.
//
// Mutation: drop the resolve after recoverFenced's gates — it stays open, red.
func TestUnprovenFence_ALaterFenceThatPassesTheGatesResolvesIt(t *testing.T) {
	db, ctx := seedDownHost(t, "best-effort", nil)
	c := newTestCoordinator("coordinator", db)
	proves := false
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		if proves {
			return fence.Result{Method: "ipmi", Success: true, Detail: "chassis power off, verified"}
		}
		return fence.Result{Method: "best-effort-ssh", Dialled: true, Detail: "SSH failed (exit status 255) [path=managed]"}
	})
	now := time.Now()
	c.Now = func() time.Time { return now }
	c.run(ctx)
	if _, _, open := unprovenCond(t, db); !open {
		t.Fatalf("setup: no condition raised (hold %q)", c.holdReason["down"])
	}
	if err := db.Execute(ctx, `UPDATE hosts SET fence_strategy = 'ipmi' WHERE name = 'down'`); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostState(ctx, db, "alive", "maintenance"); err != nil {
		t.Fatal(err)
	}
	proves = true
	for i := 0; i < 6; i++ {
		now = now.Add(5 * time.Minute)
		holdLeaseThrough(t, db, ctx, now)
		for _, o := range []string{"coordinator", "alive"} {
			failingSince(t, db, o, now.Add(-time.Hour), now)
		}
		c.run(ctx)
	}
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("setup: VM placed on %q with no host to take it", got)
	}
	if _, _, open := unprovenCond(t, db); open {
		t.Fatalf("%s still open after a proof-grade fence passed the gates (hold %q)", CondRecoveryUnprovenFence, c.holdReason["down"])
	}
}

// Under the safe-fence policy a best-effort fence is not proof: the hold
// raises the condition, naming the policy.
//
// Mutation: hold the safe-fence refusal with noteGateHold alone — no
// condition, red.
func TestUnprovenFence_TheSafeFencePolicyHoldIsAHealthCondition(t *testing.T) {
	db, ctx := seedDownHost(t, "best-effort", nil)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(fencerReturning("best-effort-ssh", true))
	c.Gate = gateEnforcing(capabilities.SafeFenceDefaultV1)
	c.SafeFenceEnforce = true
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("setup: VM recovered to %q on a best-effort fence under the safe-fence policy", got)
	}
	_, ev, open := unprovenCond(t, db)
	if !open {
		t.Fatalf("no open %s for a safe-fence hold (hold %q)", CondRecoveryUnprovenFence, c.holdReason["down"])
	}
	if !strings.Contains(ev.Detail, "safe-fence policy") || !strings.Contains(ev.Remedy, "`lv host fence-confirm down`") {
		t.Errorf("evidence does not give the reason and the way out: %+v", ev)
	}
}

// The rc9 lab's F1a: an ssh-strategy fence whose dial (or power-off) failed
// holds the host's workloads too, retried with backoff, and nothing proves
// the host is off. It is the hold an operator most needs to see — a host that
// lost power leaves an SSH fence nothing to reach — so it raises the
// condition, with the failure in its detail and no trust opt-in in its
// remedy, which a failed fence would not answer. It resolves once the
// operator's confirmation lets the recovery go ahead.
//
// Mutation: drop the raise from the failed-fence branch — no condition, red.
func TestUnprovenFence_AFailedSSHFenceIsAHealthCondition(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	lengthenStreak(t, db, ctx, 2*time.Minute)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "ssh", Detail: "ssh: connect to host 10.0.0.40 port 22: No route to host [path=managed]"}
	})
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("setup: VM recovered to %q on a failed SSH fence", got)
	}
	_, ev, open := unprovenCond(t, db)
	if !open {
		t.Fatalf("no open %s for a failed SSH fence (hold %q)", CondRecoveryUnprovenFence, c.holdReason["down"])
	}
	if !strings.Contains(ev.Detail, "SSH fence of down failed") || !strings.Contains(ev.Detail, "No route to host") {
		t.Errorf("detail does not name the failed fence: %q", ev.Detail)
	}
	if !strings.Contains(ev.Remedy, "`lv host fence-confirm down`") || !strings.Contains(ev.Remedy, "--fence-strategy ipmi|redfish") ||
		strings.Contains(ev.Remedy, "trust-ssh-poweroff") {
		t.Errorf("remedy: %q", ev.Remedy)
	}

	operatorConfirms(t, db, ctx, "down")
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM still on %q after fence-confirm (hold %q)", got, c.holdReason["down"])
	}
	if _, _, open := unprovenCond(t, db); open {
		t.Fatalf("%s still open after the recovery went ahead", CondRecoveryUnprovenFence)
	}
}

// A failed IPMI fence is not this condition: its BMC is the proof, and the
// retry is what fixes it. Only a fence that goes over SSH alone raises it.
func TestUnprovenFence_AFailedBMCFenceIsNot(t *testing.T) {
	db, ctx := seedDownHost(t, "ipmi", nil)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "ipmi", Detail: "BMC unreachable"}
	})
	c.run(ctx)
	if _, _, open := unprovenCond(t, db); open {
		t.Fatalf("%s raised for a failed ipmi fence", CondRecoveryUnprovenFence)
	}
}
