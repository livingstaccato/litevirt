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
		!strings.Contains(ev.Detail, "the trust setting does not count it") {
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

// The condition's detail stays current. (a) An operator confirmation written
// after the raise that does not stand is named in it, as in the stall alert.
// (b) A host given an ipmi strategy after its SSH fence failed, whose ipmi
// fence then fails too, is held on that failure: the detail names it, not the
// SSH fence, and the remedy no longer suggests a BMC strategy.
//
// Mutations: drop the settle sweep's re-raise — (a) red; drop the re-raise of
// an open condition on a failed BMC fence — (b) red.
func TestUnprovenFence_TheDetailStaysCurrent(t *testing.T) {
	t.Run("a stale confirmation noted later", func(t *testing.T) {
		db, ctx := seedDownHost(t, "ssh", nil)
		liveMembership(t, db)
		runStart := time.Now()
		for _, o := range []string{"coordinator", "alive"} {
			failingSince(t, db, o, runStart, runStart)
		}
		c := newTestCoordinator("coordinator", db)
		c.SetFencer(confirmedSSH("managed"))
		now := time.Now()
		c.Now = func() time.Time { return now }
		c.run(ctx)
		if _, _, open := unprovenCond(t, db); !open {
			t.Fatal("setup: no condition raised")
		}
		time.Sleep(1100 * time.Millisecond)
		fenceRowAt(t, db, "confirm-new", "manual", "manual-confirmed", time.Now())
		now = now.Add(recoveryStallAfter + time.Second)
		holdLeaseThrough(t, db, ctx, now)
		for _, o := range []string{"coordinator", "alive"} {
			failingSince(t, db, o, runStart, now)
		}
		c.run(ctx)
		if !strings.Contains(c.holdReason["down"], "confirm-new") {
			t.Fatalf("setup: the confirmation was not judged stale (hold %q)", c.holdReason["down"])
		}
		if _, ev, _ := unprovenCond(t, db); !strings.Contains(ev.Detail, "confirm-new") {
			t.Errorf("the condition's detail does not name the stale confirmation: %q", ev.Detail)
		}
	})
	t.Run("a strategy switch whose fence fails", func(t *testing.T) {
		db, ctx := seedDownHost(t, "ssh", nil)
		c := newTestCoordinator("coordinator", db)
		ipmi := false
		c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
			if ipmi {
				return fence.Result{Method: "ipmi", Detail: "BMC unreachable"}
			}
			return fence.Result{Method: "ssh", Detail: "ssh: connect: No route to host [path=managed]"}
		})
		now := time.Now()
		c.Now = func() time.Time { return now }
		c.run(ctx)
		if _, _, open := unprovenCond(t, db); !open {
			t.Fatal("setup: no condition raised")
		}
		if err := db.Execute(ctx, `UPDATE hosts SET fence_strategy = 'ipmi' WHERE name = 'down'`); err != nil {
			t.Fatal(err)
		}
		ipmi = true
		for i := 0; i < 6; i++ {
			now = now.Add(5 * time.Minute)
			holdLeaseThrough(t, db, ctx, now)
			for _, o := range []string{"coordinator", "alive"} {
				failingSince(t, db, o, now.Add(-time.Hour), now)
			}
			c.run(ctx)
		}
		if !strings.Contains(c.holdReason["down"], "BMC unreachable") {
			t.Fatalf("setup: the ipmi fence did not run and fail (hold %q)", c.holdReason["down"])
		}
		_, ev, open := unprovenCond(t, db)
		if !open {
			t.Fatal("the condition resolved while the host is still unproven")
		}
		if !strings.Contains(ev.Detail, "ipmi fence of down failed (BMC unreachable)") || strings.Contains(ev.Detail, "lost power") {
			t.Errorf("detail is not the current reason: %q", ev.Detail)
		}
		if strings.Contains(ev.Remedy, "--fence-strategy") {
			t.Errorf("remedy still suggests a BMC strategy: %q", ev.Remedy)
		}
	})
}

// The rc10 lab's N3: the remedy upper-cased the trust note's first letter,
// which begins with the host's name when the trust was revoked ("Node-5's").
// A host name is never capitalised; a note that begins with a word is.
//
// Mutation: upper-case the note's first letter unconditionally, as before —
// red.
func TestUnprovenRemedy_DoesNotCapitaliseAHostName(t *testing.T) {
	h := &corrosion.HostRecord{Name: "node-5", FenceStrategy: "ssh"}
	revoked := sshTrustNote(h, fence.Result{Method: "ssh", Success: true,
		Detail: fence.WithTrust("operator fence [path=managed]", true, "managed", "f1")}, "f1")
	if !strings.HasPrefix(revoked, "node-5's trust") {
		t.Fatalf("setup: the revoked note does not begin with the host name: %q", revoked)
	}
	if got := unprovenRemedy(h, revoked); !strings.Contains(got, ". node-5's trust") || strings.Contains(got, "Node-5") {
		t.Errorf("remedy capitalises the host name: %q", got)
	}
	unpinned := sshTrustNote(h, fence.Result{Method: "ssh", Success: true,
		Detail: fence.WithTrust("operator fence [path=legacy-unpinned]", false, "legacy-unpinned", "f1")}, "f1")
	if got := unprovenRemedy(h, unpinned); !strings.Contains(got, ". This power-off was not confirmed") {
		t.Errorf("remedy does not begin a sentence that starts with a word: %q", got)
	}

	// The same, end to end: a hold on a revoked trust.
	_, db, _ := operatorSSHRow(t, nil, fence.WithTrust("operator fence [path=managed]", true, "managed", "operator-ssh-down"))
	if _, ev, open := unprovenCond(t, db); !open || !strings.Contains(ev.Remedy, "down's trust") || strings.Contains(ev.Remedy, "Down's") {
		t.Errorf("the condition's remedy capitalises the host name (open %v): %q", open, ev.Remedy)
	}
}

// The rc10 lab's A5: an operator's `lv host fence --confirmed` of a host the
// observers had not yet watched stay down is declined ("the recorded fence
// … no longer stands") and never resumed from. The VM is held, which is safe,
// but nothing showed in `lv health`. The decline raises
// ha.recovery.unproven_fence, naming fence-confirm and undrain; the decline
// stays a decline (the VM does not move on it), and the condition resolves
// once the operator's confirmation lets the recovery go ahead.
//
// Mutation: no raise in noteResumeDeclined — red.
func TestUnprovenFence_ADeclinedRecordedFenceIsAHealthCondition(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", trustSSH)
	operatorFences(t, db, ctx)
	ageFenceRows(t, db, ctx, 2*time.Minute)
	// Every observer's failing run began after the fence: none watched the
	// host stay down across it.
	now := time.Now()
	for _, o := range []string{"coordinator", "alive"} {
		failingSince(t, db, o, now.Add(-90*time.Second), now)
	}
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fences++
		return fence.Result{Method: "ssh", Detail: "ssh: connect: No route to host [path=managed]"}
	})
	c.run(ctx)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("a declined recorded fence moved the VM to %q", got)
	}
	if fences != 0 {
		t.Fatalf("a declined recorded fence ran %d fences", fences)
	}
	if !strings.Contains(c.holdReason["down"], "no longer stands") {
		t.Fatalf("setup: the recorded fence was not declined (hold %q)", c.holdReason["down"])
	}
	row, ev, open := unprovenCond(t, db)
	if !open {
		t.Fatalf("no open %s for a recovery held on a declined recorded fence", CondRecoveryUnprovenFence)
	}
	if row.Severity != corrosion.SeverityCritical || len(ev.Workloads) != 1 || ev.Workloads[0] != "vm/vm" {
		t.Errorf("severity %q workloads %v, want critical, [vm/vm]", row.Severity, ev.Workloads)
	}
	if !strings.Contains(ev.Detail, "recorded ssh fence operator-ssh-down no longer stands") {
		t.Errorf("detail does not name the declined fence: %q", ev.Detail)
	}
	for _, want := range []string{"`lv host fence-confirm down`", "`lv host undrain down`",
		"If down is up and answering", "none of its workloads runs anywhere else", "nothing moves until a new fence proves it off", "If any moved, use `lv host fence-confirm down` instead"} {
		if !strings.Contains(ev.Remedy, want) {
			t.Errorf("remedy does not name %q: %q", want, ev.Remedy)
		}
	}
	// The undrain is offered on its precondition, never on a claim that
	// nothing moved (review I1): an earlier resume of the same fence may
	// have recovered part of the workloads.
	if strings.Contains(ev.Remedy, "Nothing was recovered") {
		t.Errorf("remedy claims nothing was recovered on the fence: %q", ev.Remedy)
	}

	operatorConfirms(t, db, ctx, "down")
	c.SetFencer(confirmedSSH("managed"))
	for i := 0; i < 3 && vmHost(t, db, ctx) == "down"; i++ {
		c.run(ctx)
	}
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM still on %q after fence-confirm (hold %q)", got, c.holdReason["down"])
	}
	if _, _, open := unprovenCond(t, db); open {
		t.Fatalf("%s still open after the recovery went ahead", CondRecoveryUnprovenFence)
	}
}
