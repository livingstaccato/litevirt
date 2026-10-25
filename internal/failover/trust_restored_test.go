package failover

import (
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// setTrust sets down's trust of a confirmed SSH power-off.
func setTrust(t *testing.T, db *corrosion.Client, on bool) {
	t.Helper()
	v := "false"
	if on {
		v = "true"
	}
	if err := corrosion.SetHostLabel(t.Context(), db, "down", corrosion.LabelTrustSSHPoweroff, v); err != nil {
		t.Fatal(err)
	}
}

// Review of the rc10 polish, I2. A recovery that rests on a trusted SSH
// power-off needs the trust recorded when the fence was judged AND the host
// trusting one when the recovery is decided: the same rule on every
// coordinator, at every moment. A revocation holds it; trust set again makes
// that fence count again. A coordinator holding it re-judges it on its next
// cycle, as a restarted one would (the reviewer's probe), with no
// fence-confirm.
//
// Mutation: no re-judgement of a held host whose trust is set again — the
// live leader holds while the restarted one recovers, red.
func TestTrustSSH_TrustSetAgainCountsTheFenceAgain(t *testing.T) {
	for _, restart := range []bool{false, true} {
		name := "live leader"
		if restart {
			name = "restarted leader"
		}
		t.Run(name, func(t *testing.T) {
			c, db, ctx := operatorSSHRow(t, nil, fence.WithTrust("operator fence [path=managed]", true, "managed", "operator-ssh-down"))
			if got := vmHost(t, db, ctx); got != "down" {
				t.Fatalf("setup: VM recovered to %q on a fence whose trust was revoked", got)
			}
			if _, _, open := unprovenCond(t, db); !open {
				t.Fatal("setup: the revocation's hold raised no condition")
			}
			setTrust(t, db, true)
			if restart {
				c = newTestCoordinator("coordinator", db)
				c.SetFencer(confirmedSSH("managed"))
			}
			c.run(ctx)
			c.run(ctx)
			if got := vmHost(t, db, ctx); got != "alive" {
				t.Fatalf("trust set again: VM still on %q (hold %q), want it recovered without fence-confirm", got, c.holdReason["down"])
			}
			if _, _, open := unprovenCond(t, db); open {
				t.Fatalf("%s still open after the recovery went ahead", CondRecoveryUnprovenFence)
			}
		})
	}
}

// The same for an owed claim retry the revocation dropped: trust set again,
// the live coordinator re-judges the fence and the recovery goes ahead.
//
// Mutation: no re-judgement of a held host whose trust is set again — red.
func TestTrustSSH_TrustSetAgainResumesARevokedClaimRetry(t *testing.T) {
	got, c := owedClaimRetry(t, true)
	if got != "down" {
		t.Fatalf("setup: the revoked claim retry moved the VM to %q", got)
	}
	db, ctx := c.db, t.Context()
	// The fixture's failed and successful fences share a second, and a
	// failed attempt wins a same-second tie: date the failed one a minute
	// earlier, as it ran, so the record names the trusted power-off.
	if err := db.Execute(ctx, `UPDATE fencing_log SET timestamp = strftime('%Y-%m-%dT%H:%M:%SZ', timestamp, '-60 seconds')
		WHERE host_name = 'down' AND result != 'fenced'`); err != nil {
		t.Fatal(err)
	}
	setTrust(t, db, true)
	c.run(ctx)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("trust set again: VM still on %q (hold %q), want it recovered", got, c.holdReason["down"])
	}
}

// A fence judged untrusted stays held whatever the setting says later: trust
// set during the hold is not trust recorded at judgement, on the live leader
// as on a restarted one.
func TestTrustSSH_TrustSetAfterAnUntrustedJudgementStillHolds(t *testing.T) {
	for _, restart := range []bool{false, true} {
		name := "live leader"
		if restart {
			name = "restarted leader"
		}
		t.Run(name, func(t *testing.T) {
			db, ctx := seedDownHost(t, "ssh", nil)
			c := newTestCoordinator("coordinator", db)
			c.SetFencer(confirmedSSH("managed"))
			c.run(ctx)
			setTrust(t, db, true)
			if restart {
				c = newTestCoordinator("coordinator", db)
				c.SetFencer(confirmedSSH("managed"))
			}
			for i := 0; i < 3; i++ {
				c.run(ctx)
			}
			if got := vmHost(t, db, ctx); got != "down" {
				t.Fatalf("trust set after an untrusted judgement recovered the VM to %q", got)
			}
		})
	}
}

// A fence judged untrusted is not re-decided every cycle once trust is set
// later: trustRestored reports only a fence whose trust was recorded at
// judgement (review round 2's churn guard).
//
// Mutation: drop RecordedTrust from trustRestored — red.
func TestTrustSSH_UntrustedJudgementIsNotReDecidedEachCycle(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(confirmedSSH("managed"))
	c.run(ctx)
	setTrust(t, db, true)
	c.run(ctx)
	c.run(ctx)
	h, err := corrosion.GetHost(ctx, db, "down")
	if err != nil || h == nil {
		t.Fatal(err)
	}
	if c.trustRestored(h) {
		t.Fatal("trustRestored reports a host whose fence was judged untrusted: it is re-decided every cycle")
	}
}

// The note for a trust revoked and set again says the fence counts again,
// not that the revocation holds the recovery.
func TestSSHTrustNote_TrustSetAgain(t *testing.T) {
	h := &corrosion.HostRecord{Name: "node-5", Labels: map[string]string{corrosion.LabelTrustSSHPoweroff: "true"}}
	note := sshTrustNote(h, fence.Result{Method: "ssh", Success: true,
		Detail: fence.WithTrust("operator fence [path=managed]", true, "managed", "f1")}, "f1")
	if !strings.Contains(note, "set again") || !strings.Contains(note, "counts again") || strings.Contains(note, "held this recovery") {
		t.Fatalf("note %q", note)
	}
}
