package failover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/fence"
)

// confirmedSSH is an SSH power-off the remote shell confirmed, by path.
func confirmedSSH(path string) Fencer {
	return func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "ssh", Success: true, Detail: "SSH forced poweroff to root@10.0.0.40: litevirt-fence-armed [path=" + path + "]"}
	}
}

// By default a confirmed SSH power-off is not proof the host is off: the VM
// is held, the fence is recorded as it ran, and the hold names the way out
// and the trust setting only as an operator's choice.
//
// Mutation: drop holdUntrustedSSH from recoverFenced — the VM moves.
func TestTrustSSH_AConfirmedPowerOffIsHeldByDefault(t *testing.T) {
	for _, strategy := range []string{"ssh", "best-effort"} {
		t.Run(strategy, func(t *testing.T) {
			db, ctx := seedDownHost(t, strategy, nil)
			c := newTestCoordinator("coordinator", db)
			c.SetFencer(confirmedSSH("managed"))
			c.run(ctx)
			if got := vmHost(t, db, ctx); got != "down" {
				t.Fatalf("VM recovered to %q on an untrusted confirmed SSH power-off", got)
			}
			hold := c.holdReason["down"]
			for _, want := range []string{"lv host fence-confirm down", "ipmi or redfish", "--trust-ssh-poweroff", "not a recommendation"} {
				if !strings.Contains(hold, want) {
					t.Fatalf("hold %q does not name %q", hold, want)
				}
			}
			// The way out: the operator confirms it off.
			operatorConfirms(t, db, ctx, "down")
			c.run(ctx)
			if got := vmHost(t, db, ctx); got != "alive" {
				t.Fatalf("VM still on %q after fence-confirm (hold %q)", got, c.holdReason["down"])
			}
		})
	}
}

// With the host trusting a confirmed SSH power-off, one confirmed over the
// pinned key (managed or legacy-pinned) recovers the VM at once. Nothing else
// is trusted: an unpinned success, a host-key mismatch, a dial failure.
//
// Mutations: trustedSSH ignores the pin (ConfirmedOverPin) — the unpinned
// case moves; trustedSSH ignores the setting — the default test above moves.
func TestTrustSSH_TheOptInTrustsOnlyAPinnedConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		strategy string
		fencer   Fencer
		want     string
	}{
		{"managed, confirmed", "ssh", confirmedSSH("managed"), "alive"},
		{"legacy-pinned, confirmed", "ssh", confirmedSSH("legacy-pinned"), "alive"},
		{"best-effort, confirmed", "best-effort", confirmedSSH("managed"), "alive"},
		{"unpinned, confirmed", "ssh", confirmedSSH("legacy-unpinned"), "down"},
		{"host-key mismatch", "ssh", func(context.Context, fence.HostConfig) fence.Result {
			return fence.Result{Method: "ssh", WrongHost: true, Detail: "Host key verification failed. [path=managed]"}
		}, "down"},
		{"dial failure", "best-effort", func(context.Context, fence.HostConfig) fence.Result {
			return fence.Result{Method: "best-effort-ssh", Dialled: true, Detail: "SSH failed (exit status 255) [path=managed]"}
		}, "down"},
		{"unconfirmed", "ssh", func(context.Context, fence.HostConfig) fence.Result {
			return fence.Result{Method: "ssh", Detail: "remote command exited 0 without confirming it ran [path=managed]"}
		}, "down"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, ctx := seedDownHost(t, tc.strategy, trustSSH)
			c := newTestCoordinator("coordinator", db)
			c.SetFencer(tc.fencer)
			c.run(ctx)
			if got := vmHost(t, db, ctx); got != tc.want {
				t.Fatalf("VM on %q, want %q (hold %q)", got, tc.want, c.holdReason["down"])
			}
		})
	}
}

// A best-effort fence the remote shell confirmed, on a host that does not
// trust one, is one more fence that proves nothing: with the host's pause
// relied on it waits that pause out, and then recovers.
//
// Mutation: drop the confirmed-ssh case from asSelfPause — it is held, red.
func TestTrustSSH_ABestEffortConfirmationWaitsOutThePause(t *testing.T) {
	c, db, ctx, mono := pauseCoordinator(t, true)
	c.SetFencer(confirmedSSH("managed"))
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM moved to %q before the pause wait", got)
	}
	wait, _ := c.partitionPauseWait(ctx)
	mono.Advance(wait + time.Second)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM on %q after the pause wait (hold %q)", got, c.holdReason["down"])
	}
}
