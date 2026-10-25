package failover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// operatorSSHRow records what an operator's `lv host fence down` over SSH
// writes ('offline' and an ssh/fenced row) with detail as given, after the
// coordinator's own fence of down failed.
func operatorSSHRow(t *testing.T, labels map[string]string, detail string) (*Coordinator, *corrosion.Client, context.Context) {
	t.Helper()
	db, ctx := seedDownHost(t, "ssh", labels)
	lengthenStreak(t, db, ctx, 2*time.Minute)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(countingFencer(new(int), sshFailedFence))
	c.run(ctx)
	ageFenceRows(t, db, ctx, 10*time.Second)
	if err := corrosion.RecordFenceWithState(ctx, db, corrosion.FenceLogRecord{
		ID: "operator-ssh-down", HostName: "down", Method: "ssh", Result: fence.LogFenced, Detail: detail,
	}, "offline"); err != nil {
		t.Fatal(err)
	}
	c.run(ctx)
	c.run(ctx)
	return c, db, ctx
}

// A row with no trust token, as an earlier build writes it, records no trust:
// on a host whose label trusts a confirmed SSH power-off now, a recovery
// resumed from it is held (fail closed).
//
// Mutation: RecordedTrust reads a detail with no token as trusted — the VM
// moves, red.
func TestTrustSSH_ARowWithoutATokenIsHeld(t *testing.T) {
	c, db, ctx := operatorSSHRow(t, trustSSH, "operator fence [path=managed]")
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM recovered to %q on a row that records no trust decision", got)
	}
	if hold := c.holdReason["down"]; !strings.Contains(hold, "lv host fence-confirm down") {
		t.Fatalf("hold %q does not name the way out", hold)
	}
}

// Revoking the trust holds a recovery not yet made on a trusted fence: a
// recovery resting on a trusted SSH power-off needs the decision recorded
// with the fence AND the host trusting one now. Trust is never retroactive,
// and its revocation is honoured.
//
// Mutation: judge by the recorded decision alone — the VM moves, red.
func TestTrustSSH_RevokingTrustHoldsAPendingRecovery(t *testing.T) {
	c, db, ctx := operatorSSHRow(t, nil, fence.WithTrust("operator fence [path=managed]", true))
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM recovered to %q on a trusted fence whose host's trust was revoked since", got)
	}
	hold := c.holdReason["down"]
	if !strings.Contains(hold, "revoked") || strings.Contains(hold, "counts later fences") {
		t.Fatalf("hold %q does not say the trust was revoked", hold)
	}
}

// The hold says what the trust setting would do only where it is true: a
// later fence confirmed over the pinned key. An unpinned confirmation is not
// counted whatever the setting, and a fence judged before the host trusted
// one stays held although it trusts one now.
//
// Mutation: key the message on the label alone, as before — the unpinned
// case says the setting counts later fences, red.
func TestTrustSSH_TheHoldSaysWhyTheTrustDidNotCount(t *testing.T) {
	for _, tc := range []struct {
		name    string
		labels  map[string]string
		detail  string
		want    []string
		notWant []string
	}{
		{"unpinned, trusted host", trustSSH, fence.WithTrust("operator fence [path=legacy-unpinned]", true),
			[]string{"not confirmed over", "pinned"}, []string{"counts later fences", "--trust-ssh-poweroff"}},
		{"judged before the trust", trustSSH, fence.WithTrust("operator fence [path=managed]", false),
			[]string{"trusts a confirmed SSH power-off now", "never this one"}, []string{"may instead set"}},
		{"untrusted host", nil, fence.WithTrust("operator fence [path=managed]", false),
			[]string{"--trust-ssh-poweroff", "pinned", "never this one", "not a recommendation"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, db, ctx := operatorSSHRow(t, tc.labels, tc.detail)
			if got := vmHost(t, db, ctx); got != "down" {
				t.Fatalf("setup: VM recovered to %q", got)
			}
			hold := c.holdReason["down"]
			for _, w := range tc.want {
				if !strings.Contains(hold, w) {
					t.Errorf("hold does not say %q: %q", w, hold)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(hold, w) {
					t.Errorf("hold says %q, which is not true here: %q", w, hold)
				}
			}
			if _, ev, open := unprovenCond(t, db); open && !strings.Contains(ev.Remedy, tc.want[0]) {
				t.Errorf("remedy does not say %q: %q", tc.want[0], ev.Remedy)
			}
		})
	}
}
