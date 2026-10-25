package failover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// owedClaimRetry: a trusted SSH power-off of down, confirmed over its pinned
// key, passes recoverFenced, but the VM cannot be placed (its only peer is in
// maintenance), and a claim retry is owed, as a claim that formed no
// certificate owes one. If revoke, the operator then revokes the trust. The
// peer comes back, and the retry runs. Returns where the VM is.
func owedClaimRetry(t *testing.T, revoke bool) (string, *Coordinator) {
	t.Helper()
	db, ctx := seedDownHost(t, "ssh", trustSSH)
	c := newTestCoordinator("coordinator", db)
	ok := false
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		if ok {
			return fence.Result{Method: "ssh", Success: true, Path: "managed",
				Detail: "SSH forced poweroff to root@10.0.0.40: litevirt-fence-armed [path=managed]"}
		}
		return fence.Result{Method: "ssh", Detail: "ssh: no route to host [path=managed]"}
	})
	now := time.Now()
	c.Now = func() time.Time { return now }
	c.run(ctx)
	if err := corrosion.UpdateHostState(ctx, db, "alive", "maintenance"); err != nil {
		t.Fatal(err)
	}
	ok = true
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
	c.retryClaimsFor("down")
	if revoke {
		if err := corrosion.SetHostLabel(ctx, db, "down", corrosion.LabelTrustSSHPoweroff, "false"); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.UpdateHostState(ctx, db, "alive", "active"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	holdLeaseThrough(t, db, ctx, now)
	for _, o := range []string{"coordinator", "alive"} {
		failingSince(t, db, o, now.Add(-time.Hour), now)
	}
	c.run(ctx)
	return vmHost(t, db, ctx), c
}

// An owed claim retry is a recovery not yet made: one that rests on a
// trusted SSH power-off is re-judged before it runs, and a revoked trust
// holds it, as recoverFenced would. The control, trust kept, recovers.
//
// Mutation: drop the re-judgement from retryClaims — the revoked case moves
// the VM, red.
func TestTrustSSH_RevokingTrustHoldsAnOwedClaimRetry(t *testing.T) {
	if got, _ := owedClaimRetry(t, false); got != "alive" {
		t.Fatalf("control: the owed retry left the VM on %q with the trust kept", got)
	}
	got, c := owedClaimRetry(t, true)
	if got != "down" {
		t.Fatalf("the owed claim retry moved the VM to %q after the trust was revoked", got)
	}
	if hold := c.holdReason["down"]; !containsAll(hold, "revoked", "lv host fence-confirm down") {
		t.Fatalf("hold %q does not say the trust was revoked and the way out", hold)
	}
}

// heldOnRow is down's VM after an operator ssh row with detail, on a host
// that trusts a confirmed SSH power-off now.
func heldOnRow(t *testing.T, detail string) string {
	t.Helper()
	_, db, ctx := operatorSSHRow(t, trustSSH, detail)
	return vmHost(t, db, ctx)
}

// Admin-set text in a fence row cannot make a fence count: neither a BMC
// address carrying "[path=managed]" after an unpinned fence's real path
// token, nor an earlier build's row whose BMC address ends in "[trust=on".
// Only the marked trust token this build writes, with the path it records
// inside it, counts.
//
// The first row is as this build would write it, had its BMC address not been
// rewritten (fence.DetailField): the marked token records the unpinned path.
//
// Mutations: RecordedTrust reads the path from RecordedPath(detail) — the
// first case moves, red; RecordedTrust accepts the unmarked "[trust=on]" —
// the second moves, red.
func TestTrustSSH_AdminTextInARowCannotMakeItCount(t *testing.T) {
	for name, detail := range map[string]string{
		"unpinned, BMC address names a pin": fence.WithTrust("SSH forced poweroff to root@10.0.0.40: litevirt-fence-armed [path=legacy-unpinned]"+
			" [fenced down as incarnation 1, serial ab, strategy ssh at 10.0.0.9 [path=managed]]", true, "legacy-unpinned", "operator-ssh-down"),
		"earlier build, BMC address ends in a token": "SSH forced poweroff to root@10.0.0.40: litevirt-fence-armed [path=managed]" +
			" [fenced down as incarnation 1, serial ab, strategy ssh at 10.0.0.9 [trust=on]",
	} {
		if got := heldOnRow(t, detail); got != "down" {
			t.Errorf("%s: VM recovered to %q", name, got)
		}
	}
	// Control: the marked token, pinned, counts.
	if got := heldOnRow(t, fence.WithTrust("operator fence [path=managed]", true, "managed", "operator-ssh-down")); got != "alive" {
		t.Errorf("control: the marked, pinned token did not count (VM on %q)", got)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// A failed SSH-only fence, retried with backoff, raises the condition with
// the newest stale confirmation, as the settle sweep does: the row is not
// rewritten twice per retry, once without the note and once with it. The
// stale note is set as noteConfirmationStale records it during the hold.
//
// Mutation: raise from the failed-fence branch with no stale note — the
// row's ObserveCount climbs by two per retry, red.
func TestUnprovenFence_AFailedFenceRetryDoesNotChurnTheRow(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "ssh", Detail: "ssh: connect: No route to host [path=managed]"}
	})
	now := time.Now()
	c.Now = func() time.Time { return now }
	step := func() {
		now = now.Add(5 * time.Minute)
		holdLeaseThrough(t, db, ctx, now)
		for _, o := range []string{"coordinator", "alive"} {
			failingSince(t, db, o, now.Add(-time.Hour), now)
		}
		c.run(ctx)
	}
	c.run(ctx)
	if _, _, open := unprovenCond(t, db); !open {
		t.Fatal("setup: no condition raised")
	}
	c.lastStale = map[string]string{"down": "the operator confirmation confirm-x does not stand for this outage"}
	step() // the sweep, or a retry, picks the note up
	row, _, _ := unprovenCond(t, db)
	before := row.ObserveCount
	retries := 0
	for i := 0; i < 6; i++ {
		n := len(fenceRowsOf(t, db))
		step()
		if len(fenceRowsOf(t, db)) > n {
			retries++
		}
	}
	if retries == 0 {
		t.Fatalf("setup: the failed fence was never retried (hold %q)", c.holdReason["down"])
	}
	row, ev, open := unprovenCond(t, db)
	if !open {
		t.Fatal("the condition resolved while the host is unproven")
	}
	if row.ObserveCount != before {
		t.Errorf("the row was rewritten %d times over %d retries with nothing new to say", row.ObserveCount-before, retries)
	}
	if !strings.Contains(ev.Detail, "confirm-x") {
		t.Errorf("the detail lost the stale confirmation: %q", ev.Detail)
	}
}

func fenceRowsOf(t *testing.T, db *corrosion.Client) []string {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT id FROM fencing_log WHERE host_name = 'down' AND method = 'ssh'`)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.String("id"))
	}
	return out
}

// The reviewer's R4-1 probe: an earlier build's FenceHost row, written before
// BMC addresses were validated, whose admin-set IPMI address ends in the
// marked token body. The row then ends in a well-formed marked token, inside
// the note's unclosed bracket. It does not count: the text before the token
// must be balanced, as every row this build writes is.
//
// Mutation: drop the balanced-brackets check from RecordedTrustToken — the VM
// moves, red.
func TestTrustSSH_AnEarlierBuildsRowCannotForgeTheMarkedToken(t *testing.T) {
	d := "SSH forced poweroff to root@10.0.0.40: litevirt-fence-armed [path=managed]" +
		" [fenced down as incarnation 1, serial ab, strategy ssh at 10.0.0.9 [trust=on;path=managed;v=2]"
	if got := heldOnRow(t, d); got != "down" {
		t.Fatalf("VM recovered to %q on a row whose admin-set BMC address forges the marked token", got)
	}
}

// The reviewer's R5-1 probe: an earlier build's FenceHost row whose admin-set
// IPMI address first closes the note's own bracket, then carries a marked
// token: "x] [trust=on;path=managed;v=2". The text before the token is then
// balanced, so no text rule can tell it from a genuine row. It does not count:
// a token counts only when it names its own row's id, which no address set
// before the row existed can contain.
//
// Mutation: RecordedTrust ignores the id — the v3 form of this probe (the
// next test's wrong-id case) moves, red.
func TestTrustSSH_AnEarlierBuildsRowCannotCloseTheNoteAndForge(t *testing.T) {
	d := "SSH forced poweroff to root@10.0.0.40: litevirt-fence-armed [path=managed]" +
		" [fenced down as incarnation 1, serial ab, strategy ssh at x] [trust=on;path=managed;v=2]"
	if got := heldOnRow(t, d); got != "down" {
		t.Fatalf("VM recovered to %q on a row whose admin-set BMC address closes the note and forges a token", got)
	}
}

// A marked token counts only for the row it names: the same well-formed,
// pinned, trusted token in a row with another id — as an admin-set address
// copied from one row could put it at the end of another — is held. The
// control, naming its own row, recovers.
//
// Mutation: RecordedTrust ignores the id — the wrong-id row moves, red.
func TestTrustSSH_ATokenNamingAnotherRowIsHeld(t *testing.T) {
	if got := heldOnRow(t, fence.WithTrust("operator fence [path=managed]", true, "managed", "some-other-row")); got != "down" {
		t.Fatalf("VM recovered to %q on a token naming another row", got)
	}
	forged := "SSH forced poweroff to root@10.0.0.40: litevirt-fence-armed [path=managed]" +
		" [fenced down as incarnation 1, serial ab, strategy ssh at x] [trust=on;path=managed;id=guess;v=3]"
	if got := heldOnRow(t, forged); got != "down" {
		t.Fatalf("VM recovered to %q on a v3 token forged with a guessed id", got)
	}
	if got := heldOnRow(t, fence.WithTrust("operator fence [path=managed]", true, "managed", "operator-ssh-down")); got != "alive" {
		t.Fatalf("control: a token naming its own row did not count (VM on %q)", got)
	}
}
