package corrosion

// Re-review 4 (uinc-r4-review.md): what retires an older incarnation's rows
// runs only when the name's incarnation changes on this node, and never
// drops a second factor whose epoch carries no incarnation.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
)

func aeBoth(t *testing.T, from, to *Client) {
	t.Helper()
	if err := to.MergeStateBytesLWW(from.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	if err := to.MergeSensitiveStateBytesLWW(from.DumpSensitiveStateBytes()); err != nil {
		t.Fatal(err)
	}
}

// Review C1 (R4-1): an account given a second factor before the latch (an
// untagged epoch, enrolled after the account's created_at, as every factor
// is) keeps it across a password change after the latch.
//
// Red on 0bef41048: factors = []. Mutations: retirement run on every users
// write — red; an untagged factor dropped by clock on a re-create — green
// here (no re-create), red in the untagged-factor re-create test below.
func TestUserIncarnation_PreLatchFactorSurvivesAPasswordChange(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	on := false
	c.SetUserIncarnationGate(func() bool { return on })
	c.SetCredentialsSplitGate(func() bool { return true })
	if err := InsertUser(ctx, c, "carol", "operator", "hash-1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // created_at is a bare second before the latch
	if err := InsertUser2FA(ctx, c, User2FARecord{Username: "carol", Method: "totp", Secret: "s-1", Label: "phone"}); err != nil {
		t.Fatal(err)
	}
	on = true
	if fs, _ := ListUser2FA(ctx, c, "carol"); len(fs) != 1 {
		t.Fatalf("fixture: factors %+v", fs)
	}
	if err := UpdateUserPassword(ctx, c, "carol", "hash-2"); err != nil {
		t.Fatal(err)
	}
	if fs, err := ListUser2FA(ctx, c, "carol"); err != nil || len(fs) != 1 || fs[0].Secret != "s-1" {
		t.Errorf("after a password change post-latch, carol's factors = %+v (err %v): she logs in with her password alone", fs, err)
	}
}

// Review C1 (R4-2): the same through an anti-entropy users merge that only
// adds another account.
//
// Red on 0bef41048: b's carol has no factor.
func TestUserIncarnation_PreLatchFactorSurvivesAnAntiEntropyUsersMerge(t *testing.T) {
	ctx := context.Background()
	a, b := newTestDB(t), newTestDB(t)
	on := false
	for _, c := range []*Client{a, b} {
		c.SetUserIncarnationGate(func() bool { return on })
		c.SetCredentialsSplitGate(func() bool { return true })
	}
	if err := InsertUser(ctx, a, "carol", "operator", "hash-1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err := InsertUser2FA(ctx, a, User2FARecord{Username: "carol", Method: "totp", Secret: "s-1", Label: "phone"}); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, a, b)
	on = true
	if err := InsertUser(ctx, a, "dave", "viewer", "hash-d"); err != nil {
		t.Fatal(err)
	}
	if err := b.MergeStateBytesLWW(a.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	for _, n := range []struct {
		name string
		c    *Client
	}{{"a", a}, {"b", b}} {
		if fs, err := ListUser2FA(ctx, n.c, "carol"); err != nil || len(fs) != 1 || fs[0].Secret != "s-1" {
			t.Errorf("%s after an anti-entropy users merge: carol's factors = %+v (err %v)", n.name, fs, err)
		}
	}
}

// Review H1 (R4-3): a node that has not latched yet enrols a factor for an
// account created after the latch elsewhere. Its epoch is untagged and
// written after the account's incarnation; every node keeps it.
//
// Red on 0bef41048: no factor on either node.
func TestUserIncarnation_AnUnlatchedNodesFactorForANewAccountIsKept(t *testing.T) {
	ctx := context.Background()
	a, u := newTestDB(t), newTestDB(t)
	uOn := false
	a.SetUserIncarnationGate(func() bool { return true })
	u.SetUserIncarnationGate(func() bool { return uOn })
	for _, c := range []*Client{a, u} {
		c.SetCredentialsSplitGate(func() bool { return true })
	}
	if err := InsertUser(ctx, a, "carol", "operator", "hash-1"); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, a, u)
	if err := InsertUser2FA(ctx, u, User2FARecord{Username: "carol", Method: "totp", Secret: "s-1", Label: "phone"}); err != nil {
		t.Fatal(err)
	}
	if err := a.MergeSensitiveStateBytesLWW(u.DumpSensitiveStateBytes()); err != nil {
		t.Fatal(err)
	}
	if fs, _ := ListUser2FA(ctx, a, "carol"); len(fs) != 1 {
		t.Fatalf("fixture: a did not take the factor: %+v", fs)
	}
	if err := UpdateUserPassword(ctx, a, "carol", "hash-2"); err != nil {
		t.Fatal(err)
	}
	uOn = true
	if err := u.MergeStateBytesLWW(a.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	if err := UpdateUserPassword(ctx, u, "carol", "hash-3"); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, u, a)
	for _, n := range []struct {
		name string
		c    *Client
	}{{"a (latched)", a}, {"u (latched since)", u}} {
		if fs, err := ListUser2FA(ctx, n.c, "carol"); err != nil || len(fs) != 1 || fs[0].Secret != "s-1" {
			t.Errorf("%s: carol's factors = %+v (err %v): password-only login", n.name, fs, err)
		}
	}
}

// Ruling of round 4: an untagged factor is never dropped by a clock alone,
// even when the name IS re-created: dropping a legitimate one is a
// password-only login. Since round 5 it is held there instead of active.
//
// Red on 0bef41048 (the untagged factor goes by clock at the re-create).
// Mutation: the untagged clock rule restored — red.
func TestUserIncarnation_AnUntaggedFactorIsNotDroppedOnARecreate(t *testing.T) {
	ctx := context.Background()
	a, l := newTestDB(t), newTestDB(t)
	lOn := false
	a.SetUserIncarnationGate(func() bool { return true })
	l.SetUserIncarnationGate(func() bool { return lOn })
	for _, c := range []*Client{a, l} {
		c.SetCredentialsSplitGate(func() bool { return true })
	}
	if err := InsertUser(ctx, a, "carol", "operator", "hash-old"); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, a, l)
	if err := DeleteUser(ctx, a, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, a, "carol", "operator", "hash-new"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	// l has not latched and enrols the carol it knows: an untagged epoch,
	// written after the new incarnation.
	if err := InsertUser2FA(ctx, l, User2FARecord{Username: "carol", Method: "totp", Secret: "s-l", Label: "phone"}); err != nil {
		t.Fatal(err)
	}
	lOn = true
	aeBoth(t, a, l)
	// Kept, and since round 5 held, not active (user_held_factor_test.go).
	if fs, err := ListHeldUser2FA(ctx, l, "carol"); err != nil || len(fs) != 1 || fs[0].Secret != "s-l" {
		t.Errorf("l: carol's held factors = %+v (err %v): an untagged factor was dropped by clock", fs, err)
	}
	if n := liveFactorRows(t, l, "carol"); n != 1 {
		t.Errorf("l: live factor rows = %d, want 1", n)
	}
}

// Review L1 (mutation F of round 4): a lifecycle row written to the deleted
// name (a re-create's reset, tagged after:) is the successor's, and survives
// the retirement even when it was stamped after the new incarnation: here a
// lagging node resets the name it sees deleted after the re-create was made
// elsewhere, over the deleted account's disable. Dropped, the disable comes
// back from the re-creator and the reset is lost cluster-wide.
//
// Green on 0bef41048 (a pin). Mutation: after:-tagged rows dropped like
// inc:-tagged ones — red.
func TestUserIncarnation_ASuccessorsResetSurvivesTheRetirement(t *testing.T) {
	ctx := context.Background()
	g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
	a, l := newTestDB(t), newTestDB(t)
	for _, c := range []*Client{a, l} {
		c.SetUserIncarnationGate(func() bool { return true })
		c.SetCredentialsSplitGate(func() bool { return true })
	}
	yes := true
	if err := InsertUser(ctx, a, "carol", "operator", "hash-old"); err != nil {
		t.Fatal(err)
	}
	if err := SetUserLifecycle(ctx, a, g, "carol", &yes, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteUser(ctx, a, "carol"); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, a, l)
	if err := InsertUser(ctx, a, "carol", "operator", "hash-new"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := ResetUserLifecycle(ctx, l, g, "carol", "admin"); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, a, l) // l adopts the re-create
	aeBoth(t, l, a)
	for _, n := range []struct {
		name string
		c    *Client
	}{{"a", a}, {"l", l}} {
		if lc, err := GetUserLifecycle(ctx, n.c, "carol"); err != nil || lc.Disabled {
			t.Errorf("%s: the re-created carol is disabled (err %v): the reset written to the deleted name was retired", n.name, err)
		}
	}
}

// A lagging factor tagged with an older incarnation that a node took before
// it held any row of the name goes when the name's first row lands there:
// that is an incarnation change too.
//
// Mutation: retirement only on a re-create over an older row (not from no
// row) — red.
func TestUserIncarnation_ALaggingFactorHeardBeforeAnyRowIsRetired(t *testing.T) {
	ctx := context.Background()
	a, l, n := newTestDB(t), newTestDB(t), newTestDB(t)
	for _, c := range []*Client{a, l, n} {
		c.SetUserIncarnationGate(func() bool { return true })
		c.SetCredentialsSplitGate(func() bool { return true })
	}
	if err := InsertUser(ctx, a, "carol", "operator", "hash-old"); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, a, l)
	if err := DeleteUser(ctx, a, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, a, "carol", "operator", "hash-new"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser2FA(ctx, a, User2FARecord{Username: "carol", Method: "totp", Secret: "s-new", Label: "phone"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := InsertUser2FA(ctx, l, User2FARecord{Username: "carol", Method: "totp", Secret: "s-lag", Label: "phone"}); err != nil {
		t.Fatal(err)
	}
	// n holds no carol yet: it takes l's sensitive rows alone, then a's.
	if err := n.MergeSensitiveStateBytesLWW(l.DumpSensitiveStateBytes()); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, a, n)
	if fs, err := ListUser2FA(ctx, n, "carol"); err != nil || len(fs) != 1 || fs[0].Secret != "s-new" {
		t.Errorf("n: carol's factors = %+v (err %v), want the new carol's s-new", fs, err)
	}
}

// Review L2 of round 4: a set_by that already holds a tag-like suffix does
// not decide the row's tag. An actor name ending "\x1fafter:…" would otherwise
// pass a lagging expiry extension off as a successor's reset.
//
// Red on 0bef41048: the lagging extension survives. Mutation: the existing
// suffix trusted — red.
func TestUserIncarnation_ASetByCannotForgeItsTag(t *testing.T) {
	ctx := context.Background()
	g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
	a, l := newTestDB(t), newTestDB(t)
	for _, c := range []*Client{a, l} {
		c.SetUserIncarnationGate(func() bool { return true })
		c.SetCredentialsSplitGate(func() bool { return true })
	}
	if err := InsertUser(ctx, a, "carol", "operator", "hash-old"); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, a, l)
	if err := DeleteUser(ctx, a, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, a, "carol", "operator", "hash-new"); err != nil {
		t.Fatal(err)
	}
	soon := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	far := time.Now().Add(480 * time.Hour).UTC().Format(time.RFC3339)
	if err := SetUserLifecycle(ctx, a, g, "carol", nil, &soon, "admin"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	forged := "admin" + userLifecycleTagSep + userTagDeleted + ":2000-01-01T00:00:00Z"
	if err := SetUserLifecycle(ctx, l, g, "carol", nil, &far, forged); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, a, l)
	aeBoth(t, l, a)
	for _, n := range []struct {
		name string
		c    *Client
	}{{"a", a}, {"l", l}} {
		if lc, err := GetUserLifecycle(ctx, n.c, "carol"); err != nil || lc.ExpiresAt != soon {
			t.Errorf("%s: the new carol's expiry = %q (err %v), want %q", n.name, lc.ExpiresAt, err, soon)
		}
	}
}

// m3, kept (R4-4): a disabled account that is deleted and re-created with no
// lifecycle reset stays disabled on a node that adopts the re-create by
// anti-entropy, including after a later users write there.
func TestUserIncarnation_ADeletedDisabledAccountStaysDisabled(t *testing.T) {
	ctx := context.Background()
	a, b := newTestDB(t), newTestDB(t)
	for _, c := range []*Client{a, b} {
		c.SetUserIncarnationGate(func() bool { return true })
		c.SetCredentialsSplitGate(func() bool { return true })
	}
	g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
	yes := true
	if err := InsertUser(ctx, a, "carol", "operator", "hash-1"); err != nil {
		t.Fatal(err)
	}
	if err := SetUserLifecycle(ctx, a, g, "carol", &yes, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := b.MergeStateBytesLWW(a.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	if err := DeleteUser(ctx, a, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, a, "carol", "operator", "hash-2"); err != nil {
		t.Fatal(err)
	}
	if err := b.MergeStateBytesLWW(a.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	if err := UpdateUserPassword(ctx, b, "carol", "hash-3"); err != nil {
		t.Fatal(err)
	}
	for _, n := range []struct {
		name string
		c    *Client
	}{{"a", a}, {"b", b}} {
		if l, err := GetUserLifecycle(ctx, n.c, "carol"); err != nil || !l.Disabled {
			t.Errorf("%s: the re-created carol is enabled (err %v)", n.name, err)
		}
	}
}

// Ruling 1 of round 4: retirement runs only when the name's incarnation
// changes. A pre-latch enable (untagged, written after the account was
// made) is the account's own: an ordinary users write after the latch must
// not drop it, or a peer that only has the disable it replaced re-disables
// the account here.
//
// Red on 0bef41048. Mutations: retirement run on every users write — red on
// b and d; the anti-entropy path's prior incarnation lost — red on b and d.
func TestUserIncarnation_APreLatchEnableSurvivesAnOrdinaryUsersWrite(t *testing.T) {
	ctx := context.Background()
	g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
	a, b, c, d := newTestDB(t), newTestDB(t), newTestDB(t), newTestDB(t)
	on := false
	for _, n := range []*Client{a, b, c, d} {
		n.SetUserIncarnationGate(func() bool { return on })
		n.SetCredentialsSplitGate(func() bool { return true })
	}
	yes, no := true, false
	if err := InsertUser(ctx, a, "carol", "operator", "hash-1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err := SetUserLifecycle(ctx, a, g, "carol", &yes, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, a, c) // c lags with the disable
	time.Sleep(10 * time.Millisecond)
	if err := SetUserLifecycle(ctx, a, g, "carol", &no, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, a, b)
	aeBoth(t, a, d)
	on = true
	if err := UpdateUserPassword(ctx, b, "carol", "hash-2"); err != nil {
		t.Fatal(err)
	}
	// The lagging c changes the password too, and d takes that users row by
	// anti-entropy, together with c's disable, which is older than d's
	// enable.
	if err := UpdateUserPassword(ctx, c, "carol", "hash-3"); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, c, d)
	aeBoth(t, c, b)
	for _, n := range []struct {
		name string
		c    *Client
	}{{"b (wrote it)", b}, {"d (pulled it)", d}} {
		if lc, err := GetUserLifecycle(ctx, n.c, "carol"); err != nil || lc.Disabled {
			t.Errorf("%s: carol is disabled after a password change and a pull from a lagging peer (err %v): her enable was retired", n.name, err)
		}
	}
}

// Re-review 5, L1: ruling 1 on the two paths APreLatchEnable does not
// reach. e takes the lagging c's password change over the WAL, and f writes
// its own through ExecuteBatchGuarded (ExecuteEntriesGuarded); each then
// pulls c's older disable, and neither has retired its pre-latch enable.
//
// Mutations: the WAL path's prior incarnation lost (replicator.go) — red on
// e; ExecuteEntriesGuarded's lost (client.go) — red on f.
func TestUserIncarnation_APreLatchEnableSurvivesWALAndGuardedUsersWrites(t *testing.T) {
	ctx := context.Background()
	g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
	a, c, e, f := newTestDB(t), newTestDB(t), newTestDB(t), newTestDB(t)
	on := false
	for _, n := range []*Client{a, c, e, f} {
		n.SetUserIncarnationGate(func() bool { return on })
		n.SetCredentialsSplitGate(func() bool { return true })
	}
	re := NewReplicator(e, "", RelayConfig{})
	yes, no := true, false
	if err := InsertUser(ctx, a, "carol", "operator", "hash-1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err := SetUserLifecycle(ctx, a, g, "carol", &yes, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, a, c) // c lags with the disable
	time.Sleep(10 * time.Millisecond)
	if err := SetUserLifecycle(ctx, a, g, "carol", &no, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, a, e)
	aeBoth(t, a, f)
	on = true
	if err := UpdateUserPassword(ctx, c, "carol", "hash-3"); err != nil {
		t.Fatal(err)
	}
	applyWAL(t, re, walEntries(t, c, "node-c"))
	if u, _ := GetUser(ctx, e, "carol"); u == nil || u.PasswordHash != "hash-3" {
		t.Fatalf("fixture: e did not apply c's password change over the WAL: %+v", u)
	}
	stmts, err := updateUserPasswordStatements(ctx, f, "carol", "hash-4", f.NowTS())
	if err != nil || len(stmts) == 0 {
		t.Fatalf("password statements: %v (%d)", err, len(stmts))
	}
	if ok, err := f.ExecuteBatchGuarded(ctx, func(*sql.Tx) (bool, error) { return true, nil }, stmts); err != nil || !ok {
		t.Fatalf("guarded password change: %v %v", ok, err)
	}
	for _, n := range []struct {
		name string
		c    *Client
	}{{"e (over the WAL)", e}, {"f (guarded)", f}} {
		if err := n.c.MergeStateBytesLWW(c.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
		if lc, err := GetUserLifecycle(ctx, n.c, "carol"); err != nil || lc.Disabled {
			t.Errorf("%s: carol is disabled after a users write and a pull from a lagging peer (err %v): her enable was retired", n.name, err)
		}
	}
}
