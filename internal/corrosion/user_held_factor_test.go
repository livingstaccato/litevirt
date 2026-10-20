package corrosion

// Re-review 5, M1: an untagged factor set on a name whose incarnation a node
// sees change is HELD there: kept, never accepted, and the account fails
// closed until an admin removes it.

import (
	"context"
	"testing"
)

// heldFixture: a (latched) deletes and re-creates carol while u, lagging and
// not latched, enrols the "old-phone" factor for the carol it knows. u then
// latches and adopts the re-create, and a pulls from u.
func heldFixture(t *testing.T) (a, u *Client) {
	t.Helper()
	ctx := context.Background()
	a, u = newTestDB(t), newTestDB(t)
	uOn := false
	a.SetUserIncarnationGate(func() bool { return true })
	u.SetUserIncarnationGate(func() bool { return uOn })
	for _, c := range []*Client{a, u} {
		c.SetCredentialsSplitGate(func() bool { return true })
	}
	if err := InsertUser(ctx, a, "carol", "operator", "hash-old"); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, a, u)
	if err := DeleteUser(ctx, a, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, a, "carol", "operator", "hash-new"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser2FA(ctx, u, User2FARecord{Username: "carol", Method: "totp", Secret: "s-old", Label: "old-phone"}); err != nil {
		t.Fatal(err)
	}
	uOn = true
	aeBoth(t, a, u)
	aeBoth(t, u, a)
	return a, u
}

func liveFactorRows(t *testing.T, c *Client, user string) int {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT COUNT(*) AS n FROM user_2fa WHERE username = ? AND deleted_at IS NULL`, user)
	if err != nil {
		t.Fatal(err)
	}
	return int(rows[0].Int("n"))
}

// The node that saw the re-create holds the set, and the node that pulls
// from it takes the hold: on both, the factor is kept, not in the active set,
// listed as held, and the account is named.
//
// Red on 0476319bb: the factor is active on both. Mutation: no hold — red.
func TestHeldFactor_ARecreateHoldsAnUntaggedSet(t *testing.T) {
	ctx := context.Background()
	a, u := heldFixture(t)
	for _, n := range []struct {
		name string
		c    *Client
	}{{"u (saw the re-create)", u}, {"a (pulled it)", a}} {
		if fs, err := ListUser2FA(ctx, n.c, "carol"); err != nil || len(fs) != 0 {
			t.Errorf("%s: active factors = %+v (err %v), want none", n.name, fs, err)
		}
		if fs, err := ListHeldUser2FA(ctx, n.c, "carol"); err != nil || len(fs) != 1 || fs[0].Label != "old-phone" {
			t.Errorf("%s: held factors = %+v (err %v), want old-phone", n.name, fs, err)
		}
		if names, err := HeldSecondFactorAccounts(ctx, n.c); err != nil || len(names) != 1 || names[0] != "carol" {
			t.Errorf("%s: accounts with held factors = %v (err %v), want [carol]", n.name, names, err)
		}
	}
}

// The new holder's enrolment starts a fresh set: her factor is the only
// active one, and the held factor stays stored.
//
// Mutation: InsertUser2FA reuses a held epoch — red.
func TestHeldFactor_ANewEnrolmentReplacesTheHeldSet(t *testing.T) {
	ctx := context.Background()
	a, _ := heldFixture(t)
	if err := InsertUser2FA(ctx, a, User2FARecord{Username: "carol", Method: "totp", Secret: "s-new", Label: "phone"}); err != nil {
		t.Fatal(err)
	}
	if fs, err := ListUser2FA(ctx, a, "carol"); err != nil || len(fs) != 1 || fs[0].Secret != "s-new" {
		t.Errorf("active factors = %+v (err %v), want only s-new", fs, err)
	}
	if n := liveFactorRows(t, a, "carol"); n != 2 {
		t.Errorf("live factor rows = %d, want 2 (the held one is kept)", n)
	}
	// Her set is her own: tagged with her incarnation, so a later re-create
	// of the name tells it apart (retireLaggingLifts).
	epoch, _, _ := activeUser2FAEpoch(ctx, a, "carol")
	u, _ := GetUser(ctx, a, "carol")
	if tag, ok := userEpochTag(epoch); !ok || u == nil || tag != u.CreatedAt {
		t.Errorf("her active epoch = %q, want one tagged with her incarnation", epoch)
	}
}

// Removing one held factor keeps the others held: the set is retired only
// with the last, so the account never reads as having no second factor
// while one is still held.
//
// Mutation: DeleteUser2FA always retires the set — red.
func TestHeldFactor_RemovingOneKeepsTheOthersHeld(t *testing.T) {
	ctx := context.Background()
	a, u := newTestDB(t), newTestDB(t)
	uOn := false
	a.SetUserIncarnationGate(func() bool { return true })
	u.SetUserIncarnationGate(func() bool { return uOn })
	for _, c := range []*Client{a, u} {
		c.SetCredentialsSplitGate(func() bool { return true })
	}
	if err := InsertUser(ctx, a, "carol", "operator", "hash-old"); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, a, u)
	if err := DeleteUser(ctx, a, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, a, "carol", "operator", "hash-new"); err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"one", "two"} {
		if err := InsertUser2FA(ctx, u, User2FARecord{Username: "carol", Method: "totp", Secret: "s-" + l, Label: l}); err != nil {
			t.Fatal(err)
		}
	}
	uOn = true
	aeBoth(t, a, u)
	if fs, _ := ListHeldUser2FA(ctx, u, "carol"); len(fs) != 2 {
		t.Fatalf("fixture: held %+v", fs)
	}
	if err := DeleteUser2FA(ctx, u, "carol", "totp", "one"); err != nil {
		t.Fatal(err)
	}
	if fs, err := ListHeldUser2FA(ctx, u, "carol"); err != nil || len(fs) != 1 || fs[0].Label != "two" {
		t.Errorf("after removing one: held = %+v (err %v), want two", fs, err)
	}
	if err := DeleteUser2FA(ctx, u, "carol", "totp", "two"); err != nil {
		t.Fatal(err)
	}
	if fs, _ := ListHeldUser2FA(ctx, u, "carol"); len(fs) != 0 {
		t.Errorf("after removing both: held = %+v", fs)
	}
	if _, live, _ := activeUser2FAEpoch(ctx, u, "carol"); live {
		t.Error("the held set outlived its last factor")
	}
}

// A name's FIRST row here is not an incarnation change that holds: a node
// that pulls a pre-latch account's factor before the account keeps it
// active.
//
// Mutation: hold on a first row too — red.
func TestHeldFactor_AFirstRowHoldsNothing(t *testing.T) {
	ctx := context.Background()
	a, n := newTestDB(t), newTestDB(t)
	on := false
	for _, c := range []*Client{a, n} {
		c.SetUserIncarnationGate(func() bool { return on })
		c.SetCredentialsSplitGate(func() bool { return true })
	}
	if err := InsertUser(ctx, a, "carol", "operator", "hash-1"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser2FA(ctx, a, User2FARecord{Username: "carol", Method: "totp", Secret: "s-1", Label: "phone"}); err != nil {
		t.Fatal(err)
	}
	on = true
	if err := n.MergeSensitiveStateBytesLWW(a.DumpSensitiveStateBytes()); err != nil {
		t.Fatal(err)
	}
	if err := n.MergeStateBytesLWW(a.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	if fs, err := ListUser2FA(ctx, n, "carol"); err != nil || len(fs) != 1 {
		t.Errorf("n: active factors = %+v (err %v), want the pre-latch factor", fs, err)
	}
}

// The hold orders just after the set it holds, not at the holder's clock:
// a set the new account wrote later still wins, on the holder and on the
// node it reaches.
//
// Mutation: the hold stamped with the holder's clock — red.
func TestHeldFactor_TheHoldDoesNotBeatALaterSet(t *testing.T) {
	ctx := context.Background()
	a, u := newTestDB(t), newTestDB(t)
	uOn := false
	a.SetUserIncarnationGate(func() bool { return true })
	u.SetUserIncarnationGate(func() bool { return uOn })
	for _, c := range []*Client{a, u} {
		c.SetCredentialsSplitGate(func() bool { return true })
	}
	if err := InsertUser(ctx, a, "carol", "operator", "hash-old"); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, a, u)
	if err := DeleteUser(ctx, a, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, a, "carol", "operator", "hash-new"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser2FA(ctx, u, User2FARecord{Username: "carol", Method: "totp", Secret: "s-old", Label: "old-phone"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser2FA(ctx, a, User2FARecord{Username: "carol", Method: "totp", Secret: "s-new", Label: "phone"}); err != nil {
		t.Fatal(err)
	}
	uOn = true
	aeBoth(t, a, u) // u holds its set, then takes a's later one
	aeBoth(t, u, a)
	for _, n := range []struct {
		name string
		c    *Client
	}{{"a", a}, {"u", u}} {
		if fs, err := ListUser2FA(ctx, n.c, "carol"); err != nil || len(fs) != 1 || fs[0].Secret != "s-new" {
			t.Errorf("%s: active factors = %+v (err %v), want the new carol's s-new", n.name, fs, err)
		}
	}
}

// The admin floor's question: an admin whose only factors are held cannot
// log in. With no other admin the condition is raised and names the
// recovery; another admin keeps the cluster loggable.
func TestHeldFactor_AnAdminWithOnlyHeldFactorsIsNotLoggable(t *testing.T) {
	ctx := context.Background()
	a, u := newTestDB(t), newTestDB(t)
	uOn := false
	a.SetUserIncarnationGate(func() bool { return true })
	u.SetUserIncarnationGate(func() bool { return uOn })
	for _, c := range []*Client{a, u} {
		c.SetCredentialsSplitGate(func() bool { return true })
	}
	if err := InsertUser(ctx, a, "boss", "admin", "hash-old"); err != nil {
		t.Fatal(err)
	}
	aeBoth(t, a, u)
	if err := DeleteUser(ctx, a, "boss"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, a, "boss", "admin", "hash-new"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser2FA(ctx, u, User2FARecord{Username: "boss", Method: "totp", Secret: "s-old", Label: "old-phone"}); err != nil {
		t.Fatal(err)
	}
	uOn = true
	aeBoth(t, a, u)
	rep, err := AdminLoginState(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Loggable || len(rep.HeldSecondFactor) != 1 || rep.HeldSecondFactor[0] != "boss" {
		t.Errorf("report = %+v, want not loggable, naming boss as held", rep)
	}
	if ok, err := UsableAdminExists(ctx, u); err != nil || !ok {
		t.Errorf("UsableAdminExists = %v (err %v): the floor would reinstate a deleted admin beside boss", ok, err)
	}
	if err := InsertUser(ctx, u, "ops", "admin", "hash-ops"); err != nil {
		t.Fatal(err)
	}
	if rep, err := AdminLoginState(ctx, u); err != nil || !rep.Loggable {
		t.Errorf("with another admin: report = %+v (err %v), want loggable", rep, err)
	}
}
