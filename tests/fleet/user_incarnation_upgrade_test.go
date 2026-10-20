package fleet

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Re-review 4, C1: a cluster with TOTP users enrolled before the upgrade
// rolls through the user_incarnation_v1 latch, then sees ordinary writes —
// a password change, an unrelated account added, another user's password
// change on the node that latched last, and an anti-entropy round. Every
// account keeps its second factor on every node.
//
// Red on 0bef41048: the factors are gone on every node after the first
// users write. That needs both of its faults: retirement on every users
// write AND the untagged clock rule. Each alone is pinned by a unit test
// (TestUserIncarnation_APreLatchEnableSurvivesAnOrdinaryUsersWrite,
// TestUserIncarnation_AnUntaggedFactorIsNotDroppedOnARecreate).
func TestFleet_PreLatchFactorsSurviveTheUpgradeAndOrdinaryWrites(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 7741})
	var held atomic.Bool
	held.Store(true)
	latchUserIncarnation(t, c, c.Nodes[2], &held) // node-2 on the previous build
	for _, n := range c.Nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
	}
	want := map[string]string{"carol": "s-carol", "erin": "s-erin"}
	for _, u := range []string{"carol", "erin"} {
		if err := corrosion.InsertUser(ctx, c.Nodes[0].DB, u, "operator", "hash-"+u); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(1100 * time.Millisecond) // a pre-latch created_at is a bare second
	c.WaitConverged(t, convergeTimeout)
	for i, u := range []string{"carol", "erin"} {
		if err := corrosion.InsertUser2FA(ctx, c.Nodes[i].DB, corrosion.User2FARecord{
			Username: u, Method: "totp", Secret: want[u], Label: "phone"}); err != nil {
			t.Fatal(err)
		}
	}
	drainAndExchange(t, c)
	check := func(when string) {
		t.Helper()
		for _, n := range c.Nodes {
			for u, secret := range want {
				fs, err := corrosion.ListUser2FA(ctx, n.DB, u)
				if err != nil || len(fs) != 1 || fs[0].Secret != secret {
					t.Errorf("%s, %s: %s's factors = %+v (err %v), want %s: a password-only login", when, n.Name, u, fs, err, secret)
				}
			}
		}
	}
	check("before the latch")

	held.Store(false) // node-2 is upgraded
	latchUserIncarnation(t, c, nil, nil)
	if err := corrosion.UpdateUserPassword(ctx, c.Nodes[1].DB, "carol", "hash-carol-2"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, c.Nodes[0].DB, "dave", "viewer", "hash-dave"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateUserPassword(ctx, c.Nodes[2].DB, "erin", "hash-erin-2"); err != nil {
		t.Fatal(err)
	}
	drainAndExchange(t, c)
	check("after ordinary writes and anti-entropy")
	for _, n := range c.Nodes {
		corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
	}
	check("after a real anti-entropy round")
}
