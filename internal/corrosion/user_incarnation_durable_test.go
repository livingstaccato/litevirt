package corrosion

// Re-review 3 (uinc-r3-review.md): the protection against an old
// incarnation's rows attaching to a new account is durable.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
)

// Review H1 (R3-1): a lagging node's own writes to a deleted account, once their
// records are gone (a restart, or a partition longer than userTightenTTL),
// survive the re-create there and reach the new account everywhere by
// anti-entropy:
//   - a factor re-enrolment (same method/label) replaces the new account's
//     factor: the new holder is locked out of her second factor, cluster-wide;
//   - an expiry extension beats the new account's own earlier expiry: the new
//     account outlives its expiry, cluster-wide.
//
// Subtest "records kept" is the control (no restart). Red on 3859a834c for
// "restart" and "partition longer than the record TTL"; green now, because
// retireLaggingLifts judges the rows by the incarnation their epoch and
// set_by carry, whatever is in memory.
//
// Mutations: retireLaggingLifts a no-op — red; the lifecycle row untagged
// (tagUserLifecycle) — the expiry red. The epoch untagged (InsertUser2FA)
// leaves this green — an untagged factor written after the new incarnation
// goes by clock — and turns the new account's own early factor red instead
// (TestFleet_AFactorPulledBeforeItsUsersRowIsKept and its siblings).
func TestUserIncarnation_ALaggingFactorAndExtensionAreRetiredDurably(t *testing.T) {
	for _, tc := range []struct {
		name   string
		forget func(c *Client)
	}{
		{"records kept", func(c *Client) {}},
		{"restart", func(c *Client) { c.userHolds = userHolds{} }},
		{"partition longer than the record TTL", func(c *Client) {
			c.userHolds.mu.Lock()
			c.userHolds.now = func() time.Time { return time.Now().Add(userTightenTTL + time.Minute) }
			c.userHolds.mu.Unlock()
			c.userHolds.mu.Lock()
			c.userHolds.expireLocked()
			c.userHolds.mu.Unlock()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
			a, l := newTestDB(t), newTestDB(t)
			for _, c := range []*Client{a, l} {
				c.SetUserIncarnationGate(func() bool { return true })
				c.SetCredentialsSplitGate(func() bool { return true })
			}
			ae := func(from, to *Client) {
				t.Helper()
				if err := to.MergeStateBytesLWW(from.DumpStateBytes()); err != nil {
					t.Fatal(err)
				}
				if err := to.MergeSensitiveStateBytesLWW(from.DumpSensitiveStateBytes()); err != nil {
					t.Fatal(err)
				}
			}
			if err := InsertUser(ctx, a, "carol", "operator", "hash-old"); err != nil {
				t.Fatal(err)
			}
			ae(a, l)
			// node a deletes and re-creates carol; the new carol enrols a
			// factor and is given an expiry. l lags.
			if err := DeleteUser(ctx, a, "carol"); err != nil {
				t.Fatal(err)
			}
			if err := InsertUser(ctx, a, "carol", "operator", "hash-new"); err != nil {
				t.Fatal(err)
			}
			if err := InsertUser2FA(ctx, a, User2FARecord{Username: "carol", Method: "totp", Secret: "s-new", Label: "phone"}); err != nil {
				t.Fatal(err)
			}
			soon := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
			far := time.Now().Add(480 * time.Hour).UTC().Format(time.RFC3339)
			if err := SetUserLifecycle(ctx, a, g, "carol", nil, &soon, "admin"); err != nil {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Millisecond)
			// l, lagging, writes to the carol it knows (the deleted one).
			if err := InsertUser2FA(ctx, l, User2FARecord{Username: "carol", Method: "totp", Secret: "s-lag", Label: "phone"}); err != nil {
				t.Fatal(err)
			}
			if err := SetUserLifecycle(ctx, l, g, "carol", nil, &far, "admin"); err != nil {
				t.Fatal(err)
			}
			tc.forget(l)
			ae(a, l) // l learns the re-create by anti-entropy
			ae(l, a) // and a pulls from l
			for _, n := range []struct {
				name string
				c    *Client
			}{{"a", a}, {"l", l}} {
				if u, err := GetUser(ctx, n.c, "carol"); err != nil || u == nil || u.PasswordHash != "hash-new" {
					t.Fatalf("%s: carol = %+v (%v)", n.name, u, err)
				}
				fs, err := ListUser2FA(ctx, n.c, "carol")
				if err != nil || len(fs) != 1 || fs[0].Secret != "s-new" {
					t.Errorf("%s: the new carol's factors = %+v (err %v), want s-new", n.name, fs, err)
				}
				lc, err := GetUserLifecycle(ctx, n.c, "carol")
				if err != nil || lc.ExpiresAt != soon {
					t.Errorf("%s: the new carol's expiry = %q (err %v), want %q", n.name, lc.ExpiresAt, err, soon)
				}
			}
		})
	}
}

// A tightening its writer judged against its own value, heard ahead of its
// incarnation, waits like a lift when it would loosen what this node holds:
// an expiry later than the one here does not shorten nothing into something
// longer (re-review 3, L2).
//
// Mutation: loosensHere always false — red.
func TestUserHolds_ATighteningThatLoosensHereWaits(t *testing.T) {
	ctx := context.Background()
	g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
	c := newTestDB(t)
	c.SetUserIncarnationGate(func() bool { return true })
	if err := InsertUser(ctx, c, "carol", "operator", "h"); err != nil {
		t.Fatal(err)
	}
	early := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	later := time.Now().Add(240 * time.Hour).UTC().Format(time.RFC3339)
	if err := SetUserLifecycle(ctx, c, g, "carol", nil, &early, "admin"); err != nil {
		t.Fatal(err)
	}
	u, _ := GetUser(ctx, c, "carol")
	newer := nextIncarnation(u.CreatedAt)
	b, _ := json.Marshal([]Statement{{SQL: userLifecycleUpsertSQL,
		Params: []interface{}{"carol", UserAttrExpiresAt, later, "admin", c.NowTS()},
		Guard:  &MutationGuard{Protocol: userIncarnationGuardV1, ResourceKind: userGuardTighten, ResourceID: "carol", Incarnation: newer}}})
	r := NewReplicator(c, "", RelayConfig{})
	if _, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: 1, Hlc: c.NowTS(), Origin: "node-1", Stmts: string(b)}}); err != nil {
		t.Fatal(err)
	}
	lc, err := GetUserLifecycle(ctx, c, "carol")
	if err != nil || lc.ExpiresAt != early {
		t.Errorf("expiry = %q (err %v), want %q kept until the newer carol lands", lc.ExpiresAt, err, early)
	}
	if c.UserHolds() == 0 {
		t.Errorf("the later expiry was not held")
	}
}

// The guard kinds are a wire contract nothing ledgers: a build that does not
// know one refuses the entry (re-review 3, L3). A new kind is a deliberate
// change — and builds from ec450cda6 to 27d2a1990 already refuse
// user_tighten, which is safe only while user_incarnation_v1 is unreleased.
func TestUserGuardKinds_AreTheKnownOnes(t *testing.T) {
	for _, k := range []string{userGuardLive, userGuardDeleted, userGuardAny, userGuardTighten} {
		if !validUserGuardKind(k) {
			t.Errorf("%q refused", k)
		}
	}
	for _, k := range []string{"", "user_tighten-held", "users", "user_live "} {
		if validUserGuardKind(k) {
			t.Errorf("%q accepted", k)
		}
	}
}

// A held grant that is given up — its account never reached this node in
// time, or the hold is full — is said so, naming the account: a login session
// it carried is not repaired by anti-entropy (re-review 3, L1).
//
// Mutation: warnHeldDropped a no-op — red.
func TestUserHolds_AGivenUpHoldIsLogged(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	var h userHolds
	h.hold("carol", userHeldWrite{guard: MutationGuard{Incarnation: "x"},
		stmts: []Statement{{SQL: sessionsInsertSQL, Params: []interface{}{"s", "carol", "local", "", "", "", "", ""}}}})
	h.mu.Lock()
	h.now = func() time.Time { return time.Now().Add(userHeldTTL + time.Minute) }
	h.expireLocked()
	h.mu.Unlock()
	if !strings.Contains(buf.String(), "gave up a user write") || !strings.Contains(buf.String(), "user=carol") {
		t.Errorf("no warning for the given-up hold: %q", buf.String())
	}
}
