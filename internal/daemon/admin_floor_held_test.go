package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// heldAdminDB is a replica on which the only admin, boss, was re-created
// while a node that had not latched user_incarnation_v1 enrolled a factor for
// the deleted boss: that factor is held, so boss cannot log in.
func heldAdminDB(t *testing.T) *corrosion.Client {
	t.Helper()
	ctx := context.Background()
	a, u := corrosion.NewTestClientT(t), corrosion.NewTestClientT(t)
	uOn := false
	a.SetUserIncarnationGate(func() bool { return true })
	u.SetUserIncarnationGate(func() bool { return uOn })
	for _, c := range []*corrosion.Client{a, u} {
		if err := corrosion.InitSchema(ctx, c); err != nil {
			t.Fatal(err)
		}
		c.SetCredentialsSplitGate(func() bool { return true })
	}
	sync := func(from, to *corrosion.Client) {
		t.Helper()
		if err := to.MergeStateBytesLWW(from.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
		if err := to.MergeSensitiveStateBytesLWW(from.DumpSensitiveStateBytes()); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertUser(ctx, a, "boss", "admin", "hash-old"); err != nil {
		t.Fatal(err)
	}
	sync(a, u)
	if err := corrosion.DeleteUser(ctx, a, "boss"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, a, "boss", "admin", "hash-new"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser2FA(ctx, u, corrosion.User2FARecord{Username: "boss", Method: "totp", Secret: "s-old", Label: "old-phone"}); err != nil {
		t.Fatal(err)
	}
	uOn = true
	sync(a, u)
	u.MarkReplicaCaughtUpForTests("peer")
	if held, _ := corrosion.ListHeldUser2FA(ctx, u, "boss"); len(held) != 1 {
		t.Fatalf("fixture: boss's held factors = %+v", held)
	}
	return u
}

func condition(t *testing.T, d *Daemon, code string) (bool, string) {
	t.Helper()
	row, found, err := corrosion.GetHealthCondition(context.Background(), d.db, adminFloorEvaluator, code, "host", d.cfg.HostName)
	if err != nil {
		t.Fatal(err)
	}
	return found && row.Lifecycle == corrosion.ConditionConfirmed, row.Evidence
}

// Re-review 5: an admin whose only factor is held never leaves the cluster
// with no recoverable admin. The floor reinstates nothing beside it; both
// conditions name the account and its recovery; and either recovery — the
// break-glass reset as root, or another admin removing the held factor —
// gives the cluster a usable admin and resolves them.
//
// Mutations: AdminLoginState counting a held-only admin as loggable — red
// ("no_unrestricted_admin open"); the held condition never raised — red.
func TestAdminFloor_AHeldOnlyAdminIsRecoverable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		recover func(t *testing.T, db *corrosion.Client)
	}{
		{"break-glass: lv user reset-admin --user boss --clear-2fa", func(t *testing.T, db *corrosion.Client) {
			run := func(ctx context.Context, write func(context.Context, capabilities.FeatureGrant) error) error {
				return write(ctx, capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy))
			}
			if err := corrosion.ResetAdminPasswordFor(context.Background(), db, run, "boss", "hash-reset", true); err != nil {
				t.Fatal(err)
			}
		}},
		{"another admin: lv 2fa disable --user boss", func(t *testing.T, db *corrosion.Client) {
			if err := corrosion.InsertUser(context.Background(), db, "ops", "admin", "hash-ops"); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.DeleteUser2FA(context.Background(), db, "boss", "totp", "old-phone"); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := heldAdminDB(t)
			d := &Daemon{cfg: &Config{HostName: "node-0"}, db: db}
			d.checkAdminFloor(ctx, 0)
			d.checkAdminFloor(ctx, 0)
			if users, _ := corrosion.ListUsers(ctx, db); len(users) != 1 {
				t.Errorf("the floor changed the accounts beside a held-only admin: %+v", users)
			}
			open, ev := condition(t, d, CondNoUnrestrictedAdmin)
			for _, want := range []string{"lv user reset-admin --user boss --clear-2fa", "lv 2fa disable --user boss --method totp", "lv 2fa enroll-code boss"} {
				if !open || !strings.Contains(ev, want) {
					t.Errorf("no_unrestricted_admin open=%v evidence=%s; want it open, naming %q", open, ev, want)
				}
			}
			if open, ev := condition(t, d, CondHeldSecondFactor); !open || !strings.Contains(ev, "boss") || !strings.Contains(ev, "lv 2fa enroll-code boss") {
				t.Errorf("held_second_factor open=%v evidence=%s; want it open, naming boss and the recovery", open, ev)
			}
			tc.recover(t, db)
			d.checkAdminFloor(ctx, 0)
			if open, ev := condition(t, d, CondNoUnrestrictedAdmin); open {
				t.Errorf("after the recovery no_unrestricted_admin is still open: %s", ev)
			}
			if open, ev := condition(t, d, CondHeldSecondFactor); open {
				t.Errorf("after the recovery held_second_factor is still open: %s", ev)
			}
		})
	}
}
