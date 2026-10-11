package health

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// login-fu review Minor 1: a plain reset-admin of an admin whose cut-off is
// dated in the future asks the real login_policy gate only to correct that
// cut-off. With a used record present but not acknowledged here and a
// recipient that never answers, the gate's first-use wait (here 10 s) must
// neither delay the reset past a few seconds nor make it fail when the CLI's
// own deadline cancels the call: the password is reset, the cut-off is left,
// and the note says so.
func TestResetAdmin_ForwardCutoffNeverWaitsOnAnUnackedGate(t *testing.T) {
	for _, c := range []struct {
		name     string
		deadline time.Duration // the CLI's deadline on the call
	}{
		{"CLI deadline longer than the bound", 20 * time.Second},
		{"CLI deadline shorter than the bound", 1500 * time.Millisecond},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newRelEnv(t)
			t.Cleanup(capabilities.OverrideFeaturesForTest(map[capabilities.Feature]capabilities.FeatureInfo{
				capabilities.FeatureLoginPolicy: {Token: capabilities.ReleaseToken, Description: "login rules"},
			}))
			releaseAckTimeout = 10 * time.Second // restored by newRelEnv's cleanup
			// host-b is unreachable: every acknowledgement request hangs until
			// its context ends.
			e.c.SetReleaseUseConfirmer(func(ctx context.Context, _, _, _ string) (bool, error) {
				<-ctx.Done()
				return false, ctx.Err()
			})
			ctx := context.Background()
			// A peer's first use, recorded but not acknowledged here.
			if err := corrosion.RecordReleaseFeatureUse(ctx, e.db, capabilities.ReleaseToken,
				string(capabilities.FeatureLoginPolicy), "host-b", false); err != nil {
				t.Fatal(err)
			}
			old, _ := bcrypt.GenerateFromPassword([]byte("old-admin-pw"), bcrypt.MinCost)
			if err := corrosion.InsertUser(ctx, e.db, "admin", "admin", string(old)); err != nil {
				t.Fatal(err)
			}
			ahead := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
			if err := e.db.Execute(ctx, `INSERT INTO user_lifecycle (username, attribute, value, set_by, updated_at)
				VALUES ('admin', ?, ?, 'peer', ?)`, corrosion.UserAttrSessionsNotBefore, ahead, e.db.NowTS()); err != nil {
				t.Fatal(err)
			}
			hash, _ := bcrypt.GenerateFromPassword([]byte("fresh-admin-pw"), bcrypt.MinCost)
			run := corrosion.FeatureRun(func(ctx context.Context, w func(context.Context, capabilities.FeatureGrant) error) error {
				return e.c.WithFeature(ctx, capabilities.FeatureLoginPolicy, w)
			})
			cliCtx, cancel := context.WithTimeout(ctx, c.deadline)
			defer cancel()
			start := time.Now()
			note, err := corrosion.ResetAdminPasswordReport(cliCtx, e.db, run, "admin", string(hash), false)
			took := time.Since(start)
			if err != nil {
				t.Fatalf("reset-admin with the gate stuck on an unacknowledged first use: %v (after %s)", err, took)
			}
			if took > 5*time.Second {
				t.Errorf("reset-admin waited %s on the gate; want at most its ~3 s bound", took)
			}
			u, _ := corrosion.GetUser(ctx, e.db, "admin")
			if u == nil || u.PasswordHash != string(hash) {
				t.Fatalf("the password was not reset: %+v", u)
			}
			if l, _ := corrosion.GetUserLifecycle(ctx, e.db, "admin"); l.SessionsNotBefore != ahead {
				t.Errorf("the cut-off changed without the grant: %q", l.SessionsNotBefore)
			}
			if !strings.Contains(note, "left in place") || !strings.Contains(note, "lv user reset-admin --user admin") {
				t.Errorf("note %q: want it to say the cut-off was left and what clears it", note)
			}
		})
	}
}
