package hostboot

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// sharing puts another live host at h's address, admitted at createdAt
// (h's own is set to hCreated).
func sharing(t *testing.T, db *corrosion.Client, other, createdAt, hCreated string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: other, Address: "10.0.0.9", SSHUser: "root",
		CertSerial: "s-" + other, State: corrosion.HostStateJoining}); err != nil {
		t.Fatal(err)
	}
	for name, at := range map[string]string{other: createdAt, "h": hCreated} {
		if _, err := db.DB().Exec(`UPDATE hosts SET created_at = ? WHERE name = ?`, at, name); err != nil {
			t.Fatal(err)
		}
	}
}

// Codex 612c78ba I1: two replicas can each admit a name at one address before
// either has the other's row, so both admissions stand. The deterministic
// loser — the later admission, the greater name on a tie — is never recorded
// active: serving refuses it, naming the host that holds the address, and
// keeps retrying, so it activates only once that host is gone. The winner
// activates as before.
//
// Mutation: drop the address check from ConfirmServing (or
// ConfirmServingReport) — the loser is recorded active.
func TestConfirmServing_TheLaterAdmissionAtAnAddressIsNotActivated(t *testing.T) {
	const early, late = "2026-10-19T10:00:00.000000000Z", "2026-10-19T10:00:05.000000000Z"
	for _, tc := range []struct {
		name, other, otherAt, hAt string
		loses                     bool
	}{
		{"admitted after the other", "z-other", early, late, true},
		{"admitted before the other", "a-other", late, early, false},
		{"admitted together, the greater name", "a-other", early, early, true},
		{"admitted together, the lesser name", "z-other", early, early, false},
	} {
		for _, confirm := range []struct {
			name string
			run  func(ctx context.Context, db *corrosion.Client) (bool, string, error)
		}{
			{"ConfirmServing", func(ctx context.Context, db *corrosion.Client) (bool, string, error) {
				return ConfirmServing(ctx, db, "h")
			}},
			{"ConfirmServingReport", func(ctx context.Context, db *corrosion.Client) (bool, string, error) {
				return ConfirmServingReport(ctx, db, "h", "upgrading", Report{Version: "v"})
			}},
		} {
			t.Run(tc.name+"/"+confirm.name, func(t *testing.T) {
				db, ctx := hostIn(t, "upgrading")
				sharing(t, db, tc.other, tc.otherAt, tc.hAt)
				flipped, _, err := confirm.run(ctx, db)
				if !tc.loses {
					if err != nil || !flipped || stateOf(t, db) != "active" {
						t.Fatalf("the winner: flipped=%v err=%v record=%q, want active", flipped, err, stateOf(t, db))
					}
					return
				}
				if err == nil || flipped || !strings.Contains(err.Error(), tc.other) || !strings.Contains(err.Error(), "lv host rm") {
					t.Fatalf("the loser: flipped=%v err=%v, want a refusal naming %s and lv host rm", flipped, err, tc.other)
				}
				if got := stateOf(t, db); got != "upgrading" {
					t.Errorf("the loser is recorded %q, want still upgrading", got)
				}
				// Retried until it lands: once the other is gone it activates.
				if err := corrosion.DeleteHost(ctx, db, tc.other); err != nil {
					t.Fatal(err)
				}
				if flipped, _, err := confirm.run(ctx, db); err != nil || !flipped {
					t.Fatalf("after the other's removal: flipped=%v err=%v", flipped, err)
				}
			})
		}
	}
}
