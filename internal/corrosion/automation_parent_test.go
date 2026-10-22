package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/automation/contract"
)

func automationParentDB(t *testing.T) *Client {
	t.Helper()
	c := lifecycleDB(t)
	c.SetUserIncarnationGate(func() bool { return true })
	c.SetCredentialsSplitGate(func() bool { return true })
	return c
}

func automationParentRead(ctx context.Context, c *Client, kind, alias string) (contract.ParentLifetime, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return contract.ParentLifetime{}, err
	}
	defer tx.Rollback()
	return readAutomationParentLifetimeTx(ctx, c, tx, kind, alias)
}

func automationParentWant(t *testing.T, c *Client, alias string) contract.ParentLifetime {
	t.Helper()
	u, err := GetUser(context.Background(), c, alias)
	if err != nil || u == nil || u.CreatedAt == "" {
		t.Fatalf("real parent fixture: %+v %v", u, err)
	}
	want := contract.ParentLifetime{Kind: "principal", Alias: u.Username, Realm: u.Realm, Birth: u.CreatedAt}
	got, err := automationParentRead(context.Background(), c, "principal", alias)
	if err != nil || got != want {
		t.Fatalf("current supported parent: got %+v, %v; want exact owner facts %+v", got, err, want)
	}
	return got
}

func automationParentUnavailable(t *testing.T, c *Client, kind, alias string) {
	t.Helper()
	got, err := automationParentRead(context.Background(), c, kind, alias)
	if !errors.Is(err, ErrAutomationLifecycleUnavailable) || got != (contract.ParentLifetime{}) {
		t.Fatalf("unavailable parent: got %+v, %v", got, err)
	}
}

// A missing reader fails after a real latched/split birth has committed. The
// same-password rebirth and rotations exercise the existing writers, not stamps
// supplied by a test or a certified identity fixture.
func TestAutomationParentPrincipalLifecycle(t *testing.T) {
	ctx := context.Background()
	c := automationParentDB(t)
	if err := InsertUser(ctx, c, " Alice\t", "operator", "same-password-hash"); err != nil {
		t.Fatal(err)
	}
	first := automationParentWant(t, c, " ALICE ")
	if first.Alias != " Alice\t" || first.Realm != "local" {
		t.Fatalf("owner bytes changed: %+v", first)
	}
	if err := UpdateUserPassword(ctx, c, first.Alias, "rotated-hash"); err != nil {
		t.Fatal(err)
	}
	if got := automationParentWant(t, c, "alice"); got != first {
		t.Fatalf("rotation changed parent: %+v -> %+v", first, got)
	}
	if err := DeleteUser(ctx, c, first.Alias); err != nil {
		t.Fatal(err)
	}
	automationParentUnavailable(t, c, "principal", "alice")
	if err := InsertUser(ctx, c, first.Alias, "operator", "same-password-hash"); err != nil {
		t.Fatal(err)
	}
	if got := automationParentWant(t, c, "alice"); got.Birth == first.Birth || got.Alias != first.Alias {
		t.Fatalf("same-password rebirth reused parent: %+v -> %+v", first, got)
	}
}

func TestAutomationParentAdminResetAndFloor(t *testing.T) {
	ctx := context.Background()
	c := automationParentDB(t)
	if err := InsertUser(ctx, c, "admin", "admin", "same-password-hash"); err != nil {
		t.Fatal(err)
	}
	first := automationParentWant(t, c, "admin")
	if err := ResetAdminPassword(ctx, c, nil, "reset-hash", false); err != nil {
		t.Fatal(err)
	}
	if got := automationParentWant(t, c, "admin"); got != first {
		t.Fatalf("reset changed parent: %+v -> %+v", first, got)
	}
	if err := DeleteUser(ctx, c, "admin"); err != nil {
		t.Fatal(err)
	}
	if name, err := ReinstateAdminIfNoneRemain(ctx, c, nil); err != nil || name != "admin" {
		t.Fatalf("real admin floor: %q %v", name, err)
	}
	if got := automationParentWant(t, c, "admin"); got.Birth == first.Birth {
		t.Fatalf("admin floor reused parent: %+v", got)
	}
}

func TestAutomationParentRefusals(t *testing.T) {
	for _, reason := range []string{"closed_gate", "tombstone", "ambiguity", "nonlocal", "missing", "project", "unsupported"} {
		t.Run(reason, func(t *testing.T) {
			ctx := context.Background()
			c := automationParentDB(t)
			if err := InsertUser(ctx, c, "alice", "operator", "hash"); err != nil {
				t.Fatal(err)
			}
			kind, alias := "principal", "alice"
			switch reason {
			case "closed_gate":
				c.SetUserIncarnationGate(nil)
			case "tombstone":
				if err := DeleteUser(ctx, c, "alice"); err != nil {
					t.Fatal(err)
				}
			case "ambiguity":
				if err := InsertUser(ctx, c, " ALICE ", "operator", "hash"); err != nil {
					t.Fatal(err)
				}
			case "nonlocal":
				// Administrative fixture represents a directory-owned stored row.
				if _, err := c.db.ExecContext(ctx, `UPDATE users SET realm='oidc' WHERE username='alice'`); err != nil {
					t.Fatal(err)
				}
			case "missing":
				alias = "missing"
			case "project":
				if err := InsertProject(ctx, c, ProjectRecord{Name: "alice"}); err != nil {
					t.Fatal(err)
				}
				kind = "project"
			case "unsupported":
				kind = "unknown"
			}
			automationParentUnavailable(t, c, kind, alias)
		})
	}
}

func TestAutomationParentKnownNewerAdmission(t *testing.T) {
	ctx := context.Background()
	c := automationParentDB(t)
	if err := InsertUser(ctx, c, "alice", "operator", "hash"); err != nil {
		t.Fatal(err)
	}
	before := automationParentWant(t, c, "alice")
	// Use the actual receiver's admission of a future-incarnation session. Do
	// not populate the holds map or manufacture local provenance directly.
	stamp := c.NowTS()
	stmts, err := json.Marshal([]Statement{{SQL: sessionsInsertSQL,
		Params: []interface{}{"future-session", "alice", "local", "", "", nowRFC3339(), nowRFC3339(), nowRFC3339()},
		Guard:  &MutationGuard{Protocol: userIncarnationGuardV1, ResourceKind: userGuardLive, ResourceID: "alice", Incarnation: nextIncarnation(before.Birth)}}})
	if err != nil {
		t.Fatal(err)
	}
	r := NewReplicator(c, "", RelayConfig{})
	if _, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: 1, Hlc: stamp, Origin: "peer", Stmts: string(stmts)}}); err != nil {
		t.Fatal(err)
	}
	var sessions int
	if err := c.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE id='future-session'`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if c.UserHolds() == 0 || sessions != 0 {
		t.Fatalf("future write not genuinely held: holds=%d sessions=%d", c.UserHolds(), sessions)
	}
	u, err := GetUser(ctx, c, "alice")
	if err != nil || u == nil || u.CreatedAt != before.Birth {
		t.Fatalf("lagging parent changed: %+v %v", u, err)
	}
	automationParentUnavailable(t, c, "principal", "alice")
}

func TestAutomationParentErrorCauses(t *testing.T) {
	ctx := context.Background()
	c := automationParentDB(t)
	if err := InsertUser(ctx, c, "alice", "operator", "hash"); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := readAutomationParentLifetimeTx(cancelled, c, tx, "principal", "alice"); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost context cause: %v", err)
	}
	// A real SQLite failure in the caller's snapshot must survive unchanged.
	if _, err := tx.ExecContext(ctx, `DROP TABLE users`); err != nil {
		t.Fatal(err)
	}
	_, storageErr := tx.QueryContext(ctx, `SELECT username FROM users`)
	if storageErr == nil {
		t.Fatal("storage failure fixture did not fail")
	}
	_, got := readAutomationParentLifetimeTx(ctx, c, tx, "principal", "alice")
	if got == nil || errors.Is(got, ErrAutomationLifecycleUnavailable) || reflect.TypeOf(got) != reflect.TypeOf(storageErr) || got.Error() != storageErr.Error() {
		t.Fatalf("lost SQLite error: got %T %v, want %T %v", got, got, storageErr, storageErr)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := readAutomationParentLifetimeTx(ctx, c, tx, "principal", "alice"); !errors.Is(err, sql.ErrTxDone) {
		t.Fatalf("lost transaction cause: %v", err)
	}
}

func TestAutomationParentLosingCreateRetainsAtomicState(t *testing.T) {
	ctx := context.Background()
	c := automationParentDB(t)
	if err := InsertUser(ctx, c, "alice", "operator", "winner-hash"); err != nil {
		t.Fatal(err)
	}
	capture := func() string {
		t.Helper()
		var state []interface{}
		for _, query := range []string{`SELECT * FROM users WHERE username='alice'`, `SELECT * FROM user_credentials WHERE username='alice'`, `SELECT * FROM local_automation_lifetimes WHERE kind='principal' AND name='alice'`, `SELECT * FROM mutation_log ORDER BY seq`} {
			rows, err := c.Query(ctx, query)
			if err != nil {
				t.Fatal(err)
			}
			state = append(state, rows)
		}
		data, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	before := capture()
	if err := InsertUser(ctx, c, "alice", "admin", "loser-hash"); err == nil {
		t.Fatal("duplicate create succeeded")
	}
	if after := capture(); after != before {
		t.Fatalf("losing create changed parent/credential/observation/log: %s -> %s", before, after)
	}
	automationParentWant(t, c, "alice")
}

func TestAutomationParentReceiverAndReseed(t *testing.T) {
	for _, mode := range []string{"wal", "anti_entropy"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			source, target := automationParentDB(t), automationParentDB(t)
			if err := InsertUser(ctx, source, "alice", "operator", "sender-hash"); err != nil {
				t.Fatal(err)
			}
			want := automationParentWant(t, source, "alice")
			origin, err := AutomationLifetime(ctx, source, "principal", "alice")
			if err != nil || origin.Witness == "" {
				t.Fatalf("sender lacks genuine origin: %+v %v", origin, err)
			}
			if mode == "wal" {
				rows, err := source.Query(ctx, `SELECT seq,hlc,origin,stmts FROM mutation_log ORDER BY seq`)
				if err != nil || len(rows) == 0 {
					t.Fatalf("sender WAL absent: %v", err)
				}
				var entries []*pb.MutationEntry
				for _, row := range rows {
					entries = append(entries, &pb.MutationEntry{Seq: int64(row.Int("seq")), Hlc: row.String("hlc"), Origin: row.String("origin"), Stmts: row.String("stmts")})
				}
				r := NewReplicator(target, "", RelayConfig{})
				if _, err := r.ApplyRemoteMutations(ctx, entries); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := target.MergeStateBytesLWW(source.DumpStateBytes()); err != nil {
					t.Fatal(err)
				}
				if err := target.MergeSensitiveStateBytesLWW(source.DumpSensitiveStateBytes()); err != nil {
					t.Fatal(err)
				}
			}
			if got := automationParentWant(t, target, "alice"); got != want {
				t.Fatalf("receiver replaced sender parent: %+v -> %+v", want, got)
			}
			if got, err := AutomationLifetime(ctx, target, "principal", "alice"); !errors.Is(err, ErrAutomationLifecycleUnavailable) {
				t.Fatalf("receiver minted origin: %+v %v", got, err)
			}
			var observations int
			if err := target.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM local_automation_lifetimes WHERE kind='principal' AND name='alice'`).Scan(&observations); err != nil || observations != 0 {
				t.Fatalf("receiver copied/minted observation: %d %v", observations, err)
			}
			// Existing originating state on the source must be invalidated by
			// actual reseed discard and remain invalid after a received restore.
			public, sensitive := source.DumpStateBytes(), source.DumpSensitiveStateBytes()
			if _, err := source.DiscardReplicatedStateForReseed(ctx); err != nil {
				t.Fatal(err)
			}
			automationParentUnavailable(t, source, "principal", "alice")
			if _, err := AutomationLifetime(ctx, source, "principal", "alice"); !errors.Is(err, ErrAutomationLifecycleUnavailable) {
				t.Fatalf("discard retained origin: %v", err)
			}
			if err := source.MergeStateBytesLWW(public); err != nil {
				t.Fatal(err)
			}
			if err := source.MergeSensitiveStateBytesLWW(sensitive); err != nil {
				t.Fatal(err)
			}
			if got := automationParentWant(t, source, "alice"); got != want {
				t.Fatalf("reseed replaced sender parent: %+v -> %+v", want, got)
			}
			if got, err := AutomationLifetime(ctx, source, "principal", "alice"); !errors.Is(err, ErrAutomationLifecycleUnavailable) {
				t.Fatalf("reseed reconstructed origin: %+v %v", got, err)
			}
		})
	}
}
