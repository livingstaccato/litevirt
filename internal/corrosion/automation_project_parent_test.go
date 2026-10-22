package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// Removing the project owner adapter loses an actual birth/adoption, while
// accepting canonical-only aliases or an unadopted row fabricates currentness.
func TestAutomationProjectParentLifecycle(t *testing.T) {
	ctx := context.Background()
	c := automationParentDB(t)
	c.SetProjectIncarnationGate(func() bool { return true })
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	firstRow, err := GetProject(ctx, c, "/acme")
	if err != nil {
		t.Fatal(err)
	}
	first, err := automationParentRead(ctx, c, "project", "/acme")
	want := contract.ParentLifetime{Kind: "project", Alias: "/acme", Birth: firstRow.Incarnation}
	if err != nil || first != want || first.Birth == "" {
		t.Fatalf("actual project birth: %+v %v", first, err)
	}
	automationParentUnavailable(t, c, "project", "acme")
	c.SetProjectIncarnationGate(nil) // owner read does not require the writer gate
	if got, e := automationParentRead(ctx, c, "project", "/acme"); e != nil || got != first {
		t.Fatalf("gate-independent current read: %+v %v", got, e)
	}
	c.SetProjectIncarnationGate(func() bool { return true })
	if err = DeleteProject(ctx, c, "/acme"); err != nil {
		t.Fatal(err)
	}
	automationParentUnavailable(t, c, "project", "/acme")
	if err = InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	next, e := automationParentRead(ctx, c, "project", "/acme")
	if e != nil || next.Birth == first.Birth {
		t.Fatalf("actual rebirth reused parent: %+v %v", next, e)
	}
}

func TestAutomationProjectParentDefaultAndRefusals(t *testing.T) {
	ctx := context.Background()
	c := automationParentDB(t)
	for _, alias := range []string{"", "/", DefaultProject, "/" + DefaultProject} {
		got, err := automationParentRead(ctx, c, "project", alias)
		if err != nil || got.Kind != "project" || got.Birth != "default" || got.Realm != "" {
			t.Fatalf("public default %q: %+v %v", alias, got, err)
		}
		if _, err = AutomationLifetime(ctx, c, "project", alias); !errors.Is(err, ErrAutomationLifecycleUnavailable) {
			t.Fatalf("public default fabricated private origin: %v", err)
		}
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "legacy"}); err != nil {
		t.Fatal(err)
	}
	automationParentUnavailable(t, c, "project", "legacy")
	c.SetProjectIncarnationGate(func() bool { return true })
	if ok, err := AdoptProjectIncarnation(ctx, c, adoptGrant(t), "legacy"); err != nil || !ok {
		t.Fatalf("actual adoption: %v %v", ok, err)
	}
	if got, err := automationParentRead(ctx, c, "project", "legacy"); err != nil || got.Alias != "legacy" || got.Birth == "" {
		t.Fatalf("adopted parent: %+v %v", got, err)
	}
	c.SetProjectIncarnationGate(nil)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/legacy"}); err != nil {
		t.Fatal(err)
	}
	automationParentUnavailable(t, c, "project", "legacy")
	automationParentUnavailable(t, c, "project", "/legacy")
	automationParentUnavailable(t, c, "project", "absent")
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := automationParentRead(canceled, c, "project", "legacy"); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost context cause: %v", err)
	}
}

// Dropping the originating rotate callback invalidates the original witness.
// A receiver, missing proof and invalid proof must never acquire one instead.
func TestAutomationProjectAdoptionPreservesOnlyGenuineOrigin(t *testing.T) {
	for _, mode := range []string{"genuine", "missing", "invalid", "guard-false", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			c := adoptionClient(t)
			if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
				t.Fatal(err)
			}
			before, err := AutomationLifetime(ctx, c, "project", "/acme")
			if err != nil {
				t.Fatal(err)
			}
			receiver := adoptionClient(t)
			receiver.SetProjectIncarnationGate(func() bool { return true })
			walTo(t, c, "origin", receiver)
			if _, e := AutomationLifetime(ctx, receiver, "project", "/acme"); !errors.Is(e, ErrAutomationLifecycleUnavailable) {
				t.Fatalf("receiver minted origin before adoption: %v", e)
			}
			switch mode {
			case "missing":
				_, err = c.db.Exec(`DELETE FROM local_automation_lifetimes WHERE kind='project'`)
			case "invalid":
				_, err = c.db.Exec(`UPDATE local_automation_lifetimes SET valid=0 WHERE kind='project'`)
			case "guard-false":
				projectAdoptionHook = func() {
					if e := DeleteProject(ctx, c, "/acme"); e != nil {
						t.Fatal(e)
					}
				}
				defer func() { projectAdoptionHook = nil }()
			case "rollback":
				_, err = c.db.Exec(`CREATE TRIGGER fail_adoption_origin BEFORE UPDATE OF valid ON local_automation_lifetimes WHEN NEW.valid=1 BEGIN SELECT RAISE(ABORT,'origin callback fails'); END`)
			}
			if err != nil {
				t.Fatal(err)
			}
			c.SetProjectIncarnationGate(func() bool { return true })
			ok, err := AdoptProjectIncarnation(ctx, c, adoptGrant(t), "/acme")
			if mode == "rollback" {
				if err == nil || ok {
					t.Fatalf("hook failure did not abort: %v %v", ok, err)
				}
				row, e := GetProject(ctx, c, "/acme")
				if e != nil || row.Incarnation != "" {
					t.Fatalf("adoption escaped rollback: %+v %v", row, e)
				}
				got, e := AutomationLifetime(ctx, c, "project", "/acme")
				if e != nil || got != before {
					t.Fatalf("rollback changed original: %+v %v", got, e)
				}
				if _, e = c.db.Exec(`DROP TRIGGER fail_adoption_origin`); e != nil {
					t.Fatal(e)
				}
				if ok, e = AdoptProjectIncarnation(ctx, c, adoptGrant(t), "/acme"); e != nil || !ok {
					t.Fatalf("hook failure wedged retry: %v %v", ok, e)
				}
				return
			}
			if err != nil || ok == (mode == "guard-false") {
				t.Fatalf("adoption outcome %v %v", ok, err)
			}
			got, e := AutomationLifetime(ctx, c, "project", "/acme")
			if mode == "genuine" {
				if e != nil || !reflect.DeepEqual(got, before) {
					t.Fatalf("adoption lost exact original: %+v -> %+v %v", before, got, e)
				}
			} else if !errors.Is(e, ErrAutomationLifecycleUnavailable) {
				t.Fatalf("non-origin healed: %+v %v", got, e)
			}
			if mode == "genuine" {
				if again, e := AdoptProjectIncarnation(ctx, c, adoptGrant(t), "/acme"); e != nil || again {
					t.Fatalf("adoption no-op: %v %v", again, e)
				}
				got, e = AutomationLifetime(ctx, c, "project", "/acme")
				if e != nil || got != before {
					t.Fatalf("no-op changed origin: %+v %v", got, e)
				}
			}
			walTo(t, c, "origin", receiver)
			if _, e = AutomationLifetime(ctx, receiver, "project", "/acme"); !errors.Is(e, ErrAutomationLifecycleUnavailable) {
				t.Fatalf("receiver minted origin at adoption: %v", e)
			}
		})
	}
}

// The unhooked adopter executes the published owner's single statement and
// guard. It has no local witness callbacks; its replicated bytes are the
// independent reference for a writer preserving genuine local provenance.
func projectAdoptUnhooked(t *testing.T, c *Client, name string) {
	t.Helper()
	ctx := context.Background()
	rows, err := c.Query(ctx, `SELECT updated_at, incarnation FROM projects WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil || len(rows) != 1 {
		t.Fatalf("unhooked prerequisite: %v", err)
	}
	u := rows[0].String("updated_at")
	at, ok := justAfterTS(u)
	if !ok {
		t.Fatal("bad reference timestamp")
	}
	applied, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		var upd, inc string
		var deleted sql.NullString
		e := tx.QueryRowContext(ctx, `SELECT deleted_at, updated_at, incarnation FROM projects WHERE name = ?`, name).Scan(&deleted, &upd, &inc)
		if errors.Is(e, sql.ErrNoRows) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		if deleted.Valid || upd != u || inc != "" {
			return false, nil
		}
		states, e := loadProjectStatesTx(ctx, tx)
		if e != nil {
			return false, e
		}
		return len(states["/acme"].live) == 1, nil
	}, []Statement{{SQL: projectsAdoptIncarnationSQL, Params: []interface{}{adoptedProjectIncarnation("/acme"), at, name}}})
	if err != nil || !applied {
		t.Fatalf("published unhooked reference: %v %v", applied, err)
	}
}

func TestAutomationProjectAdoptionMixedWritersReplicateIdenticalStatements(t *testing.T) {
	ctx := context.Background()
	hooked, unhooked := adoptionClient(t), adoptionClient(t)
	if err := InsertProject(ctx, hooked, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	original, err := AutomationLifetime(ctx, hooked, "project", "/acme")
	if err != nil {
		t.Fatal(err)
	}
	walTo(t, hooked, "hooked", unhooked)
	hooked.SetProjectIncarnationGate(func() bool { return true })
	unhooked.SetProjectIncarnationGate(func() bool { return true })
	if ok, e := AdoptProjectIncarnation(ctx, hooked, adoptGrant(t), "/acme"); e != nil || !ok {
		t.Fatalf("hooked adopter: %v %v", ok, e)
	}
	projectAdoptUnhooked(t, unhooked, "/acme")
	a, b := walEntries(t, hooked, "hooked"), walEntries(t, unhooked, "unhooked")
	if len(a) == 0 || len(b) == 0 || a[len(a)-1].Stmts != b[len(b)-1].Stmts {
		t.Fatalf("local preservation changed replicated entries: hooked=%+v unhooked=%+v", a, b)
	}
	got, err := AutomationLifetime(ctx, hooked, "project", "/acme")
	if err != nil || got != original {
		t.Fatalf("mixed adoption lost original: %+v %v", got, err)
	}
	if _, err = AutomationLifetime(ctx, unhooked, "project", "/acme"); !errors.Is(err, ErrAutomationLifecycleUnavailable) {
		t.Fatalf("unhooked receiver invented origin: %v", err)
	}
	walTo(t, hooked, "hooked", unhooked)
	walTo(t, unhooked, "unhooked", hooked)
	if projectRow(t, hooked, "/acme") != projectRow(t, unhooked, "/acme") {
		t.Fatal("mixed adopters did not converge")
	}
}
