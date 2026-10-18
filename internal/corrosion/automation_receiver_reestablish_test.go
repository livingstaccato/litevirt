package corrosion

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

func TestReceiverReestablishLegacyAllOriginals(t *testing.T) {
	f := currentProofFixture(t)
	ctx := context.Background()
	old, err := f.receiver.VerifyCurrent(ctx, f.attempt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.local.c.db.Exec(`DELETE FROM local_automation_receiver_established`); err != nil {
		t.Fatal(err)
	}
	active, spool := receiverActive(t, f.local.c), receiverStored(t, f.local.c)
	if _, err = f.receiver.Begin(ctx, f.attempt.request, nil); err == nil || !strings.Contains(err.Error(), "receiver establishment") {
		t.Fatal("unsigned legacy automatically blessed", err)
	}
	if err = f.receiver.Reestablish(ctx, f.attempt.request); err != nil {
		t.Fatal("genuine current-owner explicit repair refused", err)
	}
	rows, err := f.local.c.Query(ctx, `SELECT (SELECT COUNT(*) FROM local_automation_receiver_validations) AS originals,(SELECT COUNT(*) FROM local_automation_receiver_established) AS established`)
	if err != nil || len(rows) != 1 || rows[0].Int64("originals") == 0 || rows[0].Int64("originals") != rows[0].Int64("established") {
		t.Fatal("repair omitted originals", rows, err)
	}
	if err = f.receiver.consumeCurrent(ctx, old); err == nil {
		t.Fatal("old proof revived after fresh repair")
	}
	fresh, err := f.receiver.VerifyCurrent(ctx, f.attempt)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.receiver.consumeCurrent(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if active != receiverActive(t, f.local.c) || spool != receiverStored(t, f.local.c) {
		t.Fatal("repair changed ACTIVE or original spool")
	}
}

func TestReceiverReestablishAtomicFinalGuards(t *testing.T) {
	for _, mode := range []string{"cancel", "mutation", "inventory", "commit-failure"} {
		t.Run(mode, func(t *testing.T) {
			f := currentProofFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.local.c.db.SetMaxOpenConns(1)
			if mode == "commit-failure" {
				for _, q := range []string{`PRAGMA foreign_keys=ON`, `CREATE TABLE repair_parent(id INTEGER PRIMARY KEY)`, `CREATE TABLE repair_child(id INTEGER REFERENCES repair_parent(id) DEFERRABLE INITIALLY DEFERRED)`} {
					if _, e := f.local.c.db.Exec(q); e != nil {
						t.Fatal(e)
					}
				}
			}
			if _, err := f.local.c.db.Exec(`DELETE FROM local_automation_receiver_established`); err != nil {
				t.Fatal(err)
			}
			active, spool := receiverActive(t, f.local.c), receiverStored(t, f.local.c)
			reached := false
			f.receiver.seams = &localCommitSeams{beforeCommit: func(tx *sql.Tx) error {
				reached = true
				switch mode {
				case "cancel":
					cancel()
				case "mutation":
					_, err := tx.Exec(`UPDATE local_automation_receiver_validations SET evidence=x'00'`)
					return err
				case "inventory":
					_, err := tx.Exec(`UPDATE local_automation_receiver_current SET established_inventory=x'00'`)
					return err
				case "commit-failure":
					_, err := tx.Exec(`INSERT INTO repair_child(id) VALUES(999)`)
					return err
				}
				return nil
			}}
			err := f.receiver.Reestablish(ctx, f.attempt.request)
			if !reached || err == nil {
				t.Fatal("real repair final guard not reached/refused", reached, err)
			}
			if mode == "commit-failure" && !strings.Contains(err.Error(), "FOREIGN KEY") {
				t.Fatal("not actual commit failure", err)
			}
			rows, e := f.local.c.Query(context.Background(), `SELECT COUNT(*) AS n FROM local_automation_receiver_established`)
			if e != nil || len(rows) != 1 || rows[0].Int64("n") != 0 {
				t.Fatal("partial artifact set survived refusal", rows, e)
			}
			if active != receiverActive(t, f.local.c) || spool != receiverStored(t, f.local.c) {
				t.Fatal("failed repair changed ACTIVE/original spool")
			}
			f.receiver.seams = nil
			if err = f.receiver.Reestablish(context.Background(), f.attempt.request); err != nil {
				t.Fatal("fresh repair after refusal", err)
			}
		})
	}
}
