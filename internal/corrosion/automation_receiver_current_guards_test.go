package corrosion

import (
	"context"
	"database/sql"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

func currentProofFixture(t *testing.T) *aggregateFixture {
	t.Helper()
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{2, 1}})
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	return f
}

func TestReceiverCurrentClientClose(t *testing.T) {
	f := currentProofFixture(t)
	p, err := f.receiver.VerifyCurrent(context.Background(), f.attempt)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.local.c.Close(); err != nil {
		t.Fatal(err)
	}
	if len(f.receiver.proofs) != 0 || len(p.caps) != 0 {
		t.Fatal("closed client retained registered receiver current authority")
	}
	if err = f.receiver.consumeCurrent(context.Background(), p); err == nil {
		t.Fatal("closed client consumed current proof")
	}
}

func TestReceiverCurrentFinalGuards(t *testing.T) {
	for _, mode := range []string{"selection", "source-admission", "cancel", "actual-commit-failure", "not-full", "trust-toggle-back", "private-binding"} {
		t.Run(mode, func(t *testing.T) {
			f := currentProofFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.local.c.db.SetMaxOpenConns(1)
			if mode == "actual-commit-failure" {
				for _, q := range []string{`PRAGMA foreign_keys=ON`, `CREATE TABLE current_commit_parent(id INTEGER PRIMARY KEY)`, `CREATE TABLE current_commit_child(id INTEGER REFERENCES current_commit_parent(id) DEFERRABLE INITIALLY DEFERRED)`} {
					if _, err := f.local.c.db.Exec(q); err != nil {
						t.Fatal(err)
					}
				}
			}
			p, err := f.receiver.VerifyCurrent(ctx, f.attempt)
			if err != nil {
				t.Fatal(err)
			}
			active, spool := receiverActive(t, f.local.c), receiverStored(t, f.local.c)
			reached := false
			f.receiver.seams = &localCommitSeams{beforeCommit: func(tx *sql.Tx) error {
				reached = true
				switch mode {
				case "selection":
					_, err := tx.Exec(`UPDATE local_automation_receiver_current SET attempt='superseded'`)
					return err
				case "source-admission":
					_, err := tx.Exec(`UPDATE hosts SET cert_serial='changed' WHERE name='old-0'`)
					return err
				case "cancel":
					cancel()
				case "actual-commit-failure":
					_, err := tx.Exec(`INSERT INTO current_commit_child(id) VALUES(999)`)
					return err
				}
				return nil
			}}
			if mode == "not-full" {
				if _, err = f.local.c.db.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "trust-toggle-back" {
				var policy atomic.Bool
				if err = pki.PublishHostTrustPolicy(f.local.pki, &policy, true); err != nil {
					t.Fatal(err)
				}
				if err = pki.PublishHostTrustPolicy(f.local.pki, &policy, false); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "private-binding" {
				p.evidence.digest = strings.Repeat("0", 64)
			}
			err = f.receiver.consumeCurrent(ctx, p)
			if err == nil {
				t.Fatal("final guard accepted", mode)
			}
			if mode == "actual-commit-failure" && (!reached || !strings.Contains(err.Error(), "FOREIGN KEY")) {
				t.Fatal("did not reach real SQLite COMMIT failure", reached, err)
			}
			if mode == "selection" || mode == "source-admission" || mode == "cancel" {
				if !reached {
					t.Fatal("final seam not reached")
				}
			}
			if receiverActive(t, f.local.c) != active || receiverStored(t, f.local.c) != spool {
				t.Fatal("refusal changed active/spool")
			}
			if mode == "actual-commit-failure" {
				rows, e := f.local.c.Query(context.Background(), `SELECT COUNT(*) AS n FROM current_commit_child`)
				if e != nil || len(rows) != 1 || rows[0].Int64("n") != 0 {
					t.Fatal("failed commit did not roll back", rows, e)
				}
			}
			f.receiver.seams = nil
			if mode == "not-full" {
				if _, err = f.local.c.db.Exec(`PRAGMA synchronous=FULL`); err != nil {
					t.Fatal(err)
				}
			}
			fresh, e := f.receiver.VerifyCurrent(context.Background(), f.attempt)
			if e != nil {
				t.Fatal("fresh retry failed", e)
			}
			if e = f.receiver.consumeCurrent(context.Background(), fresh); e != nil {
				t.Fatal("fresh retry consumption", e)
			}
			if e = f.receiver.consumeCurrent(context.Background(), p); e == nil {
				t.Fatal("fresh verification revived old proof")
			}
		})
	}
}

func TestReceiverCurrentIssuanceCompleteness(t *testing.T) {
	for _, mode := range []string{"terminal", "original-record", "aggregate-binding", "local-original"} {
		t.Run(mode, func(t *testing.T) {
			f := currentProofFixture(t)
			ctx := context.Background()
			if _, err := f.receiver.auditAggregate(ctx, f.attempt); err != nil {
				t.Fatal(err)
			}
			active, spool := receiverActive(t, f.local.c), receiverStored(t, f.local.c)
			calls := 0
			f.receiver.seams = &localCommitSeams{beforeCommit: func(tx *sql.Tx) error {
				calls++
				if calls != 3 {
					return nil
				} // Actual Begin, actual C, then first issuance FULL.
				query := ""
				switch mode {
				case "terminal":
					query = `UPDATE local_automation_receiver_components SET terminal=0 WHERE component=11`
				case "original-record":
					query = `DELETE FROM local_automation_receiver_records WHERE source='old-0' AND component=5 AND ordinal=1`
				case "aggregate-binding":
					query = `UPDATE local_automation_aggregates SET coverage='changed'`
				case "local-original":
					query = `UPDATE local_automation_local_audits SET dependency='changed'`
				}
				result, err := tx.Exec(query)
				if err != nil {
					return err
				}
				n, err := result.RowsAffected()
				if err != nil || n == 0 {
					t.Fatalf("actual issuance mutation missed rows: %d %v", n, err)
				}
				return nil
			}}
			p, err := f.receiver.VerifyCurrent(ctx, f.attempt)
			if p != nil {
				p.Discard()
			}
			if calls != 3 || err == nil || !strings.Contains(err.Error(), "current complete dependency binding changed") {
				t.Fatalf("first issuance full completeness assertion: calls=%d proof=%v err=%v", calls, p != nil, err)
			}
			if receiverActive(t, f.local.c) != active || receiverStored(t, f.local.c) != spool {
				t.Fatal("first issuance refusal changed prior state")
			}
		})
	}
}

func TestReceiverCurrentWholeElectorate(t *testing.T) {
	ctx := context.Background()
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 5, Sources: 3, Heads: []int{3, 1, 1}})
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	if _, err := f.receiver.auditAggregate(ctx, f.attempt); err != nil {
		t.Fatal(err)
	}
	if _, err := f.local.c.db.Exec(`DELETE FROM local_automation_receiver_audits WHERE attempt=? AND source='old-2'`, f.attempt.id); err != nil {
		t.Fatal(err)
	}
	p, err := f.receiver.VerifyCurrent(ctx, f.attempt)
	if p != nil {
		p.Discard()
	}
	if err == nil || !strings.Contains(err.Error(), "complete old electorate observed 2 required 3") {
		t.Fatalf("first issuance whole electorate assertion: proof=%v err=%v", p != nil, err)
	}
}

func TestReceiverCurrentRetainedSummaryCompleteness(t *testing.T) {
	f := currentProofFixture(t)
	ctx := context.Background()
	if _, err := f.receiver.auditAggregate(ctx, f.attempt); err != nil {
		t.Fatal(err)
	}
	if _, err := f.local.c.db.Exec(`UPDATE local_automation_receiver_components SET terminal=0 WHERE source='old-0' AND component=11`); err != nil {
		t.Fatal(err)
	}
	p, err := f.receiver.VerifyCurrent(ctx, f.attempt)
	if p != nil {
		p.Discard()
	}
	if err == nil {
		t.Fatal("first issuance trusted retained complete summaries with missing original terminal")
	}
}
