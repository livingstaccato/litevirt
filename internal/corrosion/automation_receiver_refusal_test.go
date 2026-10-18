package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

func receiverActive(t *testing.T, c *Client) string {
	t.Helper()
	h := sha256.New()
	// Test-only full snapshot. Production ingress never scans ACTIVE payloads.
	for _, table := range []string{"local_recovery_claims", "local_incarnation_claims", "local_voter_incarnation", "local_voter_adoption", "local_voter_seals", "local_automation_history", "local_automation_prefix", "local_automation_anchors", "local_automation_requests", "local_automation_authority", "local_automation_recovery", "local_automation_staging", "voter_configs", "hosts", "mutation_log"} {
		rows, err := c.Query(context.Background(), `SELECT * FROM `+table+` ORDER BY rowid`)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		sourceHash(h, []byte(table), raw)
	}
	return hex.EncodeToString(h.Sum(nil))
}
func receiverStored(t *testing.T, c *Client) string {
	t.Helper()
	h := sha256.New()
	for _, table := range []string{"sources", "components", "records", "pages"} {
		rows, err := c.Query(context.Background(), `SELECT * FROM local_automation_receiver_`+table+` ORDER BY rowid`)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(rows)
		sourceHash(h, raw)
	}
	return hex.EncodeToString(h.Sum(nil))
}
func receiverThrough(t *testing.T, p *AutomationSourcePreparer, r *AutomationReceiver, a *AutomationReceiverAttempt, request AutomationExportRequest, ctx context.Context, through uint32) {
	t.Helper()
	for component := uint32(0); component <= through; component++ {
		request.Component = component
		request.Cursor = ""
		for {
			page, err := p.ExportAutomationSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = r.Stage(context.Background(), a, "a", request, page); err != nil {
				t.Fatalf("component %d: %v", component, err)
			}
			if page.Terminal {
				break
			}
			request.Cursor = page.Cursor
		}
	}
}
func TestReceiverCurrentSelection(t *testing.T) {
	p, r, q, exportCtx, _ := receiverFixture(t)
	ctx := context.Background()
	active := receiverActive(t, r.client)
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := p.ExportAutomationSource(exportCtx, q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Stage(ctx, a, "a", q, first); err != nil {
		t.Fatal(err)
	}
	original := receiverStored(t, r.client)
	next := q.Intent
	next.Revision++
	next.Job = "another-job"
	if _, err = r.Begin(ctx, next, nil); err == nil {
		t.Fatal("foreign job name selected current receiver without actual predecessor")
	}
	b, err := r.Begin(ctx, next, a)
	if err != nil {
		t.Fatal("authorized supersession", err)
	}
	if _, err = r.Stage(ctx, a, "a", q, first); err == nil {
		t.Fatal("superseded receiver accepted exact old page")
	}
	if _, err = r.Begin(ctx, q.Intent, nil); err == nil {
		t.Fatal("superseded attempt revived by row identity")
	}
	if _, err = r.Begin(ctx, q.Intent, b); err == nil {
		t.Fatal("lower revision superseded current attempt")
	}
	if receiverStored(t, r.client) != original {
		t.Fatal("supersession modified pinned evidence")
	}
	fresh := NewAutomationReceiver(r.client, r.dir)
	resumed, err := fresh.Begin(ctx, next, nil)
	if err != nil || resumed.id != b.id {
		t.Fatal("fresh current authorization cannot resume exact durable attempt", err)
	}
	if _, err = fresh.Stage(ctx, b, "a", q, first); err == nil {
		t.Fatal("foreign process owner handle accepted")
	}
	if active != receiverActive(t, r.client) {
		t.Fatal("receiver selection mutated active state")
	}
}
func TestReceiverCurrentTrustAndLifetime(t *testing.T) {
	for _, mode := range []string{"policy-toggle-back", "source-reimage", "source-admission", "target-reimage", "target-tombstone", "next-adopted", "reseed", "membership-change", "expired-guard", "foreign-handle"} {
		t.Run(mode, func(t *testing.T) {
			p, r, q, exportCtx, _ := receiverFixture(t)
			ctx := context.Background()
			a, err := r.Begin(ctx, q.Intent, nil)
			if err != nil {
				t.Fatal(err)
			}
			page, err := p.ExportAutomationSource(exportCtx, q)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "policy-toggle-back":
				var policy atomic.Bool
				if err = pki.PublishHostTrustPolicy(r.dir, &policy, true); err != nil {
					t.Fatal(err)
				}
				if err = pki.PublishHostTrustPolicy(r.dir, &policy, false); err != nil {
					t.Fatal(err)
				}
			case "source-reimage":
				_, err = p.client.ReplaceVoterIncarnationForTest(ctx)
			case "source-admission":
				_, err = r.client.db.Exec(`UPDATE hosts SET cert_serial='wrong' WHERE name='a'`)
			case "target-reimage":
				_, err = r.client.ReplaceVoterIncarnationForTest(ctx)
			case "target-tombstone":
				_, err = r.client.db.Exec(`UPDATE hosts SET deleted_at='gone' WHERE name='b'`)
			case "next-adopted":
				err = RecordVoterAdoption(ctx, r.client, 2)
			case "reseed":
				_, err = r.client.db.Exec(`INSERT INTO reseed_generation(id,generation) VALUES(1,99)`)
			case "membership-change":
				_, err = r.client.db.Exec(`UPDATE voter_configs SET created_at='changed' WHERE generation=2`)
			case "expired-guard":
				r.seams = &localCommitSeams{beforeCommit: func(*sql.Tx) error { a.notAfter = time.Now().Add(-time.Second); return nil }}
			case "foreign-handle":
				a = &AutomationReceiverAttempt{self: a, owner: r, id: a.id}
			}
			if err != nil {
				t.Fatal(err)
			}
			active := receiverActive(t, r.client)
			stored := receiverStored(t, r.client)
			if _, err = r.Stage(ctx, a, "a", q, page); err == nil {
				t.Fatal("changed current receiver/source authority accepted")
			}
			if receiverActive(t, r.client) != active || receiverStored(t, r.client) != stored {
				t.Fatal("failed receiver authorization changed active state or progress")
			}
		})
	}
}
func TestReceiverPageRefusalsAndAtomicity(t *testing.T) {
	p, r, q, exportCtx, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, exportCtx, 2)
	q.Component = 3
	q.MaxRecords = 1
	page, err := p.ExportAutomationSource(exportCtx, q)
	if err != nil || page.Terminal {
		t.Fatal("fixture needs multi-page real claims", err)
	}
	active := receiverActive(t, r.client)
	stored := receiverStored(t, r.client)
	for _, mode := range []string{"source", "job", "revision", "publication", "component", "schema", "codec", "section", "metadata", "record", "duplicate", "reordered", "count", "bytes", "digest", "terminal", "overflow", "EOF", "cursor", "budget", "wrapper"} {
		t.Run(mode, func(t *testing.T) {
			request := q
			bad := page
			bad.Records = append([][]byte(nil), page.Records...)
			source := "a"
			switch mode {
			case "source":
				source = "b"
			case "job":
				request.Intent.Job = "foreign"
			case "revision":
				request.Intent.Revision++
			case "publication":
				bad.Publication = strings.Repeat("a", 64)
			case "component":
				bad.Component = 12
			case "schema":
				var m automationCutMetadata
				json.Unmarshal(bad.Metadata, &m)
				m.SourceSchema = 75
				bad.Metadata, _ = json.Marshal(m)
			case "codec":
				var m automationCutMetadata
				json.Unmarshal(bad.Metadata, &m)
				m.Codec = 2
				bad.Metadata, _ = json.Marshal(m)
			case "section":
				var m automationCutMetadata
				json.Unmarshal(bad.Metadata, &m)
				m.Inventory[0].Section = "unknown"
				bad.Metadata, _ = json.Marshal(m)
			case "metadata":
				bad.Metadata = append(bytes.Clone(bad.Metadata), ' ')
			case "record":
				bad.Records[0] = []byte("invalid")
			case "duplicate":
				bad.Records = append(bad.Records, bad.Records[0])
				request.MaxRecords = 2
			case "reordered":
				next := q
				next.Cursor = page.Cursor
				bad, err = p.ExportAutomationSource(exportCtx, next)
				if err != nil {
					t.Fatal(err)
				}
			case "count":
				bad.TerminalRecords++
			case "bytes":
				bad.TerminalBytes++
			case "digest":
				bad.TerminalDigest = strings.Repeat("0", 64)
			case "terminal":
				bad.Terminal = true
				bad.Cursor = ""
			case "overflow":
				bad.TerminalRecords = math.MaxInt64
				bad.TerminalBytes = math.MaxInt64
			case "EOF":
				bad.Records = nil
			case "cursor":
				bad.Cursor = "!"
			case "budget":
				bad.Records = [][]byte{make([]byte, AutomationExportMaxBytes+1)}
			case "wrapper":
				bad.Metadata = make([]byte, maxAutomationCutMetadataBytes+1)
			}
			if _, err = r.Stage(ctx, a, source, request, bad); err == nil {
				t.Fatal("invalid bounded receiver page accepted")
			}
			if receiverStored(t, r.client) != stored || receiverActive(t, r.client) != active {
				t.Fatal("refused page made progress or mutated active state")
			}
		})
	}
	// Force the actual progress SQL to fail AFTER the record INSERT. All page
	// bytes must roll back with the progress; successful rollback is not SIGKILL.
	if _, err = r.client.db.Exec(`CREATE TRIGGER receiver_fail BEFORE INSERT ON local_automation_receiver_components WHEN NEW.component=3 BEGIN SELECT RAISE(ABORT,'injected progress failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Stage(ctx, a, "a", q, page); err == nil {
		t.Fatal("progress failure was ignored")
	}
	if receiverStored(t, r.client) != stored {
		t.Fatal("page bytes committed without progress")
	}
	if _, err = r.client.db.Exec(`DROP TRIGGER receiver_fail`); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Stage(ctx, a, "a", q, page); err != nil {
		t.Fatal("restored page could not progress", err)
	}
	after := receiverStored(t, r.client)
	bad := page
	bad.Metadata = append(bytes.Clone(bad.Metadata), ' ')
	if _, err = r.Stage(ctx, a, "a", q, bad); err == nil {
		t.Fatal("contradictory retry accepted")
	}
	if receiverStored(t, r.client) != after || receiverActive(t, r.client) != active {
		t.Fatal("retry changed progress/active state")
	}
}
func TestReceiverRejectsForgedPendingSignature(t *testing.T) {
	p, r, q, exportCtx, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	active := receiverActive(t, r.client)
	for component := uint32(0); component < 3; component++ {
		q.Component = component
		page, err := p.ExportAutomationSource(exportCtx, q)
		if err != nil || !page.Terminal {
			t.Fatal(err)
		}
		if component == 0 {
			var s sourceSignedArtifact
			if err = json.Unmarshal(page.Chunk, &s); err != nil {
				t.Fatal(err)
			}
			s.Signature[0] ^= 1
			page.Chunk, _ = json.Marshal(s)
			sum := sha256.Sum256(page.Chunk)
			page.TerminalDigest = hex.EncodeToString(sum[:])
			page.TerminalBytes = int64(len(page.Chunk))
		}
		before := receiverStored(t, r.client)
		_, err = r.Stage(ctx, a, "a", q, page)
		if component < 2 {
			if err != nil {
				t.Fatal("bounded pending metadata must remain inert until full authentication", err)
			}
		} else {
			if err == nil {
				t.Fatal("forged complete publication signature promoted")
			}
			if before != receiverStored(t, r.client) {
				t.Fatal("failed authentication advanced metadata or content")
			}
		}
	}
	if receiverActive(t, r.client) != active {
		t.Fatal("forged publication mutated active state")
	}
	rows, err := r.client.Query(ctx, `SELECT authenticated FROM local_automation_receiver_sources WHERE attempt=?`, a.id)
	if err != nil || len(rows) != 1 || rows[0].Int64("authenticated") != 0 {
		t.Fatal("forged pending source acquired authentication", err)
	}
}
func TestReceiverFullAndPrecommitFailure(t *testing.T) {
	for _, mode := range []string{"normal-sync", "cancel", "commit-error"} {
		t.Run(mode, func(t *testing.T) {
			p, r, q, exportCtx, _ := receiverFixture(t)
			ctx := context.Background()
			a, err := r.Begin(ctx, q.Intent, nil)
			if err != nil {
				t.Fatal(err)
			}
			page, err := p.ExportAutomationSource(exportCtx, q)
			if err != nil {
				t.Fatal(err)
			}
			active := receiverActive(t, r.client)
			stored := receiverStored(t, r.client)
			switch mode {
			case "normal-sync":
				r.client.db.SetMaxOpenConns(1)
				if _, err = r.client.db.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				r.seams = &localCommitSeams{beforeCommit: func(*sql.Tx) error { cancel(); return nil }}
			case "commit-error":
				r.seams = &localCommitSeams{beforeCommit: func(tx *sql.Tx) error {
					if err := tx.Rollback(); err != nil {
						return err
					}
					return nil
				}}
			}
			if _, err = r.Stage(ctx, a, "a", q, page); err == nil {
				t.Fatal("unguarded or failed FULL commit reported success")
			}
			if active != receiverActive(t, r.client) || stored != receiverStored(t, r.client) {
				t.Fatal("failed commit changed evidence or active state")
			}
		})
	}
}

func TestReceiverTerminalRechecksStoredRows(t *testing.T) {
	p, r, q, exportCtx, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, exportCtx, 2)
	q.Component = 3
	first, err := p.ExportAutomationSource(exportCtx, q)
	if err != nil || first.Terminal {
		t.Fatal(err)
	}
	if _, err = r.Stage(ctx, a, "a", q, first); err != nil {
		t.Fatal(err)
	}
	// Same-length, strictly decodable corruption of an earlier retained row.
	// The current signed cursor/counters alone cannot detect this change.
	changed := bytes.Clone(first.Records[0])
	changed[len(changed)-1] ^= 1
	if _, err = decodeSourceCutRow(0, 1, changed); err != nil {
		t.Fatal("fixture corruption broke framing", err)
	}
	if _, err = r.client.db.Exec(`UPDATE local_automation_receiver_records SET record=? WHERE attempt=? AND source='a' AND component=3 AND ordinal=1`, changed, a.id); err != nil {
		t.Fatal(err)
	}
	q.Cursor = first.Cursor
	last, err := p.ExportAutomationSource(exportCtx, q)
	if err != nil || !last.Terminal {
		t.Fatal(err)
	}
	before := receiverStored(t, r.client)
	active := receiverActive(t, r.client)
	if _, err = r.Stage(ctx, a, "a", q, last); err == nil {
		t.Fatal("terminal trusted counters instead of exact retained bytes")
	}
	if receiverStored(t, r.client) != before || receiverActive(t, r.client) != active {
		t.Fatal("failed terminal advanced rows or active state")
	}
}
func TestReceiverInventoryIndexedSeeks(t *testing.T) {
	_, r, _, _, _ := receiverFixture(t)
	for _, q := range []string{
		`SELECT ordinal,length(record) FROM local_automation_receiver_records WHERE attempt=? AND source=? AND component=? AND ordinal>? ORDER BY ordinal LIMIT 1`,
		`SELECT ordinal FROM local_automation_receiver_records WHERE attempt=? AND source=? AND component=? AND ordinal<=? LIMIT 1`,
		`SELECT component FROM local_automation_receiver_records WHERE attempt=? AND source=? AND component<? LIMIT 1`,
		`SELECT component FROM local_automation_receiver_records WHERE attempt=? AND source=? AND component>=? LIMIT 1`,
	} {
		args := []any{"attempt", "source", 0}
		if strings.Contains(q, "ordinal") {
			args = append(args, 0)
		}
		rows, err := r.client.Query(context.Background(), "EXPLAIN QUERY PLAN "+q, args...)
		if err != nil {
			t.Fatal(err)
		}
		var detail string
		for _, row := range rows {
			detail += row.String("detail")
		}
		if !strings.Contains(detail, "attempt=? AND source=? AND component") || strings.Contains(detail, "SCAN ") || strings.Contains(detail, "TEMP B-TREE") {
			t.Fatal("receiver query is not bounded indexed seek", detail)
		}
		if strings.Contains(q, "ordinal") && !strings.Contains(detail, "ordinal") {
			t.Fatal("receiver seek does not constrain ordinal", detail)
		}
	}
}
