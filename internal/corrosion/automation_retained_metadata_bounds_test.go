package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestRetainedMetadataLengthBeforeBodyAndKeysets(t *testing.T) {
	_, r, q, _, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, entries := retainedPendingPages(t, a)
	h, err := decodeRetainedHolder(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.stageRetained(ctx, a, raw, retainedPage{Records: entries, Terminal: true}); err != nil {
		t.Fatal(err)
	}
	active := receiverActive(t, r.client)
	reads := aggregateInstrument(t, r)
	tx0, err := r.client.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx0.Rollback()
	tx := &LocalTx{tx: tx0}
	// Deliberately invalid completion metadata tests only typed reading. It is
	// never a successful completion, receipt, adopted donor or private proof.
	if _, err = tx0.Exec(`INSERT INTO local_automation_retained_completions VALUES(?,?,x'7b7d',?)`, h.id, strings.Repeat("a", 64), strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	read := func(kind string) error {
		switch kind {
		case "delivery":
			_, _, err := retainedDeliveryTx(ctx, tx, h.id)
			return err
		case "object":
			_, _, _, err := retainedObjectTx(ctx, tx, h.id, 1)
			return err
		default:
			_, _, err := retainedCompletionTx(ctx, tx, h.id)
			return err
		}
	}
	for _, kind := range []string{"delivery", "object"} {
		if err = read(kind); err != nil {
			t.Fatal("real pinned metadata control", kind, err)
		}
	}
	cases := []struct {
		name, kind, query string
		args              []any
	}{
		{"delivery-attempt-blob", "delivery", `UPDATE local_automation_retained_deliveries SET attempt=CAST(attempt AS BLOB)`, nil},
		{"delivery-attempt-length", "delivery", `UPDATE local_automation_retained_deliveries SET attempt='short'`, nil},
		{"delivery-envelope-text", "delivery", `UPDATE local_automation_retained_deliveries SET envelope=CAST(envelope AS TEXT)`, nil},
		{"delivery-envelope-empty", "delivery", `UPDATE local_automation_retained_deliveries SET envelope=x''`, nil},
		{"delivery-envelope-overbound", "delivery", `UPDATE local_automation_retained_deliveries SET envelope=zeroblob(?)`, []any{maxSourceArtifactBytes + 1}},
		{"object-namespace-blob", "object", `UPDATE local_automation_retained_objects SET namespace=CAST(namespace AS BLOB) WHERE ordinal=1`, nil},
		{"object-namespace-overbound", "object", `UPDATE local_automation_retained_objects SET namespace=? WHERE ordinal=1`, []any{strings.Repeat("x", 97)}},
		{"object-descriptor-text", "object", `UPDATE local_automation_retained_objects SET descriptor=CAST(descriptor AS TEXT) WHERE ordinal=1`, nil},
		{"object-descriptor-empty", "object", `UPDATE local_automation_retained_objects SET descriptor=x'' WHERE ordinal=1`, nil},
		{"object-descriptor-overbound", "object", `UPDATE local_automation_retained_objects SET descriptor=zeroblob(?) WHERE ordinal=1`, []any{maxAutomationCutMetadataBytes + 1}},
		{"completion-evidence-blob", "completion", `UPDATE local_automation_retained_completions SET evidence_digest=CAST(evidence_digest AS BLOB)`, nil},
		{"completion-evidence-length", "completion", `UPDATE local_automation_retained_completions SET evidence_digest='short'`, nil},
		{"completion-candidate-text", "completion", `UPDATE local_automation_retained_completions SET candidate_ref='{}'`, nil},
		{"completion-candidate-empty", "completion", `UPDATE local_automation_retained_completions SET candidate_ref=x''`, nil},
		{"completion-candidate-overbound", "completion", `UPDATE local_automation_retained_completions SET candidate_ref=zeroblob(?)`, []any{maxAutomationCutMetadataBytes + 1}},
		{"completion-coverage-blob", "completion", `UPDATE local_automation_retained_completions SET coverage_digest=CAST(coverage_digest AS BLOB)`, nil},
		{"completion-coverage-length", "completion", `UPDATE local_automation_retained_completions SET coverage_digest='short'`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err = tx0.Exec(`SAVEPOINT metadata_corrupt`); err != nil {
				t.Fatal(err)
			}
			if _, err = tx0.Exec(tc.query, tc.args...); err != nil {
				t.Fatal(err)
			}
			reads.queries, reads.probes, reads.bodies = 0, 0, 0
			reads.enabled = true
			err = read(tc.kind)
			reads.enabled = false
			if err == nil {
				t.Fatal("malformed metadata accepted")
			}
			if reads.probes != 1 || reads.bodies != 0 {
				t.Fatal("invalid shape fetched body before refusal", reads.probes, reads.bodies)
			}
			if _, err = tx0.Exec(`ROLLBACK TO metadata_corrupt`); err != nil {
				t.Fatal(err)
			}
			if _, err = tx0.Exec(`RELEASE metadata_corrupt`); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, tc := range []struct{ name, table, query string }{
		{"delivery-first-null-key", "local_automation_retained_deliveries", `INSERT INTO local_automation_retained_deliveries VALUES(NULL,'bad',zeroblob(3000000))`},
		{"delivery-last-blob-key", "local_automation_retained_deliveries", `INSERT INTO local_automation_retained_deliveries VALUES(x'ffff','bad',zeroblob(3000000))`},
		{"object-fractional-key", "local_automation_retained_objects", `INSERT INTO local_automation_retained_objects SELECT delivery,1.5,'foreign',zeroblob(3000000) FROM local_automation_retained_objects LIMIT 1`},
		{"completion-first-null-key", "local_automation_retained_completions", `INSERT INTO local_automation_retained_completions VALUES(NULL,'bad',zeroblob(3000000),'bad')`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err = tx0.Exec(`SAVEPOINT metadata_keys`); err != nil {
				t.Fatal(err)
			}
			if _, err = tx0.Exec(tc.query); err != nil {
				t.Fatal(err)
			}
			var descriptor aggregateLocalTable
			for _, d := range currentEvidenceTables() {
				if d.table == tc.table {
					descriptor = d
				}
			}
			if descriptor.table == "" {
				t.Fatal("actual production evidence table missing")
			}
			reads.maxBytes = 0
			reads.enabled = true
			err = retainedHashScopedTable(ctx, tx, sha256.New(), descriptor, "", nil, nil)
			reads.enabled = false
			if err == nil {
				t.Fatal("malformed first/late key skipped by complete keyset")
			}
			if reads.maxBytes >= 1<<20 {
				t.Fatal("malformed key body materialized", reads.maxBytes)
			}
			if _, err = tx0.Exec(`ROLLBACK TO metadata_keys`); err != nil {
				t.Fatal(err)
			}
			if _, err = tx0.Exec(`RELEASE metadata_keys`); err != nil {
				t.Fatal(err)
			}
		})
	}
	if len(reads.bad) > 0 || reads.maxRows > 1 {
		t.Fatal("metadata query bounds", reads.bad, reads.maxRows)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err = retainedDeliveryTx(cancelled, tx, h.id); !errors.Is(err, context.Canceled) {
		t.Fatal("context error lost", err)
	}
	if err = tx0.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, _, err = retainedDeliveryTx(ctx, tx, h.id); !errors.Is(err, sql.ErrTxDone) {
		t.Fatal("SQL error lost", err)
	}
	if receiverActive(t, r.client) != active {
		t.Fatal("metadata refusal changed ACTIVE")
	}
	t.Logf("actual metadata plans=%d maxRows=%d; all17 malformed fields refused before body; four first/late key corruptions refused", len(reads.plans), reads.maxRows)
}

func TestRetainedMetadataFramesProbeBeforeBody(t *testing.T) {
	_, r, _, _, _ := receiverFixture(t)
	ctx := context.Background()
	active := receiverActive(t, r.client)
	reads := aggregateInstrument(t, r)
	for _, tc := range []struct {
		kind   string
		object int64
		bytes  int
	}{
		{"source", 1, AutomationExportChunkBytes + 1},
		{"native", 2, maxAutomationCutMetadataBytes + 1},
		{"receipt", 3, maxRetainedReceiptBytes + 1},
		{"directory", 0, maxAutomationCutMetadataBytes + 1},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			tx0, err := r.client.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx0.Rollback()
			tx := &LocalTx{tx: tx0}
			kind := tc.kind
			if kind == "directory" {
				kind = "receipt"
			}
			d := retainedDescriptorInput(kind)
			sections, limits, stream := retainedObjectSections(kind)
			d.ComponentInventories = nil
			if kind == "native" {
				d.OriginalIdentity = strings.Repeat("a", 32)
			}
			for i, section := range sections {
				inv := automationCutInventory{Section: section, Codec: 1}
				h := sha256.New()
				if limits[i] > 0 {
					inv.Records = 1
					inv.Bytes = 1
					h.Write([]byte("x"))
				} else {
					frame, _ := automationCutFrame("section/v1", []byte(section))
					h.Write(frame)
				}
				inv.Digest = hex.EncodeToString(h.Sum(nil))
				d.ComponentInventories = append(d.ComponentInventories, inv)
			}
			encoded, _ := json.Marshal(d)
			if _, err = decodeRetainedObject(encoded); err != nil {
				t.Fatal("valid descriptor prerequisite", err)
			}
			address, err := retainedAddress(strings.Repeat("b", 64), tc.object, d.Source, d.OriginalIdentity, stream)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx0.Exec(`INSERT INTO local_automation_receiver_records VALUES(?,?,0,1,zeroblob(?))`, address.namespace, address.source, tc.bytes); err != nil {
				t.Fatal(err)
			}
			reads.maxBytes = 0
			reads.enabled = true
			if tc.kind == "directory" {
				_, err = address.read(ctx, tx, 0, 1)
			} else {
				err = address.walk(ctx, tx, d, nil)
			}
			reads.enabled = false
			if err == nil {
				t.Fatal("over-bound metadata frame accepted")
			}
			if reads.maxBytes != 0 {
				t.Fatalf("over-bound %s frame fetched before narrow probe: %d bytes", tc.kind, reads.maxBytes)
			}
			if err = tx0.Rollback(); err != nil {
				t.Fatal(err)
			}
			if receiverActive(t, r.client) != active {
				t.Fatal("frame refusal changed ACTIVE")
			}
		})
	}
}
