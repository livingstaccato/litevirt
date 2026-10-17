package corrosion

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
)

// These witnesses mutate only retained SQLite storage after genuine signed
// publication/staging and a successful inert audit. Normal ingress cannot emit
// fractional component keys; exact stored-inventory validation must still refuse.
func TestReceiverSourceAuditFractionalRecord(t *testing.T) {
	receiverAuditFractionalComponent(t, "records")
}
func TestReceiverSourceAuditFractionalProgress(t *testing.T) {
	receiverAuditFractionalComponent(t, "components")
}
func receiverAuditFractionalComponent(t *testing.T, table string) {
	t.Helper()
	p, r, q, peer, _ := receiverAuditFixture(t, 3, nil)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, peer, 11)
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal("genuine initial audit", err)
	}
	active, derived, original := receiverActive(t, r.client), receiverAudited(t, r.client), receiverStored(t, r.client)
	query := `INSERT INTO local_automation_receiver_records(attempt,source,component,ordinal,record) SELECT attempt,source,3.5,1,record FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=0 AND ordinal=1`
	if table == "components" {
		query = `INSERT INTO local_automation_receiver_components(attempt,source,component,state,cursor,terminal) SELECT attempt,source,3.5,state,cursor,terminal FROM local_automation_receiver_components WHERE attempt=? AND source='a' AND component=0`
	}
	if _, err = r.client.db.Exec(query, a.id); err != nil {
		t.Fatal(err)
	}
	check := func() {
		rows, e := r.client.Query(ctx, `SELECT typeof(component) AS kind,component=3.5 AS exact FROM local_automation_receiver_`+table+` WHERE attempt=? AND source='a' AND component=3.5`, a.id)
		if e != nil || len(rows) != 1 || rows[0].String("kind") != "real" || rows[0].Int64("exact") != 1 {
			t.Fatal("fractional witness missing or repaired", e, rows)
		}
	}
	check()
	stored := receiverStored(t, r.client)
	err = r.AuditSource(ctx, a, "a")
	check()
	if receiverStored(t, r.client) != stored || receiverActive(t, r.client) != active || receiverAudited(t, r.client) != derived {
		t.Fatal("fractional audit changed spool/active/prior audit")
	}
	if _, e := r.client.db.Exec(`DELETE FROM local_automation_receiver_`+table+` WHERE attempt=? AND source='a' AND component=3.5`, a.id); e != nil {
		t.Fatal(e)
	}
	if receiverStored(t, r.client) != original {
		t.Fatal("test restore changed genuine rows/counters/root")
	}
	if e := r.AuditSource(ctx, a, "a"); e != nil || receiverAudited(t, r.client) != derived || receiverActive(t, r.client) != active {
		t.Fatal("exact valid retry", e)
	}
	if err == nil {
		t.Fatal("fractional stored component accepted", table)
	}
}
func TestReceiverSourceAuditMetadataText(t *testing.T) {
	p, r, q, peer, _ := receiverAuditFixture(t, 3, nil)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, peer, 11)
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal("genuine initial audit", err)
	}
	active, derived, original := receiverActive(t, r.client), receiverAudited(t, r.client), receiverStored(t, r.client)
	state := receiverAuditInstrument(t, r)
	for component := 0; component < 3; component++ {
		t.Run(fmt.Sprint(component), func(t *testing.T) {
			rows, e := r.client.Query(ctx, `SELECT record FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=? AND ordinal=1`, a.id, component)
			if e != nil || len(rows) != 1 {
				t.Fatal(e)
			}
			raw := bytes.Clone(rows[0].Bytes("record"))
			if _, e = r.client.db.Exec(`UPDATE local_automation_receiver_records SET record=CAST(record AS TEXT) WHERE attempt=? AND source='a' AND component=? AND ordinal=1`, a.id, component); e != nil {
				t.Fatal(e)
			}
			check := func() {
				rows, e := r.client.Query(ctx, `SELECT typeof(record) AS kind,CAST(record AS BLOB)=? AS exact FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=? AND ordinal=1`, raw, a.id, component)
				if e != nil || len(rows) != 1 || rows[0].String("kind") != "text" || rows[0].Int64("exact") != 1 {
					t.Fatal("same-byte TEXT witness missing or repaired", e, rows)
				}
			}
			check()
			stored := receiverStored(t, r.client)
			state.metadataBodies = [3]int{}
			state.enabled = true
			err := r.AuditSource(ctx, a, "a")
			state.enabled = false
			check()
			if receiverStored(t, r.client) != stored || receiverActive(t, r.client) != active || receiverAudited(t, r.client) != derived {
				t.Fatal("metadata audit changed spool/active/prior audit")
			}
			if _, e = r.client.db.Exec(`UPDATE local_automation_receiver_records SET record=? WHERE attempt=? AND source='a' AND component=? AND ordinal=1`, raw, a.id, component); e != nil {
				t.Fatal(e)
			}
			if receiverStored(t, r.client) != original {
				t.Fatal("test restore changed genuine metadata/counters/root")
			}
			if e = r.AuditSource(ctx, a, "a"); e != nil || receiverAudited(t, r.client) != derived || receiverActive(t, r.client) != active {
				t.Fatal("exact valid retry", e)
			}
			if err == nil {
				t.Fatal("same-byte metadata TEXT accepted", component)
			}
			if state.metadataBodies[component] != 0 || len(state.bad) != 0 {
				t.Fatal("metadata TEXT materialized before type refusal", component, state.metadataBodies, state.bad)
			}
		})
	}
}

// Malformed key probes must return a bounded scalar even when SQLite retains a
// multi-megabyte TEXT/BLOB key. Fixture snapshots/allocations below are test-only.
func TestReceiverSourceAuditMalformedKeysBounded(t *testing.T) {
	p, r, q, peer, _ := receiverAuditFixture(t, 3, nil)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, peer, 11)
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal(err)
	}
	active, derived, original := receiverActive(t, r.client), receiverAudited(t, r.client), receiverStored(t, r.client)
	state := receiverAuditInstrument(t, r)
	cases := []struct {
		name string
		key  any
	}{
		{"negative", -1}, {"negative-fraction", -0.5}, {"first-gap", 0.5}, {"middle-gap", 3.5}, {"last-gap", 11.5}, {"past-end", 12},
		{"large-text", strings.Repeat("x", 4<<20)}, {"large-blob", bytes.Repeat([]byte{0}, 4<<20)},
	}
	for _, table := range []string{"records", "components"} {
		for _, c := range cases {
			t.Run(table+"/"+c.name, func(t *testing.T) {
				query := `INSERT INTO local_automation_receiver_records(attempt,source,component,ordinal,record) SELECT attempt,source,?,1,record FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=0 AND ordinal=1`
				if table == "components" {
					query = `INSERT INTO local_automation_receiver_components(attempt,source,component,state,cursor,terminal) SELECT attempt,source,?,state,cursor,terminal FROM local_automation_receiver_components WHERE attempt=? AND source='a' AND component=0`
				}
				if _, err = r.client.db.Exec(query, c.key, a.id); err != nil {
					t.Fatal(err)
				}
				stored := receiverStored(t, r.client)
				state.maxBytes = 0
				state.maxRows = 0
				state.componentQueries = 0
				state.enabled = true
				err = r.AuditSource(ctx, a, "a")
				state.enabled = false
				if err == nil {
					t.Fatal("malformed component accepted", table, c.name)
				}
				if len(state.bad) != 0 || state.maxRows > 1 || state.maxBytes > AutomationExportChunkBytes || state.componentQueries > 26 {
					t.Fatal("malformed raw key materialized or non-indexed traversal", state.bad, state.maxRows, state.maxBytes, state.componentQueries)
				}
				if receiverStored(t, r.client) != stored || receiverActive(t, r.client) != active || receiverAudited(t, r.client) != derived {
					t.Fatal("malformed key refusal repaired storage")
				}
				if _, err = r.client.db.Exec(`DELETE FROM local_automation_receiver_`+table+` WHERE attempt=? AND source='a' AND component=?`, a.id, c.key); err != nil {
					t.Fatal(err)
				}
				if receiverStored(t, r.client) != original {
					t.Fatal("test restoration changed genuine spool")
				}
				if err = r.AuditSource(ctx, a, "a"); err != nil || receiverAudited(t, r.client) != derived || receiverActive(t, r.client) != active {
					t.Fatal("valid retry", err)
				}
			})
		}
	}
	for query, plan := range state.plans {
		if strings.HasPrefix(query, "SELECT CASE WHEN typeof(component)") {
			if !strings.Contains(plan, "component>?") {
				t.Fatal("component walk lacks indexed range", plan)
			}
			t.Logf("actual component key SQL %s => %s", query, plan)
		}
	}
}
func TestReceiverSourceAuditMalformedOrdinalBounded(t *testing.T) {
	p, r, q, peer, _ := receiverAuditFixture(t, 3, nil)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, peer, 11)
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal(err)
	}
	active, derived, original := receiverActive(t, r.client), receiverAudited(t, r.client), receiverStored(t, r.client)
	state := receiverAuditInstrument(t, r)
	for _, component := range []int{0, 5} {
		for _, kind := range []string{"fraction", "large-text", "large-blob"} {
			t.Run(fmt.Sprint(component)+"/"+kind, func(t *testing.T) {
				var key any = 1.5
				if kind == "large-text" {
					key = strings.Repeat("x", 4<<20)
				}
				if kind == "large-blob" {
					key = bytes.Repeat([]byte{0}, 4<<20)
				}
				if _, err = r.client.db.Exec(`INSERT INTO local_automation_receiver_records(attempt,source,component,ordinal,record) SELECT attempt,source,component,?,record FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=? AND ordinal=1`, key, a.id, component); err != nil {
					t.Fatal(err)
				}
				stored := receiverStored(t, r.client)
				state.maxBytes = 0
				state.maxRows = 0
				state.enabled = true
				err = r.AuditSource(ctx, a, "a")
				state.enabled = false
				if err == nil {
					t.Fatal("malformed ordinal accepted")
				}
				if len(state.bad) != 0 || state.maxRows > 1 || state.maxBytes > AutomationExportChunkBytes {
					t.Fatal("malformed ordinal materialized", state.bad, state.maxRows, state.maxBytes)
				}
				if receiverStored(t, r.client) != stored || receiverActive(t, r.client) != active || receiverAudited(t, r.client) != derived {
					t.Fatal("ordinal refusal repaired storage")
				}
				if _, err = r.client.db.Exec(`DELETE FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=? AND ordinal=?`, a.id, component, key); err != nil {
					t.Fatal(err)
				}
				if receiverStored(t, r.client) != original {
					t.Fatal("test restoration changed genuine spool")
				}
				if err = r.AuditSource(ctx, a, "a"); err != nil || receiverAudited(t, r.client) != derived || receiverActive(t, r.client) != active {
					t.Fatal("valid retry", err)
				}
			})
		}
	}
}

func TestReceiverSourceAuditMetadataLengthBeforeBody(t *testing.T) {
	p, r, q, peer, _ := receiverAuditFixture(t, 3, nil)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, peer, 11)
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal(err)
	}
	active, derived, original := receiverActive(t, r.client), receiverAudited(t, r.client), receiverStored(t, r.client)
	state := receiverAuditInstrument(t, r)
	for component := 0; component < 3; component++ {
		for _, kind := range []string{"blob", "text-nul", "text-multibyte"} {
			t.Run(fmt.Sprint(component)+"/"+kind, func(t *testing.T) {
				rows, e := r.client.Query(ctx, `SELECT record FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=? AND ordinal=1`, a.id, component)
				if e != nil || len(rows) != 1 {
					t.Fatal(e)
				}
				raw := bytes.Clone(rows[0].Bytes("record"))
				var bad any = bytes.Repeat([]byte{'x'}, AutomationExportChunkBytes+1)
				if kind == "text-nul" {
					bad = "x\x00" + strings.Repeat("x", AutomationExportChunkBytes)
				}
				if kind == "text-multibyte" {
					bad = strings.Repeat("界", AutomationExportChunkBytes)
				}
				if _, err = r.client.db.Exec(`UPDATE local_automation_receiver_records SET record=? WHERE attempt=? AND source='a' AND component=? AND ordinal=1`, bad, a.id, component); err != nil {
					t.Fatal(err)
				}
				check := func() {
					rows, e := r.client.Query(ctx, `SELECT typeof(record) AS kind,length(CAST(record AS BLOB)) AS bytes FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=? AND ordinal=1`, a.id, component)
					want := "text"
					if kind == "blob" {
						want = "blob"
					}
					if e != nil || len(rows) != 1 || rows[0].String("kind") != want || rows[0].Int64("bytes") <= AutomationExportChunkBytes {
						t.Fatal("oversized metadata witness missing/repaired", e, rows)
					}
				}
				check()
				stored := receiverStored(t, r.client)
				state.maxBytes = 0
				state.maxRows = 0
				state.metadataBodies = [3]int{}
				state.enabled = true
				err = r.AuditSource(ctx, a, "a")
				state.enabled = false
				if err == nil {
					t.Fatal("oversized metadata accepted")
				}
				if len(state.bad) != 0 || state.maxRows > 1 || state.maxBytes > AutomationExportChunkBytes || state.metadataBodies[component] != 0 {
					t.Fatal("metadata body materialized before refusal", state.bad, state.maxRows, state.maxBytes, state.metadataBodies)
				}
				check()
				if receiverStored(t, r.client) != stored || receiverActive(t, r.client) != active || receiverAudited(t, r.client) != derived {
					t.Fatal("metadata refusal repaired storage")
				}
				if _, err = r.client.db.Exec(`UPDATE local_automation_receiver_records SET record=? WHERE attempt=? AND source='a' AND component=? AND ordinal=1`, raw, a.id, component); err != nil {
					t.Fatal(err)
				}
				if receiverStored(t, r.client) != original {
					t.Fatal("test restoration changed genuine spool")
				}
				if err = r.AuditSource(ctx, a, "a"); err != nil || receiverAudited(t, r.client) != derived || receiverActive(t, r.client) != active {
					t.Fatal("valid retry", err)
				}
			})
		}
	}
}
