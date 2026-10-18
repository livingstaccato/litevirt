package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"testing"
)

func TestReceiverSourceAuditAllNineStoredSections(t *testing.T) {
	p, r, q, peer, _ := receiverAuditFixtureOptions(t, 3, receiverAuditOptions{explicitSeal: true, beforeApply: func(a *claimTestVoter, v []*claimTestVoter, record AutomationRecord) {
		receiverAuditClaimSeed(t, a, v, record)
	}})
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	q.MaxRecords = 7
	receiverThrough(t, p, r, a, q, peer, 11)
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal("complete all-nine positive", err)
	}
	active, derived := receiverActive(t, r.client), receiverAudited(t, r.client)
	for component := 3; component < 12; component++ {
		t.Run(fmt.Sprint(component), func(t *testing.T) {
			rows, err := r.client.Query(ctx, `SELECT record FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=? AND ordinal=1`, a.id, component)
			if err != nil || len(rows) != 1 {
				t.Fatal("genuine section missing", component, err)
			}
			original := bytes.Clone(rows[0].Bytes("record"))
			for _, mode := range []string{"missing", "same-length-tamper", "extra", "wrong-type"} {
				t.Run(mode, func(t *testing.T) {
					switch mode {
					case "missing":
						_, err = r.client.db.Exec(`DELETE FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=? AND ordinal=1`, a.id, component)
					case "same-length-tamper":
						bad := bytes.Clone(original)
						bad[len(bad)-1] ^= 1
						_, err = r.client.db.Exec(`UPDATE local_automation_receiver_records SET record=? WHERE attempt=? AND source='a' AND component=? AND ordinal=1`, bad, a.id, component)
					case "extra":
						_, err = r.client.db.Exec(`INSERT INTO local_automation_receiver_records(attempt,source,component,ordinal,record) VALUES(?,'a',?,9999,?)`, a.id, component, original)
					case "wrong-type":
						_, err = r.client.db.Exec(`UPDATE local_automation_receiver_records SET record=? WHERE attempt=? AND source='a' AND component=? AND ordinal=1`, string(original), a.id, component)
					}
					if err != nil {
						t.Fatal(err)
					}
					stored := receiverStored(t, r.client)
					if err = r.AuditSource(ctx, a, "a"); err == nil {
						t.Fatal("stored section corruption trusted unchanged counters", component, mode)
					}
					if receiverStored(t, r.client) != stored || receiverAudited(t, r.client) != derived || receiverActive(t, r.client) != active {
						t.Fatal("failed audit changed progress/derived/active state")
					}
					if _, err = r.client.db.Exec(`DELETE FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=? AND ordinal=9999`, a.id, component); err != nil {
						t.Fatal(err)
					}
					if _, err = r.client.db.Exec(`INSERT OR REPLACE INTO local_automation_receiver_records(attempt,source,component,ordinal,record) VALUES(?,'a',?,1,?)`, a.id, component, original); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
	if err = r.AuditSource(ctx, a, "a"); err != nil || receiverAudited(t, r.client) != derived {
		t.Fatal("exact restored retry changed audit", err)
	}
}

func TestReceiverSourceAuditProgressRecomputed(t *testing.T) {
	p, r, q, peer, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, peer, 11)
	rows, err := r.client.Query(ctx, `SELECT state FROM local_automation_receiver_components WHERE attempt=? AND source='a' AND component=3`, a.id)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	original := bytes.Clone(rows[0].Bytes("state"))
	active, derived := receiverActive(t, r.client), receiverAudited(t, r.client)
	for _, mode := range []string{"count", "bytes", "position", "digest", "overflow", "binding"} {
		t.Run(mode, func(t *testing.T) {
			var state sourceExportCursor
			if err = json.Unmarshal(original, &state); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "count":
				state.TotalRecords++
			case "bytes":
				state.TotalBytes++
			case "position":
				state.Position--
			case "digest":
				state.Digest[0] ^= 1
			case "overflow":
				state.TotalRecords = math.MaxInt64
			case "binding":
				state.Binding[0] ^= 1
			}
			raw, _ := json.Marshal(state)
			if _, err = r.client.db.Exec(`UPDATE local_automation_receiver_components SET state=? WHERE attempt=? AND source='a' AND component=3`, raw, a.id); err != nil {
				t.Fatal(err)
			}
			if err = r.AuditSource(ctx, a, "a"); err == nil {
				t.Fatal("forged terminal progress audited", mode)
			}
			if receiverAudited(t, r.client) != derived || receiverActive(t, r.client) != active {
				t.Fatal("forged progress changed active/derived state")
			}
		})
	}
}

func TestReceiverSourceAuditReopenInertEvidence(t *testing.T) {
	p, r, q, peer, dir := receiverAuditFixture(t, 3, nil)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, peer, 11)
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal(err)
	}
	active, stored, derived := receiverActive(t, r.client), receiverStored(t, r.client), receiverAudited(t, r.client)
	if err = r.client.Close(); err != nil {
		t.Fatal(err)
	}
	client, err := NewLocalClient(dir, "b")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	client.SetVoterConfigGate(func() bool { return true })
	if receiverActive(t, client) != active || receiverStored(t, client) != stored || receiverAudited(t, client) != derived {
		t.Fatal("actual file reopen changed durable inert evidence")
	}
	fresh := NewAutomationReceiver(client, r.dir)
	if err = fresh.AuditSource(ctx, a, "a"); err == nil {
		t.Fatal("durable audit revived a foreign process-owned attempt")
	}
	current, err := fresh.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal("actual current reauthorization after reopen", err)
	}
	if err = fresh.AuditSource(ctx, current, "a"); err != nil {
		t.Fatal("fresh reauthentication and full evidence audit", err)
	}
	if receiverActive(t, client) != active || receiverAudited(t, client) != derived {
		t.Fatal("reopened fresh audit changed active state or exact derived evidence")
	}
}

func TestReceiverSourceAuditExistingResultIdentity(t *testing.T) {
	p, r, q, peer, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, peer, 11)
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err = r.client.db.Exec(`UPDATE local_automation_receiver_audits SET root='foreign' WHERE attempt=?`, a.id); err != nil {
		t.Fatal(err)
	}
	active, derived := receiverActive(t, r.client), receiverAudited(t, r.client)
	if err = r.AuditSource(ctx, a, "a"); err == nil {
		t.Fatal("existing audit identity drift accepted")
	}
	if receiverActive(t, r.client) != active || receiverAudited(t, r.client) != derived {
		t.Fatal("identity refusal changed active/derived state")
	}
}

func TestReceiverSourceAuditArchivedDescriptors(t *testing.T) {
	for _, schema := range []int{69, 70, 71, 72, 73} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			p, r, q, peer, _ := receiverAuditFixture(t, 3, func(a *claimTestVoter, _ []*claimTestVoter) {
				if _, err := a.c.db.Exec(`UPDATE schema_state SET version=? WHERE id=1`, schema); err != nil {
					t.Fatal(err)
				}
			})
			ctx := context.Background()
			original, err := p.client.Query(ctx, `SELECT id,metadata,root FROM local_automation_cuts WHERE generation=1`)
			if err != nil || len(original) != 1 {
				t.Fatal(err)
			}
			meta, err := readAutomationCutMetadata(original[0])
			if err != nil || meta.SourceSchema != schema {
				t.Fatal("actual archived descriptor", err)
			}
			a, err := r.Begin(ctx, q.Intent, nil)
			if err != nil {
				t.Fatal(err)
			}
			receiverThrough(t, p, r, a, q, peer, 11)
			active := receiverActive(t, r.client)
			if err = r.AuditSource(ctx, a, "a"); err != nil {
				t.Fatal("original archived descriptor refused by schema73 audit", err)
			}
			rows, err := r.client.Query(ctx, `SELECT metadata FROM local_automation_receiver_sources WHERE attempt=? AND source='a'`, a.id)
			if err != nil || len(rows) != 1 || !bytes.Equal(rows[0].Bytes("metadata"), original[0].Bytes("metadata")) {
				t.Fatal("archive relabeled or root bytes replaced", err)
			}
			if receiverActive(t, r.client) != active {
				t.Fatal("archived source audit changed active state")
			}
		})
	}
}
