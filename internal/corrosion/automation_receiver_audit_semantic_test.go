package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// Deliberate test-only corruption of an already genuine immutable source cut.
// Recompute framing/inventory/root, then use the REAL source publication owner
// and receiver ingress. This is an authenticated semantic-corruption fixture,
// not a claim that the normal source freezer emits invalid history.
func receiverAuditChangeCut(t *testing.T, p *AutomationSourcePreparer, q *AutomationExportRequest, section int, change func([]Row) []Row) {
	t.Helper()
	ctx := context.Background()
	rows, err := p.client.Query(ctx, `SELECT id,metadata,root FROM local_automation_cuts WHERE generation=?`, q.Intent.Generation)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	metadata, err := readAutomationCutMetadata(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	var records []Row
	rows, err = p.client.Query(ctx, `SELECT ordinal,record FROM local_automation_cut_records WHERE cut_id=? AND section=? ORDER BY ordinal`, metadata.ID, section)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		record, e := decodeSourceCutRow(section, row.Int64("ordinal"), row.Bytes("record"))
		if e != nil {
			t.Fatal(e)
		}
		records = append(records, record)
	}
	records = change(records)
	if _, err = p.client.db.Exec(`DELETE FROM local_automation_cut_records WHERE cut_id=? AND section=?`, metadata.ID, section); err != nil {
		t.Fatal(err)
	}
	inv := automationCutInventory{Section: automationCutSections[section].name, Codec: 1}
	h := sha256.New()
	prefix, _ := automationCutFrame("section/v1", []byte(inv.Section))
	h.Write(prefix)
	for i, row := range records {
		raw, e := encodeAutomationCutRecord(inv.Section, int64(i+1), row)
		if e != nil {
			t.Fatal(e)
		}
		if e = addAutomationCutSize(&inv, len(raw)); e != nil {
			t.Fatal(e)
		}
		h.Write(raw)
		if _, e = p.client.db.Exec(`INSERT INTO local_automation_cut_records(cut_id,section,ordinal,record) VALUES(?,?,?,?)`, metadata.ID, section, i+1, raw); e != nil {
			t.Fatal(e)
		}
	}
	inv.Digest = hex.EncodeToString(h.Sum(nil))
	metadata.Inventory[section] = inv
	raw, root, err := automationCutRoot(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.client.db.Exec(`UPDATE local_automation_cuts SET metadata=?,root=? WHERE id=?`, raw, root, metadata.ID); err != nil {
		t.Fatal(err)
	}
	q.Intent.Revision++
	candidate, err := p.Prepare(ctx, q.Intent)
	if err != nil {
		t.Fatal("corruption did not reach actual producer publication boundary", err)
	}
	q.Publication, err = p.Publish(ctx, candidate)
	if err != nil {
		t.Fatal("actual signed corrupt publication", err)
	}
}
func receiverAuditSet(t *testing.T, row *Row, column string, value any) {
	t.Helper()
	for i, name := range row.Columns {
		if name == column {
			row.Values[i] = value
			return
		}
	}
	t.Fatal("missing fixture column", column)
}

func TestReceiverSourceAuditMissingOriginal(t *testing.T) {
	p, r, q, peer, _ := receiverAuditFixture(t, 3, nil)
	receiverAuditChangeCut(t, p, &q, 4, func(rows []Row) []Row { return rows[:0] })
	receiverAuditSemanticRefusal(t, p, r, q, peer, "expected original request missing")
}
func TestReceiverSourceAuditDuplicateReceipt(t *testing.T) {
	p, r, q, peer, _ := receiverAuditFixture(t, 3, nil)
	receiverAuditChangeCut(t, p, &q, 2, func(rows []Row) []Row {
		var receipt contract.Receipt
		if err := json.Unmarshal([]byte(rows[2].String("receipt_json")), &receipt); err != nil {
			t.Fatal(err)
		}
		receipt.OperationID = "forged-duplicate-operation"
		raw, _ := json.Marshal(receipt)
		receiverAuditSet(t, &rows[2], "receipt_json", string(raw))
		return rows
	})
	receiverAuditSemanticRefusal(t, p, r, q, peer, "receipt drift")
}
func receiverAuditSemanticRefusal(t *testing.T, p *AutomationSourcePreparer, r *AutomationReceiver, q AutomationExportRequest, peer context.Context, reason string) {
	t.Helper()
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, peer, 11)
	active, stored, derived := receiverActive(t, r.client), receiverStored(t, r.client), receiverAudited(t, r.client)
	err = r.AuditSource(ctx, a, "a")
	if err == nil {
		t.Fatal("authenticated semantic corruption audited", reason)
	}
	if reason != "" && !strings.Contains(err.Error(), reason) {
		t.Fatal("refused before intended semantic gate", reason, err)
	}
	if receiverActive(t, r.client) != active || receiverStored(t, r.client) != stored || receiverAudited(t, r.client) != derived {
		t.Fatal("semantic refusal repaired source evidence or changed active state")
	}
}

func TestReceiverSourceAuditSemanticRefusals(t *testing.T) {
	for _, mode := range []string{"history-digest", "history-receipt", "missing-anchor", "anchor-target", "anchor-signature", "extra-request", "request-identity", "request-operation", "authority-lifetime", "authority-bootstrap", "authority-missing", "claim-signature", "claim-generation", "claim-duplicate", "authority-type"} {
		t.Run(mode, func(t *testing.T) {
			p, r, q, peer, _ := receiverAuditFixture(t, 3, nil)
			section := 2
			switch mode {
			case "missing-anchor", "anchor-target", "anchor-signature":
				section = 3
			case "extra-request", "request-identity", "request-operation":
				section = 4
			case "authority-lifetime", "authority-bootstrap", "authority-missing", "authority-type":
				section = 5
			case "claim-signature", "claim-generation", "claim-duplicate":
				section = 0
			}
			receiverAuditChangeCut(t, p, &q, section, func(rows []Row) []Row {
				switch mode {
				case "history-digest":
					receiverAuditSet(t, &rows[1], "digest", strings.Repeat("0", 64))
				case "history-receipt":
					var receipt contract.Receipt
					json.Unmarshal([]byte(rows[0].String("receipt_json")), &receipt)
					receipt.ResourceUID = "wrong"
					raw, _ := json.Marshal(receipt)
					receiverAuditSet(t, &rows[0], "receipt_json", string(raw))
				case "missing-anchor":
					return rows[1:]
				case "anchor-target":
					receiverAuditSet(t, &rows[0], "generation", int64(2))
				case "anchor-signature":
					cert, _ := sourceCertificate(rows[0].String("certificate"))
					for i := range cert.Accepts {
						cert.Accepts[i].Signature = []byte("invalid")
					}
					raw, _ := cert.Encode()
					receiverAuditSet(t, &rows[0], "certificate", raw)
				case "extra-request":
					extra := Row{Columns: append([]string(nil), rows[0].Columns...), Values: append([]any(nil), rows[0].Values...)}
					receiverAuditSet(t, &extra, "request_id", "orphan")
					receiverAuditSet(t, &extra, "operation_id", "orphan-operation")
					rows = append(rows, extra)
				case "request-identity":
					receiverAuditSet(t, &rows[0], "identity", []byte(`{"wrong":true}`))
				case "request-operation":
					receiverAuditSet(t, &rows[0], "operation_id", "wrong")
				case "authority-lifetime":
					receiverAuditSet(t, &rows[0], "incarnation", "foreign")
				case "authority-bootstrap":
					receiverAuditSet(t, &rows[0], "bootstrap_request", "invented")
				case "authority-missing":
					return nil
				case "authority-type":
					receiverAuditSet(t, &rows[0], "generation", "1")
				case "claim-duplicate":
					return append(rows, rows[0])
				case "claim-signature":
					var accept ClaimAccept
					json.Unmarshal([]byte(rows[0].String("accept_json")), &accept)
					accept.Signature = []byte("invalid")
					raw, _ := json.Marshal(accept)
					receiverAuditSet(t, &rows[0], "accept_json", string(raw))
				case "claim-generation":
					receiverAuditSet(t, &rows[0], "config_generation", int64(99))
				}
				return rows
			})
			receiverAuditSemanticRefusal(t, p, r, q, peer, "")
		})
	}
}

func TestReceiverSourceAuditNativeRecovery(t *testing.T) {
	p, r, q, peer, _ := receiverAuditFixtureOptions(t, 3, receiverAuditOptions{recovery: true})
	rows, err := p.client.Query(context.Background(), `SELECT anchor_sequence FROM local_automation_history WHERE sequence=1`)
	if err != nil || len(rows) != 1 || rows[0].Int64("anchor_sequence") != 3 {
		t.Fatal("not real higher-target native recovery", err)
	}
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, peer, 11)
	active := receiverActive(t, r.client)
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal("real certified native recovery refused", err)
	}
	if receiverActive(t, r.client) != active {
		t.Fatal("native recovery audit activated receiver")
	}
	t.Log(fmt.Sprintf("native covered slot 1 retained exact target 3; immutable source publication %s", q.Publication))
}

func TestReceiverSourceAuditEmptyHeadNativeAuthority(t *testing.T) {
	for _, mode := range []string{"accepted-present", "promise-present", "accepted-missing", "promise-missing", "accepted-bootstrap-drift"} {
		t.Run(mode, func(t *testing.T) {
			p, r, q, peer, _ := receiverAuditFixture(t, 0, func(a *claimTestVoter, voters []*claimTestVoter) {
				ctx := context.Background()
				key, _ := AutomationClaimKey(1)
				installAutomationEvidence(t, a.c, key, "", 1)
				if strings.HasPrefix(mode, "promise") {
					reply, err := a.c.ClaimPrepare(ctx, key, testBallot(2, "a"), 1)
					if err != nil || !reply.Promised {
						t.Fatal("actual empty-head native promise", err)
					}
				} else {
					record := sharedAutomationRecord(t, 1, "", "req", "op", voters...)
					reply, err := a.c.ClaimAccept(ctx, key, testBallot(2, "a"), record.Value, 1, a.signer, nil)
					if err != nil || !reply.Accepted {
						t.Fatal("actual empty-head native acceptance", err)
					}
				}
				// Native original facts were established by the real admission owner.
				// Opaque text cannot replace their omitted authority inventory or repair
				// a drifted bootstrap identity; equally it cannot invalidate full evidence.
				if _, err := a.c.db.Exec(`UPDATE local_automation_authority SET provenance='arbitrary purported import authority'`); err != nil {
					t.Fatal(err)
				}
				if strings.HasSuffix(mode, "missing") {
					if _, err := a.c.db.Exec(`DELETE FROM local_automation_authority`); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "accepted-bootstrap-drift" {
					if _, err := a.c.db.Exec(`UPDATE local_automation_authority SET bootstrap_request='unrelated'`); err != nil {
						t.Fatal(err)
					}
				}
			})
			ctx := context.Background()
			a, err := r.Begin(ctx, q.Intent, nil)
			if err != nil {
				t.Fatal(err)
			}
			receiverThrough(t, p, r, a, q, peer, 11)
			active, derived := receiverActive(t, r.client), receiverAudited(t, r.client)
			err = r.AuditSource(ctx, a, "a")
			if strings.HasSuffix(mode, "present") {
				if err != nil {
					t.Fatal("complete native empty-head facts refused", err)
				}
			} else {
				if err == nil {
					t.Fatal("empty-head native claim without complete authority audited", mode)
				}
				if receiverAudited(t, r.client) != derived {
					t.Fatal("missing native provenance committed partial audit")
				}
			}
			if receiverActive(t, r.client) != active {
				t.Fatal("native empty-head audit changed active state")
			}
		})
	}
}
