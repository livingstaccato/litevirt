package corrosion

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"github.com/litevirt/litevirt/internal/pki"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetainedOriginalSourceSharedAudit(t *testing.T) {
	ctx := context.Background()
	promise := workloadKey()
	promise.TargetName = "retained-promise"
	promise.Incarnation = "retained-lifetime"
	losing, _ := AutomationClaimKey(2)
	p, r, q, exportCtx, _ := receiverAuditFixtureOptions(t, 3, receiverAuditOptions{beforeApply: func(v *claimTestVoter, _ []*claimTestVoter, record AutomationRecord) {
		d, err := automationDecision(record.Value)
		if err != nil {
			t.Fatal(err)
		}
		if d.Sequence != 2 {
			return
		}
		value := sharedAutomationRecord(t, 2, d.ParentDigest, "retained-loser", "retained-loser-op", v)
		reply, err := v.c.ClaimAccept(ctx, losing, testBallot(1, "a"), value.Value, 1, v.signer, nil)
		if err != nil || !reply.Accepted {
			t.Fatal("real original losing acceptance", err)
		}
	}, beforeFreeze: func(v *claimTestVoter, _ []*claimTestVoter) {
		reply, err := v.c.ClaimPrepare(ctx, promise, testBallot(11, "a"), 1)
		if err != nil || !reply.Promised {
			t.Fatal("real original promise-only", err)
		}
	}})
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, exportCtx, 11)
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal(err)
	}
	rows, err := r.client.Query(ctx, `SELECT id,head,lineage,coverage,records,payloads,requests FROM local_automation_receiver_audits WHERE attempt=? AND source='a'`, a.id)
	if err != nil || len(rows) != 1 {
		t.Fatal("real original source audit unavailable", err)
	}
	want := rows[0]
	var head AutomationPrefix
	if json.Unmarshal(want.Bytes("head"), &head) != nil {
		t.Fatal("original head malformed")
	}
	before := receiverActive(t, r.client)
	// Original signed publication and spool remain unchanged. A distinct scratch
	// identity proves this adapter shares semantic verification independently of
	// a live attempt; it is not a successful adopted-holder fixture.
	for _, mode := range []string{"complete", "retained-address", "foreign-current-root", "promise-only", "losing-acceptance", "anchor", "receipt", "terminal-record", "wrong-original-generation", "currently-revoked-original"} {
		t.Run(mode, func(t *testing.T) {
			tx, err := r.client.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			local := &LocalTx{tx: tx}
			namespace, err := aggregateScratchTx(ctx, local)
			if err != nil {
				t.Fatal(err)
			}
			s := receiverAuditStore{tx: local, attempt: a.id, source: "a", id: namespace, evidenceID: want.String("id"), publication: a.publications["a"]}
			original := receiverAuditContext{a.id, a.request, a.facts}
			switch mode {
			case "retained-address", "foreign-current-root", "currently-revoked-original":
				publication := s.publication
				m := publication.manifest
				address, e := retainedAddress(strings.Repeat("a", 64), 1, m.Source, publication.id, retainedSourceStream)
				if e != nil {
					t.Fatal(e)
				}
				d := retainedObjectDescriptor{1, "source", retainedObjectLayout("source"), publication.id, m.Source, m.Incarnation, nil}
				sections, _, _ := retainedObjectSections("source")
				for i := 0; i < 3; i++ {
					n := publication.metadataBytes[i]
					sum := publication.metadataDigests[i]
					d.ComponentInventories = append(d.ComponentInventories, automationCutInventory{sections[i], 1, (n + AutomationExportChunkBytes - 1) / AutomationExportChunkBytes, n, hex.EncodeToString(sum[:])})
				}
				d.ComponentInventories = append(d.ComponentInventories, m.Cut.Inventory...)
				if e = walkAutomationStoredFrames(ctx, local, "local_automation_receiver_records", "attempt=? AND source=?", []any{a.id, m.Source}, "component", maxAutomationCutRecordBytes, func(component int, n int64, raw []byte) error { return address.save(ctx, local, component, n, raw) }); e != nil {
					t.Fatal(e)
				}
				predecessor, e := decodeReceiverBinding(a.id, a.request.Job, a.request.Revision, a.binding)
				if e != nil {
					t.Fatal(e)
				}
				roster := aggregateRosterEntry{m.Source, m.Incarnation, want.String("id"), publication.id, m.Root, m.Cut.ID, want.String("coverage")}
				view := a.view
				if mode == "foreign-current-root" {
					_, other, request, _, _ := receiverFixture(t)
					attempt, err := other.Begin(ctx, request.Intent, nil)
					if err != nil {
						t.Fatal(err)
					}
					view = attempt.view
					if view.RootDigest() == a.view.RootDigest() {
						t.Fatal("foreign root fixture did not differ")
					}
				}
				if mode == "currently-revoked-original" {
					leaf, err := x509.ParseCertificate(publication.chain[0])
					if err != nil {
						t.Fatal(err)
					}
					if err = pki.GenerateCRL(filepath.Join(p.dir, "ca.crt"), filepath.Join(p.dir, "ca.key"), filepath.Join(r.dir, "crl.pem"), []string{leaf.SerialNumber.Text(16)}); err != nil {
						t.Fatal(err)
					}
					view, err = pki.CaptureHostTrust(ctx, r.dir, r.client.hostName)
					if err != nil {
						t.Fatal(err)
					}
					cap, err := view.ValidateHostCertificate(ctx, publication.chain, m.Source)
					if err == nil {
						cap.Discard()
						t.Fatal("current revocation setup failed")
					}
				}
				s.publication, e = address.publication(ctx, local, d, predecessor, roster, view)
				if mode == "foreign-current-root" {
					if e == nil {
						t.Fatalf("original publication with invalid current trust accepted: %s", mode)
					}
					if err := tx.Rollback(); err != nil {
						t.Fatal(err)
					}
					if receiverActive(t, r.client) != before {
						t.Fatal("root refusal modified ACTIVE")
					}
					return
				}
				if e != nil {
					t.Fatalf("actual retained publication bytes refused: %v", e)
				}
				s.attempt = address.namespace
			case "promise-only", "losing-acceptance":
				key, component := promise, 4
				if mode == "losing-acceptance" {
					key, component = losing, 3
				}
				raw, _ := json.Marshal(key)
				result, e := tx.Exec(`DELETE FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=? AND ordinal=(SELECT ordinal FROM local_automation_receiver_refs WHERE audit=? AND component=? AND claim_key=?)`, a.id, component, want.String("id"), component, raw)
				err = e
				if err == nil {
					n, e := result.RowsAffected()
					if e != nil || n != 1 {
						t.Fatal("intended original omission not reached", n, e)
					}
				}
			case "anchor":
				_, err = tx.Exec(`DELETE FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=6 AND ordinal=1`, a.id)
			case "receipt":
				_, err = tx.Exec(`DELETE FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=7 AND ordinal=1`, a.id)
			case "terminal-record":
				_, err = tx.Exec(`DELETE FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=11 AND ordinal=(SELECT MAX(ordinal) FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=11)`, a.id, a.id)
			case "wrong-original-generation":
				original.request.Generation++
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.auditRetainedSource(ctx, original)
			if mode == "complete" || mode == "retained-address" || mode == "currently-revoked-original" {
				if err != nil {
					t.Fatalf("unchanged genuine source rejected by retained shared audit: %v", err)
				}
				if got.head != head || got.lineage != want.String("lineage") || got.coverage != want.String("coverage") || got.records != want.Int64("records") || got.payloads != want.Int64("payloads") || got.requests != want.Int64("requests") {
					t.Fatal("shared original semantic result changed")
				}
			} else if err == nil {
				t.Fatal("incomplete/spliced original audit accepted")
			}
			if err = tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			if receiverActive(t, r.client) != before {
				t.Fatal("retained original audit modified ACTIVE state")
			}
		})
	}
}
