package fleet

import (
	"encoding/json"
	"fmt"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The real engine reducer must audit already-applied receipts and every anchor,
// not just resume beyond an apparently up-to-date prefix counter.
func TestAutomationCutAuditsSource(t *testing.T) {
	for _, mode := range []string{"complete", "prefix-loss", "history-gap", "anchor-gap", "anchor-bit", "anchor-signature", "receipt-drift", "request-drift", "pending", "unsupported", "missing-prefix-parent"} {
		t.Run(mode, func(t *testing.T) {
			f := NewAutomationFixture(t, 3)
			if _, err := f.Engine(0).Submit(f.ctx, f.Barrier(0, "cut-barrier")); err != nil {
				t.Fatal(err)
			}
			f.Converge(t)
			db := f.cluster.Nodes[0].DB
			want := f.Head(t, 0)
			var query string
			switch mode {
			case "prefix-loss":
				query = `DELETE FROM local_automation_prefix`
			case "history-gap":
				query = `DELETE FROM local_automation_history WHERE sequence=1`
			case "anchor-gap":
				query = `DELETE FROM local_automation_anchors WHERE sequence=1`
			case "anchor-bit":
				query = `UPDATE local_automation_anchors SET digest='corrupt' WHERE sequence=1`
			case "anchor-signature":
				r, ok, err := db.AutomationRecord(f.ctx, 1)
				if err != nil || !ok {
					t.Fatal(err)
				}
				for i := range r.Certificate.Accepts {
					r.Certificate.Accepts[i].Signature = []byte{1}
				}
				cert, err := r.Certificate.Encode()
				if err != nil {
					t.Fatal(err)
				}
				if err = localExec(f.ctx, db, `UPDATE local_automation_anchors SET certificate=? WHERE sequence=1`, cert); err != nil {
					t.Fatal(err)
				}
			case "receipt-drift":
				query = `UPDATE local_automation_history SET receipt_json='{}' WHERE sequence=1`
			case "request-drift":
				query = `UPDATE local_automation_requests SET identity=x'01' WHERE request_id='same-request'`
			case "pending":
				query = `INSERT INTO local_automation_recovery (id,sequence,digest,next_sequence,next_digest,base_sequence,base_digest,generation,members_hash,certificate) VALUES (1,3,'x',2,'y',1,'z',1,'h','{}')`
			case "unsupported":
				r, ok, err := db.AutomationRecord(f.ctx, 2)
				if err != nil || !ok {
					t.Fatal(err)
				}
				d, err := contract.DecodeDecision(r.Value.Automation.Envelope)
				if err != nil {
					t.Fatal(err)
				}
				d.Command.Kind = "admit_create"
				r.Value.Automation.Envelope, err = contract.EncodeDecision(d)
				if err != nil {
					t.Fatal(err)
				}
				value, err := json.Marshal(r.Value)
				if err != nil {
					t.Fatal(err)
				}
				if err = localExec(f.ctx, db, `UPDATE local_automation_history SET value_json=?,digest=? WHERE sequence=2`, string(value), r.Value.MustDigest()); err != nil {
					t.Fatal(err)
				}

			case "missing-prefix-parent":
				if err := localExec(f.ctx, db, `DELETE FROM local_automation_requests`); err != nil {
					t.Fatal(err)
				}
				if err := localExec(f.ctx, db, `DELETE FROM local_automation_prefix`); err != nil {
					t.Fatal(err)
				}
				if err := localExec(f.ctx, db, `DELETE FROM local_automation_anchors`); err != nil {
					t.Fatal(err)
				}
				query = `DELETE FROM local_automation_history`
			}
			if query != "" {
				if err := localExec(f.ctx, db, query); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := corrosion.AdoptedVoterConfig(f.ctx, db)
			if err != nil {
				t.Fatal(err)
			}
			if err = db.SealVoterGeneration(f.ctx, cfg.Generation, "cut-test"); err != nil {
				t.Fatal(err)
			}
			before := f.Head(t, 0)
			id, err := f.Engine(0).FreezeMembershipCut(f.ctx, cfg.Generation)
			if mode == "complete" || mode == "prefix-loss" {
				if err != nil || id == "" {
					t.Fatalf("complete source refused: %v", err)
				}
				if f.Head(t, 0) != want {
					t.Fatal("prefix was not reconstructed exactly")
				}
			} else {
				if f.Head(t, 0) != before {
					t.Fatal("failed audit changed active prefix")
				}
				if err == nil {
					t.Fatal("incomplete/corrupt source produced content cut")
				}
				rows, e := db.Query(f.ctx, `SELECT count(*) AS n FROM local_automation_cuts`)
				if e != nil || rows[0].Int64("n") != 0 {
					t.Fatal("failed audit left a complete cut", e)
				}
			}
		})
	}
}

func TestAutomationCutRetainsLosingAcceptance(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	n := f.cluster.Nodes[0]
	head := f.Head(t, 0)
	command := f.Barrier(0, "losing-request")
	d := contract.Decision{Sequence: 2, ParentDigest: head.Digest, Command: command, Assignment: []byte(fmt.Sprintf(`{"version":1,"cluster_uid":%q,"operation_id":"losing-operation","recorded_at":"2026-10-15T00:00:00Z"}`, head.ClusterUID))}
	envelope, err := contract.EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	value := corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: envelope}}
	signer, err := corrosion.LoadClaimSigner(n.PKIDir, n.Name)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := corrosion.AutomationClaimKey(2)
	cfg, err := corrosion.AdoptedVoterConfig(f.ctx, n.DB)
	if err != nil {
		t.Fatal(err)
	}
	accept, err := n.DB.ClaimAccept(f.ctx, key, corrosion.Ballot{Round: 1, Coordinator: n.Name, Nonce: []byte{1}}, value, cfg.Generation, signer, nil)
	if err != nil || !accept.Accepted {
		t.Fatal(accept, err)
	}
	f.Isolate(0)
	if _, err = f.Engine(1).Submit(f.ctx, f.Barrier(1, "winning-request")); err != nil {
		t.Fatal(err)
	}
	chosen, ok, err := f.cluster.Nodes[1].DB.AutomationRecord(f.ctx, 2)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if chosen.Value.MustDigest() == value.MustDigest() {
		t.Fatal("fixture did not create a losing acceptance")
	}
	if err = f.Engine(0).Install(f.ctx, chosen); err != nil {
		t.Fatal(err)
	}
	if err = n.DB.SealVoterGeneration(f.ctx, cfg.Generation, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Engine(0).FreezeMembershipCut(f.ctx, cfg.Generation); err != nil {
		t.Fatal("legitimate older losing acceptance falsely treated as fork", err)
	}
	retained, ok, err := n.DB.ClaimState(f.ctx, key)
	if err != nil || !ok || retained.ValueDigest != value.MustDigest() {
		t.Fatal("cut rewrote losing acceptance", err)
	}
}

func TestAutomationCutManyLargeRecords(t *testing.T) { largeAutomationCutFixture(t) }
func largeAutomationCutFixture(t *testing.T) (*AutomationFixture, *corrosion.VoterConfig, string) {
	t.Helper()
	f := NewAutomationFixture(t, 3)
	n := f.cluster.Nodes[0]
	for seq := 2; seq <= 34; seq++ {
		head := f.Head(t, 0)
		command := f.Barrier(0, fmt.Sprintf("bulk-%d", seq))
		if seq%8 == 0 {
			command.Body = []byte("{" + strings.Repeat(" ", 700000) + `"version":1}`)
		}
		d := contract.Decision{Sequence: uint64(seq), ParentDigest: head.Digest, Command: command, Assignment: []byte(fmt.Sprintf(`{"version":1,"cluster_uid":%q,"operation_id":"bulk-op-%d","recorded_at":"2026-10-15T00:00:00Z"}`, head.ClusterUID, seq))}

		if seq == 32 {
			assignment := string(d.Assignment)
			lo, hi := 0, 1<<20
			for lo < hi {
				mid := (lo + hi + 1) / 2
				d.Assignment = []byte("{" + strings.Repeat(" ", mid) + assignment[1:])
				if _, err := contract.EncodeDecision(d); err == nil {
					lo = mid
				} else {
					hi = mid - 1
				}
			}
			d.Assignment = []byte("{" + strings.Repeat(" ", lo) + assignment[1:])
			envelope, err := contract.EncodeDecision(d)
			if err != nil || len(envelope) < contract.MaxDecisionBytes-3 {
				t.Fatal("fixture missed maximum supported decision", len(envelope), err)
			}
			t.Logf("maximum supported decision envelope=%d (ceiling %d)", len(envelope), contract.MaxDecisionBytes)
		}
		r := f.certifyFixtureDecision(t, d)
		for i := range f.engines {
			if err := f.Engine(i).Install(f.ctx, r); err != nil {
				t.Fatal(err)
			}
		}
	}
	cfg, err := corrosion.AdoptedVoterConfig(f.ctx, n.DB)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		result, e := n.DB.ClaimPrepare(f.ctx, corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: fmt.Sprintf("export-promise-%03d", i), OwnerEpoch: 1}, corrosion.Ballot{Round: 100, Coordinator: n.Name, Nonce: []byte("export-many")}, cfg.Generation)
		if e != nil || !result.Promised {
			t.Fatal("actual promise fixture", result, e)
		}
	}
	if err = n.DB.SealVoterGeneration(f.ctx, cfg.Generation, "test"); err != nil {
		t.Fatal(err)
	}
	id, err := f.Engine(0).FreezeMembershipCut(f.ctx, cfg.Generation)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := n.DB.Query(f.ctx, `SELECT count(*) AS n,max(length(record)) AS biggest,sum(length(record)) AS total FROM local_automation_cut_records WHERE cut_id=? AND section=2`, id)
	if err != nil || rows[0].Int64("n") != 34 || rows[0].Int64("biggest") < 1<<20 || rows[0].Int64("total") < 4<<20 {
		t.Fatal("large multi-record history was not preserved", rows, err)
	}
	t.Logf("history records=%d maximum=%d total=%d; production scans hold one indexed LIMIT 1 record", rows[0].Int64("n"), rows[0].Int64("biggest"), rows[0].Int64("total"))
	return f, cfg, id
}
