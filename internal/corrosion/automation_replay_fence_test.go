package corrosion

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

func TestAutomationPartialReplayCannotAdmitAtRewoundHead(t *testing.T) {
	for _, mode := range []string{"interior-anchor", "budget"} {
		t.Run(mode, func(t *testing.T) {
			_, original, b, c := threeVoters(t)
			dir := t.TempDir()
			file, err := NewLocalClient(dir, "a")
			if err != nil {
				t.Fatal(err)
			}
			if err := InitSchema(context.Background(), file); err != nil {
				t.Fatal(err)
			}
			file.SetVoterConfigGate(func() bool { return true })
			inc, err := file.VoterIncarnation(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			a := &claimTestVoter{name: "a", c: file, signer: original.signer, pki: original.pki, inc: inc}
			adoptHandBuilt(t, 1, membersOf(a, b, c), a)
			t.Cleanup(func() { a.c.Close() })
			ctx := context.Background()
			parent := ""
			for seq := uint64(1); seq <= 7; seq++ {
				record := sharedAutomationRecord(t, seq, parent, mode+"-request-"+string(rune('0'+seq)), mode+"-operation-"+string(rune('0'+seq)), a, b)
				if _, err := applySharedAutomation(t, a.c, record, contract.Reduce, automationFreshAnchor); err != nil {
					t.Fatal(err)
				}
				parent = record.Value.MustDigest()
			}
			key, _ := AutomationClaimKey(1)
			installAutomationEvidence(t, a.c, key, "", 1)
			trusted, err := a.c.AutomationHead(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				if _, err := tx.Exec(ctx, `DELETE FROM local_automation_semantic_heads WHERE stage=''`); err != nil {
					return err
				}
				if mode == "interior-anchor" {
					_, err := tx.Exec(ctx, `UPDATE local_automation_anchors SET digest=? WHERE sequence=6`, strings.Repeat("c", 64))
					return err
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			permanent := func() []Row {
				rows, err := a.c.Query(ctx, `SELECT 'history' AS kind,sequence AS seq,digest AS a,value_json AS b,receipt_json AS c FROM local_automation_history UNION ALL SELECT 'request',0,scope,hex(identity),receipt_json FROM local_automation_requests UNION ALL SELECT 'anchor',sequence,digest,certificate,members_hash FROM local_automation_anchors ORDER BY kind,seq,a`)
				if err != nil {
					t.Fatal(err)
				}
				return rows
			}
			before := permanent()
			budget := 256
			if mode == "budget" {
				budget = 2
			}
			if err := a.c.AutomationReplay(ctx, contract.Reduce, budget); err == nil {
				t.Fatal("incomplete reconstruction reported success")
			}
			head, err := a.c.AutomationHead(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if head != trusted {
				t.Errorf("known certified head rewound: before=%+v after=%+v", trusted, head)
			}
			var derived contract.Prefix
			if err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				var err error
				derived, err = automationSemanticHeadTx(ctx, tx, "")
				return err
			}); err != nil {
				t.Fatal(err)
			}
			want := uint64(5)
			if mode == "budget" {
				want = 2
			}
			if derived.Sequence != want {
				t.Fatalf("fixture did not reach partial replay boundary: %+v", derived)
			}
			// Control command and valid generic authority deliberately avoid business
			// class-provider/Engine closure: the actual durable voter must fence this.
			if err := a.c.Close(); err != nil {
				t.Fatal(err)
			}
			a.c, err = NewLocalClient(dir, "a")
			if err != nil {
				t.Fatal(err)
			}
			a.c.SetVoterConfigGate(func() bool { return true })
			if reopened, err := a.c.AutomationHead(ctx); err != nil || reopened != trusted {
				t.Errorf("reopen lost certified head: %+v %v", reopened, err)
			}
			if _, err := a.c.AutomationMembership(ctx); err == nil {
				t.Error("partial replay exposed authoritative membership/read frontier")
			}
			key, value := automationFixture(t, derived.Sequence+1, derived.Digest)
			result, err := a.c.ClaimAccept(ctx, key, testBallot(8, "a"), value, 1, a.signer, nil)
			if err != nil || result.Accepted || result.Accept != nil || result.Refusal != RefusalAutomationUnavailable {
				t.Errorf("partial replay admitted lower fresh slot: %+v err=%v", result, err)
			}
			if _, found, err := a.c.ClaimState(ctx, key); err != nil || found {
				t.Errorf("partial replay refusal mutated durable claim: found=%v err=%v", found, err)
			}
			if !reflect.DeepEqual(before, permanent()) {
				t.Fatal("rebuild altered permanent receipts/history/anchors")
			}
			if mode == "interior-anchor" {
				rows, err := a.c.Query(ctx, `SELECT digest FROM local_automation_history WHERE sequence=6`)
				if err != nil || len(rows) != 1 {
					t.Fatal(err)
				}
				if err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
					_, err := tx.Exec(ctx, `UPDATE local_automation_anchors SET digest=? WHERE sequence=6`, rows[0].String("digest"))
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			// Resume in bounded batches across the reopened client. Neither reset
			// nor a transient error may discard progress or reopen authority early.
			for attempt := 0; attempt < 4; attempt++ {
				err = a.c.AutomationReplay(ctx, contract.Reduce, 2)
				if err == nil {
					break
				}
			}
			if err != nil {
				t.Fatal("bounded replay never completed", err)
			}
			if err := a.c.Close(); err != nil {
				t.Fatal(err)
			}
			a.c, err = NewLocalClient(dir, "a")
			if err != nil {
				t.Fatal(err)
			}
			a.c.SetVoterConfigGate(func() bool { return true })
			if head, err := a.c.AutomationHead(ctx); err != nil || head != trusted {
				t.Fatal("completed replay changed certified head", head, err)
			}
			if _, err := a.c.AutomationMembership(ctx); err != nil {
				t.Fatal("complete reopened projection not authoritative", err)
			}
			freshKey, fresh := automationFixture(t, 8, trusted.Digest)
			accepted, err := a.c.ClaimAccept(ctx, freshKey, testBallot(9, "a"), fresh, 1, a.signer, nil)
			if err != nil || !accepted.Accepted || accepted.Accept == nil {
				t.Fatal("complete replay did not restore control admission", accepted, err)
			}

		})
	}
}
