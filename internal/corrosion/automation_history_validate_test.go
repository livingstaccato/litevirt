package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

func sharedAutomationRecord(t *testing.T, seq uint64, parent, request, operation string, voters ...*claimTestVoter) AutomationRecord {
	t.Helper()
	_, v := automationFixture(t, seq, parent)
	d, err := automationDecision(v)
	if err != nil {
		t.Fatal(err)
	}
	d.Command.RequestID = request
	a, err := contract.DecodeAssignment(d)
	if err != nil {
		t.Fatal(err)
	}
	a.OperationID = operation
	d.Assignment, err = json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	v.Automation.Envelope, err = contract.EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := AutomationClaimKey(seq)
	ballot := testBallot(2, "a")
	r := AutomationRecord{Value: v, Certificate: ClaimCertificate{Key: key, Ballot: ballot, ConfigGeneration: 1, ValueDigest: v.MustDigest()}}
	for _, voter := range voters {
		signed, err := voter.signer.Sign(key, 1, ballot, v.MustDigest(), voter.inc)
		if err != nil {
			t.Fatal(err)
		}
		r.Certificate.Accepts = append(r.Certificate.Accepts, signed)
	}
	return r
}

func applySharedAutomation(t *testing.T, c *Client, r AutomationRecord, reduce AutomationReducer, kind automationApplicationKind) (contract.Receipt, error) {
	t.Helper()
	d, err := automationDecision(r.Value)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := AdoptedVoterConfig(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	var receipt contract.Receipt
	err = c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
		var err error
		receipt, err = automationApplyTx(context.Background(), tx, r, d, r.Value.MustDigest(), reduce, automationApplicationProvenance{kind: kind, sequence: d.Sequence, generation: 1, membersHash: cfg.MembersHash})
		return err
	})
	return receipt, err
}

func sharedActiveRows(t *testing.T, c *Client) []Row {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT 'prefix' AS kind,cluster_uid AS a,sequence AS b,digest AS c,'' AS d FROM local_automation_prefix UNION ALL SELECT 'history',value_json,sequence,digest,receipt_json FROM local_automation_history UNION ALL SELECT 'request',scope,0,hex(identity),receipt_json FROM local_automation_requests UNION ALL SELECT 'anchor',members_hash,sequence,digest,certificate FROM local_automation_anchors ORDER BY kind,b,a`)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestAutomationHistoryEvaluatorReadOnly(t *testing.T) {
	_, a, b, _ := threeVoters(t)
	r := sharedAutomationRecord(t, 1, "", "original", "original-operation", a, b)
	before := sharedActiveRows(t, a.c)
	in := automationHistoryInput{Value: r.Value, Digest: r.Value.MustDigest()}
	result, next, err := evaluateAutomationHistory(in)
	if err != nil || next.Sequence != 1 || next.ClusterUID != "established-cluster" || !result.SaveRequest {
		t.Fatal(result, next, err)
	}
	if _, err = applySharedAutomation(t, a.c, r, contract.Reduce, automationFreshAnchor); err != nil {
		t.Fatal(err)
	}
	applied := sharedActiveRows(t, a.c)
	if reflect.DeepEqual(before, applied) {
		t.Fatal("adapter did not persist")
	}
	for _, valid := range []bool{true, false} {
		expected := result.Receipt
		if !valid {
			expected.OperationID = "drift"
		}
		in.Expected = &expected
		got, _, err := evaluateAutomationHistory(in)
		if valid && (err != nil || got.Receipt != result.Receipt) {
			t.Fatal(err)
		}
		if !valid && err == nil {
			t.Fatal("detached evaluator accepted receipt drift")
		}
		if !reflect.DeepEqual(applied, sharedActiveRows(t, a.c)) {
			t.Fatal("read-only evaluator changed active state")
		}
	}
}

// Removing the actual shared receipt comparison must fail every named path.
func TestAutomationHistorySharedReceiptValidation(t *testing.T) {
	for _, path := range []string{"evaluator", "replay-adapter", "source-adapter"} {
		t.Run(path, func(t *testing.T) {
			_, a, b, _ := threeVoters(t)
			r := sharedAutomationRecord(t, 1, "", "original", "original-operation", a, b)
			result, _, err := evaluateAutomationHistory(automationHistoryInput{Value: r.Value, Digest: r.Value.MustDigest()})
			if err != nil {
				t.Fatal(err)
			}
			expected := result.Receipt
			expected.OperationID = "corrupt"
			if path == "evaluator" {
				if _, _, err = evaluateAutomationHistory(automationHistoryInput{Value: r.Value, Digest: r.Value.MustDigest(), Expected: &expected}); err == nil {
					t.Fatal("shared evaluator accepted supplied receipt drift")
				}
				return
			}
			if _, err = applySharedAutomation(t, a.c, r, contract.Reduce, automationFreshAnchor); err != nil {
				t.Fatal(err)
			}
			if path == "source-adapter" {
				original := sharedAutomationRecord(t, 2, r.Value.MustDigest(), "barrier", "barrier-operation", a, b)
				originalReceipt, err := applySharedAutomation(t, a.c, original, contract.Reduce, automationFreshAnchor)
				if err != nil {
					t.Fatal(err)
				}
				duplicate := sharedAutomationRecord(t, 3, original.Value.MustDigest(), "barrier", "duplicate-operation", a, b)
				if got, err := applySharedAutomation(t, a.c, duplicate, contract.Reduce, automationFreshAnchor); err != nil || got != originalReceipt {
					t.Fatal(got, err)
				}
				// Preserve all full values, signatures, predecessors and original request
				// receipts. Only the later duplicate's stored result is corrupt.
				drift := originalReceipt
				drift.OperationID = "corrupt-duplicate"
				encoded, err := json.Marshal(drift)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = a.c.db.Exec(`UPDATE local_automation_history SET receipt_json=? WHERE sequence=3`, string(encoded)); err != nil {
					t.Fatal(err)
				}
				if err = a.c.SealVoterGeneration(context.Background(), 1, "shared receipt predicate"); err != nil {
					t.Fatal(err)
				}
				before := sharedActiveRows(t, a.c)
				if _, err = a.c.FreezeAutomationCut(context.Background(), 1, contract.Reduce); err == nil {
					t.Fatal("source adapter accepted retained duplicate receipt drift")
				}
				if !reflect.DeepEqual(before, sharedActiveRows(t, a.c)) {
					t.Fatal("refused source audit wrote active state")
				}
				return
			}

			receipt, _ := json.Marshal(expected)
			if _, err = a.c.db.Exec(`UPDATE local_automation_history SET receipt_json=?`, string(receipt)); err != nil {
				t.Fatal(err)
			}
			if _, err = a.c.db.Exec(`DELETE FROM local_automation_requests`); err != nil {
				t.Fatal(err)
			}
			if _, err = a.c.db.Exec(`DELETE FROM local_automation_prefix`); err != nil {
				t.Fatal(err)
			}
			before := sharedActiveRows(t, a.c)
			if _, err = applySharedAutomation(t, a.c, r, contract.Reduce, automationAnchoredReplay); err == nil {
				t.Fatal("shared replay adapter accepted stored receipt drift")
			}
			if !reflect.DeepEqual(before, sharedActiveRows(t, a.c)) {
				t.Fatal("refused replay wrote active state")
			}
		})
	}
}

func TestAutomationHistoryCompatibilityCallbacks(t *testing.T) {
	for _, mode := range []string{"concrete", "refusing", "mismatch"} {
		t.Run(mode, func(t *testing.T) {
			_, a, b, _ := threeVoters(t)
			r := sharedAutomationRecord(t, 1, "", "original", "operation", a, b)
			refusal := errors.New("deliberate refusing reducer")
			callback := AutomationReducer(contract.Reduce)
			if mode == "refusing" {
				callback = func(AutomationProjection, contract.Decision) (AutomationReduction, error) {
					return AutomationReduction{}, refusal
				}
			}
			if mode == "mismatch" {
				callback = func(p AutomationProjection, d contract.Decision) (AutomationReduction, error) {
					result, err := contract.Reduce(p, d)
					result.Receipt.OperationID = "callback-selected"
					return result, err
				}
			}
			before := sharedActiveRows(t, a.c)
			_, err := applySharedAutomation(t, a.c, r, callback, automationFreshAnchor)
			if mode == "concrete" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("callback became semantic authority")
			}
			if mode == "refusing" && !errors.Is(err, refusal) {
				t.Fatal("callback refusal lost", err)
			}
			if !reflect.DeepEqual(before, sharedActiveRows(t, a.c)) {
				t.Fatal("callback refusal changed active state")
			}
		})
	}
}

func TestAutomationHistoryDuplicateOriginalReceipt(t *testing.T) {
	for _, path := range []string{"evaluator", "active-adapter"} {
		t.Run(path, func(t *testing.T) {
			_, a, b, _ := threeVoters(t)
			genesis := sharedAutomationRecord(t, 1, "", "genesis", "genesis-operation", a, b)
			if _, err := applySharedAutomation(t, a.c, genesis, contract.Reduce, automationFreshAnchor); err != nil {
				t.Fatal(err)
			}
			original := sharedAutomationRecord(t, 2, genesis.Value.MustDigest(), "original", "original-operation", a, b)
			receipt, err := applySharedAutomation(t, a.c, original, contract.Reduce, automationFreshAnchor)
			if err != nil {
				t.Fatal(err)
			}
			duplicate := sharedAutomationRecord(t, 3, original.Value.MustDigest(), "original", "later-operation", a, b)
			d, err := automationDecision(duplicate.Value)
			if err != nil {
				t.Fatal(err)
			}
			request, err := a.c.AutomationRequest(context.Background(), contract.Scope(d), d.Command.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			head, err := a.c.AutomationHead(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if path == "evaluator" {
				result, next, err := evaluateAutomationHistory(automationHistoryInput{Value: duplicate.Value, Digest: duplicate.Value.MustDigest(), Projection: AutomationProjection{Head: head, Existing: request}})
				if err != nil || result.Receipt != receipt || result.SaveRequest || next.ClusterUID != head.ClusterUID {
					t.Fatal("evaluator replaced original entire receipt", result, err)
				}
			} else {
				got, err := applySharedAutomation(t, a.c, duplicate, contract.Reduce, automationFreshAnchor)
				if err != nil || got != receipt {
					t.Fatal("active adapter replaced original entire receipt", got, err)
				}
			}
		})
	}
}

func TestAutomationRequestSharedPredicates(t *testing.T) {
	_, value := automationFixture(t, 1, "")
	d, err := automationDecision(value)
	if err != nil {
		t.Fatal(err)
	}
	result, err := contract.Reduce(AutomationProjection{}, d)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "scope", "request", "operation", "identity", "receipt"} {
		t.Run(mode, func(t *testing.T) {
			scope, request, operation, identity, receipt := result.Scope, d.Command.RequestID, result.Receipt.OperationID, result.Identity, result.Receipt
			switch mode {
			case "scope":
				scope = "wrong"
			case "request":
				request = "wrong"
			case "operation":
				operation = "wrong"
			case "identity":
				identity = []byte{1}
			case "receipt":
				receipt.ResourceUID = "wrong"
			}
			err := validateAutomationRequest(scope, request, operation, identity, receipt, result.Receipt, d)
			if mode == "valid" && err != nil {
				t.Fatal(err)
			}
			if mode != "valid" && err == nil {
				t.Fatal("request drift accepted", mode)
			}
		})
	}
}
