package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/pki"
)

func updateFirst(t *testing.T) (*executionStorageFixture, AutomationRecord, contract.VMIntent) {
	t.Helper()
	f := updateFixture(t)
	config := updateConfig(t, f.config)
	config.Labels = map[string]string{"role": "db"}
	record := f.sign(updateDecision(t, f, `{"labels":{"values":{"role":"db"}}}`, config, "rev:first", updateOrigin(f)))
	f.apply(t, record)
	return f, record, config
}
func updateNext(t *testing.T, f *executionStorageFixture, first AutomationRecord, config contract.VMIntent) contract.Decision {
	t.Helper()
	d, e := automationDecision(first.Value)
	if e != nil {
		t.Fatal(e)
	}
	config = updateConfig(t, config)
	config.Labels = map[string]string{"role": "web"}
	return updateDecision(t, f, `{"labels":{"values":{"role":"web"}}}`, config, "rev:next", contract.HistoryReference{Sequence: d.Sequence, Digest: first.Value.MustDigest()})
}
func updateFallback(t *testing.T, f *executionStorageFixture, d contract.Decision) contract.Decision {
	t.Helper()
	a, e := contract.DecodeAssignment(d)
	if e != nil {
		t.Fatal(e)
	}
	a.Update.PreviousDesired = updateOrigin(f)
	a.Update.Configuration = updateConfig(t, f.config)
	a.Update.Configuration.Labels = map[string]string{"role": "web"}
	d.Assignment = automationExecutionJSON(t, a)
	return d
}
func updateBarrier(t *testing.T, f *executionStorageFixture) AutomationRecord {
	t.Helper()
	head, e := f.c.AutomationHead(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	return f.sign(contract.Decision{Sequence: head.Sequence + 1, ParentDigest: head.Digest, Command: contract.Command{Kind: "read_barrier", ClusterUID: head.ClusterUID, PrincipalID: "host", RequestID: fmt.Sprintf("update-replay-barrier-%d", head.Sequence+1), Body: []byte(`{"version":1}`)}, Assignment: automationExecutionJSON(t, contract.Assignment{Version: 1, ClusterUID: head.ClusterUID, OperationID: fmt.Sprintf("update-replay-barrier-op-%d", head.Sequence+1), RecordedAt: "2026-10-23T20:00:00Z"})})
}
func updateTxSnapshot(ctx context.Context, tx *LocalTx, stage string) (map[string][]Row, error) {
	out := map[string][]Row{}
	for _, d := range automationSemanticTables {
		rows, e := tx.Query(ctx, "SELECT * FROM "+d.table+" WHERE stage=? ORDER BY rowid", stage)
		if e != nil {
			return nil, e
		}
		out[d.table] = rows
	}
	return out, nil
}
func TestAutomationUpdateFULLStageReplayAndOriginalClosure(t *testing.T) {
	f, first, config := updateFirst(t)
	updateTransfer(t, f)
	next := updateNext(t, f, first, config)
	f.apply(t, f.sign(next))
	f.apply(t, updateBarrier(t, f))
	ctx := context.Background()
	before := updateSnapshot(t, f.c)
	if e := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error { _, e := auditAutomationCutTx(ctx, tx, contract.Reduce); return e }); e != nil {
		t.Fatal("isolated source update replay", e)
	}
	if !reflect.DeepEqual(before, updateSnapshot(t, f.c)) {
		t.Fatal("source audit changed active update state")
	}
	if e := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationResetSemanticProjectionTx(ctx, tx, "") }); e != nil {
		t.Fatal(e)
	}
	if e := f.c.AutomationReplay(ctx, contract.Reduce, 128); e != nil {
		t.Fatal("active original replay with ownership/update", e)
	}
	if !reflect.DeepEqual(before, updateSnapshot(t, f.c)) {
		t.Fatal("active reset/replay changed any historical receipt or business row")
	}
	f.reopen(t)
	if !reflect.DeepEqual(before, updateSnapshot(t, f.c)) {
		t.Fatal("cold reopen changed original update state")
	}
}
func TestAutomationUpdateFULLMissingLatestBehindOwnership(t *testing.T) {
	for _, stage := range []string{"active", "isolated"} {
		t.Run(stage, func(t *testing.T) {
			f, first, config := updateFirst(t)
			updateTransfer(t, f)
			next := updateNext(t, f, first, config)
			bad := updateFallback(t, f, next)
			ctx := context.Background()
			positive := func(tx *LocalTx, stage string, head contract.Prefix) error {
				p := contract.Projection{Head: head}
				if e := automationSemanticProjectionSourceTx(ctx, tx, stage, &p, next, nil); e != nil {
					return e
				}
				r, e := contract.Reduce(p, next)
				if e != nil || r.Receipt.Code != "" || r.AdmissionEffect == nil {
					return fmt.Errorf("positive U predecessor not usable: %+v %v", r.Receipt, e)
				}
				return nil
			}
			head := contract.Prefix{ClusterUID: next.Command.ClusterUID, Sequence: next.Sequence - 1, Digest: next.ParentDigest}
			firstDecision, e := automationDecision(first.Value)
			if e != nil {
				t.Fatal(e)
			}
			operation := fmt.Sprintf("update-op-%d", firstDecision.Sequence)
			if stage == "active" {
				if e = f.c.ExecuteLocal(ctx, func(tx *LocalTx) error { return positive(tx, "", head) }); e != nil {
					t.Fatal("positive before tamper", e)
				}
				if e = f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
					_, e := tx.Exec(ctx, `DELETE FROM local_automation_admissions WHERE stage='' AND operation_id=?`, operation)
					return e
				}); e != nil {
					t.Fatal(e)
				}
				before := updateSnapshot(t, f.c)
				if _, e = applySharedAutomation(t, f.c, f.sign(bad), contract.Reduce, automationFreshAnchor); e == nil {
					t.Fatal("ACTIVE closure fell back to create after deleting only latest U behind O")
				}
				if !reflect.DeepEqual(before, updateSnapshot(t, f.c)) {
					t.Fatal("ACTIVE missing-U refusal changed business/history/request/op/head")
				}
				return
			}
			barrier := updateBarrier(t, f)
			f.apply(t, barrier)
			stop := errors.New("isolated missing-U witnessed")
			visited := false
			e = f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				_, e := auditAutomationCutTx(ctx, tx, func(p AutomationProjection, d contract.Decision) (AutomationReduction, error) {
					r, e := contract.Reduce(p, d)
					if e != nil || d.Sequence != next.Sequence {
						return r, e
					}
					visited = true
					const scope = "source-cut-audit"
					if e = positive(tx, scope, p.Head); e != nil {
						return r, e
					}
					if _, e = tx.Exec(ctx, `DELETE FROM local_automation_admissions WHERE stage=? AND operation_id=?`, scope, operation); e != nil {
						return r, e
					}
					before, e := updateTxSnapshot(ctx, tx, scope)
					if e != nil {
						return r, e
					}
					q := contract.Projection{Head: p.Head}
					if e = automationSemanticProjectionSourceTx(ctx, tx, scope, &q, bad, nil); e == nil {
						return r, errors.New("ISOLATED closure fell back to create after deleting only latest U behind O")
					}
					after, e := updateTxSnapshot(ctx, tx, scope)
					if e != nil {
						return r, e
					}
					if !reflect.DeepEqual(before, after) {
						return r, errors.New("isolated refusal changed stage bytes")
					}
					return r, stop
				})
				return e
			})
			if !visited || !errors.Is(e, stop) {
				t.Fatal("isolated inverse closure witness missing", visited, e)
			}
		})
	}
}
func TestAutomationUpdateFULLHistoryAndAdmissionCorruption(t *testing.T) {
	for _, mode := range []string{"missing-history", "receipt", "configuration", "scope", "extra", "future"} {
		t.Run(mode, func(t *testing.T) {
			f, first, config := updateFirst(t)
			next := updateNext(t, f, first, config)
			ctx := context.Background()
			d, e := automationDecision(first.Value)
			if e != nil {
				t.Fatal(e)
			}
			if e = f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				q := map[string]string{"missing-history": `DELETE FROM local_automation_history WHERE sequence=?`, "receipt": `UPDATE local_automation_history SET receipt_json='{}' WHERE sequence=?`, "configuration": `UPDATE local_automation_admissions SET configuration_json='{}' WHERE sequence=?`, "scope": `UPDATE local_automation_admissions SET project_uid='foreign' WHERE sequence=?`, "extra": `UPDATE local_automation_admissions SET operation_id='extra' WHERE sequence=?`, "future": `UPDATE local_automation_admissions SET sequence=999 WHERE sequence=?`}[mode]
				_, e := tx.Exec(ctx, q, d.Sequence)
				return e
			}); e != nil {
				t.Fatal(e)
			}
			before := updateSnapshot(t, f.c)
			if _, e = applySharedAutomation(t, f.c, f.sign(next), contract.Reduce, automationFreshAnchor); e == nil {
				t.Fatal("corrupt original accepted", mode)
			}
			if !reflect.DeepEqual(before, updateSnapshot(t, f.c)) {
				t.Fatal("original corruption refusal changed state", mode)
			}
		})
	}
}

// Continue the existing fixture only after its established bootstrap premise,
// signed completed14 and real projection verification. No new authority rows.
func updateConsumerContinuation(t *testing.T) func(*executionStorageFixture) {
	return func(f *executionStorageFixture) {
		config := updateConfig(t, f.config)
		config.Labels = map[string]string{"role": "db"}
		f.apply(t, f.sign(updateDecision(t, f, `{"labels":{"values":{"role":"db"}}}`, config, "rev:consumer", updateOrigin(f))))
		t.Log("native-issuance=false runtime-effects=false authority=certified-history-fixture existing-G1-bootstrap-premise=true")
	}
}
func TestAutomationUpdateFULLReceiverReconstruction(t *testing.T) {
	f, _ := retainedCompatibilityCurrent37Fixture(t, updateConsumerContinuation(t))
	ctx := context.Background()
	before := receiverActive(t, f.local.c)
	for i := range f.producers {
		if e := f.receiver.AuditSource(ctx, f.attempt, f.producers[i].client.hostName); e != nil {
			t.Fatal("actual receiver update audit", e)
		}
	}
	rows, e := f.local.c.Query(ctx, `SELECT receipt FROM local_automation_receiver_requests WHERE request_id='update-request-15'`)
	if e != nil || len(rows) == 0 {
		t.Fatal("receiver original update receipt missing", rows, e)
	}
	for _, row := range rows {
		var receipt contract.Receipt
		if json.Unmarshal(row.Bytes("receipt"), &receipt) != nil || receipt.ResourceRevision != "rev:consumer" || receipt.State != "accepted" {
			t.Fatal("receiver update receipt lost", receipt)
		}
	}
	if receiverActive(t, f.local.c) != before {
		t.Fatal("receiver update audit activated effects")
	}
}
func TestAutomationUpdateFULLFixtureDefaultHead14(t *testing.T) {
	f, _ := retainedCompatibilityCurrent37Fixture(t)
	head, e := f.local.c.AutomationHead(context.Background())
	if e != nil || head.Sequence != 14 {
		t.Fatal("optional fixture callback changed default certified history", head, e)
	}
}
func TestAutomationUpdateFULLRetainedWarmCold(t *testing.T) {
	ctx := context.Background()
	f, bundle := retainedCompatibilityCurrent37Fixture(t, updateConsumerContinuation(t))
	before := receiverActive(t, f.local.c)
	c := f.local.c
	sqltx, e := c.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	tx := &LocalTx{tx: sqltx}
	header, directory := retainedCopyOriginalAggregate(t, ctx, tx, f, bundle)
	frames := retainedCompatibilityFrames(t, ctx, tx, directory)
	view := f.attempt.view
	check := func(tx *LocalTx) {
		t.Helper()
		got, e := rebuildRetainedAggregate(ctx, tx, header, f.attempt.binding, directory, view)
		if e != nil || got.id != bundle || got.local.head != header.Head {
			t.Fatal("actual retained update rebuild", e)
		}
		rows, e := tx.Query(ctx, `SELECT revision,original_operation_id,last_operation_id FROM local_automation_resources WHERE stage=? AND uid='resource-uid'`, "receiver-audit:"+got.local.store.id)
		if e != nil || len(rows) != 1 || rows[0].String("revision") != "rev:consumer" || rows[0].String("original_operation_id") != "create-op" || rows[0].String("last_operation_id") != "update-op-15" {
			t.Fatal("retained update/birth state differs", rows, e)
		}
		if !reflect.DeepEqual(frames, retainedCompatibilityFrames(t, ctx, tx, directory)) {
			t.Fatal("retained update changed original frame bytes")
		}
		retainedCompatibilityClean(t, ctx, tx, got)
	}
	check(tx)
	if e = sqltx.Commit(); e != nil {
		t.Fatal(e)
	}
	if receiverActive(t, c) != before {
		t.Fatal("warm retained update rebuild changed ACTIVE")
	}
	if e = c.Close(); e != nil {
		t.Fatal(e)
	}
	c, e = NewLocalClient(f.dir, f.local.name)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetVoterConfigGate(func() bool { return true })
	view, e = pki.CaptureHostTrust(ctx, f.local.pki, f.local.name)
	if e != nil {
		t.Fatal(e)
	}
	cold, e := c.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	check(&LocalTx{tx: cold})
	if e = cold.Rollback(); e != nil {
		t.Fatal(e)
	}
	if receiverActive(t, c) != before {
		t.Fatal("cold retained update rebuild changed ACTIVE")
	}
}

func TestAutomationUpdateFULLOrdinaryOriginDecoder(t *testing.T) {
	c, record, sign, _ := targetCertifiedFixtureAt(t, contract.OrdinaryCreateCommand, "")
	ctx := context.Background()
	receipt, e := applySharedAutomation(t, c, record, contract.Reduce, automationFreshAnchor)
	if e != nil || receipt.Code != "" || receipt.Generation != 0 {
		t.Fatal("ordinary allocation prerequisite", receipt, e)
	}
	if e = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		h, e := automationUpdateHistoryTx(ctx, tx, nil, 4)
		if e != nil {
			return e
		}
		origin, birth, e := automationUpdateAdmission(h)
		if e != nil {
			return e
		}
		if origin.Method != contract.OrdinaryCreateCommand || origin.PinnedConfiguration == nil || origin.PinnedConfiguration.Name != "ordinary" || origin.BindingGeneration != 0 || birth.OriginalOperationID != "target-op" || birth.UID != "ordinary-uid" {
			return fmt.Errorf("ordinary certified config/birth decoded incorrectly")
		}
		managed, e := automationAdmissionRecordTx(ctx, tx, "", "target-op")
		if e != nil {
			return e
		}
		if managed != nil {
			return fmt.Errorf("ordinary allocation fabricated a managed create admission")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	_ = sign // No new producer, target release, ownership or executor is fabricated.
}

func TestAutomationUpdateFULLReceiverOwnerCannotBorrowActiveHistory(t *testing.T) {
	f, first, config := updateFirst(t)
	d := updateNext(t, f, first, config)
	ctx := context.Background()
	before := updateSnapshot(t, f.c)
	e := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		p := contract.Projection{Head: contract.Prefix{ClusterUID: d.Command.ClusterUID, Sequence: d.Sequence - 1, Digest: d.ParentDigest}}
		missing := receiverAutomationKeySource{receiverAuditStore{tx: tx, id: "missing-update-receiver"}}
		return automationSemanticProjectionSourceTx(ctx, tx, "", &p, d, missing)
	})
	if e == nil {
		t.Fatal("receiver update owner borrowed active originals")
	}
	if !reflect.DeepEqual(before, updateSnapshot(t, f.c)) {
		t.Fatal("missing receiver owner changed active update bytes")
	}
}
