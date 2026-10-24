package corrosion

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

func TestAutomationUpdateFULLCallbackIsolation(t *testing.T) {
	for _, mode := range []string{"patch", "lineage", "erase-admission", "identity", "revision", "decision-bytes"} {
		t.Run(mode, func(t *testing.T) {
			f := updateFixture(t)
			config := updateConfig(t, f.config)
			config.Labels = map[string]string{"role": "db"}
			record := f.sign(updateDecision(t, f, `{"labels":{"values":{"role":"db"}}}`, config, "rev:callback", updateOrigin(f)))
			before := updateSnapshot(t, f.c)
			called := false
			_, e := applySharedAutomation(t, f.c, record, func(p AutomationProjection, d contract.Decision) (AutomationReduction, error) {
				called = true
				r, e := contract.Reduce(p, d)
				if e != nil {
					return r, e
				}
				switch mode {
				case "decision-bytes":
					copy(d.Command.Body, bytes.ReplaceAll(d.Command.Body, []byte(`"role":"db"`), []byte(`"role":"xx"`)))
					copy(d.Assignment, bytes.ReplaceAll(d.Assignment, []byte(`"role":"db"`), []byte(`"role":"xx"`)))
					r, e = contract.Reduce(p, d)
				case "patch":
					p.Update.PreviousDesired.PinnedConfiguration.Disks[0].SizeBytes++
					r, e = contract.Reduce(p, d)
				case "lineage":
					p.Update.OriginResource.DomainUUID = "callback-domain"
					r, e = contract.Reduce(p, d)
				case "erase-admission":
					r.AdmissionEffect = nil
				case "identity":
					r.ResourceEffect.OriginalOperationID = "callback-origin"
				case "revision":
					r.ResourceEffect.Revision = "callback-revision"
				}
				return r, e
			}, automationFreshAnchor)
			if !called || e == nil {
				t.Fatal("callback mutation accepted", mode, called, e)
			}
			if !reflect.DeepEqual(before, updateSnapshot(t, f.c)) {
				t.Fatal("callback mutated real nested projection or persisted drift", mode)
			}
		})
	}
}
func TestAutomationUpdateFULLRetainedReceiptAfterHandoff(t *testing.T) {
	f := updateFixture(t)
	config := updateConfig(t, f.config)
	config.Labels = map[string]string{"role": "db"}
	original := f.sign(updateDecision(t, f, `{"labels":{"values":{"role":"db"}}}`, config, "rev:first", updateOrigin(f)))
	first := f.apply(t, original)
	updateTransfer(t, f)
	head, e := f.c.AutomationHead(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	d, e := automationDecision(original.Value)
	if e != nil {
		t.Fatal(e)
	}
	d.Sequence = head.Sequence + 1
	d.ParentDigest = head.Digest
	d.Command.Session = 99
	d.Command.SessionID = "unrelated-later-session"
	a, e := contract.DecodeAssignment(d)
	if e != nil {
		t.Fatal(e)
	}
	a.OperationID = "retry-later-assignment"
	d.Assignment = automationExecutionJSON(t, a)
	before := updateSnapshot(t, f.c)
	retry := f.sign(d)
	got := f.apply(t, retry)
	if got != first {
		t.Fatal("retry after handoff lost original receipt", got, first)
	}
	after := updateSnapshot(t, f.c)
	for _, descriptor := range automationSemanticTables {
		if descriptor.table == "local_automation_semantic_heads" {
			continue
		}
		if !reflect.DeepEqual(before[descriptor.table], after[descriptor.table]) {
			t.Fatal("retained retry emitted business effects", descriptor.table)
		}
	}
	// The retry contributes history but neither a new admission nor a new desired
	// operation. Genuine source replay must reconstruct the original assignment.
	if e = f.c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
		_, e := auditAutomationCutTx(context.Background(), tx, contract.Reduce)
		return e
	}); e != nil {
		t.Fatal("source replay lost original retry authority", e)
	}
	d.Sequence++
	d.ParentDigest = retry.Value.MustDigest()
	d.Command.Body = []byte(strings.Replace(string(d.Command.Body), `"role":"db"`, `"role":"altered"`, 1))
	a.OperationID = "retry-changed-body"
	a.Update.Configuration.Labels = map[string]string{"role": "altered"}
	d.Assignment = automationExecutionJSON(t, a)
	got, e = applySharedAutomation(t, f.c, f.sign(d), contract.Reduce, automationFreshAnchor)
	if e != nil || got.Code != contract.CodeIdempotencyConflict {
		t.Fatal("changed retry body escaped permanent identity", got, e)
	}
}
func TestAutomationUpdateDoesNotActivateExecutor(t *testing.T) {
	f := updateFixture(t)
	config := updateConfig(t, f.config)
	config.Labels = map[string]string{"role": "db"}
	record := f.sign(updateDecision(t, f, `{"labels":{"values":{"role":"db"}}}`, config, "rev:executor-refusal", updateOrigin(f)))
	receipt := f.apply(t, record)
	head, e := f.c.AutomationHead(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	b := contract.ExecutionBody{Version: 1, OperationID: receipt.OperationID, Admission: contract.HistoryReference{Sequence: receipt.Sequence, Digest: record.Value.MustDigest()}, ResourceRevision: receipt.ResourceRevision, DomainUUID: "domain-uuid", Incarnation: "runtime-incarnation", HostUID: "host-uid", HostIncarnation: "positive-host-uid"}
	d, e := automationDecision(f.grant.Value)
	if e != nil {
		t.Fatal(e)
	}
	d.Sequence = head.Sequence + 1
	d.ParentDigest = head.Digest
	d.Command.RequestID = "update-executor-refused"
	d.Command.Body = automationExecutionJSON(t, b)
	d.Assignment = automationExecutionJSON(t, contract.Assignment{Version: 1, ClusterUID: head.ClusterUID, OperationID: "update-executor-op", RecordedAt: "2026-10-23T20:00:00Z", Execution: &contract.ExecutionAssignment{Version: 1, ExecutorGeneration: 1}})
	before := updateSnapshot(t, f.c)
	if _, e = applySharedAutomation(t, f.c, f.sign(d), contract.Reduce, automationFreshAnchor); e == nil {
		t.Fatal("update activated create-only executor")
	}
	if !reflect.DeepEqual(before, updateSnapshot(t, f.c)) {
		t.Fatal("refused update executor changed original artifacts/history")
	}
	if e = f.c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
		a, _, e := automationExecutionAdmissionTx(context.Background(), tx, nil, head, updateOrigin(f))
		if e != nil {
			return e
		}
		if a.OperationID != "create-op" {
			return fmt.Errorf("create execution provenance changed")
		}
		return nil
	}); e != nil {
		t.Fatal("old create authentication changed", e)
	}
}
