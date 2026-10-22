package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// UNFORMATTED_UNCOMPILED_UNRUN. These are certified-history FULL corruption
// controls using the approved fixture signers, not native issuance evidence.
func TestAutomationExecutionFULLAcceptedOriginalReceiptClosure(t *testing.T) {
	for _, kind := range []string{"admission", "grant", "progress", "retirement", "terminal"} {
		for _, field := range []string{"RequestID", "OperationID", "ResourceUID", "Code", "Sequence", "Generation", "ResourceRevision", "Revision", "State"} {
			t.Run(kind+"/"+field, func(t *testing.T) {
				f, original, receipt := executionReceiptAcceptedFixture(t, kind)
				d, err := automationDecision(original.Value)
				if err != nil {
					t.Fatal(err)
				}
				// Both actual current loading and source replay must accept the
				// genuine predecessor before any negative receipt mutation.
				executionReceiptRequireBaseline(t, f)
				before := executionStorageSnapshot(t, f.c)
				changed := receipt
				switch field {
				case "RequestID":
					changed.RequestID += "-corrupt"
				case "OperationID":
					changed.OperationID += "-corrupt"
				case "ResourceUID":
					changed.ResourceUID += "-corrupt"
				case "Code":
					changed.Code = contract.CodeValidation
				case "Sequence":
					changed.Sequence--
				case "Generation":
					changed.Generation++
				case "ResourceRevision":
					changed.ResourceRevision += "-corrupt"
				case "Revision":
					changed.Revision = 1
				case "State":
					changed.State = "corrupt-accepted-state"
				}
				corrupt := executionReceiptWriteSingleFieldCorruption(t, f, d.Sequence, receipt, changed, before)
				want := "execution original accepted receipt differs"
				if field == "RequestID" || field == "Code" {
					want = "execution original receipt differs"
				}
				if field == "Sequence" {
					want = "execution retained retry differs from original receipt"
				}
				executionReceiptRequireRefusal(t, f, want, corrupt)
			})
		}
	}
}

func executionReceiptAcceptedFixture(t *testing.T, kind string) (*executionStorageFixture, AutomationRecord, contract.Receipt) {
	t.Helper()
	f := newExecutionStorageFixture(t)
	receipt := f.start(t)
	original, state := f.grant, "accepted"
	switch kind {
	case "admission":
		original = f.admission
		receipt = f.apply(t, original)
	case "grant":
	case "progress", "retirement", "terminal":
		artifacts := f.artifacts()
		original = f.progress(t, "running", artifacts)
		receipt = f.apply(t, original)
		state = "running"
		if kind == "retirement" {
			body := f.body(t)
			retired := artifacts[0]
			retired.State = "deleted"
			body.Artifacts = []contract.ArtifactRecord{retired}
			original = f.next(t, "retire_artifact", body)
			receipt = f.apply(t, original)
			state = "succeeded"
		} else if kind == "terminal" {
			original = f.terminal(t, "succeeded", artifacts)
			receipt = f.apply(t, original)
			state = "succeeded"
		}
	default:
		t.Fatal("unknown receipt fixture kind", kind)
	}
	d, err := automationDecision(original.Value)
	if err != nil {
		t.Fatal(err)
	}
	a, err := contract.DecodeAssignment(d)
	if err != nil {
		t.Fatal(err)
	}
	// Independent expected complete fixture receipt, rather than invoking the
	// production original-receipt validator to establish the test's positive.
	want := contract.Receipt{RequestID: d.Command.RequestID, OperationID: a.OperationID, ResourceUID: "resource-uid", Sequence: d.Sequence, Generation: 1, ResourceRevision: "rev:opaque-alpha", State: state}
	if receipt != want {
		t.Fatalf("genuine accepted %s receipt differs: got=%+v want=%+v", kind, receipt, want)
	}
	return f, original, receipt
}

func executionReceiptRequireBaseline(t *testing.T, f *executionStorageFixture) {
	t.Helper()
	before := executionStorageSnapshot(t, f.c)
	if p := f.projection(t); p.Execution == nil || !reflect.DeepEqual(p.Execution.Grant, &f.want) {
		t.Fatal("genuine execution receipt baseline missing")
	}
	ctx := context.Background()
	if err := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error { _, err := auditAutomationCutTx(ctx, tx, contract.Reduce); return err }); err != nil {
		t.Fatal("genuine receipt source baseline refused", err)
	}
	if !reflect.DeepEqual(before, executionStorageSnapshot(t, f.c)) {
		t.Fatal("genuine receipt baseline changed stored evidence")
	}
}

// Change exactly one field of exactly one original-history receipt. Explicit
// readback proves the canonical negative input took effect; every other field,
// certified envelope/anchor, request, derived row and cursor stays byte-equal.
func executionReceiptWriteSingleFieldCorruption(t *testing.T, f *executionStorageFixture, sequence uint64, original, changed contract.Receipt, before map[string][]Row) map[string][]Row {
	t.Helper()
	oldValue, newValue := reflect.ValueOf(original), reflect.ValueOf(changed)
	fields := 0
	for i := 0; i < oldValue.NumField(); i++ {
		if !reflect.DeepEqual(oldValue.Field(i).Interface(), newValue.Field(i).Interface()) {
			fields++
		}
	}
	if fields != 1 {
		t.Fatal("receipt corruption did not change exactly one field", fields)
	}
	oldRaw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	newRaw, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if string(oldRaw) == string(newRaw) {
		t.Fatal("receipt mutation was ineffective")
	}
	ctx := context.Background()
	if err := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		result, err := tx.Exec(ctx, `UPDATE local_automation_history SET receipt_json=? WHERE sequence=? AND receipt_json=?`, string(newRaw), sequence, string(oldRaw))
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("receipt corruption changed %d rows", n)
		}
		rows, err := tx.Query(ctx, `SELECT receipt_json FROM local_automation_history WHERE sequence=? LIMIT 1`, sequence)
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].String("receipt_json") != string(newRaw) {
			return fmt.Errorf("receipt corruption readback differs")
		}
		var observed contract.Receipt
		if err := json.Unmarshal([]byte(rows[0].String("receipt_json")), &observed); err != nil {
			return err
		}
		canonical, err := json.Marshal(observed)
		if err != nil {
			return err
		}
		if observed != changed || string(canonical) != string(newRaw) {
			return fmt.Errorf("receipt corruption is not the exact canonical changed object")
		}
		return nil
	}); err != nil {
		t.Fatal("effective canonical receipt corruption", err)
	}
	after := executionStorageSnapshot(t, f.c)
	for table, rows := range before {
		if table != "local_automation_history" {
			if !reflect.DeepEqual(rows, after[table]) {
				t.Fatal("receipt corruption changed other evidence", table)
			}
			continue
		}
		if len(rows) != len(after[table]) {
			t.Fatal("receipt corruption changed history count")
		}
		matched := 0
		for i, row := range rows {
			later := after[table][i]
			if !reflect.DeepEqual(row.Columns, later.Columns) || len(row.Values) != len(later.Values) {
				t.Fatal("receipt corruption changed history shape")
			}
			for j, column := range row.Columns {
				if row.Int64("sequence") == int64(sequence) && column == "receipt_json" {
					matched++
					if row.String(column) != string(oldRaw) || later.String(column) != string(newRaw) {
						t.Fatal("receipt mutation witness differs")
					}
				} else if !reflect.DeepEqual(row.Values[j], later.Values[j]) {
					t.Fatal("receipt corruption changed another original field", column)
				}
			}
		}
		if matched != 1 {
			t.Fatal("receipt corruption original row witness missing", matched)
		}
	}
	return after
}

func executionReceiptRequireRefusal(t *testing.T, f *executionStorageFixture, want string, corrupt map[string][]Row) {
	t.Helper()
	probe := f.progress(t, "running", nil)
	d, err := automationDecision(probe.Value)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	err = f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		head, err := automationHeadTx(ctx, tx)
		if err != nil {
			return err
		}
		_, err = automationProjectionTx(ctx, tx, head, d, nil)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatal("complete accepted original receipt refusal missing", want, err)
	}
	if !reflect.DeepEqual(corrupt, executionStorageSnapshot(t, f.c)) {
		t.Fatal("receipt refusal changed corrupt predecessor")
	}
	if err := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error { _, err := auditAutomationCutTx(ctx, tx, contract.Reduce); return err }); err == nil {
		t.Fatal("source audit accepted corrupt immutable receipt")
	}
	if !reflect.DeepEqual(corrupt, executionStorageSnapshot(t, f.c)) {
		t.Fatal("failed receipt source audit changed corrupt predecessor")
	}
}

func TestAutomationExecutionFULLRetainedReceiptUsesOriginalAssignment(t *testing.T) {
	for _, corruptTarget := range []string{"original", "retry"} {
		t.Run(corruptTarget, func(t *testing.T) {
			f := newExecutionStorageFixture(t)
			first := f.start(t)
			before := executionStorageSnapshot(t, f.c)
			d, err := automationDecision(f.grant.Value)
			if err != nil {
				t.Fatal(err)
			}
			d.Sequence++
			d.ParentDigest = f.grant.Value.MustDigest()
			a, err := contract.DecodeAssignment(d)
			if err != nil {
				t.Fatal(err)
			}
			a.OperationID = "receipt-retry-distinct-assignment"
			d.Assignment = automationExecutionJSON(t, a)
			retry := f.sign(d)
			if got := f.apply(t, retry); got != first || got.OperationID == a.OperationID || got.Sequence == d.Sequence {
				t.Fatal("retained retry did not preserve original complete receipt", got, first)
			}
			after := executionStorageSnapshot(t, f.c)
			for _, table := range executionStorageTables {
				if !reflect.DeepEqual(before[table], after[table]) {
					t.Fatal("retained retry rewrote derived execution", table)
				}
			}
			executionReceiptRequireBaseline(t, f)
			changed := first
			changed.Revision = 1
			sequence, want := first.Sequence, "execution original accepted receipt differs"
			if corruptTarget == "retry" {
				sequence, want = d.Sequence, "execution retained retry differs from original receipt"
			}
			corrupt := executionReceiptWriteSingleFieldCorruption(t, f, sequence, first, changed, executionStorageSnapshot(t, f.c))
			executionReceiptRequireRefusal(t, f, want, corrupt)
		})
	}
}
