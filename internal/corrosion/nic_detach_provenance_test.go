package corrosion

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestDetachedNICMACs_RequiresBoundCompletedIncarnation(t *testing.T) {
	const mac = "52:54:00:aa:dd:71"
	for _, tc := range []struct {
		name, terminal, facts string
		want, fail, reaped    bool
	}{
		{"admission_only", "", "", false, false, false}, {"failed", OpStepFailed, "", false, false, false},
		{"legacy_completed", OpStepCompleted, "", false, true, false}, {"malformed_completed", OpStepCompleted, "bad", false, true, false},
		{"current_completed", OpStepCompleted, "current", true, false, false}, {"historical_epoch_reaped", OpStepCompleted, "current", true, false, true},
		{"other_incarnation", OpStepCompleted, "old", false, false, false}, {"wrong_mac", OpStepCompleted, "wrong_mac", false, true, false},
		{"wrong_execution_epoch", OpStepCompleted, "wrong_epoch", false, true, false}, {"conflicting_terminals", OpStepCompleted, "conflict", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := testClient(t)
			if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h1", State: "stopped", Spec: "{}"}, nil, nil); err != nil {
				t.Fatal(err)
			}
			vm, err := GetVM(ctx, c, "vm1")
			if err != nil || vm == nil || vm.CreatedAt == "" {
				t.Fatal("missing actual incarnation", vm, err)
			}
			op := OperationRecord{ID: "detach-provenance", Method: "DetachDevice", ResourceKind: "vm", ResourceID: "vm1", OperationKind: string(OpDeviceDetach), RequestHash: NICDetachRequestHash("vm1", mac), VMOwnerEpoch: 2}
			if err := InsertOperation(ctx, c, op); err != nil {
				t.Fatal(err)
			}
			facts := ""
			if tc.facts == "bad" {
				facts = "{"
			} else if tc.facts != "" {
				stamp, cm, epoch := vm.CreatedAt, mac, int64(2)
				if tc.facts == "old" {
					stamp = "1999-01-01T00:00:00Z"
				}
				if tc.facts == "wrong_mac" {
					cm = "52:54:00:aa:dd:72"
				}
				if tc.facts == "wrong_epoch" {
					epoch = 3
				}
				b, _ := json.Marshal(map[string]any{"version": 1, "vm_created_at": stamp, "mac": cm, "owner_epoch": epoch})
				facts = string(b)
			}
			if tc.terminal != "" {
				if err := AppendOperationStep(ctx, c, OperationStepRecord{OperationID: op.ID, OwnerEpoch: 2, StepName: tc.terminal, Facts: facts}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.facts == "conflict" {
				if err := AppendOperationStep(ctx, c, OperationStepRecord{OperationID: op.ID, OwnerEpoch: 2, StepName: OpStepFailed}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.reaped {
				if _, err := c.DB().Exec(`UPDATE vms SET vm_owner_epoch=7 WHERE name='vm1'`); err != nil {
					t.Fatal(err)
				}
				if _, err := c.DB().Exec(`UPDATE operations SET deleted_at='2020-01-01T00:00:00Z' WHERE id=?`, op.ID); err != nil {
					t.Fatal(err)
				}
				if _, err := c.DB().Exec(`UPDATE operation_steps SET deleted_at='2020-01-01T00:00:00Z' WHERE operation_id=?`, op.ID); err != nil {
					t.Fatal(err)
				}
			}
			got, err := DetachedNICMACs(ctx, c, "vm1", []string{strings.ToUpper(mac)})
			if (err != nil) != tc.fail {
				t.Errorf("provenance refusal=%v want refusal=%v; result=%v", err, tc.fail, got)
			}
			if !tc.fail && got[mac] != tc.want {
				t.Errorf("header/incorrect lifetime became successful detach proof: got=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestNICDetachCompletion_StrictFacts(t *testing.T) {
	valid := `{"version":1,"vm_created_at":"original","mac":"52:54:00:aa:00:91","owner_epoch":0}`
	for _, raw := range []string{valid, strings.Replace(valid, `"owner_epoch":0`, `"owner_epoch":null`, 1), strings.Replace(valid, `"owner_epoch":0`, `"owner_epoch":0,"owner_epoch":0`, 1), strings.Replace(valid, `"owner_epoch":0`, `"extra":0,"owner_epoch":0`, 1)} {
		_, err := decodeNICDetachCompletion(raw)
		if (err == nil) != (raw == valid) {
			t.Errorf("strict completed provenance accepted malformed facts %s: %v", raw, err)
		}
	}
}

func TestCompleteNICDetach_TransactionGuardsOriginalIncarnation(t *testing.T) {
	for _, change := range []string{"none", "incarnation", "owner", "generation", "barrier", "header", "terminal"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			c := testClient(t)
			const mac = "52:54:00:aa:00:92"
			if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h1", State: "stopped", Spec: "{}"}, nil, nil); err != nil {
				t.Fatal(err)
			}
			vm, err := GetVM(ctx, c, "vm1")
			if err != nil || vm == nil {
				t.Fatal(vm, err)
			}
			op := OperationRecord{ID: "guarded-detach", Method: "DetachDevice", ResourceKind: "vm", ResourceID: "vm1", OperationKind: string(OpDeviceDetach), RequestHash: NICDetachRequestHash("vm1", mac)}
			if ok, err := c.BeginVMOperation(ctx, op, vm.Spec, 0, 0); err != nil || !ok {
				t.Fatal(ok, err)
			}
			edits := map[string]string{"incarnation": `UPDATE vms SET created_at='replacement' WHERE name='vm1'`, "owner": `UPDATE vms SET vm_owner_epoch=1 WHERE name='vm1'`, "generation": `UPDATE vms SET spec_generation=2 WHERE name='vm1'`, "barrier": `UPDATE vms SET active_operation_id='other' WHERE name='vm1'`, "header": `UPDATE operations SET request_hash='different' WHERE id='guarded-detach'`}
			if sql := edits[change]; sql != "" {
				if _, err := c.DB().Exec(sql); err != nil {
					t.Fatal(err)
				}
			}
			if change == "terminal" {
				if err := AppendOperationStep(ctx, c, OperationStepRecord{OperationID: op.ID, StepName: OpStepFailed}); err != nil {
					t.Fatal(err)
				}
			}
			snap := func() []Row {
				rows, err := c.Query(ctx, `SELECT * FROM vms WHERE name='vm1'`)
				if err != nil {
					t.Fatal(err)
				}
				return rows
			}
			before := snap()
			ok, err := c.CompleteVMNICDetach(ctx, "vm1", op.ID, 0, 1, vm.CreatedAt, mac)
			if err != nil || ok != (change == "none") {
				t.Fatalf("completion guard=%v err=%v change=%s", ok, err, change)
			}
			rows, err := c.Query(ctx, `SELECT * FROM operation_steps WHERE operation_id=? AND step_name='completed'`, op.ID)
			if err != nil {
				t.Fatal(err)
			}
			if change != "none" && (!reflect.DeepEqual(before, snap()) || len(rows) != 0) {
				t.Fatal("stale completion changed row or published facts")
			}
			if change == "none" && len(rows) != 1 {
				t.Fatal("successful completion did not record facts")
			}
		})
	}
}
