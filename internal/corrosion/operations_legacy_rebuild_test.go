package corrosion

import (
	"context"
	"reflect"
	"testing"
)

// Storage CAS only: this interface supplies no automation permit or runtime authority.
type snapshotVMOperationBeginner interface {
	BeginVMOperationAtSnapshot(context.Context, OperationRecord, string, VMDeleteSnapshot) (bool, error)
}

func snapshotCASReadVM(t *testing.T, c *Client) *VMRecord {
	t.Helper()
	vm, err := GetVM(context.Background(), c, "snapshot-vm")
	if err != nil || vm == nil {
		t.Fatalf("read actual ordinary VM: vm=%+v err=%v", vm, err)
	}
	return vm
}

func snapshotCASFixture(t *testing.T) (*Client, VMDeleteSnapshot, OperationRecord) {
	t.Helper()
	c := newTestDB(t)
	c.SetVMSnapshotClaimCapability(func() bool { return true }, func(context.Context) bool { return true })
	spec := `{"cpu":2,"domain_uuid":"old-domain","firewall_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	if err := InsertVM(context.Background(), c, VMRecord{
		Name: "snapshot-vm", HostName: "snapshot-host", Project: "default",
		State: "stopped", Spec: spec,
		FirewallCarry: CarryFirewallID(TagMemberVM, spec),
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	vm := snapshotCASReadVM(t, c)
	snap := SnapshotForDelete(*vm)
	if snap.CreatedAt == "" || snap.HostName != "snapshot-host" || snap.IdentityHash == "" ||
		snap.FirewallID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || vm.Project != "default" ||
		vm.OwnerEpoch != 0 || vm.SpecGeneration != 0 {
		t.Fatalf("ordinary fixture lacks exact snapshot facts: vm=%+v snapshot=%+v", vm, snap)
	}
	op := OperationRecord{
		ID:     DeterministicOperationID("UpdateVM", "user:alice@local", "default", vm.Name, "snapshot-key"),
		Method: "UpdateVM", Principal: "user:alice@local", Project: "default",
		ResourceKind: "vm", ResourceID: vm.Name, OperationKind: string(OpResourceUpdateStopped),
		RequestHash: "snapshot-request", IdempotencyKey: "snapshot-key",
	}
	return c, snap, op
}

func snapshotCASRequire(t *testing.T, c *Client) snapshotVMOperationBeginner {
	t.Helper()
	begin, ok := any(c).(snapshotVMOperationBeginner)
	if !ok {
		t.Fatal("missing BeginVMOperationAtSnapshot storage capability after real ordinary VM setup")
	}
	return begin
}

// Entire ordinary row + both journal tables, including timestamps and tombstones.
func snapshotCASImage(t *testing.T, c *Client) [][]Row {
	t.Helper()
	var out [][]Row
	for _, query := range []string{
		`SELECT * FROM vms ORDER BY name`,
		`SELECT * FROM operations ORDER BY id`,
		`SELECT * FROM operation_steps ORDER BY operation_id,owner_epoch,step_name`,
		`SELECT * FROM mutation_log ORDER BY seq`,
	} {
		rows, err := c.Query(context.Background(), query)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rows)
	}
	return out
}

func snapshotCASRefuse(t *testing.T, c *Client, op OperationRecord, snap VMDeleteSnapshot) {
	t.Helper()
	before := snapshotCASImage(t, c)
	applied, err := snapshotCASRequire(t, c).BeginVMOperationAtSnapshot(context.Background(), op, `{"cpu":4}`, snap)
	if applied {
		t.Fatalf("snapshot mismatch/competing operation applied: err=%v", err)
	}
	// Validation may return an error; both conflict and stale-precondition outcomes
	// must leave every ordinary row/header/step untouched.
	if after := snapshotCASImage(t, c); !reflect.DeepEqual(before, after) {
		t.Fatalf("refusal mutated row or journal: err=%v\nbefore=%+v\nafter=%+v", err, before, after)
	}
}

func TestBeginVMOperationAtSnapshot(t *testing.T) {
	// One capability RED after actual setup. Child behavior cases are deliberately
	// not run until the selected production interface exists.
	probe, _, _ := snapshotCASFixture(t)
	snapshotCASRequire(t, probe)

	t.Run("exact_row_and_retry", func(t *testing.T) {
		c, snap, op := snapshotCASFixture(t)
		begin := snapshotCASRequire(t, c)
		if applied, err := begin.BeginVMOperationAtSnapshot(context.Background(), op, `{"cpu":4}`, snap); err != nil || !applied {
			t.Fatalf("exact row claim: applied=%v err=%v", applied, err)
		}
		vm := snapshotCASReadVM(t, c)
		if vm.CreatedAt != snap.CreatedAt || vm.HostName != snap.HostName || vm.OwnerEpoch != snap.OwnerEpoch ||
			vm.SpecGeneration != snap.SpecGeneration+1 || vm.ActiveOperationID != op.ID ||
			jsonExactString(vm.Spec, "firewall_id") != snap.FirewallID {
			t.Fatalf("wrong claimed transition: %+v", vm)
		}
		var cpu int
		rows, err := c.Query(context.Background(), `SELECT json_extract(spec,'$.cpu') AS cpu FROM vms WHERE name=?`, op.ResourceID)
		if err != nil || len(rows) != 1 {
			t.Fatalf("desired spec read: %+v %v", rows, err)
		}
		cpu = rows[0].Int("cpu")
		if cpu != 4 {
			t.Fatalf("desired CPU=%d want 4", cpu)
		}
		header, err := GetOperation(context.Background(), c, op.ID)
		if err != nil || header == nil || !sameOperationClaim(*header, op) {
			t.Fatalf("immutable operation identity lost: %+v %v", header, err)
		}
		steps, err := ListOperationSteps(context.Background(), c, op.ID, snap.OwnerEpoch)
		if err != nil || len(steps) != 1 || steps[0].StepName != OpStepPlanned {
			t.Fatalf("expected exactly one planned step: %+v %v", steps, err)
		}
		before := snapshotCASImage(t, c)
		if applied, err := begin.BeginVMOperationAtSnapshot(context.Background(), op, `{"cpu":4}`, snap); err != nil || !applied {
			t.Fatalf("same operation retry: applied=%v err=%v", applied, err)
		}
		if after := snapshotCASImage(t, c); !reflect.DeepEqual(before, after) {
			t.Fatal("retry changed persisted row/header/step")
		}
		wrong := snap
		wrong.CreatedAt += "-wrong"
		snapshotCASRefuse(t, c, op, wrong)
		wrong = snap
		wrong.IdentityHash = "wrong-preclaim-identity"
		snapshotCASRefuse(t, c, op, wrong)
		wrong = snap
		wrong.SpecGeneration++
		snapshotCASRefuse(t, c, op, wrong)
		other := op
		other.ID += "-other"
		snapshotCASRefuse(t, c, other, SnapshotForDelete(*vm))
	})

	t.Run("exact_axes", func(t *testing.T) {
		for _, axis := range []string{"created", "host", "epoch", "generation", "identity", "empty_created", "empty_identity"} {
			t.Run(axis, func(t *testing.T) {
				c, snap, op := snapshotCASFixture(t)
				switch axis {
				case "created":
					snap.CreatedAt += "-wrong"
				case "host":
					snap.HostName += "-wrong"
				case "epoch":
					snap.OwnerEpoch++
				case "generation":
					snap.SpecGeneration++
				case "identity":
					snap.IdentityHash = "wrong"
				case "empty_created":
					snap.CreatedAt = ""
				case "empty_identity":
					snap.IdentityHash = ""
				}
				snapshotCASRefuse(t, c, op, snap)
			})
		}
	})

	t.Run("replacement_ABA", func(t *testing.T) {
		for _, sameSpec := range []bool{false, true} {
			t.Run(map[bool]string{false: "different_domain", true: "created_at_only"}[sameSpec], func(t *testing.T) {
				c, snap, op := snapshotCASFixture(t)
				old := snapshotCASReadVM(t, c)
				if err := DeleteVM(context.Background(), c, old.Name); err != nil {
					t.Fatal(err)
				}
				spec := old.Spec
				if !sameSpec {
					spec = `{"cpu":2,"domain_uuid":"new-domain","firewall_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
				}
				if err := InsertVM(context.Background(), c, VMRecord{
					Name: old.Name, HostName: old.HostName, Project: old.Project, Spec: spec, State: "stopped",
					FirewallCarry: CarryFirewallID(TagMemberVM, old.Spec),
				}, nil, nil); err != nil {
					t.Fatal(err)
				}
				now := SnapshotForDelete(*snapshotCASReadVM(t, c))
				if now.CreatedAt == snap.CreatedAt || now.OwnerEpoch != snap.OwnerEpoch ||
					now.SpecGeneration != snap.SpecGeneration || now.FirewallID != snap.FirewallID ||
					(sameSpec && now.IdentityHash != snap.IdentityHash) {
					t.Fatalf("not the intended real ordinary replacement: old=%+v new=%+v", snap, now)
				}
				snapshotCASRefuse(t, c, op, snap)
			})
		}
	})

	t.Run("missing_or_tombstoned", func(t *testing.T) {
		c, snap, op := snapshotCASFixture(t)
		missing := op
		missing.ID += "-missing"
		missing.ResourceID = "missing-vm"
		snapshotCASRefuse(t, c, missing, snap)
		if err := DeleteVM(context.Background(), c, op.ResourceID); err != nil {
			t.Fatal(err)
		}
		snapshotCASRefuse(t, c, op, snap)
	})

	t.Run("retry_after_reopen", func(t *testing.T) {
		ctx := context.Background()
		dir := t.TempDir()
		c, err := NewLocalClient(dir, "snapshot-host")
		if err != nil {
			t.Fatal(err)
		}
		c.SetVMSnapshotClaimCapability(func() bool { return true }, func(context.Context) bool { return true })
		t.Cleanup(func() {
			if c != nil {
				c.Close()
			}
		})
		if err := InitSchema(ctx, c); err != nil {
			t.Fatal(err)
		}
		if err := InsertVM(ctx, c, VMRecord{Name: "snapshot-vm", HostName: "snapshot-host", Project: "default", State: "stopped", Spec: `{}`}, nil, nil); err != nil {
			t.Fatal(err)
		}
		snap := SnapshotForDelete(*snapshotCASReadVM(t, c))
		op := OperationRecord{ID: "reopen-snapshot-op", Method: "UpdateVM", Principal: "user:alice@local", Project: "default", ResourceKind: "vm", ResourceID: "snapshot-vm", OperationKind: string(OpResourceUpdateStopped), RequestHash: "reopen-request", IdempotencyKey: "reopen-key"}
		if applied, err := snapshotCASRequire(t, c).BeginVMOperationAtSnapshot(ctx, op, `{"cpu":4}`, snap); err != nil || !applied {
			t.Fatalf("begin: applied=%v err=%v", applied, err)
		}
		before := snapshotCASImage(t, c)
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		c, err = NewLocalClient(dir, "snapshot-host")
		if err != nil {
			t.Fatal(err)
		}
		c.SetVMSnapshotClaimCapability(func() bool { return true }, func(context.Context) bool { return true })
		if applied, err := snapshotCASRequire(t, c).BeginVMOperationAtSnapshot(ctx, op, `{"cpu":4}`, snap); err != nil || !applied {
			t.Fatalf("reopen retry: applied=%v err=%v", applied, err)
		}
		if after := snapshotCASImage(t, c); !reflect.DeepEqual(before, after) {
			t.Fatal("reopen retry mutated persisted claim")
		}
	})
}
