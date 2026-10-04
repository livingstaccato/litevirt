package corrosion

import (
	"context"
	"testing"
)

// The VM operation barrier writes must never modify a tombstoned row.
//
// BeginVMOperation's claim (spec, spec_generation + 1, active_operation_id)
// and the barrier clear that CompleteVMOperation, AbortVMOperation and
// FailVMOperation share are keyed on the name plus the owner/generation CAS,
// and a tombstone carries all of those. The origin's Go guard reads the row
// with `deleted_at IS NULL`, but a receiver applies the statement it is sent:
// an operation begun while the VM was live on its origin, reaching a peer that
// already holds the tombstone, stamped a barrier and a new spec generation onto
// the deleted row. Like the VM state writers they keep their wire shape and are
// made tombstone-safe by DispLiveRowUpdate (live_row_update.go).

type vmOpRowImage struct {
	spec, activeOp, updatedAt, deletedAt string
	ownerEpoch, specGen                  int64
}

func vmOpRow(t *testing.T, c *Client) vmOpRowImage {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT spec, active_operation_id, updated_at, deleted_at, vm_owner_epoch, spec_generation
		   FROM vms WHERE name = 'vm1'`)
	if err != nil {
		t.Fatalf("read vm1: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want one vm1 row, have %d", len(rows))
	}
	r := rows[0]
	return vmOpRowImage{r.String("spec"), r.String("active_operation_id"), r.String("updated_at"),
		r.String("deleted_at"), r.Int64("vm_owner_epoch"), r.Int64("spec_generation")}
}

func tombstoneOp(id string) OperationRecord {
	return OperationRecord{
		ID:     DeterministicOperationID("UpdateVM", "user:alice@local", "", "vm1", id),
		Method: "UpdateVM", Principal: "user:alice@local", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpResourceUpdateRunning), RequestHash: "hash-" + id, IdempotencyKey: id,
	}
}

// tombstonedVMHoldingOp: vm1 had op "k1" begun (generation 0 → 1) and was
// then tombstoned with the barrier still set — the row a clear would reach.
func tombstonedVMHoldingOp(t *testing.T, c *Client) OperationRecord {
	t.Helper()
	ctx := context.Background()
	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "host-a", State: "stopped", Spec: `{}`}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	op := tombstoneOp("k1")
	if applied, err := c.BeginVMOperation(ctx, op, `{"cpu":4}`, 0, 0); err != nil || !applied {
		t.Fatalf("BeginVMOperation: applied=%v err=%v", applied, err)
	}
	if err := DeleteVM(ctx, c, "vm1"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	got := vmOpRow(t, c)
	if got.deletedAt == "" || got.activeOp != op.ID || got.specGen != 1 {
		t.Fatalf("setup: want vm1 tombstoned holding %s at generation 1, have %+v", op.ID, got)
	}
	return op
}

func TestVMOperationWrites_DoNotModifyATombstone(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, c *Client) OperationRecord
		write func(c *Client, op OperationRecord) (bool, error)
	}{
		{"BeginVMOperation", func(t *testing.T, c *Client) OperationRecord {
			tombstonedVM(t, c)
			return tombstoneOp("k2")
		}, func(c *Client, op OperationRecord) (bool, error) {
			return c.BeginVMOperation(ctx, op, `{"cpu":8}`, 0, 0)
		}},
		{"CompleteVMOperation", tombstonedVMHoldingOp, func(c *Client, op OperationRecord) (bool, error) {
			return c.CompleteVMOperation(ctx, "vm1", op.ID, 0, 1)
		}},
		{"AbortVMOperation", tombstonedVMHoldingOp, func(c *Client, op OperationRecord) (bool, error) {
			return c.AbortVMOperation(ctx, "vm1", op.ID, 0, 1)
		}},
		{"FailVMOperation", tombstonedVMHoldingOp, func(c *Client, op OperationRecord) (bool, error) {
			return c.FailVMOperation(ctx, "vm1", op.ID, 0, 1, `{"code":"Internal"}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestDB(t)
			op := tc.setup(t, c)
			before := vmOpRow(t, c)
			applied, err := tc.write(c, op)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if applied {
				t.Error("an operation write to a tombstone must report applied=false")
			}
			if after := vmOpRow(t, c); after != before {
				t.Errorf("the write modified a tombstoned row:\n before %+v\n after  %+v", before, after)
			}
		})
	}
}

// The receive side: the origin's row was live when it wrote, and this receiver
// already holds the tombstone. An older sender emits exactly these shapes.
func TestReplicatedVMOperationWrite_DoesNotLandOnATombstone(t *testing.T) {
	const far = "2999-01-01T00:00:00.000001Z"
	const hlcTS = "2999000000000-0000-peer"
	held := tombstoneOp("k1").ID
	for _, tc := range []struct {
		name      string
		tombstone func(t *testing.T, c *Client)
		live      func(t *testing.T, c *Client)
		stmt      Statement
		wantLive  func(r vmOpRowImage) bool
	}{
		{"begin",
			tombstonedVM,
			func(t *testing.T, c *Client) {
				if err := InsertVM(context.Background(), c, VMRecord{Name: "vm1", HostName: "host-a", State: "stopped", Spec: `{}`}, nil, nil); err != nil {
					t.Fatalf("InsertVM: %v", err)
				}
			},
			Statement{SQL: vmOperationBeginSQL, Params: []interface{}{`{"cpu":8}`, "op-remote", far, "vm1", int64(0), int64(0)}},
			func(r vmOpRowImage) bool { return r.activeOp == "op-remote" && r.specGen == 1 },
		},
		{"barrier clear",
			func(t *testing.T, c *Client) { tombstonedVMHoldingOp(t, c) },
			func(t *testing.T, c *Client) {
				ctx := context.Background()
				if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "host-a", State: "stopped", Spec: `{}`}, nil, nil); err != nil {
					t.Fatalf("InsertVM: %v", err)
				}
				if applied, err := c.BeginVMOperation(ctx, tombstoneOp("k1"), `{"cpu":4}`, 0, 0); err != nil || !applied {
					t.Fatalf("BeginVMOperation: applied=%v err=%v", applied, err)
				}
			},
			Statement{SQL: vmOperationClearSQL, Params: []interface{}{far, "vm1", held, int64(0), int64(1)}},
			func(r vmOpRowImage) bool { return r.activeOp == "" },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestDB(t)
			tc.tombstone(t, c)
			before := vmOpRow(t, c)
			applyRemote(t, c, hlcTS, tc.stmt)
			if after := vmOpRow(t, c); after != before {
				t.Errorf("a replicated operation write modified a tombstoned row:\n before %+v\n after  %+v", before, after)
			}
		})
		t.Run(tc.name+" live row", func(t *testing.T) {
			c := newTestDB(t)
			tc.live(t, c)
			applyRemote(t, c, hlcTS, tc.stmt)
			if got := vmOpRow(t, c); !tc.wantLive(got) || got.deletedAt != "" {
				t.Errorf("a replicated operation write did not reach a live row: %+v", got)
			}
		})
	}
}

// The wire shape must not change (see TestVMStateWriters_KeepTheirWireShape).
func TestVMOperationWrites_KeepTheirWireShape(t *testing.T) {
	for _, sql := range []string{vmOperationBeginSQL, vmOperationClearSQL} {
		e, err := LedgerEntryFor(sql)
		if err != nil {
			t.Fatalf("LedgerEntryFor(%q): %v", sql, err)
		}
		if e.Disposition != DispLiveRowUpdate {
			t.Errorf("%q: disposition %s, want %s", sql, e.Disposition, DispLiveRowUpdate)
		}
		if _, ok := stmtLedger[e.Fingerprint]; !ok {
			t.Errorf("%q is not in the generated ledger", sql)
		}
	}
}
