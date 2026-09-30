package corrosion

import (
	"context"
	"errors"
	"testing"
)

// VM state writes must never modify a tombstoned row.
//
// Observed on the kvm003-f3 lab, 2026-09-30: a stale delete tombstoned claimvm
// cluster-wide while it kept running on node-4. node-4's health checker had
// listed the VM before the tombstone arrived and wrote "running" after it, and
// UpdateVMStateStrict's `WHERE name = ?` matched the tombstone. That write
// replicated too, so every replica ended up holding a row that was both
// `running` and deleted.
//
// The writers keep their wire shape (a receiver on the previous release must
// still recognise what they send). Their ledger disposition, DispLiveRowUpdate,
// is what makes them tombstone-safe: the origin and every receiver apply them
// through the `AND deleted_at IS NULL` form.

// tombstonedVM inserts vm1 on host-a in state `stopped` and tombstones it.
func tombstonedVM(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "host-a", State: "stopped", Spec: `{}`}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := DeleteVM(ctx, c, "vm1"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if !vm1Deleted(t, c) {
		t.Fatal("setup: vm1 must be tombstoned")
	}
}

type vmRowImage struct {
	host, state, detail, deletedAt string
}

func vm1Row(t *testing.T, c *Client) vmRowImage {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT host_name, state, state_detail, deleted_at FROM vms WHERE name = 'vm1'`)
	if err != nil {
		t.Fatalf("read vm1: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want one vm1 row, have %d", len(rows))
	}
	return vmRowImage{rows[0].String("host_name"), rows[0].String("state"),
		rows[0].String("state_detail"), rows[0].String("deleted_at")}
}

func vm1Deleted(t *testing.T, c *Client) bool { return vm1Row(t, c).deletedAt != "" }

// The writers, as the production callers invoke them.
var vmStateWriters = []struct {
	name   string
	strict bool // a zero-row write is an error the caller sees
	write  func(ctx context.Context, c *Client) error
}{
	{"UpdateVMState", false, func(ctx context.Context, c *Client) error {
		return UpdateVMState(ctx, c, "vm1", "running", "reconciled from libvirt")
	}},
	{"UpdateVMStateStrict", true, func(ctx context.Context, c *Client) error {
		return UpdateVMStateStrict(ctx, c, "vm1", "running", "reconciled from libvirt: domain running")
	}},
	{"UpdateVMStateAtEpoch", false, func(ctx context.Context, c *Client) error {
		return UpdateVMStateAtEpoch(ctx, c, "vm1", "running", "", 0)
	}},
	{"UpdateVMHost", false, func(ctx context.Context, c *Client) error {
		return UpdateVMHost(ctx, c, "vm1", "host-b", "running")
	}},
	{"CommitMigrationOwnership", true, func(ctx context.Context, c *Client) error {
		committed, err := CommitMigrationOwnership(ctx, c, "vm1", "host-a", "host-b", "running", nil)
		if err == nil && !committed {
			return ErrNoRowsAffected
		}
		return err
	}},
}

func TestVMStateWriters_DoNotModifyATombstone(t *testing.T) {
	for _, w := range vmStateWriters {
		t.Run(w.name, func(t *testing.T) {
			ctx := context.Background()
			c := newTestDB(t)
			tombstonedVM(t, c)
			before := vm1Row(t, c)

			err := w.write(ctx, c)
			if w.strict && !errors.Is(err, ErrNoRowsAffected) {
				t.Errorf("a write to a tombstone must report ErrNoRowsAffected so its caller does not act on it, got %v", err)
			}
			if !w.strict && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if after := vm1Row(t, c); after != before {
				t.Errorf("the write modified a tombstoned row:\n before %+v\n after  %+v", before, after)
			}
		})
	}
}

// The guard must not cost a live row anything.
func TestVMStateWriters_StillWriteALiveRow(t *testing.T) {
	for _, w := range vmStateWriters {
		t.Run(w.name, func(t *testing.T) {
			ctx := context.Background()
			c := newTestDB(t)
			if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "host-a", State: "stopped", Spec: `{}`}, nil, nil); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			if err := w.write(ctx, c); err != nil {
				t.Fatalf("write to a live row: %v", err)
			}
			if got := vm1Row(t, c); got.state != "running" || got.deletedAt != "" {
				t.Errorf("live row not written: %+v", got)
			}
		})
	}
}

// The receive side, which is also what an OLDER peer relies on: it still sends
// the name-keyed shape, and it can have been written against a row that was
// live on the sender while this receiver already holds the tombstone.
func TestReplicatedVMStateWrite_DoesNotLandOnATombstone(t *testing.T) {
	const far = "2999-01-01T00:00:00.000001Z"
	const hlcTS = "2999000000000-0000-peer"
	for _, tc := range []struct {
		name string
		stmt Statement
	}{
		{"state", Statement{SQL: vmStateUpdateSQL,
			Params: []interface{}{"running", "reconciled from libvirt", far, "vm1"}}},
		{"state at epoch", Statement{SQL: vmStateAtEpochSQL,
			Params: []interface{}{"running", "", far, "vm1", int64(0)}}},
		{"host and state", Statement{SQL: vmHostStateSQL,
			Params: []interface{}{"host-b", "running", far, "vm1"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestDB(t)
			tombstonedVM(t, c)
			before := vm1Row(t, c)
			applyRemote(t, c, hlcTS, tc.stmt)
			if after := vm1Row(t, c); after != before {
				t.Errorf("a replicated state write modified a tombstoned row:\n before %+v\n after  %+v", before, after)
			}
		})
		t.Run(tc.name+" live row", func(t *testing.T) {
			ctx := context.Background()
			c := newTestDB(t)
			if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "host-a", State: "stopped", Spec: `{}`}, nil, nil); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			applyRemote(t, c, hlcTS, tc.stmt)
			if got := vm1Row(t, c); got.state != "running" {
				t.Errorf("a replicated state write did not reach a live row: %+v", got)
			}
		})
	}
}

// The wire shape must not change: a receiver on the previous release knows
// these fingerprints and no other, and a shape it does not know back-pressures
// the sender's whole stream.
func TestVMStateWriters_KeepTheirWireShape(t *testing.T) {
	for _, sql := range []string{vmStateUpdateSQL, vmStateAtEpochSQL, vmHostStateSQL} {
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
