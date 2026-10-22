package corrosion

import (
	"context"
	"errors"
	"testing"
)

// The replay of an operator-stop marker writes only while the row is still
// the one the marker recorded: on that host, of that incarnation, at that
// owner epoch — checked inside the write's transaction, so a transfer that
// lands after the replay's read is not written over.
//
// Mutation: the guard always true — each mismatched call writes: red.
func TestUpdateVMStateIfOwner_GuardsHostIncarnationEpoch(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := InsertVM(ctx, c, VMRecord{Name: "web", HostName: "node-a", State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	row, err := GetVM(ctx, c, "web")
	if err != nil || row == nil {
		t.Fatal(err)
	}
	for name, call := range map[string]struct {
		host, createdAt string
		epoch           int64
	}{
		"another host":        {"node-b", row.CreatedAt, row.OwnerEpoch},
		"another incarnation": {"node-a", "1999-01-01T00:00:00Z", row.OwnerEpoch},
		"a later epoch":       {"node-a", row.CreatedAt, row.OwnerEpoch + 2},
	} {
		err := UpdateVMStateIfOwner(ctx, c, "web", call.host, call.createdAt, call.epoch, "stopped", "operator-stop")
		if !errors.Is(err, ErrNoRowsAffected) {
			t.Errorf("%s: err %v, want ErrNoRowsAffected", name, err)
		}
		if got, _ := GetVM(ctx, c, "web"); got.State != "running" || got.StateDetail != "" {
			t.Fatalf("%s: row written: %s/%q", name, got.State, got.StateDetail)
		}
	}
	if err := UpdateVMStateIfOwner(ctx, c, "web", "node-a", row.CreatedAt, row.OwnerEpoch, "stopped", "operator-stop"); err != nil {
		t.Fatalf("the recorded identity: %v", err)
	}
	if got, _ := GetVM(ctx, c, "web"); got.State != "stopped" || got.StateDetail != "operator-stop" {
		t.Errorf("row %s/%q, want stopped/operator-stop", got.State, got.StateDetail)
	}
	if err := UpdateVMStateIfOwner(ctx, c, "gone", "node-a", row.CreatedAt, row.OwnerEpoch, "stopped", "operator-stop"); !errors.Is(err, ErrNoRowsAffected) {
		t.Errorf("no row: err %v, want ErrNoRowsAffected", err)
	}
}
