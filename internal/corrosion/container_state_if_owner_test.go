package corrosion

import (
	"context"
	"errors"
	"testing"
)

// The replay of a container's operator-stop marker writes only while the
// row is still the one the marker recorded: of that incarnation, at that
// owner epoch — checked inside the write's transaction.
//
// Mutation: the guard always true — the re-created row is written: red.
func TestSetContainerStateDetailIfOwner_GuardsIncarnationEpoch(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := UpsertContainer(ctx, c, ContainerRecord{HostName: "node-a", Name: "web", State: "running"}); err != nil {
		t.Fatal(err)
	}
	row, err := GetContainer(ctx, c, "node-a", "web")
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
		err := SetContainerStateDetailIfOwner(ctx, c, call.host, "web", call.createdAt, call.epoch, "stopped", "operator-stop")
		if !errors.Is(err, ErrNoRowsAffected) {
			t.Errorf("%s: err %v, want ErrNoRowsAffected", name, err)
		}
		if got, _ := GetContainer(ctx, c, "node-a", "web"); got.State != "running" || got.StateDetail != "" {
			t.Fatalf("%s: row written: %s/%q", name, got.State, got.StateDetail)
		}
	}
	if err := SetContainerStateDetailIfOwner(ctx, c, "node-a", "web", row.CreatedAt, row.OwnerEpoch, "stopped", "operator-stop"); err != nil {
		t.Fatalf("the recorded identity: %v", err)
	}
	if got, _ := GetContainer(ctx, c, "node-a", "web"); got.State != "stopped" || got.StateDetail != "operator-stop" {
		t.Errorf("row %s/%q, want stopped/operator-stop", got.State, got.StateDetail)
	}
}
