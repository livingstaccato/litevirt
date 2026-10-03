package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Placement is strict about litevirt.lxc, so a label that never lands leaves a
// capable host refusing every container. Written only at start, two real cases
// stuck until the next restart: the start-time write found no host row yet (the
// UPDATE matched nothing), and the label was replaced afterwards — the labels
// column is one JSON value, so a concurrent read-modify-write elsewhere drops
// it. The keeper heals both within an interval.
//
// Mutation: make keepLXCLabel return without re-asserting — neither label
// appears and both halves go red.
func TestKeepLXCLabel_HealsALabelThatDidNotLand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	available := func() bool { return true }

	// The start-time assert finds no host row: nothing is written.
	if _, err := assertLXCLabel(ctx, db, "node-1", available); err != nil {
		t.Fatalf("assert with no host row: %v", err)
	}
	go keepLXCLabel(ctx, db, "node-1", available, 10*time.Millisecond)

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "node-1", Address: "10.0.0.1", SSHUser: "root", GRPCPort: 7443, State: "active",
	}); err != nil {
		t.Fatalf("insert host: %v", err)
	}
	waitRunsContainers(t, ctx, db, "node-1", "the host row appeared after the start-time write")

	if err := db.Execute(ctx, `UPDATE hosts SET labels = '{"zone":"a"}' WHERE name = 'node-1'`); err != nil {
		t.Fatalf("replace labels: %v", err)
	}
	waitRunsContainers(t, ctx, db, "node-1", "a later write replaced the labels")
}

func waitRunsContainers(t *testing.T, ctx context.Context, db *corrosion.Client, host, why string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		h, err := corrosion.GetHost(ctx, db, host)
		if err == nil && h != nil && corrosion.HostRunsContainers(*h) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s is not labelled %s=true after 5s (%s): %+v, err %v",
				host, corrosion.LabelLXCCapable, why, h, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
