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
// Mutation: make keepCapabilityLabels return without re-asserting — neither
// label appears and both halves go red.
func TestKeepCapabilityLabels_HealsALabelThatDidNotLand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	labels := []capabilityLabel{{key: corrosion.LabelLXCCapable, capable: func() bool { return true }}}

	// The start-time assert finds no host row: nothing is written.
	if _, err := assertCapabilityLabels(ctx, db, "node-1", labels); err != nil {
		t.Fatalf("assert with no host row: %v", err)
	}
	go keepCapabilityLabels(ctx, db, "node-1", labels, 10*time.Millisecond)

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

// A host re-added while its data directory still held its old database: at
// start its own row already carries every capability label, so the start-time
// assert writes nothing; then the re-admission's row, labels reset, wins on
// every node, this one included. Every label comes back without a restart,
// TPM and Secure Boot as well as LXC (the review of fix/readmit-hosts-tie, m-2:
// the two were written only at start).
//
// Mutation: the keeper re-asserts LXC alone — red on litevirt.tpm.
func TestKeepCapabilityLabels_RepublishesEveryLabelAfterAReadmission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "node-1", Address: "10.0.0.1", SSHUser: "root", GRPCPort: 7443, State: "active",
	}); err != nil {
		t.Fatalf("insert host: %v", err)
	}
	yes := func() bool { return true }
	labels := []capabilityLabel{
		{key: corrosion.LabelLXCCapable, capable: yes},
		{key: corrosion.LabelTPMCapable, capable: yes},
		{key: corrosion.LabelSecureBootCapable, capable: yes},
	}
	if _, err := assertCapabilityLabels(ctx, db, "node-1", labels); err != nil {
		t.Fatalf("start-time assert: %v", err)
	}
	go keepCapabilityLabels(ctx, db, "node-1", labels, 10*time.Millisecond)

	// The re-admitted row wins: its labels are reset.
	if err := db.Execute(ctx, `UPDATE hosts SET labels = NULL WHERE name = 'node-1'`); err != nil {
		t.Fatalf("reset labels: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		h, err := corrosion.GetHost(ctx, db, "node-1")
		if err == nil && h != nil && h.Labels[corrosion.LabelLXCCapable] == "true" &&
			h.Labels[corrosion.LabelTPMCapable] == "true" && h.Labels[corrosion.LabelSecureBootCapable] == "true" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("node-1's capability labels did not come back after its labels were reset: %+v, err %v", h, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
