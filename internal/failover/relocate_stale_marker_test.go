package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A stale relocate-restore marker that names no target falls back to placing
// the container afresh. When no host has a container runtime, that placement
// already marks it relocate-skipped and audits why; the fallback must not then
// skip — and audit — it a second time as "no collision-free target".
//
// Mutation: drop the early return on a placement that skipped — the fallback's
// own skip writes a second ct.relocate.skipped row and the test goes red.
func TestRelocate_StaleMarkerWithNoRuntimeAuditsOneSkip(t *testing.T) {
	db, src, cands := relocateSetup(t, "alpine:3.19", corrosion.CurrentSchemaVersion)
	ctx := context.Background()
	if err := corrosion.SetHostLabel(ctx, db, "surv", corrosion.LabelLXCCapable, "false"); err != nil {
		t.Fatal(err)
	}
	c := newTestCoordinator("coord", db)
	c.Restorer = &fakeRestorer{db: db}
	c.RelocateRestoreTimeout = time.Nanosecond // any marker is immediately stale
	if err := corrosion.SetContainerStateDetail(ctx, db, "src", "ct1", "relocating",
		corrosion.RelocateRestoreDetail("", "tok1")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)

	c.relocateContainers(ctx, src, cands)

	rows, err := db.Query(ctx, `SELECT detail FROM audit_log WHERE target = 'ct1' AND action = 'ct.relocate.skipped'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("ct.relocate.skipped rows for ct1 = %v (err %v), want exactly one", rows, err)
	}
	if g, _ := corrosion.GetContainer(ctx, db, "src", "ct1"); g == nil || g.StateDetail != corrosion.ContainerRelocateSkippedDetail {
		t.Fatalf("ct1 = %+v, want it left on src marked relocate-skipped", g)
	}
}

// A stale relocate-restore marker abandons the restore its token named: the
// fallback image-recreate mints a proof of its own. The abandoned restore's
// proof is failed (terminal), not left prepared or in_progress forever — and
// so can no longer be claimed by a restore arriving late.
//
// Mutation: drop the abandonment — the proof stays prepared and the test goes
// red.
func TestRelocate_StaleMarkerFailsTheAbandonedRestoreProof(t *testing.T) {
	db, src, cands := relocateSetup(t, "alpine:3.19", corrosion.CurrentSchemaVersion)
	ctx := context.Background()
	c := newTestCoordinator("coord", db)
	c.Restorer = &fakeRestorer{db: db}
	c.RelocateRestoreTimeout = time.Nanosecond
	if err := corrosion.WriteActionProof(ctx, db, corrosion.ActionProof{
		ID: "restore-proof", Action: corrosion.ActionRelocate, TargetKind: "container",
		TargetName: "ct1", DestHost: "surv", Coordinator: "coord", RelocationToken: "tok1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SetContainerStateDetail(ctx, db, "src", "ct1", "relocating",
		corrosion.RelocateRestoreDetail("surv", "tok1")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)

	c.relocateContainers(ctx, src, cands)

	if tgt, _ := corrosion.GetContainer(ctx, db, "surv", "ct1"); tgt == nil {
		t.Fatal("the stale marker did not fall back to image-recreate; the scenario needs it to")
	}
	pr, ok, err := corrosion.GetActionProof(ctx, db, "restore-proof")
	if err != nil || !ok || pr.Status != corrosion.ProofFailed {
		t.Fatalf("abandoned restore proof = %q (ok %v, err %v), want failed", pr.Status, ok, err)
	}
}
