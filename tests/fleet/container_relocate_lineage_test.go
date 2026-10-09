package fleet

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A host-loss relocation moves a container, not the backup it is rebuilt
// from. A copy restored beside its original carries a lineage of its own and a
// pointer to the parent backup it came from; when its host dies, failover may
// rebuild it from that parent backup, and the relocated container must still
// be the copy. Were it to take the backup's lineage it would become a second
// live holder of the original's owner_id, and the original's host-loss restore
// could then pick the copy's backups.
//
// The coordinator marks the row and drives the restore at once, so on a fast
// failover the target's replica need not have seen the mark yet. Nothing is
// replicated in this cluster unless a scenario pumps it, so the target here
// never sees the mark: the coordinator must carry the lineage in the request.
func TestContainerRelocate_ACopyKeepsItsLineageBeforeTheTargetSeesTheMark(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	coord, dead, target := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	const name = "ct-copy"
	const token = "tok-lineage"

	// The parent lineage's backup, taken on the host that will die.
	createContainer(t, c, dead, name)
	dead.CT.Seed(name, "parent-bytes")
	repo, ts := backupContainer(t, c, dead, name)
	row, err := corrosion.GetContainer(ctx, dead.DB, dead.Name, name)
	if err != nil || row == nil {
		t.Fatalf("row on %s: %v", dead.Name, err)
	}
	parent := corrosion.DecodeCreateSpec(row.CreateSpec)
	if parent.OwnerID == "" {
		t.Fatal("create minted no owner_id; the scenario would prove nothing")
	}

	// The coordinator's replica: the container on the dead host is a copy
	// restored from that backup, marked to relocate onto target.
	cp := parent
	cp.OwnerID, cp.RestoredFromOwnerID, cp.RestoredFromTS = "own-copy", parent.OwnerID, ts
	marked := *row
	marked.CreateSpec = corrosion.EncodeCreateSpec(cp)
	marked.State, marked.StateDetail = "relocating", corrosion.RelocateRestoreDetail(target.Name, token)
	if err := corrosion.UpsertContainer(ctx, coord.DB, marked); err != nil {
		t.Fatal(err)
	}
	// The target's replica has not seen it.
	if rec, err := corrosion.GetContainer(ctx, target.DB, dead.Name, name); err != nil || rec != nil {
		t.Fatalf("the target already holds the relocating row (%+v, %v): the scenario needs it absent", rec, err)
	}

	coord.Server.SetBackupRepos(map[string]string{"main": repo})
	outcome, err := coord.Server.RestoreContainerFromBackup(ctx, name, target.Name, token)
	if err != nil || outcome != corrosion.RestoreLanded {
		t.Fatalf("relocate: (%v, %v)", outcome, err)
	}
	if got := target.CT.Payload(name); got != "parent-bytes" {
		t.Fatalf("target payload = %q: the backup's bytes did not land", got)
	}

	moved, err := corrosion.GetContainer(ctx, target.DB, target.Name, name)
	if err != nil || moved == nil {
		t.Fatalf("relocated row on %s: %v", target.Name, err)
	}
	got := corrosion.DecodeCreateSpec(moved.CreateSpec)
	if got.OwnerID != "own-copy" || got.RestoredFromOwnerID != parent.OwnerID || got.RestoredFromTS != ts {
		t.Fatalf("relocated lineage = owner %q parent %q@%q, want the copy's own-copy with parent %s@%s",
			got.OwnerID, got.RestoredFromOwnerID, got.RestoredFromTS, parent.OwnerID, ts)
	}
	if o, err := target.CT.ReadOwner(name); err != nil || o == nil || o.OwnerID != "own-copy" {
		t.Fatalf("relocated on-disk owner record = %+v (%v), want own-copy", o, err)
	}
}
