// Fleet scenario: what an operator's promote onto a witness leaves behind.
//
// The promote re-homes the VM's rows onto the witness, so nothing named the
// files the VM left on the host it came from: its real disk (newer than the
// replica the promotion rebuilt from) and its cloud-init seed stayed there,
// unrecorded. (The failover coordinator's own promotion recorded them; the
// operator's did not.)
//
// Decided: nothing is removed by the promote. The old host may be down, and its
// disk may be the only copy of what the guest wrote after the replica. The disk
// is recorded as stranded (vm_disk_stranded, vm/<name>@<host>), so the host,
// once back, sets it aside as <path>.superseded-<time> and keeps it under the
// superseded-disks retention rules; the replica on the witness is the fallback
// copy until the VM is protected again, and the orphan sweep removes it with
// the VM or its schedule.

package fleet

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/health"
)

// Red on ba91f3c21: no vm_disk_stranded record is written by the operator's
// promote.
//
// Mutation: drop the s.noteDisksLeftByPromote call in doPromoteLocal - no
// record, red.
func TestFleet_AnOperatorPromoteRecordsAndKeepsWhatItLeavesOnTheOldHost(t *testing.T) {
	wr := newWitnessReplica(t)
	ctx := context.Background()
	enforceGateWithWitness(t, wr.c, wr.w)
	wr.loseOwner(t)
	if _, err := wr.promote(t); err != nil {
		t.Fatalf("operator promote on the witness: %v", err)
	}

	recs, err := health.StrandedDisksOf(ctx, wr.b.DB, "db")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Host != wr.a.Name || recs[0].MovedTo != wr.w.Name ||
		len(recs[0].Disks) != 1 || recs[0].Disks[0].Path != wr.root {
		t.Fatalf("stranded records after the promote = %+v, want db's disk %s on %s, moved to %s", recs, wr.root, wr.a.Name, wr.w.Name)
	}
	// Recorded and kept: the promote itself removed nothing from the old host.
	if _, err := os.Stat(filepath.Join(wr.c.tmpRoot, "fs-"+wr.a.Name, wr.root)); err != nil {
		t.Errorf("the old host's disk is gone after the promote: %v", err)
	}
}
