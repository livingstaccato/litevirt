// Fleet scenario: the reverse replication schedule of a VM promoted onto a
// witness.
//
// A promote re-homes the VM on the witness and switches its replication
// schedule to run witness -> the host it left. The witness is stopped-only and
// refuses every run (the execution gate: local_not_active_worker), so the
// scheduler logged an error and the run reported the same failure as an audit
// row on each pass until the VM was moved. A schedule must not run from a host
// that cannot act: it is paused with ONE audit entry and ONE notification that
// say why and how it resumes, and the run itself returns no error.

package fleet

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/scheduler"
)

// Red on ba91f3c21: every run returns the gate refusal.
//
// Mutations: drop the witness branch in RunReplication - the runs return the
// refusal again and go red; report on every pass (clear the transition) - the
// audit count goes red.
func TestFleet_AScheduleOnAWitnessIsPausedOnceNotFailedEveryRun(t *testing.T) {
	wr := newWitnessReplica(t)
	ctx := context.Background()
	enforceGateWithWitness(t, wr.c, wr.w)
	// The host the VM left has the pool too, so the promote can switch the
	// schedule to replicate back to it (as on the lab).
	if err := corrosion.UpsertStoragePool(ctx, wr.a.DB, corrosion.StoragePoolRecord{
		HostName: wr.a.Name, Name: "dr", Driver: "dir", Target: filepath.Join(wr.c.tmpRoot, "dr"), State: "active"}); err != nil {
		t.Fatal(err)
	}
	wr.loseOwner(t)
	if _, err := wr.promote(t); err != nil {
		t.Fatalf("operator promote on the witness: %v", err)
	}
	scheds, err := corrosion.ListBackupSchedules(ctx, wr.w.DB)
	if err != nil {
		t.Fatal(err)
	}
	var sched *corrosion.BackupScheduleRecord
	for i := range scheds {
		if scheds[i].VMName == "db" && scheds[i].Type == "replication" {
			sched = &scheds[i]
		}
	}
	if sched == nil || sched.TargetHost != wr.a.Name {
		t.Fatalf("db's schedule after the promote = %+v, want it reversed to %s", sched, wr.a.Name)
	}

	for i := 0; i < 4; i++ {
		if err := wr.w.Server.RunReplication(ctx, *sched, time.Now().Add(time.Duration(i)*time.Minute)); !errors.Is(err, scheduler.ErrRunPaused) {
			t.Fatalf("run %d of the schedule from the witness returned %v, want it paused (scheduler.ErrRunPaused), not failed", i, err)
		}
	}
	rows, err := wr.w.DB.Query(ctx, `SELECT detail, result FROM audit_log WHERE action = 'vm.replicate' AND target = 'db'`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d vm.replicate audit rows for db after 4 runs, want exactly one", len(rows))
	}
	detail := rows[0].String("detail")
	for _, want := range []string{"witness", "paused", "lv migrate db", "--cold"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the audit entry %q does not say %q", detail, want)
		}
	}
	if strings.Contains(detail, "local_not_active_worker") {
		t.Errorf("the audit entry is the bare gate refusal: %q", detail)
	}
}
