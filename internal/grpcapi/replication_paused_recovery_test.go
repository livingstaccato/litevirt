package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A schedule paused on a witness keeps its reason as its last error
// (scheduler.ErrRunPaused), so the worker that takes the VM over starts from a
// failing state and its first good run is reported as a recovery (review M3).
//
// Mutation: start a run's state as healthy whatever last_run_err says in
// replState - no recovery is reported and this goes red.
func TestReplicationOutcome_AFirstGoodRunAfterAPausedOneReportsTheRecovery(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	s := &Server{hostName: "worker-1", db: db}
	sched := corrosion.BackupScheduleRecord{
		VMName: "db", Repo: "dr", Type: "replication",
		LastRunErr: "schedule paused: vm db is on witness-1, a witness that runs no workloads",
	}
	s.replicationOutcome(ctx, sched, "vm", "db", "", "node-0", "dr", "", nil)

	rows, err := db.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'vm.replicate' AND target = 'db'`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !strings.Contains(rows[0].String("detail"), "replicates again") {
		t.Fatalf("audit rows after the first good run = %v, want one that says it replicates again", rows)
	}
}
