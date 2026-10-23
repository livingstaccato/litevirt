package grpcapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/scheduler"
)

// The owner-now checks come before the witness pause: a witness that is
// fenced, still warming up or not an active member holds a VM row that may be
// stale, so its run is skipped (scheduler.ErrRunSkipped: nothing recorded, no
// replication.suspended) and is paused (scheduler.ErrRunPaused, one audit entry
// and notification) only once it may act as the owner and refuses on its role
// alone.
//
// Mutation: put the witness pause back before mayReplicateVMAsOwnerWith in
// RunReplication - every "skipped" row returns the pause and a vm.replicate
// audit row is written; this goes red.
func TestRunReplication_AWitnessSkipsBeforeItPauses(t *testing.T) {
	for _, tc := range []struct {
		name, state, gate string
		skipped           bool
	}{
		{"fenced witness", "fenced", health.ReasonLocalNotActiveWorker, true},
		{"joining witness", "joining", health.ReasonLocalNotActiveWorker, true},
		{"warming-up witness", "active", health.ReasonWarmup, true},
		{"active witness, role only", "active", health.ReasonLocalNotActiveWorker, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			ctx := context.Background()
			if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.13", State: tc.state, Role: "witness"}); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "ipmi-f", HostName: s.hostName, Spec: "{}", State: "stopped"}, nil, nil); err != nil {
				t.Fatal(err)
			}
			s.SetGate(reasonGate{fakeServerGate: fakeServerGate{enforced: true}, reason: tc.gate})
			err := s.RunReplication(ctx, notOwnerSched, time.Now())
			if err == nil {
				t.Fatal("the run succeeded")
			}
			if got := errors.Is(err, scheduler.ErrRunSkipped); got != tc.skipped {
				t.Fatalf("RunReplication = %v; skipped %v, want %v", err, got, tc.skipped)
			}
			if !tc.skipped && !errors.Is(err, scheduler.ErrRunPaused) {
				t.Fatalf("RunReplication = %v, want the pause", err)
			}
			rows, qerr := s.db.Query(ctx, `SELECT 1 AS n FROM audit_log WHERE action = 'vm.replicate' AND target = 'ipmi-f'`)
			if qerr != nil {
				t.Fatal(qerr)
			}
			if want := map[bool]int{true: 0, false: 1}[tc.skipped]; len(rows) != want {
				t.Errorf("%d vm.replicate audit rows, want %d", len(rows), want)
			}
		})
	}
}
