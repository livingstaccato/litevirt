package grpcapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/scheduler"
)

// Lab 4 finding 7, the runner's half: a host whose own view still holds a VM
// it may not act as the owner of now (back from a fence, warming up, not an
// active member) answers its replication run with scheduler.ErrRunSkipped,
// which the scheduler logs at info and does not record, instead of a failure.
// A run that fails for another reason is still a failure.
//
// Mutation: return the owner gate's error unwrapped from RunReplication —
// "fenced" is a failure again.
func TestRunReplication_NotOwnerNowIsSkipped(t *testing.T) {
	for _, tc := range []struct {
		state   string
		skipped bool
	}{
		{"fenced", true},
		{"joining", true},
		{"active", false}, // passes the gate, then fails on the missing disk
	} {
		t.Run(tc.state, func(t *testing.T) {
			s := testServer(t)
			ctx := context.Background()
			if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.13", State: tc.state}); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
				Name: "ipmi-f", HostName: s.hostName, Spec: "{}", State: "running",
			}, nil, nil); err != nil {
				t.Fatal(err)
			}
			err := s.RunReplication(ctx, corrosion.BackupScheduleRecord{
				VMName: "ipmi-f", Repo: "default", Type: "replication", TargetPool: "default", KeepReplicas: 2,
			}, time.Now())
			if err == nil {
				t.Fatal("the run succeeded")
			}
			if got := errors.Is(err, scheduler.ErrRunSkipped); got != tc.skipped {
				t.Fatalf("RunReplication = %v; skipped %v, want %v", err, got, tc.skipped)
			}
		})
	}
}
