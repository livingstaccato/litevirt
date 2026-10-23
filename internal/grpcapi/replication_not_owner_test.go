package grpcapi

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/scheduler"
)

// notOwnerServer is a server whose own host row is in state, holding vm
// ipmi-f; gateReason, when set, makes its execution gate refuse with it.
func notOwnerServer(t *testing.T, state, gateReason string) *Server {
	t.Helper()
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.13", State: state}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "ipmi-f", HostName: s.hostName, Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if gateReason != "" {
		s.SetGate(reasonGate{fakeServerGate: fakeServerGate{enforced: true}, reason: gateReason})
	}
	return s
}

var notOwnerSched = corrosion.BackupScheduleRecord{
	VMName: "ipmi-f", Repo: "default", Type: "replication", TargetPool: "default", KeepReplicas: 2,
}

// Lab 4 finding 7, the runner's half: a host whose own view still holds a VM
// it may not act as the owner of now (back from a fence and warming up, not
// an active member) answers its replication run with scheduler.ErrRunSkipped,
// which the scheduler logs at info and does not record, instead of a failure.
// A run that fails for another reason is still a failure. "warmup" is the
// lab's case: the execution gate refusing while the host warms up.
//
// Mutation: return the owner gate's error unwrapped from RunReplication —
// every skipped case is a failure again.
func TestRunReplication_NotOwnerNowIsSkipped(t *testing.T) {
	for _, tc := range []struct {
		name, state, gate string
		skipped           bool
	}{
		{"fenced", "fenced", "", true},
		{"joining", "joining", "", true},
		{"warmup", "active", health.ReasonWarmup, true},
		{"active", "active", "", false}, // passes the gate, then fails on the missing disk
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := notOwnerServer(t, tc.state, tc.gate)
			err := s.RunReplication(context.Background(), notOwnerSched, time.Now())
			if err == nil {
				t.Fatal("the run succeeded")
			}
			if got := errors.Is(err, scheduler.ErrRunSkipped); got != tc.skipped {
				t.Fatalf("RunReplication = %v; skipped %v, want %v", err, got, tc.skipped)
			}
			if tc.gate != "" && !strings.Contains(err.Error(), "("+tc.gate+")") {
				t.Errorf("RunReplication = %v, want the gate's reason %q", err, tc.gate)
			}
		})
	}
}

// Review minor: a skip is quiet, so a host that stays unable to act as the
// owner (still fenced, never caught up) took no replica and raised nothing.
// Skips that last replNotOwnerGrace raise `replication.skipped` (warn), at
// most hourly while they continue; a run that is not skipped ends the
// episode, and the next skip starts the grace again.
//
// Mutation: drop the notOwnerSkip call — no alert is raised.
func TestRunReplication_ALastingNotOwnerSkipIsAlerted(t *testing.T) {
	s := notOwnerServer(t, "fenced", "")
	var mu sync.Mutex
	var seen []notify.Notification
	s.notifySeen = func(n notify.Notification) {
		mu.Lock()
		defer mu.Unlock()
		if n.Kind == "replication.skipped" {
			seen = append(seen, n)
		}
	}
	alerts := func() int { mu.Lock(); defer mu.Unlock(); return len(seen) }
	run := func() {
		if err := s.RunReplication(context.Background(), notOwnerSched, time.Now()); !errors.Is(err, scheduler.ErrRunSkipped) {
			t.Fatalf("run = %v, want skipped", err)
		}
	}

	run() // inside the grace: quiet
	if alerts() != 0 {
		t.Fatalf("a skip inside the grace alerted: %+v", seen)
	}
	old := replNotOwnerGrace
	replNotOwnerGrace = 0
	t.Cleanup(func() { replNotOwnerGrace = old })
	run()
	if alerts() != 1 || seen[0].Severity != notify.SevWarn || seen[0].Subject != "ipmi-f" ||
		!strings.Contains(seen[0].Detail, "no replica of it is being taken") {
		t.Fatalf("alerts %+v, want one warn naming ipmi-f", seen)
	}
	run() // within the hour: not repeated
	if alerts() != 1 {
		t.Fatalf("re-alerted within the hour: %+v", seen)
	}
	// A run that is not skipped ends the episode; the next skip alerts afresh.
	s.replicationOutcome(context.Background(), notOwnerSched, "vm", "ipmi-f", "default", "", "default", "", errors.New("x"))
	run()
	if alerts() != 2 {
		t.Fatalf("a new episode did not alert: %+v", seen)
	}
}
