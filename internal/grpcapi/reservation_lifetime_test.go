package grpcapi

import (
	"context"
	"github.com/litevirt/litevirt/internal/corrosion"
	"sync"
	"testing"
	"time"
)

func TestReservationRecovery_CancelParkedSweepJoinsBeforeDBClose(t *testing.T) {
	s := testServer(t)
	sweepVM(t, s, "vm1", 1, sweepAgoNano(48*time.Hour), "")
	sweepOp(t, s, "done", corrosion.OpResourceUpdateRunning, "vm1", 0, sweepVector(s.hostName, 512), sweepAgo(time.Hour), sweepLeakSteps())
	ctx, cancel := context.WithCancel(context.Background())
	parked, release, done, loopDone := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unpark := func() { once.Do(func() { close(release) }) }
	join := func(ch <-chan struct{}) {
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Error("reservation owner failed bounded join")
		}
	}
	t.Cleanup(func() { cancel(); unpark(); join(done); join(loopDone) })
	s.resSweep.beforeReclassify = func(string) { close(parked); <-release }
	go func() { defer close(loopDone); s.RunReservationRecovery(ctx) }()
	go func() { defer close(done); s.SweepReservationsOnce(ctx) }()
	select {
	case <-parked:
	case <-time.After(5 * time.Second):
		t.Fatal("sweep did not reach locked seam")
	}
	cancel()
	select {
	case <-done:
		t.Fatal("cancellation was incorrectly treated as completion of parked work")
	default:
	}
	unpark()
	join(done)
	join(loopDone)
	t.Log("parked sweep and recovery loop joined while private DB remains open")
}
