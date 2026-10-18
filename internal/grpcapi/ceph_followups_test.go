package grpcapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/health"
)

// Breaker minor 1. A VM whose own probe got no answer keeps its own record
// until its own probe answers, not for a fixed two minutes: one not probed
// again for longer (deferred for time on every pass) is still probed, never
// started on a proof another VM's probe made later.
//
// Mutation "record lapses at cephKeyProofTTL" (ownFailed bounded by it):
// red.
func TestPrepareHardwareForStart_AFailedVMsOwnRecordOutlastsTheProofTTL(t *testing.T) {
	f := newCephPoolFixture(t)
	x := f.insertPoolVM(t, "x-db", "ceph", "lv", "stopped")
	y := f.insertPoolVM(t, "y-web", "ceph", "lv", "stopped")
	now := time.Now()
	prev := cephProofNow
	cephProofNow = func() time.Time { return now }
	t.Cleanup(func() { cephProofNow = prev })
	f.world.downImages = map[string]bool{"lv/x-db-root": true}
	if _, err := f.s.PrepareHardwareForStart(health.WithWalkProbeTurn(context.Background()), &x); !errors.Is(err, health.ErrStartProbeFailed) {
		t.Fatalf("x, whose image does not answer: %v, want ErrStartProbeFailed", err)
	}
	now = now.Add(cephKeyProofTTL + time.Minute)
	if _, err := f.s.PrepareHardwareForStart(context.Background(), &y); err != nil {
		t.Fatalf("y, on the same key: %v", err)
	}
	before := f.world.probes()
	_, err := f.s.PrepareHardwareForStart(health.WithWalkProbeTurn(context.Background()), &x)
	if f.world.probes() != before+1 || !errors.Is(err, health.ErrStartProbeFailed) {
		t.Fatalf("x %s after its failure, y having proved the key: %v, %d new probes; want x probed itself, not started on y's proof",
			cephKeyProofTTL+time.Minute, err, f.world.probes()-before)
	}
}
