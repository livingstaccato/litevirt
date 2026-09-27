package health

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The grace is judged when a probe's result LANDS, not when it was launched.
// A probe in flight while `lv restart` reboots the guest (NoteVMStarted; the
// row stays running, so the incarnation is unchanged) lands after the restart
// cleared the failure run — and with retries 1, counting it acted on the
// freshly booted guest.
func TestVMCheck_ProbeLandingInsideAStartGraceDoesNotAct(t *testing.T) {
	f := newGraceFixture(t, restartCheck)
	f.v.SetProbeFunc(func(ctx context.Context, vm corrosion.VMRecord, h *pb.HealthCheckSpec) (bool, string) {
		// The operator's restart lands while this probe is in flight.
		f.clock.advance(time.Second)
		f.v.NoteVMStarted(vm.Name)
		return false, "tcp 10.0.0.9:81: connection refused"
	})
	f.v.SweepOnce(f.ctx)
	if n := f.starts(); n != 0 {
		t.Fatalf("a probe launched before a restart and landing after it acted on the rebooted guest (%d starts)", n)
	}
	if fails, acts := f.counters(); fails != 0 || acts != 0 {
		t.Errorf("a failure landing inside the start grace counted: failures=%d actions=%d", fails, acts)
	}
}
