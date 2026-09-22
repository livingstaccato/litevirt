package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A state write lost to cancellation has a bucket — WriteClassCancelled exists
// for exactly "the daemon is shutting down, or the RPC's caller hung up". The
// interruptible-backoff fix returned on ctx.Done() BEFORE reaching
// noteStateWriteFail, and persistVMState's own `!committed` guard does not fire
// either, so a write dropped this way was counted nowhere — invisible against a
// flat failure total during precisely the fleet-wide shutdown it describes.
func TestPersistVMStateDirect_ACancelledWriteIsCounted(t *testing.T) {
	s := gateTestServer(t)
	s.db.Close() // make the write fail so the retry loop is entered

	var gotOp, gotClass string
	n := 0
	s.onStateWriteFail = func(op, class string) { gotOp, gotClass = op, class; n++ }

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_ = s.persistVMStateDirect(ctx, "vm1", "running", "detail", corrosion.OpVMState)

	if n == 0 {
		t.Fatal("a state write dropped to cancellation was recorded nowhere; " +
			"WriteClassCancelled exists to give it a bucket")
	}
	if gotOp != corrosion.OpVMState {
		t.Errorf("op = %q, want %q", gotOp, corrosion.OpVMState)
	}
	if gotClass != corrosion.WriteClassCancelled {
		t.Errorf("class = %q, want %q — a cancelled write must not be filed as a generic "+
			"db error, or shutdown noise is indistinguishable from a failing store",
			gotClass, corrosion.WriteClassCancelled)
	}
}
