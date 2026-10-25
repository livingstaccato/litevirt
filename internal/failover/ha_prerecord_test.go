package failover

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A first-use record that writes no data: the release gate's grant is handed
// a write that does nothing, so an operator's disarm written while the record
// was pending still stands after it.
//
// Mutation: write an armed row in the pre-record — the operator's disarm is
// overwritten and this goes red.
func TestHADisarmPreRecord_WritesNoPolicy(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	ts := setHA(t, db, corrosion.HADisarmed)
	calls := 0
	err := HADisarmPreRecord(ctx, func(ctx context.Context, f capabilities.Feature, write func(context.Context, capabilities.FeatureGrant) error) error {
		calls++
		if f != capabilities.FeatureHADisarm {
			t.Fatalf("pre-record of %q", f)
		}
		return write(ctx, capabilities.GrantForTest(t, f))
	})
	if err != nil || calls != 1 {
		t.Fatalf("pre-record: err=%v calls=%d", err, calls)
	}
	if p, _ := corrosion.GetHAPolicy(ctx, db); p.UpdatedAt != ts || p.State != corrosion.HADisarmed {
		t.Fatalf("the pre-record touched the policy: %+v", p)
	}
}

// The pre-recorder runs on the lease holder only once the token latched,
// retries a failed attempt with backoff, stops once paid, and never blocks a
// coordinator cycle: its call runs on its own goroutine.
func TestHAPreRecorder_RetriesAndNeverBlocksACycle(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", trustSSH)
	c := newTestCoordinator("coordinator", db)
	blocked := make(chan struct{})
	var attempts atomic.Int32
	var paid atomic.Bool
	p := &HAPreRecorder{
		HoldsLease: c.HoldsLease, Latched: func() bool { return true },
		Paid: func(context.Context) (bool, error) { return paid.Load(), nil },
		Record: func(ctx context.Context) error {
			if attempts.Add(1) == 1 {
				return errors.New("a recipient is unreachable")
			}
			<-blocked // blocks until the test releases it
			return nil
		},
		Poll: 5 * time.Millisecond, Backoff: 5 * time.Millisecond, Timeout: time.Hour,
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go p.Run(rctx)
	c.run(ctx) // takes the lease
	deadline := time.Now().Add(5 * time.Second)
	for attempts.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := attempts.Load(); n < 2 {
		t.Fatalf("the pre-record was tried %d times, want a retry after the failure", n)
	}
	done := make(chan struct{})
	go func() { c.RunOnce(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a blocked pre-record held a coordinator cycle")
	}
	close(blocked)

	// Paid: never called again.
	paid.Store(true)
	called := false
	p2 := &HAPreRecorder{HoldsLease: func() bool { return true }, Latched: func() bool { return true },
		Paid:   func(context.Context) (bool, error) { return true, nil },
		Record: func(context.Context) error { called = true; return nil }}
	p2.Run(ctx)
	if called {
		t.Fatal("a paid first use was recorded again")
	}
}
