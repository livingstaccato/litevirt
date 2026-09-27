package health

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// An unchanged unready verdict is re-published at most once per
// HeartbeatInterval, not on every probe.
//
// A wedged store answers "not ready" for as long as it stays wedged, and the
// row used to be rewritten on every probe to keep its updated_at fresh: one
// replicated write per observer per peer per checkInterval, ~1,800 an hour
// from each observer. HeartbeatInterval is the freshness bound healthy rows
// already meet (TestHeartbeatFitsInsideHealthFreshness), and nothing reads
// unready-row freshness more tightly than that. A transition — into unready,
// out of it, or a count change — still writes on the probe that observed it.
func TestCheckHost_UnreadyRewritesAreRateLimited(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()
	addr, port := healthyPeer(t)
	c := probingChecker(t, db)

	// Steps well under stallThreshold, so the fake clock never reads as this
	// process having stopped (which would withhold probes and void the count).
	const step = 400 * time.Millisecond
	now := time.Unix(1_800_000_000, 0)
	c.clock = func() time.Time { return now }

	ready, silent := false, false
	c.SetPeerReadiness(func(context.Context, string, string) (bool, string, error) {
		switch {
		case silent:
			return false, "", errors.New("context deadline exceeded")
		case ready:
			return true, "", nil
		}
		return false, "database read timed out", nil
	})
	var written []string
	c.writeFn = func(ctx context.Context, q string, args ...interface{}) error {
		written = append(written, args[2].(string))
		return db.Execute(ctx, q, args...)
	}
	host := corrosion.HostRecord{Name: "host-b", Address: addr, GRPCPort: port}

	// 20 unready probes inside one heartbeat interval: one write.
	start := now
	for i := 0; i < 20; i++ {
		c.checkHost(ctx, host)
		now = now.Add(step)
	}
	if now.Sub(start) >= HeartbeatInterval+step {
		t.Fatalf("test setup: 20 probes spanned %v, not inside one %v heartbeat", now.Sub(start), HeartbeatInterval)
	}
	if len(written) != 1 {
		t.Fatalf("%d writes over 20 unchanged unready probes inside one heartbeat interval, want 1", len(written))
	}

	// Crossing the interval re-publishes the same verdict exactly once, on the
	// first probe at or past it.
	for now.Sub(start) < HeartbeatInterval {
		c.checkHost(ctx, host)
		if len(written) != 1 {
			t.Fatalf("re-published %v after the first write, before the %v heartbeat was due", now.Sub(start), HeartbeatInterval)
		}
		now = now.Add(step)
	}
	c.checkHost(ctx, host)
	if len(written) != 2 || written[1] != StatusUnready {
		t.Fatalf("writes = %v once the heartbeat interval had passed, want a second %q", written, StatusUnready)
	}

	// unready → healthy writes at once, inside the interval.
	now = now.Add(step)
	ready = true
	c.checkHost(ctx, host)
	if len(written) != 3 || written[2] != "healthy" {
		t.Fatalf("writes = %v after the peer became ready, want an immediate healthy write", written)
	}

	// healthy → unready writes at once, too.
	now = now.Add(step)
	ready = false
	c.checkHost(ctx, host)
	if len(written) != 4 || written[3] != StatusUnready {
		t.Fatalf("writes = %v after the peer became unready again, want an immediate unready write", written)
	}

	// A count change writes at once: the peer goes silent, and the second
	// unanswered probe takes the stored count from 1 to 2 while the status is
	// still unready.
	silent = true
	for i := 0; i < 2; i++ {
		now = now.Add(step)
		c.checkHost(ctx, host)
	}
	if len(written) != 5 {
		t.Fatalf("%d writes after the unready count changed, want 5 (an immediate write)", len(written))
	}
}
