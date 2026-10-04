package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// A host `lv host add` admitted whose daemon has not yet started is down to
// every observer, and is not fenced (kvm003 drill 6, finding B6). Once its
// daemon's boot write records it 'active', the same quorum fences it.
//
// Mutation: drop the 'joining' skip in run — the joining host is fenced.
func TestJoiningHostIsNotFenced(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	if err := corrosion.UpdateHostState(ctx, db, "down", corrosion.HostStateJoining); err != nil {
		t.Fatalf("UpdateHostState: %v", err)
	}
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fences++
		return fence.Result{Method: "ssh", Success: true}
	})

	c.run(ctx)
	c.run(ctx)
	if fences != 0 {
		t.Fatalf("a joining host was fenced (%d fences)", fences)
	}

	if err := corrosion.UpdateHostStartup(ctx, db, "down", "active", "", 0, 0, 0, false); err != nil {
		t.Fatalf("boot write: %v", err)
	}
	c.run(ctx)
	if fences != 1 {
		t.Fatalf("the booted host, still quorum-down, was fenced %d times, want 1", fences)
	}
}
