package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The refusal has to be WIRED, not merely available.
//
// internal/fence refuses a watchdog fence for a host that is not self, but only
// if FenceHost tells it which host that is. A handler that passed IsSelf: true
// unconditionally -- or forgot the field, whose zero value refuses everything --
// leaves every fence test in internal/fence green and the guard either inert or
// broken. Pinning it here is what makes the caller's half real.
func TestFenceHost_RefusesAWatchdogStrategyOnARemoteHost(t *testing.T) {
	s := testServer(t)
	s.hostName = "node-a"
	ctx := adminCtx()

	// A WRITABLE stand-in for /dev/watchdog: an absent device would fail the
	// open and hide whether the dispatch was refused at all.
	dev := filepath.Join(t.TempDir(), "watchdog")
	if err := os.WriteFile(dev, nil, 0o600); err != nil {
		t.Fatalf("seed fake watchdog device: %v", err)
	}
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: "node-b", Address: "10.0.0.2", State: "active",
		FenceStrategy: "watchdog", WatchdogDev: dev,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	res, err := s.FenceHost(ctx, &pb.FenceHostRequest{Name: "node-b", Confirmed: true})
	if err != nil {
		t.Fatalf("FenceHost: %v", err)
	}
	if res.Result == "fenced" {
		t.Fatalf("fencing node-b via watchdog from node-a reported %q (%s); the watchdog "+
			"that armed was THIS node's, and the coordinator now treats a local countdown "+
			"as a verified power-off of the remote host", res.Result, res.Detail)
	}
	if !strings.Contains(strings.ToLower(res.Detail), "self-only") {
		t.Errorf("Detail = %q, want it to name the strategy as self-only", res.Detail)
	}
}

// The self case must still DISPATCH, or a node loses its own last resort.
//
// It asserts the dispatch, not a successful fence: InsertHost does not persist
// watchdog_dev (it writes fence_strategy and not the device column), so the
// fence lands on the default /dev/watchdog, which no test machine has. That is
// fine for this property -- an error naming the device proves the call reached
// fenceWatchdog rather than being refused as remote, and that is exactly the
// half the guard must not break.
func TestFenceHost_SelfWatchdogIsStillDispatched(t *testing.T) {
	s := testServer(t)
	s.hostName = "node-a"
	ctx := adminCtx()

	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: "node-a", Address: "10.0.0.1", State: "active",
		FenceStrategy: "watchdog",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	res, err := s.FenceHost(ctx, &pb.FenceHostRequest{Name: "node-a", Confirmed: true})
	if err != nil {
		t.Fatalf("FenceHost: %v", err)
	}
	if strings.Contains(strings.ToLower(res.Detail), "self-only") {
		t.Fatalf("a node fencing ITSELF via watchdog was refused as remote: %s", res.Detail)
	}
	if !strings.Contains(res.Detail, "watchdog") {
		t.Errorf("Detail = %q, want the watchdog dispatch to have been reached", res.Detail)
	}
}
