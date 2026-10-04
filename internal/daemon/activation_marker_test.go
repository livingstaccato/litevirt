package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestActivationMarkers_EveryReaderFindsWhatTheCheckerWrites guards the one
// path scheme behind the durable capability latches. The health checker writes
// them, under the base the daemon hands it at startup; three readers in this
// package find them by path on their own: the rollback preflight, and the
// on-disk credentials and host-membership gates. If a reader's idea of the path
// drifts from the writer's, the reader sees nothing — and every one of them
// fails OPEN on nothing: a rolled-back binary leaves WAL quarantine, and the
// split gates stay on the previous release's behaviour on a node that has
// latched.
//
// The markers are written by a real Checker through Enforced, wired with the
// daemon's own base, so the test fails whichever copy of the scheme moves.
// The "future" token stands in for a newer binary's latch: the pinger
// advertises it, so this checker latches and writes it exactly as that binary
// would, and the preflight must then see a token this build does not know.
//
// Mutations, each red: wire the checker with any other base than
// health.ActivationMarkerBase; glob ActivationMarkersOnDisk with another
// separator than markerPathFor joins with. (Before the scheme was one helper,
// both renaming the daemon's private base-name copy and changing health's
// "<base>.<token>" join were red too.)
func TestActivationMarkers_EveryReaderFindsWhatTheCheckerWrites(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	if err := corrosion.RegisterHost(ctx, db, corrosion.HostRecord{
		Name: "host-a", Address: "10.0.0.1", State: "active", Role: "worker",
	}); err != nil {
		t.Fatalf("register host: %v", err)
	}

	const future = "some_future_token_v9"
	dataDir := t.TempDir()
	checker := health.NewChecker("host-a", "/etc/litevirt/pki", db)
	checker.SetPeerPinger(func(context.Context, string) ([]string, time.Time, error) {
		return append(capabilities.Supported(), future), time.Time{}, nil
	})
	d := &Daemon{db: db, checker: checker, cfg: &Config{DataDir: dataDir}}
	d.wireActivationMarker()

	creds, members := CredentialsSplitLatchedOnDisk(dataDir), HostMembershipLatchedOnDisk(dataDir)
	if creds() || members() || len(preflightCapabilityRollback(dataDir)) > 0 {
		t.Fatal("a reader sees a latch before anything has latched")
	}
	for _, tok := range []string{capabilities.CredentialsSplitV1, capabilities.HostMembershipSplitV1, future} {
		if !checker.Enforced(ctx, tok) || !checker.DurablyLatched(tok) {
			t.Fatalf("%s did not latch durably with the only host advertising it; the rest is vacuous", tok)
		}
	}
	if !creds() {
		t.Error("CredentialsSplitLatchedOnDisk does not find the marker the checker wrote")
	}
	if !members() {
		t.Error("HostMembershipLatchedOnDisk does not find the marker the checker wrote")
	}
	if got := preflightCapabilityRollback(dataDir); len(got) != 1 || got[0] != future {
		t.Errorf("preflightCapabilityRollback = %v, want [%s]: the rollback check cannot see the "+
			"markers the checker writes, so a rolled-back binary is never quarantined", got, future)
	}
}
