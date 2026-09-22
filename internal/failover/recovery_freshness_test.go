package failover

import (
	"testing"

	"github.com/litevirt/litevirt/internal/health"
)

// The health checker's heartbeat and this package's freshness cutoff are only
// correct RELATIVE to each other, and they live in different packages.
//
// recoverHosts counts a host_health row toward recovery quorum only while it
// is newer than healthFreshness. A steadily healthy peer produces no status
// transitions, so the only thing keeping its row inside that window is
// health.HeartbeatInterval rewriting it. If the heartbeat ever grows past the
// cutoff — or the cutoff shrinks below it — every row is stale by the time
// recovery looks, quorum is never met, and a fenced host that has genuinely
// come back stays `offline` until an operator runs `lv host undrain`.
//
// That failure is invisible in both packages' own tests, because each is
// internally consistent. It only shows up here.
func TestRecovery_HeartbeatOutpacesFreshness(t *testing.T) {
	if health.HeartbeatInterval >= healthFreshness {
		t.Fatalf("health.HeartbeatInterval (%s) >= healthFreshness (%s): a healthy row "+
			"expires before it is rewritten, so recovery quorum can never be met and a "+
			"recovered host stays offline forever",
			health.HeartbeatInterval, healthFreshness)
	}

	// Two heartbeats must fit inside the window, so a single dropped or
	// delayed probe cycle does not age the row out on its own.
	if 2*health.HeartbeatInterval > healthFreshness {
		t.Errorf("health.HeartbeatInterval (%s) leaves no margin: two intervals (%s) exceed "+
			"healthFreshness (%s), so one missed probe cycle strands the recovery",
			health.HeartbeatInterval, 2*health.HeartbeatInterval, healthFreshness)
	}

	// The heartbeat is a rewrite on the probe tick, so it can only be as
	// punctual as the probe loop itself.
	if health.HeartbeatInterval < health.CheckInterval() {
		t.Errorf("health.HeartbeatInterval (%s) is shorter than the probe interval (%s); "+
			"it would fire on every tick, which is the O(N^2) write rate the state filter exists to avoid",
			health.HeartbeatInterval, health.CheckInterval())
	}
}
