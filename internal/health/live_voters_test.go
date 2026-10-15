package health

import (
	"testing"
	"time"
)

// LiveVoters is exactly the set quorumOver counts: self when a member, each
// member probed healthy since this node's last stall, and never an uncounted
// member. The HA-disarm peer veto reads this set, so it must not drift from
// the quorum the gate decides on.
func TestLiveVoters_IsTheSetTheQuorumCounts(t *testing.T) {
	c := NewChecker("host-a", "/etc/litevirt/pki", testCheckerDB(t))
	c.SeedPeersForTests(map[string]bool{"host-b": true, "host-c": false, "host-d": true, "host-e": true})
	voters := map[string]bool{"host-a": true, "host-b": true, "host-c": true, "host-d": true, "host-x": true}
	uncounted := map[string]bool{"host-d": true}
	live := c.LiveVoters(voters, uncounted)
	if len(live) != 2 || !live["host-a"] || !live["host-b"] {
		t.Fatalf("LiveVoters = %v, want host-a (self) and host-b", live)
	}
	_, n, needed := c.quorumOver(voters, uncounted)
	if n != len(live) || needed != 3 {
		t.Fatalf("quorumOver live=%d needed=%d, LiveVoters has %d", n, needed, len(live))
	}
	if SuspectThreshold*(ProbeInterval+ProbeTimeout)+ProbeInterval+ProbeTimeout != 20*time.Second {
		t.Fatal("the probe constants changed: re-derive failover's peer answer window and its docs")
	}
}
