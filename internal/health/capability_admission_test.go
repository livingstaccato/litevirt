package health

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestCapabilityActive_APhantomGossipMemberCannotHoldAReplicationGatedLatch is
// colonelpanik/litevirt#259. A ReplicationGated token is confirmed against every
// memberlist member, and memberlist has no keyring, so before admission anyone
// on the gossip segment could announce a name that answers nothing and hold
// lease_term_ledger_v1 un-latched cluster-wide for as long as it kept
// announcing. Neither a made-up name nor a real host's name from somewhere else
// may be a recipient.
func TestCapabilityActive_APhantomGossipMemberCannotHoldAReplicationGatedLatch(t *testing.T) {
	const tok = capabilities.LeaseTermLedgerV1
	if !capabilities.ReplicationGated(tok) {
		t.Fatalf("%s is no longer ReplicationGated; this test no longer covers the membership path", tok)
	}
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker")
	gateHost(t, db, "host-b", "active", "worker") // recorded at 10.0.0.9
	db.SetGossipForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{
			{Name: "host-b", Addr: "10.0.0.9:7946"},
			{Name: "phantom", Addr: "10.0.0.66:7946"},   // no hosts row
			{Name: "host-b", Addr: "10.0.0.66:7946"},    // a real name, the wrong address
			{Name: "zz-phantom", Addr: "10.0.0.9:7946"}, // a real address, no row
		}
	})
	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	// A phantom is not a daemon: it answers nothing.
	c.SetPeerPinger(func(_ context.Context, host string) ([]string, time.Time, error) {
		if host == "host-a" || host == "host-b" {
			return []string{tok}, time.Time{}, nil
		}
		return nil, time.Time{}, errors.New("dial " + host + ": connection refused")
	})

	hosts, err := corrosion.ListHosts(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	targets := c.activationTargets(hosts, tok)
	for _, bad := range []string{"phantom", "zz-phantom"} {
		if slices.Contains(targets, bad) {
			t.Errorf("activation targets %v include the unadmitted gossip member %q", targets, bad)
		}
	}
	if ok, reason := c.CapabilityActive(context.Background(), tok); !ok {
		t.Fatalf("%s did not latch (reason %q) with every real recipient supporting it: a gossip "+
			"member with no hosts row is holding it off", tok, reason)
	}
}
