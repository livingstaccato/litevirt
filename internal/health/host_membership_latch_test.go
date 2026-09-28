package health

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestCapabilityActive_HostMembershipSplitWaitsForAnOldBuildRecipient: the
// split must not latch while any host this node replicates to is on a build
// that reads state only from hosts.state — including one parked in
// maintenance, which does not vote but still receives every statement and
// reads the voter set the moment it returns to service.
func TestCapabilityActive_HostMembershipSplitWaitsForAnOldBuildRecipient(t *testing.T) {
	const tok = capabilities.HostMembershipSplitV1
	if !capabilities.Mandatory(tok) || !capabilities.ReplicationGated(tok) {
		t.Fatalf("%s must be mandatory (a fact about the binary) and ReplicationGated "+
			"(a claim about every replication recipient)", tok)
	}
	if !slices.Contains(capabilities.Supported(), tok) || !slices.Contains(capabilities.All(), tok) {
		t.Fatalf("%s must be advertised by this build and known to the latch preload", tok)
	}
	setup := func(t *testing.T) *Checker {
		t.Helper()
		db := testCheckHostDB(t)
		gateHost(t, db, "host-a", "active", "worker")
		gateHost(t, db, "host-b", "active", "worker")
		gateHost(t, db, "host-old", "maintenance", "worker")
		db.SetMembersForTests(func() []corrosion.PeerInfo {
			return []corrosion.PeerInfo{{Name: "host-b"}, {Name: "host-old"}}
		})
		return NewChecker("host-a", "/etc/litevirt/pki", db)
	}

	t.Run("an old-build recipient holds it off", func(t *testing.T) {
		c := setup(t)
		c.SetPeerPinger(func(_ context.Context, host string) ([]string, time.Time, error) {
			if host == "host-old" {
				return []string{capabilities.SplitBrainGateV1}, time.Time{}, nil // the previous release
			}
			return capabilities.Supported(), time.Time{}, nil
		})
		if ok, _ := c.CapabilityActive(context.Background(), tok); ok {
			t.Fatalf("%s latched with host-old — the previous build, in maintenance, still "+
				"receiving replication — listening. It cannot decode host_membership, and it would "+
				"go on reading a hosts.state nothing updates any more", tok)
		}
	})

	t.Run("it latches once every recipient has rolled", func(t *testing.T) {
		c := setup(t)
		c.SetPeerPinger(func(context.Context, string) ([]string, time.Time, error) {
			return capabilities.Supported(), time.Time{}, nil
		})
		if ok, reason := c.CapabilityActive(context.Background(), tok); !ok {
			t.Fatalf("%s did not latch on a uniform build (reason %q)", tok, reason)
		}
	})
}
