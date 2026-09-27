package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestCapabilityActive_CredentialsSplitWaitsForAnOldBuildRecipient: the split
// must not latch while any host this node replicates to is on a build that
// reads secrets from the old columns only — including one parked in
// maintenance, which does not vote but still receives the clear and still
// serves logins.
func TestCapabilityActive_CredentialsSplitWaitsForAnOldBuildRecipient(t *testing.T) {
	const tok = capabilities.CredentialsSplitV1
	if !capabilities.Mandatory(tok) || !capabilities.ReplicationGated(tok) {
		t.Fatalf("%s must be mandatory (a fact about the binary) and ReplicationGated "+
			"(a claim about every replication recipient)", tok)
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
				"receiving replication — listening. The clear it licenses would leave host-old "+
				"with no IPMI password, login or API token to read", tok)
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
