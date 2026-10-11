package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestCapabilityActive_HostMembershipRetireWaitsForAnOldBuildRecipient: the
// retire token must not latch while a host this node replicates to — one in
// maintenance included — runs a build without it.
func TestCapabilityActive_HostMembershipRetireWaitsForAnOldBuildRecipient(t *testing.T) {
	const tok = capabilities.HostMembershipRetireV1
	if !capabilities.Mandatory(tok) || !capabilities.ReplicationGated(tok) {
		t.Fatalf("%s must be mandatory and ReplicationGated", tok)
	}
	var previous []string
	for _, c := range capabilities.Supported() {
		if c != tok {
			previous = append(previous, c)
		}
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
	t.Run("a previous-build recipient holds it off", func(t *testing.T) {
		c := setup(t)
		c.SetPeerPinger(func(_ context.Context, host string) ([]string, time.Time, error) {
			if host == "host-old" {
				return previous, time.Time{}, nil
			}
			return capabilities.Supported(), time.Time{}, nil
		})
		if ok, _ := c.CapabilityActive(context.Background(), tok); ok {
			t.Fatalf("%s latched with a previous build, in maintenance, still receiving replication", tok)
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
