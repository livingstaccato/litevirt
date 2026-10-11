package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestCapabilityActive_CredentialsClearWaitsForAnOldBuildRecipient: the clear
// must not latch while any host this node replicates to runs a build without
// it — including one parked in maintenance, which does not vote but still
// receives the clears. Here that host runs the dual-write build: it advertises
// credentials_split_v1 and not credentials_clear_v1.
func TestCapabilityActive_CredentialsClearWaitsForAnOldBuildRecipient(t *testing.T) {
	const tok = capabilities.CredentialsClearV1
	if !capabilities.Mandatory(tok) || !capabilities.ReplicationGated(tok) {
		t.Fatalf("%s must be mandatory (a fact about the binary) and ReplicationGated "+
			"(a claim about every replication recipient)", tok)
	}
	previous := make([]string, 0, len(capabilities.Supported()))
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
			t.Fatalf("%s latched with host-old — a previous build, in maintenance, still "+
				"receiving replication — listening", tok)
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
