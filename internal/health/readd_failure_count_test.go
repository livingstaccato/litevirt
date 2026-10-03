package health

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A host removed from the cluster and added back under the same name is a new
// machine to this observer: its first failed probe publishes one failure, not
// the count the old one had built up (kvm003 drill 6, finding B6). The old
// count, carried over, put the new machine past the fence threshold on its
// first probe, and the coordinator fenced it part-way through `lv host add`.
//
// Mutation: drop the prune of peers no longer in the host table from
// checkAllPeers — the first verdict carries the old count plus one.
func TestCheckAllPeers_ForgetsARemovedHostsFailures(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()
	for _, h := range []corrosion.HostRecord{
		{Name: "obs", Address: "10.9.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "01"},
		{Name: "gone", Address: "10.9.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "02"},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}
	c := NewChecker("obs", t.TempDir(), db)
	var published []int
	c.writeFn = func(_ context.Context, _ string, args ...interface{}) error {
		if len(args) > 3 && args[1] == "gone" {
			if n, ok := args[3].(int); ok {
				published = append(published, n)
			}
		}
		return nil
	}
	c.SetPeerReadiness(func(context.Context, string, string) (bool, string, error) {
		return false, "", errors.New("connection refused")
	})

	for i := 0; i < FailuresToFence+3; i++ {
		c.checkAllPeers(ctx)
	}
	if n := len(published); n == 0 || published[n-1] < FailuresToFence {
		t.Fatalf("precondition: published %v, want a count past %d", published, FailuresToFence)
	}

	if err := corrosion.DeleteHost(ctx, db, "gone"); err != nil {
		t.Fatalf("DeleteHost: %v", err)
	}
	c.checkAllPeers(ctx)
	if err := corrosion.AdmitHost(ctx, db, corrosion.HostRecord{
		Name: "gone", Address: "10.9.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "03",
	}); err != nil {
		t.Fatalf("AdmitHost: %v", err)
	}
	published = nil
	c.checkAllPeers(ctx)
	if len(published) != 1 || published[0] != 1 {
		t.Fatalf("first verdict on the re-added host published %v, want [1]: a count from before the removal", published)
	}
}
