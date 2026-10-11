package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestQuorumProof_AnUnknownVoterNeverCountsLive (re-review I2): on a derived
// voter set, a host this node reads as unknown (no membership row, a frozen
// hosts copy) stays in the denominator but its probes never count toward live.
// It may be in maintenance on the cluster's view — out of the voter set there —
// and counting it could hand a minority partition {self, a, h} a majority.
func TestQuorumProof_AnUnknownVoterNeverCountsLive(t *testing.T) {
	ctx := context.Background()
	db := testCheckHostDB(t)
	db.SetHostMembershipGate(func() bool { return true })
	for _, h := range []string{"host-n", "host-a", "host-b", "host-c", "host-h"} {
		gateHost(t, db, h, "active", "worker")
	}
	if _, err := db.SplitHostMembership(ctx); err != nil {
		t.Fatal(err)
	}
	db.SetHostMembershipRetireGate(func() bool { return true })
	db.Mu().Lock()
	_, err := db.DB().Exec(`DELETE FROM host_membership WHERE host_name = 'host-h'`)
	db.Mu().Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := corrosion.GetHost(ctx, db, "host-h"); h == nil || h.State != corrosion.HostStateUnknown {
		t.Fatalf("precondition: host-h reads %+v, want unknown", h)
	}

	c := NewChecker("host-n", "/etc/litevirt/pki", db)
	warm(c, map[string]bool{"host-a": true, "host-h": true, "host-b": false, "host-c": false})
	st, live, needed := c.QuorumProof(ctx)
	if needed != 3 {
		t.Fatalf("needed = %d, want 3 (host-h stays in the denominator)", needed)
	}
	if st == QuorumYes || live != 2 {
		t.Errorf("state=%d live=%d: the unknown host-h counted toward live and gave a minority a majority", st, live)
	}
}
