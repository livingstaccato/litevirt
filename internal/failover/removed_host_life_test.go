package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The coordinator recovers the workloads still recorded on a host removed for
// good only on a proof-grade fence of that host's LAST life
// (corrosion.HostProofGradeFence, now RemovedHostProvedOff's rule). A name
// removed with `lv host rm --force` whose only proof is the confirmation of
// the machine removed under it before it was given to another is not
// recovered: that confirmation says nothing about the machine that may still
// be running vm1. The remedy keeps the workflow: `lv host fence-confirm` of
// the removed host, once it is powered off, and the next pass recovers it.
//
// Mutation "live-only life" (HostProofGradeFence reads the life of a live
// row only, as before) — red: vm1 is claimed on the old confirmation.
func TestRecoverRemovedHosts_AnEarlierLifesFenceRecoversNothing(t *testing.T) {
	ctx := context.Background()
	cl := &fakeClaimer{decide: decideOurs}
	db, c := claimFixture(t, cl)
	db.SetHostMembershipGate(func() bool { return true })
	if _, err := db.SplitHostMembership(ctx); err != nil || !db.HostMembershipLive() {
		t.Fatalf("split: live=%v err=%v", db.HostMembershipLive(), err)
	}
	now := time.Now().UTC()
	fence := func(id, method, result string, at time.Time) {
		t.Helper()
		if err := db.Execute(ctx, `INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
			VALUES (?, 'dead', ?, ?, ?, '')`, id, method, result, at.Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	// The earlier life's confirmation, then the name's last life: admitted
	// and active, then removed with --force.
	fence("old", "manual", "manual-confirmed", now.Add(-time.Hour))
	if err := corrosion.UpdateHostState(ctx, db, "dead", "active"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().Exec(`UPDATE host_membership SET updated_at = ? WHERE host_name = 'dead'`,
		now.Add(-time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteHost(ctx, db, "dead"); err != nil {
		t.Fatal(err)
	}
	if !c.acquireLease(ctx) {
		t.Fatal("the coordinator does not hold the lease")
	}

	c.recoverRemovedHosts(ctx)
	if len(cl.calls) != 0 {
		t.Fatalf("vm1 was claimed for recovery on the confirmation of an earlier life of dead: %v", cl.calls)
	}

	fence("new", "manual", "manual-confirmed", now)
	c.recoverRemovedHosts(ctx)
	if len(cl.calls) == 0 {
		t.Fatal("vm1 was not claimed for recovery after dead was confirmed off in its last life")
	}
}
