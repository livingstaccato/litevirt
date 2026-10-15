package failover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Re-review 5 I1: the shared-disk transfer binds to the newest proof-grade
// fence. An operator confirmation from before the host last came back is
// still under five minutes old when the host fails again, and the host is
// recorded down by then, so the life cut cannot apply. A best-effort fence
// that reported success without landing is newer than the confirmation and
// proves nothing: the shared disk must not get a second writer. Observers'
// runs span the confirmation and nobody saw the host answer, so only the
// newer attempt refuses it.
//
// Mutation: drop the newer-unverified-attempt check — the transfer binds to
// the old confirmation and the shared-disk VM moves.
func TestSharedDiskFence_ANewerBestEffortFenceOutranksAnEarlierConfirmation(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	for _, h := range []string{"bad", "good"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "best-effort", CPUTotal: 8, MemTotal: 8192,
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	seedVMWithDisk(t, ctx, db, "sd", "bad", "nfs")
	seedVMWithDisk(t, ctx, db, "ld", "bad", "local")
	fenceQuorum(t, ctx, db, []string{"coordinator", "good"}, "bad")
	if err := db.Execute(ctx, `UPDATE host_health SET consecutive_failures = 1000 WHERE target = 'bad'`); err != nil {
		t.Fatal(err)
	}
	seed := func(id, method, result string, age time.Duration) {
		if err := db.Execute(ctx,
			`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES (?, 'bad', ?, ?, ?, 'seeded')`,
			id, method, result, time.Now().Add(-age).UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	seed("op-bad", "manual", "manual-confirmed", 2*time.Minute)
	// The best-effort fence of this outage reported success; failover()
	// recorded the host offline with its row.
	seed("ssh-bad", "best-effort-ssh", "fenced", 0)
	if err := corrosion.UpdateHostState(ctx, db, "bad", "offline"); err != nil {
		t.Fatal(err)
	}
	c := newTestCoordinator("coordinator", db)
	c.SharedStorageFenceEnforce = true
	c.Gate = gateEnforcing(capabilities.SharedStorageFenceV1)
	c.recoverWorkloads(ctx, &corrosion.HostRecord{Name: "bad", State: "offline"})
	if sd, _ := corrosion.GetVM(ctx, db, "sd"); sd == nil || sd.HostName != "bad" {
		t.Fatalf("the shared-disk VM moved on a confirmation older than the best-effort fence: %+v", sd)
	}
	if ld, _ := corrosion.GetVM(ctx, db, "ld"); ld == nil || ld.HostName == "bad" {
		t.Fatalf("the local-disk VM must still move: %+v", ld)
	}
	if hold := c.holdReason["bad"]; !strings.Contains(hold, "lv host fence-confirm bad") {
		t.Fatalf("hold %q names no remedy", hold)
	}
}

// Re-review 5 I1: a confirmation binds a shared-disk transfer only while it
// stands for the outage the host is in now (confirmationStands): nobody has
// seen the host answer since, by a host_health row or this node's probe.
//
// Mutation: drop the confirmationStands check — both refusals bind.
func TestProofGradeFenceRef_AConfirmationBindsOnlyWhileItStands(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	lengthenStreak(t, db, ctx, 10*time.Minute)
	confirmAgo(t, db, ctx, time.Minute)
	c := newTestCoordinator("coordinator", db)
	if ref, _ := corrosion.ParseFenceEpoch(c.proofGradeFenceRef(ctx, "down")); ref.FenceID != "operator-down" {
		t.Fatalf("control: a standing confirmation binds nothing (%+v)", ref)
	}
	c.LastContact = func(string) (time.Time, bool) { return time.Now(), true }
	if got := c.proofGradeFenceRef(ctx, "down"); got != "" {
		t.Fatalf("this node probed the host healthy after the confirmation, and it still binds: %q", got)
	}
	c.LastContact = nil
	if err := db.Execute(ctx, `INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES ('outsider', 'down', 'unready', 1, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`); err != nil {
		t.Fatal(err)
	}
	if got := c.proofGradeFenceRef(ctx, "down"); got != "" {
		t.Fatalf("an observer saw the host answer after the confirmation, and it still binds: %q", got)
	}
}

// The newer-attempt rule does not touch the documented flows: a manual
// fence's own "awaiting confirmation" row, newer than a confirmation made
// before it (the afresh path), is no evidence the host ran, and an IPMI
// fence beside an older SSH one still binds.
func TestProofGradeFenceRef_AManualFenceRowAfterTheConfirmationStillBinds(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	lengthenStreak(t, db, ctx, 10*time.Minute)
	confirmAgo(t, db, ctx, time.Minute)
	fenceRowAgo(t, db, "manual-1", "manual", "partial", 0)
	c := newTestCoordinator("coordinator", db)
	if ref, _ := corrosion.ParseFenceEpoch(c.proofGradeFenceRef(ctx, "down")); ref.FenceID != "operator-down" {
		t.Fatalf("a manual fence after the confirmation refused it (%+v)", ref)
	}
	fenceRowAgo(t, db, "ssh-old", "best-effort-ssh", "fenced", 2*time.Minute)
	fenceRowAgo(t, db, "ipmi-new", "ipmi", "fenced", 0)
	if ref, _ := corrosion.ParseFenceEpoch(c.proofGradeFenceRef(ctx, "down")); ref.FenceID != "ipmi-new" {
		t.Fatalf("an IPMI fence newer than an SSH one does not bind (%+v)", ref)
	}
}
