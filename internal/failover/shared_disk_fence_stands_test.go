package failover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
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

// sharedDiskFixture is a best-effort host 'bad' with a shared-disk VM sd and a
// local-disk VM ld, a peer 'good', a voter quorum failing bad whose runs
// span the last hour, and the shared-storage fence enforced.
func sharedDiskFixture(t *testing.T) (*corrosion.Client, context.Context, *Coordinator) {
	t.Helper()
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
	c := newTestCoordinator("coordinator", db)
	c.SharedStorageFenceEnforce = true
	c.Gate = gateEnforcing(capabilities.SharedStorageFenceV1)
	return db, ctx, c
}

func badFenceRow(t *testing.T, db *corrosion.Client, id, method, result string, age time.Duration) {
	t.Helper()
	if err := db.Execute(context.Background(),
		`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES (?, 'bad', ?, ?, ?, 'seeded')`,
		id, method, result, time.Now().Add(-age).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
}

// Follow-up re-review N1: the confirm-first order on a best-effort host. The
// operator powers the host off and confirms it (recorded fenced); this
// coordinator fences it afresh on that confirmation, and the lenient SSH
// fence, unable to reach the host that is off, proves nothing; the
// confirmation is what recovers it (the split-brain guard's best-effort
// case). The fence's row is this coordinator's own fence on the
// confirmation, not a sign the host ran since: the shared-disk VM moves in
// one step, as on main.
//
// Mutations: drop the afresh exemption — the newer best-effort row refuses the
// binding and sd stays on bad; drop best-effort from the guard's
// confirmation case — nothing moves.
func TestSharedDiskFence_ABestEffortHostConfirmedOffFirstMovesInOneStep(t *testing.T) {
	db, ctx, c := sharedDiskFixture(t)
	if err := corrosion.UpdateHostState(ctx, db, "bad", "fenced"); err != nil {
		t.Fatal(err)
	}
	badFenceRow(t, db, "op-bad", "manual", "manual-confirmed", 10*time.Second)
	fences := 0
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fences++
		return fence.Result{Method: "best-effort-ssh", Detail: "unreachable; assumed off", Success: true}
	})
	c.run(ctx)
	if fences != 1 {
		t.Fatalf("setup: %d fences, want the afresh fence", fences)
	}
	if sd, _ := corrosion.GetVM(ctx, db, "sd"); sd == nil || sd.HostName != "good" {
		t.Fatalf("the shared-disk VM of a host confirmed off first did not move in one step: %+v (hold %q)", sd, c.holdReason["bad"])
	}
}

// Follow-up re-review m-a: a read error while judging the binding does not
// spend the transfer. The hold says it retries, and the next cycle, with the
// rows readable, moves the shared-disk VM without a second confirmation.
//
// Mutation: treat the read error as a refusal (no retry owed) — the second
// cycle moves nothing.
func TestSharedDiskFence_AReadErrorAtTheBindingRetries(t *testing.T) {
	db, ctx, c := sharedDiskFixture(t)
	badFenceRow(t, db, "op-bad", "manual", "manual-confirmed", 10*time.Second)
	if err := corrosion.UpdateHostState(ctx, db, "bad", "offline"); err != nil {
		t.Fatal(err)
	}
	c.fenced["bad"] = true
	c.noteRecoveryAt("bad", time.Now().Add(-10*time.Second), time.Now().Add(-10*time.Second))
	if _, err := db.DB().ExecContext(ctx, `ALTER TABLE host_health RENAME TO host_health_gone`); err != nil {
		t.Fatal(err)
	}
	c.recoverWorkloads(ctx, &corrosion.HostRecord{Name: "bad", State: "offline"})
	if _, err := db.DB().ExecContext(ctx, `ALTER TABLE host_health_gone RENAME TO host_health`); err != nil {
		t.Fatal(err)
	}
	if sd, _ := corrosion.GetVM(ctx, db, "sd"); sd == nil || sd.HostName != "bad" {
		t.Fatalf("the shared-disk VM moved on a binding that could not be judged: %+v", sd)
	}
	if hold := c.holdReason["bad"]; !strings.Contains(hold, "retrying") || strings.Contains(hold, "fence-confirm") {
		t.Fatalf("hold %q: want a retry named, and no confirmation asked for", hold)
	}
	fences := 0
	c.SetFencer(countingFencer(&fences, fence.Result{Method: "test", Success: true}))
	c.run(ctx)
	if sd, _ := corrosion.GetVM(ctx, db, "sd"); sd == nil || sd.HostName != "good" || fences != 0 {
		t.Fatalf("the next cycle did not retry the shared-disk transfer on the same authority: %+v after %d fences (hold %q)",
			sd, fences, c.holdReason["bad"])
	}
}

// Follow-up re-review m-c: a stopped shared-disk VM left on its host because
// the binding was refused says why, as a running one's hold does.
//
// Mutation: skip it with the generic stopped detail — the reason is missing.
func TestSharedDiskFence_AStoppedVMNamesWhyItWasNotMoved(t *testing.T) {
	db, ctx, c := sharedDiskFixture(t)
	if err := db.Execute(ctx, `UPDATE vms SET state = 'stopped', state_detail = '' WHERE name = 'sd'`); err != nil {
		t.Fatal(err)
	}
	badFenceRow(t, db, "op-bad", "manual", "manual-confirmed", 2*time.Minute)
	badFenceRow(t, db, "ssh-bad", "best-effort-ssh", "fenced", 0)
	if err := corrosion.UpdateHostState(ctx, db, "bad", "offline"); err != nil {
		t.Fatal(err)
	}
	c.recoverWorkloads(ctx, &corrosion.HostRecord{Name: "bad", State: "offline"})
	if sd, _ := corrosion.GetVM(ctx, db, "sd"); sd == nil || sd.HostName != "bad" {
		t.Fatalf("setup: the stopped shared-disk VM moved: %+v", sd)
	}
	evs, err := corrosion.ListVMEvents(ctx, db, "sd", 10, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if strings.Contains(e.Detail, "not proof-grade") && strings.Contains(e.Detail, "fence-confirm bad") {
			return
		}
	}
	t.Fatalf("no skip event names the refused binding and the remedy: %+v", evs)
}

// The afresh exemption lasts only until the next fence decision for the host
// that is not afresh. Here a recorded best-effort fence, newer than the
// confirmation, is resumed: the confirmation is not what this decision was
// made on, so the newer attempt refuses the binding.
//
// Mutation: keep afreshConfirm across that decision — the shared-disk VM
// moves on the confirmation.
func TestSharedDiskFence_TheAfreshExemptionEndsAtTheNextDecision(t *testing.T) {
	db, ctx, c := sharedDiskFixture(t)
	badFenceRow(t, db, "op-bad", "manual", "manual-confirmed", 2*time.Minute)
	badFenceRow(t, db, "ssh-bad", "best-effort-ssh", "fenced", time.Minute)
	if err := corrosion.UpdateHostState(ctx, db, "bad", "offline"); err != nil {
		t.Fatal(err)
	}
	c.afreshConfirm = map[string]string{"bad": "op-bad"}
	c.run(ctx)
	if sd, _ := corrosion.GetVM(ctx, db, "sd"); sd == nil || sd.HostName != "bad" {
		t.Fatalf("the shared-disk VM moved on a confirmation the decision was not made on: %+v", sd)
	}
	if ld, _ := corrosion.GetVM(ctx, db, "ld"); ld == nil || ld.HostName == "bad" {
		t.Fatalf("setup: the recorded fence was not resumed (ld on %+v, hold %q)", ld, c.holdReason["bad"])
	}
}

// Re-review m2-1: the afresh exemption covers only the fence this
// coordinator ran on the confirmation (fencedOn), not any newer attempt. An
// operator's `lv host fence` after it, best effort, proves nothing about the
// host now, and refuses the binding as it would without the exemption.
//
// Mutation: exempt every newer attempt while afreshConfirm holds (the code
// before) — the confirmation still binds.
func TestSharedDiskFence_TheAfreshExemptionCoversOnlyItsOwnFence(t *testing.T) {
	db, ctx, c := sharedDiskFixture(t)
	badFenceRow(t, db, "op-bad", "manual", "manual-confirmed", 2*time.Minute)
	badFenceRow(t, db, "own-ssh", "best-effort-ssh", "fenced", time.Minute)
	if err := corrosion.UpdateHostState(ctx, db, "bad", "fenced"); err != nil {
		t.Fatal(err)
	}
	c.afreshConfirm = map[string]string{"bad": "op-bad"}
	c.noteFencedOn("bad", "own-ssh")
	if ref, why, _ := c.proofGradeFenceRefWhy(ctx, "bad"); ref == "" {
		t.Fatalf("control: the confirmation does not bind past this coordinator's own afresh fence: %s", why)
	}
	badFenceRow(t, db, "operator-ssh", "best-effort-ssh", "fenced", 0)
	ref, why, retry := c.proofGradeFenceRefWhy(ctx, "bad")
	if ref != "" || retry {
		t.Fatalf("an operator's best-effort fence after the confirmation was exempted: ref %q retry %v", ref, retry)
	}
	if !strings.Contains(why, "not proof-grade") {
		t.Fatalf("why %q: want the newer attempt named", why)
	}
}

// Re-review m2-2: the m-a retry in the shape it exists for. A best-effort
// host confirmed off first is fenced afresh on the confirmation, and the
// binding then cannot be read. The transfer is not spent: the next cycle
// retries it on the same fence and the same confirmation, with no second
// fence and no second confirmation, and the afresh exemption still covers
// the fence it ran.
//
// Mutation: drop the exemption from the retry (clear afreshConfirm when the
// retry runs) — the second cycle refuses on the coordinator's own fence and
// sd stays on bad.
func TestSharedDiskFence_AReadErrorAfterAnAfreshFenceRetriesOnIt(t *testing.T) {
	db, ctx, c := sharedDiskFixture(t)
	if err := corrosion.UpdateHostState(ctx, db, "bad", "fenced"); err != nil {
		t.Fatal(err)
	}
	badFenceRow(t, db, "op-bad", "manual", "manual-confirmed", 10*time.Second)
	// The afresh best-effort fence counts as a self-pause (waited out at
	// once here), so the recovery reaches the binding.
	c.PartitionPauseEnforced = func(context.Context) bool { return true }
	c.PeerPausesOnLoss = func(string) bool { return true }
	c.PauseWaitFor = func(int) time.Duration { return 0 }
	fences := 0
	broken := false
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fences++
		if fences == 1 {
			// The binding that follows this fence cannot read host_health.
			if _, err := db.DB().ExecContext(ctx, `ALTER TABLE host_health RENAME TO host_health_gone`); err != nil {
				t.Error(err)
			}
			broken = true
		}
		return fence.Result{Method: "best-effort-ssh", Detail: "unreachable; assumed off", Success: true}
	})
	c.run(ctx)
	if broken {
		if _, err := db.DB().ExecContext(ctx, `ALTER TABLE host_health_gone RENAME TO host_health`); err != nil {
			t.Fatal(err)
		}
	}
	if fences != 1 {
		t.Fatalf("setup: %d fences, want the afresh fence", fences)
	}
	if sd, _ := corrosion.GetVM(ctx, db, "sd"); sd == nil || sd.HostName != "bad" {
		t.Fatalf("setup: the shared-disk VM moved on a binding that could not be judged: %+v", sd)
	}
	if hold := c.holdReason["bad"]; !strings.Contains(hold, "retrying") || strings.Contains(hold, "fence-confirm") {
		t.Fatalf("hold %q: want a retry named, and no confirmation asked for", hold)
	}
	c.run(ctx)
	if sd, _ := corrosion.GetVM(ctx, db, "sd"); sd == nil || sd.HostName != "good" || fences != 1 {
		t.Fatalf("the next cycle did not retry the transfer on the afresh fence: %+v after %d fences (hold %q)",
			sd, fences, c.holdReason["bad"])
	}
	rows, err := db.Query(ctx, `SELECT id FROM fencing_log WHERE host_name = 'bad' AND result = 'manual-confirmed'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("confirmations %d (%v), want the operator's one", len(rows), err)
	}
}
