package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// goneFixture: node-a's reconciler over a replica with three hosts, a VM
// and a container on node-a, and conditions raised against them.
type goneFixture struct {
	t  *testing.T
	db *corrosion.Client
	r  *Reconciler
}

func newGoneFixture(t *testing.T) *goneFixture {
	t.Helper()
	ctx := context.Background()
	f := &goneFixture{t: t, db: corrosion.NewTestClientT(t)}
	if err := corrosion.InitSchema(ctx, f.db); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"node-a", "node-b", "node-c"} {
		if err := corrosion.InsertHost(ctx, f.db, corrosion.HostRecord{Name: h, Address: "127.0.0.1", GRPCPort: 7443, State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	f.r = NewReconciler("node-a", t.TempDir(), f.db, libvirtfake.New())
	return f
}

func (f *goneFixture) vm(name, host string) {
	f.t.Helper()
	if err := corrosion.InsertVM(context.Background(), f.db, corrosion.VMRecord{Name: name, HostName: host, State: "stopped"}, nil, nil); err != nil {
		f.t.Fatal(err)
	}
}

func (f *goneFixture) ct(name, host string) {
	f.t.Helper()
	if err := corrosion.UpsertContainer(context.Background(), f.db, corrosion.ContainerRecord{Name: name, HostName: host, State: "stopped", Image: "alpine"}); err != nil {
		f.t.Fatal(err)
	}
}

// raise opens a condition as its raiser would (an older node re-raising
// included).
func (f *goneFixture) raise(evaluator, code, kind, subject string) {
	f.t.Helper()
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := corrosion.UpsertHealthCondition(context.Background(), f.db, corrosion.HealthCondition{
		Evaluator: evaluator, Code: code, SubjectKind: kind, SubjectID: subject,
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityWarning,
		ObserveCount: 1, FirstSeen: ts, LastSeen: ts, ConfirmedAt: ts, Reporter: "node-b",
	}); err != nil {
		f.t.Fatal(err)
	}
}

type condID struct{ evaluator, code, kind, subject string }

func (f *goneFixture) lifecycle(c condID) (string, string) {
	f.t.Helper()
	rows, err := f.db.Query(context.Background(),
		`SELECT lifecycle, updated_at FROM health_conditions
		 WHERE evaluator = ? AND code = ? AND subject_kind = ? AND subject_id = ? AND deleted_at IS NULL`,
		c.evaluator, c.code, c.kind, c.subject)
	if err != nil || len(rows) != 1 {
		f.t.Fatalf("%v: %d rows, %v", c, len(rows), err)
	}
	return rows[0].String("lifecycle"), rows[0].String("updated_at")
}

func (f *goneFixture) pass() { f.r.ReconcileOnce(context.Background()) }

// A condition naming a VM or container that was deleted resolves on the
// next pass; lab 1 accumulated about 80 that never did. One naming a live
// workload, a name with no row at all (no proof it was deleted), or a
// relocated container (tombstoned on one host, live on another) stays open,
// and so does each code that outlives its subject by design.
//
// Mutations: drop the sweep from the pass — every "want resolved" goes red;
// treat a missing row as deleted — vm-never goes red; judge a container by
// one host's row — ct-b goes red; empty the keep list — each kept code goes
// red; rewrite a resolved row — the idempotence check goes red; drop the
// replica freshness check — the stale-replica pass goes red.
func TestGoneSubject_ConditionsOfADeletedWorkloadResolve(t *testing.T) {
	f := newGoneFixture(t)
	ctx := context.Background()
	f.vm("vm-a", "node-a")
	f.vm("vm-b", "node-a")
	f.ct("ct-a", "node-a")
	f.ct("ct-b", "node-a")

	resolved := []condID{
		{VMProbeEvaluator, CondVMProbeFailing, "vm", "vm-a"},
		{corrosion.PartitionPauseEvaluator, corrosion.CondVMSettled, "vm", "vm-a@node-b"},
		{corrosion.PartitionPauseEvaluator, corrosion.CondVMSettleDeclined, "vm", "vm-a@node-b"},
		{"replica_set", "vm.promoted_partial", "vm", "vm-a"},
		{"shared_disk_start", "vm.shared_disk_withheld", "vm", "vm-a"},
		{DiskMissingEvaluator, CondVMDiskMissing, "vm", "vm-a@node-b"},
		{corrosion.PartitionPauseEvaluator, corrosion.CondCTSettled, "container", "ct-a@node-b"},
		{"recovery_claim", "ha.claim.legacy_held", "container", "ct-a"},
	}
	open := []condID{
		{VMProbeEvaluator, CondVMProbeFailing, "vm", "vm-b"},
		{VMProbeEvaluator, CondVMProbeFailing, "vm", "vm-never"},
		{corrosion.PartitionPauseEvaluator, corrosion.CondCTSettled, "container", "ct-b@node-a"},
		// Kept: each outlives its subject by design.
		{OrphanRuntimeEvaluator, CondVMOrphanRuntime, "vm", "vm-a"},
		{OrphanRuntimeEvaluator, CondCTOrphanRuntime, "container", "ct-a"},
		{"dual_run", "vm_dual_run", "vm", "vm-a"},
		{"dual_run", "runtime_owner_mismatch", "vm", "vm-a"},
		{DiskMissingEvaluator, CondVMDiskStranded, "vm", "vm-a@node-b"},
		{DiskMissingEvaluator, CondVMFailoverHeld, "vm", "vm-a@node-b"},
		{DiskMissingEvaluator, CondVMStartCancelled, "vm", "vm-a@node-b"},
		{CTRootfsEvaluator, CondCTRootfsStranded, "container", "ct-a@node-b"},
	}
	for _, c := range append(append([]condID{}, resolved...), open...) {
		f.raise(c.evaluator, c.code, c.kind, c.subject)
	}

	// Nothing is gone yet: a pass resolves nothing.
	f.pass()
	for _, c := range resolved {
		if lc, _ := f.lifecycle(c); lc != corrosion.ConditionConfirmed {
			t.Fatalf("%v is %s while its subject exists, want it left open", c, lc)
		}
	}

	if err := corrosion.DeleteVM(ctx, f.db, "vm-a"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteContainer(ctx, f.db, "node-a", "ct-a"); err != nil {
		t.Fatal(err)
	}
	// ct-b relocates: its node-a row is tombstoned, a node-b row is live.
	if err := corrosion.DeleteContainer(ctx, f.db, "node-a", "ct-b"); err != nil {
		t.Fatal(err)
	}
	f.ct("ct-b", "node-b")

	// A replica that has not caught up may hold a tombstone a later write
	// undoes on the cluster (a VM created again under the name), so it
	// decides nothing.
	f.r.SetReplicaFreshness(func() (bool, string) { return false, "not caught up" })
	f.pass()
	for _, c := range resolved {
		if lc, _ := f.lifecycle(c); lc != corrosion.ConditionConfirmed {
			t.Fatalf("%v is %s after a pass on a replica that has not caught up, want it left open", c, lc)
		}
	}
	f.r.SetReplicaFreshness(nil)

	f.pass()
	at := map[condID]string{}
	for _, c := range resolved {
		lc, u := f.lifecycle(c)
		if lc != corrosion.ConditionResolved {
			t.Errorf("%v is %s after its subject was deleted, want resolved", c, lc)
		}
		at[c] = u
	}
	for _, c := range open {
		if lc, _ := f.lifecycle(c); lc != corrosion.ConditionConfirmed {
			t.Errorf("%v is %s, want it left open", c, lc)
		}
	}
	if t.Failed() {
		return
	}
	got, ok, err := corrosion.GetHealthCondition(ctx, f.db, VMProbeEvaluator, CondVMProbeFailing, "vm", "vm-a")
	if err != nil || !ok || got.ResolvedAt == "" || got.Reporter != "node-a" {
		t.Fatalf("resolved row = (%+v, %v, %v), want resolved_at set and reporter node-a", got, ok, err)
	}

	// Idempotent: a further pass writes nothing.
	f.pass()
	for _, c := range resolved {
		if _, u := f.lifecycle(c); u != at[c] {
			t.Errorf("%v was rewritten by a pass after it resolved (updated_at %s → %s)", c, at[c], u)
		}
	}

	// An older node re-raises one: the next pass resolves it again, once.
	f.raise(VMProbeEvaluator, CondVMProbeFailing, "vm", "vm-a")
	f.pass()
	if lc, _ := f.lifecycle(resolved[0]); lc != corrosion.ConditionResolved {
		t.Fatalf("%v re-raised by an older node is %s after a pass, want resolved again", resolved[0], lc)
	}
}

// A condition naming a removed host resolves on the next pass — its own
// (subject host), a pool on it (pool@host), and a workload's on it
// (vm@host) — while those that outlive a removal by design stay open:
// certificate revocation owed for the host, the deputy's reservation_stale,
// and the inputs failover recovery reads.
//
// Mutations: drop the host check — every "want resolved" goes red; parse
// pool@host by its prefix — the pool one goes red; empty the keep list —
// each kept code goes red.
func TestGoneSubject_ConditionsOfARemovedHostResolve(t *testing.T) {
	f := newGoneFixture(t)
	ctx := context.Background()
	f.vm("vm-b", "node-a")

	resolved := []condID{
		{"netbox", "netbox_dhcp_would_race", "host", "node-c"},
		{"nfs_pool", "nfs_mount_missing", "host", "pool1@node-c"},
		{"stall", "observer_stalled", "host", "node-c"},
		{DiskMissingEvaluator, CondVMDiskMissing, "vm", "vm-b@node-c"},
	}
	open := []condID{
		{"netbox", "netbox_dhcp_would_race", "host", "node-b"},
		{"nfs_pool", "nfs_mount_missing", "host", "pool1@node-b"},
		{"certificate", "revocation_owed", "host", "node-c/1a2b3c"},
		{"certificate", "key_file_unsafe", "host", "node-c"},
		{"audit", "audit_chain_held", "host", "node-c"},
		{"reservation-sweep", "reservation_stale", "host", "node-c"},
		{corrosion.PartitionPauseEvaluator, corrosion.CondPartitionPaused, "host", "node-c"},
		{corrosion.PartitionPauseEvaluator, corrosion.CondPartitionPauseFailed, "host", "node-c"},
		{"failover", "refence_failed", "host", "node-c"},
		{"iscsi_lun_hold", "iscsi_lun_hold_standing", "host", "node-c"},
	}
	for _, c := range append(append([]condID{}, resolved...), open...) {
		f.raise(c.evaluator, c.code, c.kind, c.subject)
	}
	if err := corrosion.DeleteHost(ctx, f.db, "node-c"); err != nil {
		t.Fatal(err)
	}
	f.pass()
	for _, c := range resolved {
		if lc, _ := f.lifecycle(c); lc != corrosion.ConditionResolved {
			t.Errorf("%v is %s after node-c was removed, want resolved", c, lc)
		}
	}
	for _, c := range open {
		if lc, _ := f.lifecycle(c); lc != corrosion.ConditionConfirmed {
			t.Errorf("%v is %s, want it left open", c, lc)
		}
	}
}
