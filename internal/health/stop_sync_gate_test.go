package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// stopSyncFixture: vm1 is this host's (node-a) running VM per the DB, and its
// domain is defined and destroyed out of band — the reconciler's stop-sync
// trigger. extraHosts are admitted into the hosts table besides node-a.
func stopSyncFixture(t *testing.T, extraHosts ...string) (*corrosion.Client, *Reconciler) {
	t.Helper()
	db := testReconcilerDB(t)
	ctx := context.Background()
	for _, h := range append([]string{"node-a"}, extraHosts...) {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", CertSerial: "s-" + h, State: "active",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake := libvirtfake.New()
	if err := fake.DefineDomain(`<domain><name>vm1</name></domain>`); err != nil {
		t.Fatal(err)
	}
	fake.SetState("vm1", libvirtfake.StateShutdown)
	fake.SetStateReason("vm1", "destroyed")
	return db, NewReconciler("node-a", t.TempDir(), db, fake)
}

func vmState(t *testing.T, db *corrosion.Client) string {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v %+v", err, vm)
	}
	return vm.State
}

// The replica-freshness gate holds the sync while the replica has not caught
// up, and releases it the moment it has.
func TestStopSync_DeferredUntilReplicaCaughtUp(t *testing.T) {
	db, r := stopSyncFixture(t, "node-b")
	caught := false
	r.SetReplicaFreshness(func() (bool, string) { return caught, "not yet" })

	r.ReconcileOnce(context.Background())
	if got := vmState(t, db); got != "running" {
		t.Fatalf("stop sync published from an uncaught-up replica: state=%q", got)
	}

	caught = true
	r.ReconcileOnce(context.Background())
	if got := vmState(t, db); got != "stopped" {
		t.Fatalf("once caught up the stop sync must proceed: state=%q", got)
	}
}

// A cluster of one has nobody to catch up with and nobody else who could own
// the VM: the gate must not strand a single-node cluster's stop syncs forever.
func TestStopSync_SingleNodeClusterIsNotGated(t *testing.T) {
	db, r := stopSyncFixture(t) // hosts table: node-a only
	r.SetReplicaFreshness(func() (bool, string) { return false, "never" })

	r.ReconcileOnce(context.Background())
	if got := vmState(t, db); got != "stopped" {
		t.Fatalf("a single-node cluster's stop sync must not wait for a peer that does not exist: state=%q", got)
	}
}

// An active ownership condition holds the sync even on a caught-up replica,
// mirroring the self-heal restart; resolving it releases the sync.
func TestStopSync_RefusedUnderActiveOwnershipCondition(t *testing.T) {
	db, r := stopSyncFixture(t, "node-b")
	r.SetReplicaFreshness(func() (bool, string) { return true, "" })
	ctx := context.Background()
	cond := corrosion.HealthCondition{
		Evaluator: "ownership", Code: "runtime_owner_mismatch",
		SubjectKind: "vm", SubjectID: "vm1",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityWarning,
		FirstSeen: "2026-09-24T00:00:00Z", LastSeen: "2026-09-24T00:00:00Z", Reporter: "node-b",
	}
	if err := corrosion.UpsertHealthCondition(ctx, db, cond); err != nil {
		t.Fatalf("UpsertHealthCondition: %v", err)
	}

	r.ReconcileOnce(ctx)
	if got := vmState(t, db); got != "running" {
		t.Fatalf("stop sync published for a VM whose ownership is in dispute: state=%q", got)
	}

	cond.Lifecycle = corrosion.ConditionResolved
	cond.ResolvedAt = "2026-09-24T00:01:00Z"
	if err := corrosion.UpsertHealthCondition(ctx, db, cond); err != nil {
		t.Fatalf("resolve condition: %v", err)
	}
	r.ReconcileOnce(ctx)
	if got := vmState(t, db); got != "stopped" {
		t.Fatalf("with the dispute resolved the stop sync must proceed: state=%q", got)
	}
}
