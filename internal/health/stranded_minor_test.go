package health

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// M8: the returning host leaves the disk in place under a shut-off domain
// that still holds a managed-save image: a resume needs the disk at its path.
//
// Mutation: drop the managed-save check in tendStrandedDisk — the disk is
// renamed and the test is red.
func TestTendStrandedDisks_LeavesTheDiskOfADomainWithSavedState(t *testing.T) {
	db, fake, r, _, path := strandedFixture(t)
	recordWeb(t, db, time.Now())
	if err := fake.DefineDomain(`<domain><name>web</name></domain>`); err != nil {
		t.Fatal(err)
	}
	fake.SetManagedSaveImage("web", true)
	r.tendStrandedDisks(context.Background())
	if !exists(path) {
		t.Fatal("the disk of a domain with a managed-save image was moved")
	}
}

// M8: a file another VM on this host still uses at that path (a linked
// clone's base) is never set aside.
//
// Mutation: drop the DisksReferencingPath check — the base is renamed and the
// test is red.
func TestTendStrandedDisks_LeavesAFileAWorkloadHereUses(t *testing.T) {
	db, _, r, _, path := strandedFixture(t)
	ctx := context.Background()
	recordWeb(t, db, time.Now())
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "clone", HostName: "node-a", State: "running", Spec: "{}"},
		nil, []corrosion.DiskRecord{{VMName: "clone", DiskName: "root", HostName: "node-a", Path: path + ".clone",
			BackingDisk: path, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	r.tendStrandedDisks(ctx)
	if !exists(path) {
		t.Fatal("a linked clone's base on this host was moved")
	}
}

// M8: nothing is set aside while this node's replica has not caught up: a
// row it has not received yet would read as the VM elsewhere.
//
// Mutation: drop the replicaTrusted gate in tendStrandedDisks — the disk is
// renamed and the test is red.
func TestTendStrandedDisks_WaitsForTheReplica(t *testing.T) {
	db, _, r, _, path := strandedFixture(t)
	ctx := context.Background()
	recordWeb(t, db, time.Now())
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "node-b", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active"}); err != nil {
		t.Fatal(err)
	}
	r.SetReplicaFreshness(func() (bool, string) { return false, "catching up" })
	r.tendStrandedDisks(ctx)
	if !exists(path) {
		t.Fatal("a disk was set aside from a replica that had not caught up")
	}
}

// M2: a disk whose directory is not there yet (a volume not mounted) keeps
// its record entry: dropping it would surface nothing once the directory
// appears, and lose a record-only retention.
//
// Mutation: drop the parent-directory check — the entry is dropped and the
// test is red.
func TestTendStrandedDisks_KeepsTheEntryWhileItsDirectoryIsMissing(t *testing.T) {
	db, _, r, _, path := strandedFixture(t)
	ctx := context.Background()
	recordWeb(t, db, time.Now())
	moved := filepath.Dir(path) + ".unmounted"
	if err := os.Rename(filepath.Dir(path), moved); err != nil {
		t.Fatal(err)
	}
	r.tendStrandedDisks(ctx)
	if row, ev, ok := strandedRow(t, db, "web", "node-a"); !ok || row.Lifecycle == corrosion.ConditionResolved || len(ev.Disks) != 1 {
		t.Fatalf("the entry was dropped while its directory was missing: %+v", ev)
	}
	if err := os.Rename(moved, filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	r.tendStrandedDisks(ctx)
	if _, ev, _ := strandedRow(t, db, "web", "node-a"); len(ev.Disks) != 1 || ev.Disks[0].Copy == "" {
		t.Fatalf("once the directory is back the disk is not set aside: %+v", ev)
	}
}

// M4: a restore whose link into place fails puts the disk it set aside back
// at the disk's path, so the VM is never left with no disk there.
//
// Mutation: drop the roll-back — the disk path is empty after the failure
// and the test is red.
func TestRestoreSupersededDisk_PutsTheDiskBackWhenTheLinkFails(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "disks", "web-root.qcow2")
	copyPath := supersededAt(t, path, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	if err := os.WriteFile(path, []byte("rebuilt blank"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "web", HostName: "node-a", State: "stopped", Spec: "{}"},
		nil, []corrosion.DiskRecord{{VMName: "web", DiskName: "root", HostName: "node-a", Path: path, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	old := linkFile
	linkFile = func(string, string) error { return errors.New("operation not permitted") }
	defer func() { linkFile = old }()
	if _, err := RestoreSupersededDisk(ctx, db, dataDir, "node-a", copyPath, func(string) bool { return false }, time.Now()); err == nil {
		t.Fatal("the restore reported success with the link failing")
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "rebuilt blank" {
		t.Fatalf("after a failed restore the disk at %s is %q (err %v), want the disk it had", path, b, err)
	}
	if !exists(copyPath) {
		t.Fatal("the copy is gone after a failed restore")
	}
}

// M5: a lagging replica cannot clear ct_rootfs_stranded.
//
// Mutation: drop the replicaTrusted gate in tendStrandedRootfs — the record
// is cleared from a replica that still shows the old row here, red.
func TestTendStrandedRootfs_WaitsForTheReplica(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if _, err := RecordStrandedRootfs(ctx, db, "coord", "web", "node-a", "node-b", "image-recreate", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{HostName: "node-a", Name: "web", State: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "node-b", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active"}); err != nil {
		t.Fatal(err)
	}
	cc := NewContainerChecker("node-a", db, newFakeCtRuntime())
	cc.SetReplicaFreshness(func() (bool, string) { return false, "catching up" })
	cc.tendStrandedRootfs(ctx, map[string]bool{"web": true})
	if got, _ := StrandedRootfsOf(ctx, db, "web"); len(got) != 1 {
		t.Fatalf("records = %+v, want it kept while the replica catches up", got)
	}
}

// M6: a record for a removed host clears once the container is gone
// everywhere: the removed host will never tend it.
//
// Mutation: drop the removed-host branch — the record stays open, red.
func TestTendStrandedRootfs_ClearsARemovedHostsRecordOnceTheContainerIsGone(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if _, err := RecordStrandedRootfs(ctx, db, "coord", "web", "gone-host", "node-b", "image-recreate", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{HostName: "node-b", Name: "web", State: "running"}); err != nil {
		t.Fatal(err)
	}
	cc := NewContainerChecker("node-c", db, newFakeCtRuntime())
	cc.tendStrandedRootfs(ctx, map[string]bool{})
	if got, _ := StrandedRootfsOf(ctx, db, "web"); len(got) != 1 {
		t.Fatalf("cleared while the container still exists: %+v", got)
	}
	if err := corrosion.DeleteContainer(ctx, db, "node-b", "web"); err != nil {
		t.Fatal(err)
	}
	cc.tendStrandedRootfs(ctx, map[string]bool{})
	if got, _ := StrandedRootfsOf(ctx, db, "web"); len(got) != 0 {
		t.Fatalf("records = %+v, want none once the host is gone and the container deleted", got)
	}
}

// M9: re-recording a hold that has not changed writes nothing, and keeps when
// it began.
//
// Mutation: always upsert — LastSeen moves and the test is red.
func TestRecordHeldForHost_DoesNotRewriteAnUnchangedHold(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	disks := []corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "node-a", Path: "/x/vm1.qcow2", StorageType: "local"}}
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if _, err := RecordHeldForHost(ctx, db, "coord", "vm1", "node-a", disks, t0); err != nil {
		t.Fatal(err)
	}
	first, _, _ := corrosion.GetHealthCondition(ctx, db, DiskMissingEvaluator, CondVMFailoverHeld, "vm", "vm1@node-a")
	if _, err := RecordHeldForHost(ctx, db, "coord", "vm1", "node-a", disks, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	again, _, _ := corrosion.GetHealthCondition(ctx, db, DiskMissingEvaluator, CondVMFailoverHeld, "vm", "vm1@node-a")
	if again.LastSeen != first.LastSeen || again.Evidence != first.Evidence || again.ObserveCount != first.ObserveCount {
		t.Fatalf("an unchanged hold was rewritten: %+v then %+v", first, again)
	}
}
