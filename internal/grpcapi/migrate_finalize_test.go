package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFinalizeMigrationOwnership_CommitFailurePreservesSource reproduces the P0
// migration-cutover bug: after libvirt has already cut the VM over to the target,
// the ownership DB write is committed unchecked and the source disk is deleted
// regardless. If that write fails, the pre-fix code still deletes the source disk
// (data loss) and reports success (stale/dual ownership in Corrosion).
//
// A BEFORE UPDATE trigger on vm_disks forces the disk-ownership write to fail. The
// correct post-condition — the source disk survives and the failure surfaces — must
// hold; this test fails against the pre-fix behavior and passes once the commit is a
// hard gate before the source delete.
func TestFinalizeMigrationOwnership_CommitFailurePreservesSource(t *testing.T) {
	s := testServer(t) // hostName = "test-host"
	ctx := adminCtx()

	const vmName = "mig-vm"
	insertTestVM(t, ctx, s.db, vmName, s.hostName, "running")

	// A real host-local source disk file that a --with-storage migration would
	// orphan and then try to delete on the source host.
	diskPath := filepath.Join(t.TempDir(), vmName+"-root.qcow2")
	if err := os.WriteFile(diskPath, []byte("disk-contents"), 0o600); err != nil {
		t.Fatalf("write disk file: %v", err)
	}
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: vmName, DiskName: "root", HostName: s.hostName,
		Path: diskPath, StorageType: "local",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}

	// Snapshot the disks before cutover, exactly as MigrateVM does.
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}

	// Inject a failure of the disk-ownership UPDATE (simulates a Corrosion write
	// error at the post-cutover commit).
	if err := s.db.Execute(ctx,
		`CREATE TRIGGER inject_fail BEFORE UPDATE ON vm_disks BEGIN SELECT RAISE(ABORT, 'inject'); END;`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}

	ferr := s.finalizeMigrationOwnership(ctx, vm, "target-host", true, disks)

	if ferr == nil {
		t.Error("finalizeMigrationOwnership returned nil; want an error when the ownership commit cannot land")
	}
	if _, statErr := os.Stat(diskPath); os.IsNotExist(statErr) {
		t.Error("source disk was deleted even though the ownership commit failed (data loss)")
	}
}

// TestFinalizeMigrationOwnership_Success proves the happy path: the VM and every
// disk are repointed to the target, and the orphaned host-local source disk is
// removed only after the commit lands.
func TestFinalizeMigrationOwnership_Success(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	const vmName = "mig-ok"
	insertTestVM(t, ctx, s.db, vmName, s.hostName, "running")
	diskPath := filepath.Join(t.TempDir(), vmName+"-root.qcow2")
	if err := os.WriteFile(diskPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write disk file: %v", err)
	}
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: vmName, DiskName: "root", HostName: s.hostName, Path: diskPath, StorageType: "local",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	vm, _ := corrosion.GetVM(ctx, s.db, vmName)

	if err := s.finalizeMigrationOwnership(ctx, vm, "target-host", true, disks); err != nil {
		t.Fatalf("finalizeMigrationOwnership: %v", err)
	}

	got, _ := corrosion.GetVM(ctx, s.db, vmName)
	if got.HostName != "target-host" {
		t.Errorf("VM host_name = %q, want target-host", got.HostName)
	}
	after, _ := corrosion.GetVMDisks(ctx, s.db, vmName)
	if len(after) != 1 || after[0].HostName != "target-host" {
		t.Errorf("disk host_name not repointed to target: %+v", after)
	}
	if _, statErr := os.Stat(diskPath); !os.IsNotExist(statErr) {
		t.Error("orphaned source disk should have been removed after a successful commit")
	}
}

// TestCommitMigrationOwnership_DriftDeclines proves the guard refuses to clobber a
// concurrent retarget that changed a disk's storage type after the pre-cutover
// snapshot was taken.
func TestCommitMigrationOwnership_DriftDeclines(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	const vmName = "mig-drift"
	insertTestVM(t, ctx, s.db, vmName, s.hostName, "running")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: vmName, DiskName: "root", HostName: s.hostName, Path: "/pool/a.qcow2", StorageType: "local",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(ctx, s.db, vmName)

	// A concurrent move changed the disk's storage type after the snapshot.
	if err := s.db.Execute(ctx,
		`UPDATE vm_disks SET storage_type = 'ceph' WHERE vm_name = ? AND disk_name = 'root'`, vmName); err != nil {
		t.Fatalf("mutate disk: %v", err)
	}

	committed, err := corrosion.CommitMigrationOwnership(ctx, s.db, vmName, s.hostName, "target-host", "running", disks)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if committed {
		t.Error("commit succeeded despite disk placement drift; want decline")
	}
	if got, _ := corrosion.GetVM(ctx, s.db, vmName); got.HostName != s.hostName {
		t.Errorf("VM host changed to %q on a declined commit; want %s", got.HostName, s.hostName)
	}
}

// TestCommitMigrationOwnership_Idempotent proves a retry after the move already
// landed (VM + disks on target) returns committed=true, not a precondition failure.
func TestCommitMigrationOwnership_Idempotent(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	const vmName = "mig-idem"
	insertTestVM(t, ctx, s.db, vmName, s.hostName, "running")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: vmName, DiskName: "root", HostName: s.hostName, Path: "/pool/a.qcow2", StorageType: "nfs",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(ctx, s.db, vmName)

	if ok, err := corrosion.CommitMigrationOwnership(ctx, s.db, vmName, s.hostName, "target-host", "running", disks); err != nil || !ok {
		t.Fatalf("first commit: ok=%v err=%v", ok, err)
	}
	// Retry with the same source/target — now already on target.
	ok, err := corrosion.CommitMigrationOwnership(ctx, s.db, vmName, s.hostName, "target-host", "running", disks)
	if err != nil {
		t.Fatalf("idempotent retry errored: %v", err)
	}
	if !ok {
		t.Error("idempotent retry returned committed=false; want true (already on target)")
	}
}

// TestFinalizeMigrationOwnership_DeclinedCommitMovesTheVMRow: the cutover has
// happened and the commit declines on disk drift. The guest runs on the
// target, so the VM row must say so; a row left `migrating` on the source is
// one nothing heals (owner-assert skips `migrating`). The drifted disk row is
// left as it is and the error still surfaces.
//
// Mutation: drop the RepointMigratedVM fallback — the row stays on the source,
// `migrating`.
func TestFinalizeMigrationOwnership_DeclinedCommitMovesTheVMRow(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	const vmName = "mig-declined"
	insertTestVM(t, ctx, s.db, vmName, s.hostName, "migrating")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: vmName, DiskName: "root", HostName: s.hostName, Path: "/pool/a.qcow2", StorageType: "nfs",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err := s.db.Execute(ctx,
		`UPDATE vm_disks SET path = '/pool/b.qcow2' WHERE vm_name = ? AND disk_name = 'root'`, vmName); err != nil {
		t.Fatalf("mutate disk: %v", err)
	}
	vm, _ := corrosion.GetVM(ctx, s.db, vmName)

	if err := s.finalizeMigrationOwnership(ctx, vm, "target-host", false, disks); err == nil {
		t.Fatal("finalizeMigrationOwnership returned nil on a declined commit; want the failure surfaced")
	}
	got, _ := corrosion.GetVM(ctx, s.db, vmName)
	if got.HostName != "target-host" || got.State != "running" {
		t.Fatalf("after a declined commit the VM row is %s/%s; want target-host/running, where the guest runs",
			got.HostName, got.State)
	}
	if after, _ := corrosion.GetVMDisks(ctx, s.db, vmName); len(after) != 1 || after[0].HostName != s.hostName {
		t.Fatalf("the drifted disk row was rewritten: %+v", after)
	}
}

// TestFinalizeMigrationOwnership_DeclinedCommitLeavesAMovedRowAlone: the
// fallback moves only a row still on the source in `migrating`. One that has
// moved since (to a third host) is not overwritten.
func TestFinalizeMigrationOwnership_DeclinedCommitLeavesAMovedRowAlone(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	const vmName = "mig-moved"
	insertTestVM(t, ctx, s.db, vmName, s.hostName, "migrating")
	vm, _ := corrosion.GetVM(ctx, s.db, vmName)
	if err := corrosion.UpdateVMHost(ctx, s.db, vmName, "third-host", "running"); err != nil {
		t.Fatal(err)
	}
	if err := s.finalizeMigrationOwnership(ctx, vm, "target-host", false, nil); err == nil {
		t.Fatal("want the declined commit surfaced")
	}
	if got, _ := corrosion.GetVM(ctx, s.db, vmName); got.HostName != "third-host" {
		t.Fatalf("the fallback overwrote a row that had moved to third-host: %+v", got)
	}
}

// TestCommitMigrationOwnership_ADiskRowLeftOnAnotherHostCommits: a disk row
// still naming a host the VM left (failover before disk rows moved with it)
// is not drift when it is unchanged since the snapshot. It commits, and moves.
// One that moved to yet another host after the snapshot is still drift.
//
// Mutation: restore the source-or-target-only host check — the unchanged row
// declines.
func TestCommitMigrationOwnership_ADiskRowLeftOnAnotherHostCommits(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	const vmName = "mig-stale-disk"
	insertTestVM(t, ctx, s.db, vmName, s.hostName, "running")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: vmName, DiskName: "root", HostName: "failed-host", Path: "/pool/a.qcow2", StorageType: "nfs",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}
	disks, _ := corrosion.GetVMDisks(ctx, s.db, vmName)

	if err := s.db.Execute(ctx,
		`UPDATE vm_disks SET host_name = 'elsewhere' WHERE vm_name = ? AND disk_name = 'root'`, vmName); err != nil {
		t.Fatal(err)
	}
	if ok, err := corrosion.CommitMigrationOwnership(ctx, s.db, vmName, s.hostName, "target-host", "running", disks); err != nil || ok {
		t.Fatalf("a disk row moved since the snapshot: ok=%v err=%v, want a decline", ok, err)
	}
	if err := s.db.Execute(ctx,
		`UPDATE vm_disks SET host_name = 'failed-host' WHERE vm_name = ? AND disk_name = 'root'`, vmName); err != nil {
		t.Fatal(err)
	}
	if ok, err := corrosion.CommitMigrationOwnership(ctx, s.db, vmName, s.hostName, "target-host", "running", disks); err != nil || !ok {
		t.Fatalf("a disk row unchanged since the snapshot: ok=%v err=%v, want a commit", ok, err)
	}
	if after, _ := corrosion.GetVMDisks(ctx, s.db, vmName); len(after) != 1 || after[0].HostName != "target-host" {
		t.Fatalf("disk row not moved to the target: %+v", after)
	}
}
