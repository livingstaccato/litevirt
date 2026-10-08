package grpcapi

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// lab-recheck-5 FAIL 4. On main (3e4ba50b) `lv backup restore-from --vm
// rc5-prom2 --disk root --target-path <rc5-prom2's own overlay>` restored over
// that file: RestoreFromBackup wrote a temp file and os.Rename'd it over the
// target (backup_snapshot.go:610 resolveRestoreTarget, :645 temp, :660
// os.Rename at 3e4ba50b). This build refused it — `AlreadyExists … a restore
// or copy never replaces a file` — and the message did not name --in-place,
// the one way left to do it. When target_path is exactly the destination
// VM's own recorded disk file, the restore now is --in-place: the same checks
// (the backup's project is the VM's, the VM is stopped on this host, no
// snapshots, the file that disk's alone) and the same rebuild onto the disk's
// own backing. Any other existing file stays refused, naming --in-place.

func restoreTargetPath(ctx context.Context, f *restoreFixture, vm, ts, target string) error {
	return f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: vm, DiskName: "root", Timestamp: ts, TargetPath: target,
	}, &progressStream[pb.RestoreFromBackupProgress]{ctx: ctx})
}

// The lab case: a VM main promoted with --no-localize, its overlay on a
// replica in the default pool, restored by an admin with main's command.
//
// Red against 1c105363: `AlreadyExists desc = "…/pv-promoted-web-root-….qcow2"
// already exists; a restore or copy never replaces a file`.
func TestRestoreFromBackup_TargetPathOnTheVMsOwnDiskIsInPlace(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	disk, replica, content := mainPromotedRestoreVM(t, f, "qcow2")
	const ts = "2026-10-08T10:04:15Z"
	pushVMWithIdentity(t, f, "pv", disk, ts, "", "", nil) // main's backup
	if err := os.Remove(disk); err != nil {
		t.Fatal(err)
	}
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", replica, "-F", "qcow2", disk)
	if err := restoreTargetPath(adminCtx(), f, "pv", ts, disk); err != nil {
		t.Fatalf("restore-from --target-path <the VM's own disk>: %v", err)
	}
	requireRestoredOnto(t, disk, replica, content)
	f.assertVictimIntact(t)
}

// It is --in-place, not a looser path: a running VM's disk is refused as
// --in-place refuses it, and left as it was.
func TestRestoreFromBackup_TargetPathOnTheVMsOwnDiskKeepsInPlacesChecks(t *testing.T) {
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	ctx := context.Background()
	disks, _ := corrosion.GetVMDisks(ctx, f.s.db, "web")
	own := disks[0].Path
	if err := corrosion.UpdateVMState(ctx, f.s.db, "web", "running", ""); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(own)
	err := restoreTargetPath(adminCtx(), f, "web", restoreTS, own)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "stop it") {
		t.Errorf("--target-path on a running VM's own disk: got %v, want --in-place's FailedPrecondition", err)
	}
	if after, _ := os.ReadFile(own); !bytes.Equal(before, after) {
		t.Error("a running VM's disk was replaced")
	}
	// Stopped again, the same request restores it.
	if err := corrosion.UpdateVMState(ctx, f.s.db, "web", "stopped", ""); err != nil {
		t.Fatal(err)
	}
	if err := restoreTargetPath(adminCtx(), f, "web", restoreTS, own); err != nil {
		t.Fatalf("--target-path on the stopped VM's own disk: %v", err)
	}
	f.assertVictimIntact(t)
}

// Any other existing file is still refused, for an admin too — another VM's
// disk included — and the refusal names --in-place. A non-admin still may not
// name a target at all, not even the VM's own disk.
func TestRestoreFromBackup_TargetPathOnAnyOtherFileIsRefusedNamingInPlace(t *testing.T) {
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	err := restoreTargetPath(adminCtx(), f, "web", restoreTS, f.victim)
	if status.Code(err) != codes.AlreadyExists || !strings.Contains(err.Error(), "--in-place") {
		t.Errorf("admin restore onto another VM's disk: got %v, want AlreadyExists naming --in-place", err)
	}
	f.assertVictimIntact(t)

	disks, _ := corrosion.GetVMDisks(context.Background(), f.s.db, "web")
	own := disks[0].Path
	before, _ := os.ReadFile(own)
	// The VM's file, but named for another of its disks: not that disk's own.
	err = f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: "r", VmName: "web", DiskName: "data", Timestamp: restoreTS, TargetPath: own,
	}, &progressStream[pb.RestoreFromBackupProgress]{ctx: adminCtx()})
	if status.Code(err) != codes.AlreadyExists || !strings.Contains(err.Error(), "--in-place") {
		t.Errorf("--disk data with root's file as target_path: got %v, want AlreadyExists naming --in-place", err)
	}
	if err := restoreTargetPath(f.alice, f, "web", restoreTS, own); status.Code(err) != codes.PermissionDenied {
		t.Errorf("an operator naming the VM's own disk as target_path: got %v, want PermissionDenied", err)
	}
	if after, _ := os.ReadFile(own); !bytes.Equal(before, after) {
		t.Error("an operator's target_path replaced the disk")
	}
}
