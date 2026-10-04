package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// `lv vm delete base --keep-disks` exists so linked clones stay valid: it
// tombstones the base's rows and leaves base-root.qcow2 on disk, still named by
// every overlay's backing_disk. Creating a NEW VM that reuses the name then runs
// the debris glob for "base-*.qcow2" — and the keep set it is given is derived
// from the named VM's LIVE rows, of which a freshly-created name has none by
// construction (createVM refuses a duplicate live name before reaching here).
//
// So the guard cannot protect anything on that path, the base file is removed,
// and every clone's backing chain is destroyed with no recovery.
func TestProtectedDiskPaths_ProtectsABaseStillBackingALiveClone(t *testing.T) {
	s, _ := provableCreateServer(t)
	ctx := adminCtx()

	basePath := s.images.DiskPath("base", "root")
	if err := os.MkdirAll(filepath.Dir(basePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(basePath, []byte("base image"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A live linked clone whose overlay still names the base as its backing file.
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "clone1", HostName: "test-host", State: "stopped"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "clone1", DiskName: "root", HostName: "test-host",
			Path: s.images.DiskPath("clone1", "root"), StorageType: "local",
			BackingDisk: basePath,
		}},
	); err != nil {
		t.Fatalf("InsertVM clone1: %v", err)
	}

	// The base itself has NO live rows — it was deleted with --keep-disks, and a
	// new VM is about to be created under the same name.
	keep := s.protectedDiskPaths(ctx, "base")
	if err := s.images.DeleteVMDisks("base", keep); err != nil {
		t.Fatalf("DeleteVMDisks: %v", err)
	}

	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		t.Fatal("the debris glob deleted a base image that a live linked clone still names as " +
			"its backing file — every overlay's chain is destroyed, unrecoverably, and " +
			"--keep-disks exists precisely to prevent this")
	}
}

// protectedDiskPaths' own comment claims it "Fails CLOSED in both directions".
// Returning nil on a read error protects nothing, so the glob then deletes every
// <vm>-*.qcow2 including a live clone base — a transient SQLITE_BUSY is enough.
func TestProtectedDiskPaths_FailsClosedWhenItCannotRead(t *testing.T) {
	s, _ := provableCreateServer(t)
	ctx := adminCtx()

	basePath := s.images.DiskPath("base", "root")
	if err := os.MkdirAll(filepath.Dir(basePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(basePath, []byte("base image"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Make every disk read fail.
	s.db.Close()

	keep := s.protectedDiskPaths(ctx, "base")
	if err := s.images.DeleteVMDisks("base", keep); err != nil {
		t.Fatalf("DeleteVMDisks: %v", err)
	}

	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		t.Fatal("a failed disk read let the glob delete everything — the read that decides " +
			"whether a file is still referenced cannot fail OPEN, which is what the function's " +
			"own comment already claims it does not do")
	}
}
