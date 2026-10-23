package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Lab 2 drill 4, F5: `lv rm --force` of a just-created VM failed with "its
// file is still there after its removal", and a retry succeeded. It was no
// race with qemu: the domain was gone, and the removal was never attempted.
// kept-disks.json could not be read at that moment, which holds every path
// (keptHolds), so the recorded-location delete left the file on purpose and
// returned nil; the verification then found the file and reported a removal
// that failed. The retry ran once the file had been repaired. The leftover
// now says why the file was left.
func TestFreeRecordedVMDisks_AHeldFileIsNamedForItsHold(t *testing.T) {
	ctx := adminCtx()
	s, base, was := debrisFixture(t)
	insertTestVM(t, ctx, s.db, "web", s.hostName, "stopped")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "web", DiskName: "root", HostName: s.hostName, StorageType: "local", Path: base, DeleteWithVM: true,
	}); err != nil {
		t.Fatal(err)
	}
	registry := filepath.Join(s.dataDir, diskKeptFile)
	if err := os.WriteFile(registry, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, left := s.freeRecordedVMDisks(ctx, "web", nil)
	sameBytes(t, "a disk file while kept-disks.json cannot be read", base, was)
	if len(left) != 1 || left[0].err == nil {
		t.Fatalf("leftovers = %+v, want the held disk", left)
	}
	msg := left[0].err.Error()
	if strings.Contains(msg, "still there after its removal") || !strings.Contains(msg, registry) ||
		!strings.Contains(msg, "cannot be read") {
		t.Errorf("the held disk is named as %q; want the hold (%s cannot be read), not a removal that failed", msg, registry)
	}

	// Once the registry is repaired, the same delete frees it.
	if err := os.Remove(registry); err != nil {
		t.Fatal(err)
	}
	if _, _, left := s.freeRecordedVMDisks(ctx, "web", nil); len(left) != 0 {
		t.Fatalf("leftovers after the repair = %+v", left)
	}
	if exists(base) {
		t.Error("the disk was not freed after the repair")
	}
}

// A file that is really still there after a removal that ran is still named
// as such: the check that a file is gone is not weakened.
func TestFreeRecordedVMDisks_AFileLeftByARemovalThatRanIsStillNamed(t *testing.T) {
	ctx := adminCtx()
	s, base, _ := debrisFixture(t)
	insertTestVM(t, ctx, s.db, "web", s.hostName, "stopped")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "web", DiskName: "root", HostName: s.hostName, StorageType: "local", Path: base, DeleteWithVM: true,
	}); err != nil {
		t.Fatal(err)
	}
	old := afterRecordedDiskDelete
	t.Cleanup(func() { afterRecordedDiskDelete = old })
	afterRecordedDiskDelete = func(path string) { _ = os.WriteFile(path, []byte("recreated"), 0o600) }
	_, _, left := s.freeRecordedVMDisks(ctx, "web", nil)
	if len(left) != 1 || left[0].err == nil || !strings.Contains(left[0].err.Error(), "still there after its removal") {
		t.Fatalf("leftovers = %+v, want the file named as still there", left)
	}
}
