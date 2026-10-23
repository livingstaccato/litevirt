package grpcapi

import (
	"bytes"
	"errors"
	"log/slog"
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

// Round 1, finding 1: a held file reads as held, with its reason, on every
// surface that names it: the kept disk's reason (leftoversKept), the "a VM
// delete kept a disk" warning, the vm.disk_kept event, and the disk_leftover
// health condition. None of them says its removal failed.
func TestFreeRecordedVMDisks_AHeldFileReadsAsHeldEverywhere(t *testing.T) {
	ctx := adminCtx()
	s, base, was := debrisFixture(t)
	insertTestVM(t, ctx, s.db, "web", s.hostName, "stopped")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "web", DiskName: "root", HostName: s.hostName, StorageType: "local", Path: base, DeleteWithVM: true,
	}); err != nil {
		t.Fatal(err)
	}
	// Another VM's kept disk backs on web's disk file: kept-disks.json holds it.
	registryKeep(t, s, "other", base)
	_, _, left := s.freeRecordedVMDisks(ctx, "web", nil)
	sameBytes(t, "a disk file a kept disk backs on", base, was)
	if len(left) != 1 {
		t.Fatalf("leftovers = %+v, want the held disk", left)
	}
	kept := s.leftoversKept(left)
	if len(kept) != 1 {
		t.Fatalf("kept = %+v", kept)
	}
	heldOK := func(what, text string) {
		t.Helper()
		if strings.Contains(text, "removal failed") || strings.Contains(text, "still there after its removal") ||
			!strings.Contains(text, "not removed") || !strings.Contains(text, "the delete of VM other kept") {
			t.Errorf("%s reads %q; want it held, with its reason, never a failed removal", what, text)
		}
	}
	heldOK("the kept disk's reason", kept[0].Reason)

	logs := captureGRPCSlog(t)
	s.recordKeptDisks(ctx, "web", kept)
	heldOK("the delete's warning", logs.String())
	evs, err := corrosion.ListVMEvents(ctx, s.db, "web", 50, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range evs {
		if e.Type == "vm.disk_kept" {
			found = true
			heldOK("the vm.disk_kept event", e.Detail)
		}
	}
	if !found {
		t.Error("no vm.disk_kept event")
	}
	s.JudgeKeptDisksForTest(ctx)
	row, ok, err := corrosion.GetHealthCondition(ctx, s.db, diskLeftoverEvaluator, condDiskLeftover, "host", s.hostName)
	if err != nil || !ok {
		t.Fatalf("disk_leftover not raised: %v", err)
	}
	if !strings.Contains(row.Evidence, filepath.Base(base)) {
		t.Fatalf("disk_leftover does not name %s: %s", base, row.Evidence)
	}
	heldOK("disk_leftover", row.Evidence)
}

// A disk whose removal really failed still reads as a failed removal there.
func TestLeftoversKept_AFailedRemovalStillSaysSo(t *testing.T) {
	s, _, _ := debrisFixture(t)
	kept := s.leftoversKept([]diskLeftover{{disk: "root", path: "/x/web-root.qcow2", err: errors.New("its file is still there after its removal")}})
	if len(kept) != 1 || !strings.HasPrefix(kept[0].Reason, "its removal failed: ") {
		t.Errorf("kept = %+v, want the failed removal named as such", kept)
	}
}

func captureGRPCSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}
