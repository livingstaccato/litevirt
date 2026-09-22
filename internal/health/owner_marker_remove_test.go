package health

import (
	"os"
	"path/filepath"
	"testing"
)

// RemoveVMOwnerEpochMarker had one error for two outcomes with opposite
// consequences: "the marker is still on disk", which wedges the next VM to take
// this name (a marker above a row at 0 is a mismatch convergence never repairs),
// and "the marker is gone, only its empty directory remains", which is harmless.
// Both callers logged the dangerous reading, so an operator chasing the log
// would be chasing a benign leftover — or, worse, would learn to ignore it.
func TestRemoveVMOwnerEpochMarker_ABenignLeftoverIsNotReportedAsAFailure(t *testing.T) {
	dir := t.TempDir()
	if err := WriteVMOwnerEpochMarker(dir, "vm1", 3); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	// Something else in the directory: the marker itself removes cleanly, the
	// directory cannot. That is the benign half.
	if err := os.WriteFile(filepath.Join(dir, "vms", "vm1", "other"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := RemoveVMOwnerEpochMarker(dir, "vm1"); err != nil {
		t.Fatalf("a leftover directory was reported as a failure to remove the marker: %v — "+
			"the marker IS gone, and reporting it as still present sends an operator after "+
			"a wedge that does not exist", err)
	}
	if _, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); ok {
		t.Fatal("the marker is still readable")
	}
}

// The dangerous half must still be reported: a marker that is genuinely still on
// disk wedges the next VM to reuse the name.
func TestRemoveVMOwnerEpochMarker_AStuckMarkerIsReported(t *testing.T) {
	dir := t.TempDir()
	if err := WriteVMOwnerEpochMarker(dir, "vm1", 3); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	// Root ignores directory write permission, so the unlink below would succeed
	// and this test would report a false failure rather than a real one.
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the directory permission this test depends on")
	}
	vmDir := filepath.Join(dir, "vms", "vm1")
	// Read-only directory: the marker file cannot be unlinked.
	if err := os.Chmod(vmDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(vmDir, 0o700) })

	if err := RemoveVMOwnerEpochMarker(dir, "vm1"); err == nil {
		t.Fatal("a marker that is still on disk was reported as removed; the next VM to " +
			"take this name meets a generation above its own, which convergence never repairs")
	}
}
