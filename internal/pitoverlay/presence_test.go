package pitoverlay

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// C-1 of the pit-restore review: only a clean ENOENT of both the overlay and
// its binding is "absent"; any other stat error, or a binding left without
// its overlay, is "unknown" — never read as absence.
//
// Mutations "any error is absent" and "the binding is not looked at" — red.
func TestPresenceOf_OnlyENOENTOfBothIsAbsent(t *testing.T) {
	disk := filepath.Join(t.TempDir(), "d.qcow2")
	if err := os.WriteFile(disk, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	check := func(what string, want Presence) {
		t.Helper()
		if got, _ := PresenceOf(disk); got != want {
			t.Errorf("%s: PresenceOf = %v, want %v", what, got, want)
		}
	}
	check("nothing beside the disk", OverlayAbsent)

	if err := os.WriteFile(SidecarPath(disk), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	check("a binding with no overlay", OverlayUnknown)

	if err := os.WriteFile(Path(disk), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	check("overlay and binding", OverlayPresent)

	_ = os.Remove(Path(disk))
	_ = os.Remove(SidecarPath(disk))
	for _, e := range []error{syscall.EIO, syscall.ESTALE, syscall.EACCES} {
		restore := SetLstatForTest(func(p string) (os.FileInfo, error) {
			return nil, &os.PathError{Op: "lstat", Path: p, Err: e}
		})
		got, err := PresenceOf(disk)
		restore()
		if got != OverlayUnknown || !errors.Is(err, e) {
			t.Errorf("lstat %v: PresenceOf = %v, %v; want unknown, with the error", e, got, err)
		}
	}
}

// The set-aside evidence is an orphan of this disk's overlay, not its
// binding alone, nor another disk's.
//
// Mutation "no evidence ever" / "any file is evidence" — red.
func TestSetAsideEvidence(t *testing.T) {
	dir := t.TempDir()
	disk := filepath.Join(dir, "d.qcow2")
	if SetAsideEvidence(disk) {
		t.Fatal("evidence with nothing beside the disk")
	}
	other := filepath.Join(dir, "e.qcow2")
	if err := os.WriteFile(Path(other)+".orphan-20261011-161109", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(disk)+".orphan-20261011-161109.id", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if SetAsideEvidence(disk) {
		t.Fatal("another disk's orphan, or a lone binding, taken as evidence")
	}
	if err := os.WriteFile(Path(disk)+".orphan-20261011-161109", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !SetAsideEvidence(disk) {
		t.Fatal("this disk's set-aside overlay is not evidence")
	}
}
