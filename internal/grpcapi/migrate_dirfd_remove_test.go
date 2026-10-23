package grpcapi

import (
	"os"
	"path/filepath"
	"testing"
)

// The stub removals (EnsureDisks' undo and replace, the firmware discard) go
// through removeDiskFileBeneath: with the disk's directory swapped for a link
// to a directory holding a same-named file, that file survives.
//
// Mutation: os.Remove(p) in removeDiskFileBeneath - the victim goes and this is
// red. A path outside every disk root is refused.
func TestRemoveDiskFileBeneathDoesNotFollowASwappedDirectory(t *testing.T) {
	data, victimDir := t.TempDir(), t.TempDir()
	s := &Server{hostName: "h", dataDir: data}
	dir := filepath.Join(data, "disks", "sub")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(dir, "stub.qcow2")
	if err := os.WriteFile(stub, []byte("stub"), 0o600); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(victimDir, "stub.qcow2")
	if err := os.WriteFile(victim, []byte("victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Plain removal works.
	if err := s.removeDiskFileBeneath(stub, false); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Lstat(stub); !os.IsNotExist(err) {
		t.Errorf("the stub is still there: %v", err)
	}
	// Swap the directory for a link to the victim's directory.
	if err := os.Rename(dir, dir+".gone"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimDir, dir); err != nil {
		t.Fatal(err)
	}
	if err := s.removeDiskFileBeneath(stub, false); err == nil {
		t.Errorf("removal through a swapped link did not report it")
	}
	if _, err := os.Lstat(victim); err != nil {
		t.Errorf("the file behind the link was removed: %v", err)
	}
	if err := s.removeDiskFileBeneath(filepath.Join(victimDir, "stub.qcow2"), false); err == nil {
		t.Errorf("a path outside every disk root was removed")
	}
}
