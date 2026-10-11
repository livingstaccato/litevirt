//go:build unix

package image

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func umask022(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
}

func wantPerm(t *testing.T, p string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s is %04o, want %04o", p, got, want)
	}
}

// A new store's image and disk directories are searchable, not listable
// (0711), and the disks made in them are the owner's alone (0600). Pulled base
// images were already 0600 on main (a CreateTemp published by link), and every
// overlay on a lab node reads through one, so the file mode is the one qemu is
// proven to open after libvirt's label; the directory keeps the search bit
// libvirt never sets for it.
//
// Mutations: Init at 0755 — the directories go red; CreateEmptyDisk's MkdirAll
// at 0755 — the second store's disk dir goes red.
func TestStore_NewDirsAndDisksAreNotWorldReadable(t *testing.T) {
	umask022(t)
	s := NewStore(filepath.Join(t.TempDir(), "data"))
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	wantPerm(t, s.imageDir, 0o711)
	wantPerm(t, s.diskDir, 0o711)
	p, err := s.CreateEmptyDisk("vm", "root", "1M")
	if err != nil {
		t.Fatal(err)
	}
	wantPerm(t, p, 0o600)

	// A store whose disk dir does not exist yet (Init not run): the disk
	// create makes it.
	s2 := NewStore(filepath.Join(t.TempDir(), "data2"))
	if err := os.MkdirAll(s2.imageDir, 0o711); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.CreateEmptyDisk("vm", "root", "1M"); err != nil {
		t.Fatal(err)
	}
	wantPerm(t, s2.diskDir, 0o711)
}

// No backfill: Init leaves an existing directory's mode as it is.
//
// Mutation: chmod in Init — this goes red.
func TestStore_InitLeavesExistingDirsAlone(t *testing.T) {
	data := t.TempDir()
	for _, d := range []string{"images", "disks"} {
		if err := os.Mkdir(filepath.Join(data, d), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(data, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := NewStore(data).Init(); err != nil {
		t.Fatal(err)
	}
	wantPerm(t, filepath.Join(data, "images"), 0o755)
	wantPerm(t, filepath.Join(data, "disks"), 0o755)
}

// A healed base image is a new file (a copy renamed over the damaged one), so
// it gets the owner-only mode a pulled image has, never 0644.
//
// Mutation: the heal temp at 0o644 — this goes red.
func TestPublish_AHealedImageIsOwnerOnly(t *testing.T) {
	umask022(t)
	s := NewStore(t.TempDir())
	_ = s.Init()
	good := []byte("the base overlays were built on")
	p, err := s.Publish("img", stage(t, s, good), digestOf(good))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Path, []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if h, err := s.Publish("img", stage(t, s, good), digestOf(good)); err != nil || len(h.Healed) != 1 {
		t.Fatalf("heal: %+v %v", h, err)
	}
	wantPerm(t, p.Path, 0o600)
}
