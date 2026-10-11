//go:build unix

package diskmode

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func umask022(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
}

func perm(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// MkdirAll makes new directories 0711 and leaves an existing one as it is.
//
// Mutations: MkdirAll with 0o755 — the new dir goes red; a chmod of the leaf
// after MkdirAll — the existing dir goes red.
func TestMkdirAll_NewIsSearchableOnlyExistingUntouched(t *testing.T) {
	umask022(t)
	root := t.TempDir()
	p := filepath.Join(root, "a", "b")
	if err := MkdirAll(p); err != nil {
		t.Fatal(err)
	}
	if got := perm(t, p); got != 0o711 {
		t.Errorf("new dir %04o, want 0711", got)
	}
	old := filepath.Join(root, "old")
	if err := os.Mkdir(old, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := MkdirAll(old); err != nil {
		t.Fatal(err)
	}
	if got := perm(t, old); got != 0o755 {
		t.Errorf("existing dir changed to %04o", got)
	}
}

// Create makes a new 0600 file and never opens an existing name or a symlink.
//
// Mutations: drop O_EXCL — the existing-file case goes red; drop O_NOFOLLOW
// with O_EXCL kept — still refused (O_EXCL refuses a symlink too), so the
// symlink case pins O_EXCL, not O_NOFOLLOW.
func TestCreate_NewOwnerOnlyNeverOverAName(t *testing.T) {
	umask022(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := Create(p); err != nil {
		t.Fatal(err)
	}
	if got := perm(t, p); got != 0o600 {
		t.Errorf("new file %04o, want 0600", got)
	}
	if err := Create(p); !errors.Is(err, fs.ErrExist) {
		t.Errorf("Create over an existing file: %v, want ErrExist", err)
	}
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := Create(link); err == nil {
		t.Error("Create through a symlink succeeded")
	}
}

// Narrow clears group and other bits, keeps the owner's, refuses a symlink and
// a non-regular file.
//
// Mutations: Narrow chmods to File regardless — the 0400 case goes red; Narrow
// follows a symlink — the victim goes red.
func TestNarrow_ClearsGroupAndOtherOnly(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ in, want os.FileMode }{{0o644, 0o600}, {0o664, 0o600}, {0o444, 0o400}, {0o600, 0o600}} {
		p := filepath.Join(dir, tc.in.String())
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, tc.in); err != nil {
			t.Fatal(err)
		}
		if err := Narrow(p); err != nil {
			t.Fatal(err)
		}
		if got := perm(t, p); got != tc.want {
			t.Errorf("Narrow(%04o) = %04o, want %04o", tc.in, got, tc.want)
		}
	}
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(victim, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := Narrow(link); err == nil {
		t.Error("Narrow through a symlink succeeded")
	}
	if got := perm(t, victim); got != 0o644 {
		t.Errorf("the symlink's target was changed to %04o", got)
	}
	if err := Narrow(dir); err == nil {
		t.Error("Narrow of a directory succeeded")
	}
}
