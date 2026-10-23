package grpcapi

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// openPinnedDir walks below its root with no link followed, makes what is
// missing when asked, and holds the directory it reached: a name swapped for a
// link afterwards still leads a write to the held directory.
//
// Mutations: follow links in openBeneath - the link rows go red; skip the
// mkdirat - the create row goes red.
func TestOpenPinnedDir(t *testing.T) {
	for _, off := range []bool{false, true} {
		name := "openat2"
		if off {
			name = "fallback"
		}
		t.Run(name, func(t *testing.T) {
			openat2Disabled = off
			t.Cleanup(func() { openat2Disabled = false })
			root := t.TempDir()
			outside := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "a", "b"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "inroot")); err != nil {
				t.Fatal(err)
			}

			pd, err := openPinnedDir(root, "a/b", false)
			if err != nil {
				t.Fatalf("existing dir: %v", err)
			}
			// Swap a for a link elsewhere: the held directory is unchanged.
			if err := os.Rename(filepath.Join(root, "a"), filepath.Join(root, "a.judged")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(root, "a")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(pd.path("f"), []byte("x"), 0o600); err != nil {
				t.Fatalf("write through the held dir: %v", err)
			}
			pd.close()
			if _, err := os.Lstat(filepath.Join(root, "a.judged", "b", "f")); err != nil {
				t.Errorf("the file is not in the judged directory: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(outside, "b", "f")); err == nil {
				t.Errorf("the file went through the swapped link")
			}

			for _, rel := range []string{"link", "link/x", "inroot", "a/b"} { // a is a link now
				if pd, err := openPinnedDir(root, rel, true); !errors.Is(err, errBeneath) {
					pd.close()
					t.Errorf("openPinnedDir(%q) = %v, want errBeneath", rel, err)
				}
			}
			if _, err := openPinnedDir(root, "../x", false); !errors.Is(err, errBeneath) {
				t.Errorf("dotdot: %v, want errBeneath", err)
			}
			if _, err := openPinnedDir(root, "missing/x", false); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("missing without create: %v, want not-exist", err)
			}
			pd, err = openPinnedDir(root, "new/deep", true)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			pd.close()
			if fi, err := os.Stat(filepath.Join(root, "new", "deep")); err != nil || !fi.IsDir() {
				t.Errorf("the created directory is not there: %v", err)
			}
			if err := removeBeneath(root, root, filepath.Join(root, "new", "deep", "nothing")); err != nil {
				t.Errorf("removing an absent file: %v", err)
			}
		})
	}
}
