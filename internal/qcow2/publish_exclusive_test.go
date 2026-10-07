package qcow2

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Create never replaces an existing file, and never touches a file that
// happens to sit at the old predictable temp name "<path>.tmp" — a planted
// symlink there, or another create's temp.
func TestCreate_ExclusiveAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a-b-root.qcow2")
	if err := os.WriteFile(path, []byte("project B's disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	planted := path + ".tmp"
	if err := os.WriteFile(planted, []byte("someone else's"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Create(path, 1<<20, nil); !errors.Is(err, fs.ErrExist) {
		t.Errorf("Create over an existing file: got %v, want fs.ErrExist", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "project B's disk" {
		t.Error("the existing file was replaced")
	}
	if got, _ := os.ReadFile(planted); string(got) != "someone else's" {
		t.Error("a file at <path>.tmp was removed or replaced")
	}

	fresh := filepath.Join(dir, "new.qcow2")
	if err := Create(fresh, 1<<20, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".new.qcow2.") {
			t.Errorf("a temp %q survived the publish (a second link to the image)", e.Name())
		}
	}
	fi, _ := os.Stat(fresh)
	if n := linkCount(fi); n != 1 {
		t.Errorf("published image has %d links, want 1", n)
	}
}
