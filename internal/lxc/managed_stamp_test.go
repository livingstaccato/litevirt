package lxc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagedStamp_LivesAndDiesWithTheContainerDir(t *testing.T) {
	root := t.TempDir()
	r := &LxcRunner{Lxcpath: root}

	// No directory: refused, and nothing is created.
	if err := r.StampManaged("ct1"); err == nil {
		t.Fatal("stamping a container with no directory must fail")
	}
	if _, err := os.Stat(filepath.Join(root, "ct1")); !os.IsNotExist(err) {
		t.Fatalf("a refused stamp created the container directory (stat err %v)", err)
	}

	if err := os.MkdirAll(filepath.Join(root, "ct1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if ok, err := r.IsManaged("ct1"); err != nil || ok {
		t.Fatalf("unstamped: (%v,%v), want (false,nil)", ok, err)
	}
	if err := r.StampManaged("ct1"); err != nil {
		t.Fatal(err)
	}
	if ok, err := r.IsManaged("ct1"); err != nil || !ok {
		t.Fatalf("stamped: (%v,%v), want (true,nil)", ok, err)
	}

	// lxc-destroy removes the directory; a hand-made container under the same
	// name starts unstamped.
	if err := os.RemoveAll(filepath.Join(root, "ct1")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "ct1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if ok, _ := r.IsManaged("ct1"); ok {
		t.Error("a recreated container directory inherited the stamp")
	}

	if _, err := r.IsManaged("../escape"); err == nil {
		t.Error("an unsafe name must be refused")
	}
}
