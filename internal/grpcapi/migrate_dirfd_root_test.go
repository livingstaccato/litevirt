package grpcapi

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The disk root itself is judged for what its descriptor names: a pool
// directory below a data-dir area that has been swapped for a link elsewhere is
// refused, an area root or an operator's own pool directory that is a link to
// another volume keeps working, and a link into the PKI directory is refused.
//
// Mutations: drop the check argument in openDiskDir - the swapped-pool-dir and
// the link-to-PKI rows go red; make the below-area branch return nil - the
// swapped-pool-dir row goes red.
func TestDiskRootCheck(t *testing.T) {
	data, pki, other, vol := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	s := &Server{hostName: "h", dataDir: data, pkiDir: pki}
	mk := func(p string) string {
		t.Helper()
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	link := func(target, at string) string {
		t.Helper()
		mk(filepath.Dir(at))
		if err := os.Symlink(target, at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	cases := []struct {
		name string
		root string
		ok   bool
	}{
		{"a real pool dir below mounts/", mk(filepath.Join(data, "mounts", "nfs1", "p")), true},
		{"a pool dir below mounts/ swapped for a link elsewhere", link(other, filepath.Join(data, "mounts", "nfs1", "q")), false},
		{"disks/ itself a link to another volume (the operator's)", link(vol, filepath.Join(data, "disks")), true},
		{"an operator pool dir outside the areas, a link to another volume", link(vol, filepath.Join(other, "oppool")), true},
		{"an operator pool dir outside the areas, a link to the PKI dir", link(pki, filepath.Join(other, "evilpool")), false},
	}
	for _, tc := range cases {
		pd, err := s.openDiskDir(tc.root, ".", false, false)
		if pd != nil {
			pd.close()
		}
		if (err == nil) != tc.ok {
			t.Errorf("%s: openDiskDir(%s) = %v, want ok=%v", tc.name, tc.root, err, tc.ok)
		}
		if !tc.ok && !errors.Is(err, errBeneath) {
			t.Errorf("%s: %v, want errBeneath", tc.name, err)
		}
	}
}

// Without /proc/self/fd a held directory cannot be named, so nothing is opened:
// a removal reports the failure and the file stays, never "already gone".
//
// Mutation: drop the os.Stat(pd.dir()) guard in openPinnedDirChecked - the open
// succeeds and the create-side checks in the receive would be the only guard;
// this goes red.
func TestNoProcFailsClosed(t *testing.T) {
	data := t.TempDir()
	s := &Server{hostName: "h", dataDir: data}
	dir := filepath.Join(data, "disks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "x.qcow2")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	procFDPrefix = "/nonexistent-proc/fd/"
	t.Cleanup(func() { procFDPrefix = "/proc/self/fd/" })
	if pd, err := s.openDiskDir(dir, ".", true, false); !errors.Is(err, errNoProcFD) {
		pd.close()
		t.Errorf("open without /proc = %v, want errNoProcFD", err)
	}
	if err := s.removeDiskFileBeneath(f, false); err == nil {
		t.Errorf("a removal without /proc reported success")
	}
	if _, err := os.Lstat(f); err != nil {
		t.Errorf("the file went: %v", err)
	}
}
