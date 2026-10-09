package lxc

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/safename"
)

// exportUnprivileged makes an unprivileged container's archive on a source
// runner, as a backup or migrate carries it.
func exportUnprivileged(t *testing.T, base int64) *bytes.Buffer {
	t.Helper()
	r, _ := secRunner(t)
	tpl := mkRootfs(t, filepath.Join(t.TempDir(), "tpl"))
	if _, err := r.Create(context.Background(), CreateOpts{Name: "c1", Template: tpl, Confinement: ConfinementDefault, IDMap: &IDMap{Base: base, Size: IDMapSize}}); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := r.ExportContainer(context.Background(), "c1", &b); err != nil {
		t.Fatal(err)
	}
	return &b
}

// A fresh target host (it has never created or converted an unprivileged
// container) that hands out subordinate ranges gets root's range for a
// restored or migrated container at import, and again at start.
func TestImport_EnsuresRootSubIDsOnAFreshTarget(t *testing.T) {
	archive := exportUnprivileged(t, 1_000_131_072)
	defer subidFixture(t)()
	dst := &LxcRunner{Lxcpath: filepath.Join(t.TempDir(), "dst"), IDMappedRootfs: "off"}
	if err := dst.ImportContainer(context.Background(), "c1", archive); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{subUIDPath, subGIDPath} {
		b, _ := os.ReadFile(p)
		if !strings.Contains(string(b), "root:1000131072:65536") {
			t.Errorf("%s after import = %q, want root's range", p, b)
		}
	}
	// Start ensures it too (the file edited away by hand since).
	_ = os.WriteFile(subUIDPath, nil, 0o644)
	subIDsMu.Lock()
	subIDsEnsured = map[int64]bool{}
	subIDsMu.Unlock()
	if err := dst.prepareStart("c1"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(subUIDPath); !strings.Contains(string(b), "root:1000131072:65536") {
		t.Errorf("subuid after start = %q", b)
	}
}

// A restore lays the archive down in a 0700 staging directory and moves it
// into place: the container's directory never exists with the archive's own
// (possibly 0755) mode while setuid binaries are in it.
func TestImport_ExtractsIntoAPrivateStagingDir(t *testing.T) {
	archive := exportUnprivileged(t, 1_000_000_000)
	dst := &LxcRunner{Lxcpath: filepath.Join(t.TempDir(), "dst"), IDMappedRootfs: "off"}
	defer subidFixture(t)()
	var sawDest string
	old := extractRootfs
	extractRootfs = func(r io.Reader, dest, top string) ([]string, error) {
		sawDest = dest
		if fi, err := os.Stat(dest); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("extracting into %s mode %v (%v), want 0700", dest, fi.Mode().Perm(), err)
		}
		if _, err := os.Stat(filepath.Join(dst.Lxcpath, "c1")); err == nil {
			t.Error("the container directory exists before the extraction finished")
		}
		return safename.ExtractRootfsTarReport(r, dest, top)
	}
	defer func() { extractRootfs = old }()
	if err := dst.ImportContainer(context.Background(), "c1", archive); err != nil {
		t.Fatal(err)
	}
	if sawDest == "" || sawDest == dst.Lxcpath {
		t.Fatalf("extracted straight into %q", sawDest)
	}
	if _, err := os.Stat(sawDest); !os.IsNotExist(err) {
		t.Errorf("staging dir %s left behind", sawDest)
	}
	if fi, err := os.Stat(filepath.Join(dst.Lxcpath, "c1", "rootfs")); err != nil || !fi.IsDir() {
		t.Fatalf("not moved into place: %v", err)
	}
}
