package cloudinit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isoWriteSteps checks that steps is one durable write of the seed at iso:
// its temp file synced, renamed onto iso, then iso's directory synced.
func isoWriteSteps(t *testing.T, steps []string, iso string) {
	t.Helper()
	dir := filepath.Dir(iso)
	tmpPrefix := "sync " + filepath.Join(dir, "."+filepath.Base(iso)+".")
	if len(steps) != 3 || !strings.HasPrefix(steps[0], tmpPrefix) || !strings.HasSuffix(steps[0], ".tmp") ||
		steps[1] != "rename "+iso || steps[2] != "syncdir "+dir {
		t.Fatalf("seed write steps = %q; want [sync <temp of %s>, rename %s, syncdir %s]", steps, iso, iso, dir)
	}
}

// A seed is written durably, as its stamp is (TestStampSeed_IsDurable): the
// image's bytes are synced before the rename makes it the seed, and the
// directory after it. Without, a power cut can leave an empty or truncated
// seed beside a stamp that survived (abort round 3, concern 1).
//
// Mutations: drop the file sync, the directory sync, or sync after the
// rename — red.
func TestGenerateISO_IsDurable(t *testing.T) {
	UseGoISOWithoutGenisoimage(t)
	dir := t.TempDir()
	iso := filepath.Join(dir, "vm.iso")
	steps := ObserveSeedWrites(t, dir)
	if err := GenerateISO(Config{InstanceID: "vm", LocalHostname: "vm", UserData: "#cloud-config\n"}, iso); err != nil {
		t.Fatal(err)
	}
	isoWriteSteps(t, steps(), iso)
	if s, err := ReadSeed(iso); err != nil || s.InstanceID() != "vm" {
		t.Fatalf("ReadSeed = %+v, %v", s, err)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, ".*.tmp")); len(m) != 0 {
		t.Errorf("temp files left: %v", m)
	}
}

// A rebuild writes the seed the same way.
func TestRebuildISO_IsDurable(t *testing.T) {
	UseGoISOWithoutGenisoimage(t)
	dir := t.TempDir()
	iso := filepath.Join(dir, "vm.iso")
	if err := GenerateISO(Config{InstanceID: "vm", LocalHostname: "vm"}, iso); err != nil {
		t.Fatal(err)
	}
	steps := ObserveSeedWrites(t, dir)
	changed, err := RebuildISO(iso, "version: 2\n", "")
	if err != nil || !changed {
		t.Fatalf("RebuildISO = %v, %v; want a rewrite", changed, err)
	}
	isoWriteSteps(t, steps(), iso)
}

// A seed whose bytes cannot be synced is not placed: nothing at its path, no
// temp left.
func TestGenerateISO_ASyncFailureLeavesNoSeed(t *testing.T) {
	UseGoISOWithoutGenisoimage(t)
	prev := fileSync
	fileSync = func(*os.File) error { return errors.New("EIO") }
	t.Cleanup(func() { fileSync = prev })
	dir := t.TempDir()
	iso := filepath.Join(dir, "vm.iso")
	if err := GenerateISO(Config{InstanceID: "vm", LocalHostname: "vm"}, iso); err == nil || !strings.Contains(err.Error(), "EIO") {
		t.Fatalf("GenerateISO = %v; want the sync's error", err)
	}
	if _, err := os.Lstat(iso); !os.IsNotExist(err) {
		t.Errorf("a seed is at %s after a failed sync: %v", iso, err)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, ".*.tmp")); len(m) != 0 {
		t.Errorf("temp files left: %v", m)
	}
}
