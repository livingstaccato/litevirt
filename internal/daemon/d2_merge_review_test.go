package daemon

import (
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/libvirt"
)

// D2 merge review M-1: the NVRAM flusher watches the host store's NVRAM
// directory, and with no store (or a store without a data dir) the
// configured data dir's. Pointing it anywhere else is red.
//
// Mutation: drop the data dir from the store branch — the store's NVRAM
// directory is not watched, red.
func TestNvramFlusherDirs_TheHostStoresNvramDir(t *testing.T) {
	cfgDir, storeDir := t.TempDir(), t.TempDir()
	nvramOf := func(dataDir string) string { return filepath.Dir(libvirt.NvramPath(dataDir, "x")) }
	d := &Daemon{cfg: &Config{DataDir: cfgDir}, fwStore: &libvirt.FirmwareStore{DataDir: storeDir}}
	if dirs := d.nvramFlusherDirs(); !slices.Contains(dirs, nvramOf(storeDir)) || slices.Contains(dirs, nvramOf(cfgDir)) {
		t.Errorf("with a store: %v, want the store's %s and not %s", dirs, nvramOf(storeDir), nvramOf(cfgDir))
	}
	for name, d := range map[string]*Daemon{
		"no store":              {cfg: &Config{DataDir: cfgDir}},
		"store with no datadir": {cfg: &Config{DataDir: cfgDir}, fwStore: &libvirt.FirmwareStore{}},
	} {
		if dirs := d.nvramFlusherDirs(); !slices.Contains(dirs, nvramOf(cfgDir)) {
			t.Errorf("%s: %v, want the configured data dir's %s", name, dirs, nvramOf(cfgDir))
		}
	}
}

// D2 merge review M-2: the live firmware move label reads the vTPM label's
// result from the same cycle (the last completed pass) and never starts a
// pass of its own: one swtpm tree walk per label cycle.
//
// Mutation: make the fw-live check probe (start a pass) — a second walk per
// cycle, red.
func TestTPMReadyProbe_StartsNoPass(t *testing.T) {
	look := func(string) (string, error) { return "/usr/bin/x", nil }
	v, h := newTestVTPMSync(true, libvirt.SwtpmSyncReport{State: libvirt.SwtpmSyncOn})
	ready := tpmReadyProbe(look, v)
	if ready() {
		t.Fatal("ready before any pass completed")
	}
	if calls, _ := h.snapshot(); len(calls) != 0 {
		t.Fatalf("the fw-live check started %d pass(es) of its own", len(calls))
	}
	if !tpmCapableProbe(look, v.probe)() {
		t.Fatal("fixture: the vTPM label's pass did not complete")
	}
	for range 3 {
		if !ready() {
			t.Fatal("not ready after the vTPM label's pass completed")
		}
	}
	if calls, _ := h.snapshot(); len(calls) != 1 {
		t.Fatalf("%d passes for one vTPM label probe and three fw-live checks, want 1", len(calls))
	}
	missing := func(f string) (string, error) { return "", exec.ErrNotFound }
	if tpmReadyProbe(missing, v)() {
		t.Error("ready with swtpm missing")
	}
}
