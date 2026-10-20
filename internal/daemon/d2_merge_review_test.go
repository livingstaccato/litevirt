package daemon

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
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

// Controller ruling on the D2 merge follow-up: a live firmware move never
// targets a host whose vTPM state is not durable. The gate reads the last
// vtpm_state_sync pass (no walk): no pass yet, or vtpm_state_not_durable
// open, refuses with the condition and its remedy; a durable pass passes.
//
// Mutation: ignore the condition in vtpmDurableErr — the not-durable case
// passes, red.
func TestVTPMDurableErr(t *testing.T) {
	look := func(string) (string, error) { return "/usr/bin/x", nil }
	durable, _ := newTestVTPMSync(true, libvirt.SwtpmSyncReport{State: libvirt.SwtpmSyncOn, Base: "/srv/swtpm"})
	if err := durable.vtpmDurableErr(); err == nil || !strings.Contains(err.Error(), "no vtpm_state_sync pass") {
		t.Errorf("before any pass: %v, want refused", err)
	}
	tpmCapableProbe(look, durable.probe)()
	if err := durable.vtpmDurableErr(); err != nil {
		t.Errorf("after a durable pass: %v, want nil", err)
	}
	notDurable, _ := newTestVTPMSync(true, libvirt.SwtpmSyncReport{State: libvirt.SwtpmSyncRenameNotSynchronous, Base: "/srv/swtpm", FS: "xfs"})
	tpmCapableProbe(look, notDurable.probe)()
	err := notDurable.vtpmDurableErr()
	if err == nil || !strings.Contains(err.Error(), CondVTPMStateNotDurable) || !strings.Contains(err.Error(), "dirsync") {
		t.Errorf("not durable: %v, want refused naming %s and its remedy", err, CondVTPMStateNotDurable)
	}
}

// The ruling, at both gates: the fw-live label and a move's Prepare (the
// host check, read at move time) refuse a host whose vTPM state is not
// durable, naming the condition; with it durable both pass.
//
// Mutation: drop the durability check from fwLiveMigrateCheck — both pass,
// red.
func TestFwLive_RefusesANonDurableVTPMHost(t *testing.T) {
	notDurable := func() error {
		return errors.New("this host's vTPM state is not durable (" + CondVTPMStateNotDurable + ")")
	}
	in := okInputs()
	in.vtpmDurable = notDurable
	if fwLiveMigrateCapable(context.Background(), in) {
		t.Error("the label is capable on a host whose vTPM state is not durable")
	}
	h := okHost()
	h.vtpmDurable = notDurable
	if _, err := (fwLiveHostCheck{cfg: MigrationConfig{}, h: h}).Check(context.Background()); err == nil || !strings.Contains(err.Error(), CondVTPMStateNotDurable) {
		t.Errorf("Prepare's check = %v, want refused naming %s", err, CondVTPMStateNotDurable)
	}
	h.vtpmDurable = func() error { return nil }
	if _, err := (fwLiveHostCheck{cfg: MigrationConfig{}, h: h}).Check(context.Background()); err != nil {
		t.Errorf("Prepare's check with durable vTPM state = %v", err)
	}
}

// D2 merge follow-up nit: startNvramFlusher starts the flusher on
// nvramFlusherDirs, the host store's NVRAM directory.
//
// Mutation: start it on nvramDirs("") — the store's directory is not
// watched, red.
func TestStartNvramFlusher_WatchesTheStoresNvramDir(t *testing.T) {
	storeDir := t.TempDir()
	var got []string
	old := newNvramFlusher
	newNvramFlusher = func(dirs ...string) *libvirt.NvramFlusher { got = dirs; return libvirt.NewNvramFlusher(dirs...) }
	t.Cleanup(func() { newNvramFlusher = old })
	d := &Daemon{cfg: &Config{}, fwStore: &libvirt.FirmwareStore{DataDir: storeDir}}
	ctx, cancel := context.WithCancel(context.Background())
	_, stop := d.startNvramFlusher(ctx)
	cancel()
	stop()
	if want := filepath.Dir(libvirt.NvramPath(storeDir, "x")); !slices.Contains(got, want) {
		t.Errorf("the flusher watches %v, want %s", got, want)
	}
}

// The ruling's wiring: both the fw-live label and the Prepare host check in
// daemon.go are given the vTPM pass's durability gate.
//
// Mutation: pass nil for either — red.
func TestFwLive_DurabilityGateWiredInDaemon(t *testing.T) {
	b, err := os.ReadFile("daemon.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, want := range []string{
		"newFwLiveLabel(d.cfg.Migration, d.fwStore, firmwarePaths, d.virt.LibvirtVersion, tpmReady, vtpmSync.vtpmDurableErr)",
		"newFwLiveHostCheck(d.cfg.Migration, d.fwStore, firmwarePaths, d.virt.LibvirtVersion, tpmAvailable, vtpmSync.vtpmDurableErr)",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("daemon.go does not wire %s", want)
		}
	}
}
