package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/systemdunit"
)

// TestEnsureSystemdUnits_InstalledAtStart (re-review I-6): an upgrade writes
// the unit the RUNNING (old) binary carries, so a host upgraded from a build
// without the per-NIC table cleanup never gets it — and a rollback to that
// build would leave the stale table enforcing. The new binary installs its
// own unit when it starts, where a unit is installed at all.
func TestEnsureSystemdUnits_InstalledAtStart(t *testing.T) {
	dir := t.TempDir()
	main, rollback := filepath.Join(dir, "litevirt.service"), filepath.Join(dir, "litevirt-rollback.service")
	old := "[Unit]\nDescription=litevirt (an older build's unit)\n[Service]\nExecStart=/usr/local/bin/litevirt daemon\n"
	if err := os.WriteFile(main, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	reloads := 0
	paths := systemdUnitPaths{main: main, rollback: rollback}
	ensureSystemdUnitsAt(paths, func() error { reloads++; return nil })
	got, err := os.ReadFile(main)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "ExecStartPre="+systemdunit.NICTableCleanup) {
		t.Fatalf("the unit installed at start carries no per-NIC table cleanup:\n%s", got)
	}
	if reloads != 1 {
		t.Errorf("systemd reloaded %d times, want 1", reloads)
	}
	ensureSystemdUnitsAt(paths, func() error { reloads++; return nil })
	if reloads != 1 {
		t.Errorf("an unchanged unit was rewritten and reloaded (%d reloads)", reloads)
	}

	// A host with no unit installed (not run by systemd) gets none.
	none := systemdUnitPaths{main: filepath.Join(dir, "absent.service"), rollback: filepath.Join(dir, "absent-rb.service")}
	ensureSystemdUnitsAt(none, func() error { reloads++; return nil })
	if _, err := os.Stat(none.main); !os.IsNotExist(err) {
		t.Errorf("a unit was created on a host that had none: %v", err)
	}
}
