package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/systemdunit"
)

// TestEnsureSystemdUnits_InstalledAtStart (re-review I-6, m7): an upgrade
// writes the unit the RUNNING (old) binary carries, so a host upgraded from a
// build without the per-NIC table cleanup never gets it — and a rollback to
// that build would leave the stale table enforcing. The new binary installs
// the cleanup when it starts, where a unit is installed at all: as a drop-in,
// so the main unit — and whatever an operator changed in it — is left alone.
func TestEnsureSystemdUnits_InstalledAtStart(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "litevirt.service")
	dropin := filepath.Join(dir, "litevirt.service.d", "10-nic-table-cleanup.conf")
	old := "[Unit]\nDescription=litevirt (an older build's unit, locally edited)\n[Service]\nExecStart=/usr/local/bin/litevirt daemon\nEnvironment=LOCAL=1\n"
	if err := os.WriteFile(main, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	reloads := 0
	paths := systemdUnitPaths{main: main, dropin: dropin}
	ensureSystemdUnitsAt(paths, func() error { reloads++; return nil })
	if got, _ := os.ReadFile(main); string(got) != old {
		t.Errorf("the main unit was rewritten at start; local edits are lost:\n%s", got)
	}
	got, err := os.ReadFile(dropin)
	if err != nil || !strings.Contains(string(got), "ExecStartPre="+systemdunit.NICTableCleanup) || !strings.Contains(string(got), "[Service]") {
		t.Fatalf("no drop-in with the per-NIC table cleanup: %q, %v", got, err)
	}
	if reloads != 1 {
		t.Errorf("systemd reloaded %d times, want 1", reloads)
	}
	ensureSystemdUnitsAt(paths, func() error { reloads++; return nil })
	if reloads != 1 {
		t.Errorf("an unchanged drop-in was rewritten and reloaded (%d reloads)", reloads)
	}

	// A unit that has the step already (installed by this build) gets no
	// drop-in: the cleanup must not run twice.
	cur := filepath.Join(dir, "cur.service")
	curDrop := filepath.Join(dir, "cur.service.d", "10-nic-table-cleanup.conf")
	if err := os.WriteFile(cur, []byte(systemdunit.Main), 0o644); err != nil {
		t.Fatal(err)
	}
	ensureSystemdUnitsAt(systemdUnitPaths{main: cur, dropin: curDrop}, func() error { return nil })
	if _, err := os.Stat(curDrop); !os.IsNotExist(err) {
		t.Errorf("a drop-in was added to a unit that has the cleanup: %v", err)
	}

	// A host with no unit installed (not run by systemd) gets nothing.
	none := systemdUnitPaths{main: filepath.Join(dir, "absent.service"), dropin: filepath.Join(dir, "absent.service.d", "x.conf")}
	ensureSystemdUnitsAt(none, func() error { reloads++; return nil })
	if _, err := os.Stat(none.dropin); !os.IsNotExist(err) {
		t.Errorf("a drop-in was created on a host that has no unit: %v", err)
	}
}
