package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMigrationRotation_AbsentIsNil(t *testing.T) {
	r, err := loadMigrationRotation(t.TempDir())
	if err != nil || r != nil {
		t.Fatalf("r=%v err=%v; want nil, nil", r, err)
	}
	if MigrationRotationInProgress(t.TempDir()) {
		t.Fatal("no file, yet a rotation is in progress")
	}
}

// Mutation: drop markDone's append — the reloaded state forgets node-1.
func TestMigrationRotation_RoundTripsAndResumes(t *testing.T) {
	dir := t.TempDir()
	r := &migrationRotation{Phase: phaseTrustBoth, NewCAFingerprint: "ff"}
	r.markDone("node-1", phaseTrustBoth)
	if err := r.save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := loadMigrationRotation(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got.hostDone("node-1", phaseTrustBoth) || got.hostDone("node-2", phaseTrustBoth) {
		t.Fatalf("reloaded = %+v", got)
	}
	if !MigrationRotationInProgress(dir) {
		t.Fatal("a trust-both rotation is not reported in progress")
	}
	st, _ := os.Stat(filepath.Join(dir, rotationFileName))
	if st.Mode().Perm() != 0o600 {
		t.Errorf("state file mode %v; want 0600", st.Mode().Perm())
	}
}

func TestMigrationRotation_DoneIsNotInProgress(t *testing.T) {
	dir := t.TempDir()
	if err := (&migrationRotation{Phase: phaseDone}).save(dir); err != nil {
		t.Fatal(err)
	}
	if MigrationRotationInProgress(dir) {
		t.Fatal("a finished rotation is reported in progress")
	}
}

func TestMigrationRotation_Phases(t *testing.T) {
	if got := (&migrationRotation{}).phases(); !reflect.DeepEqual(got, []string{phaseTrustBoth, phaseReissue, phaseDropOld}) {
		t.Errorf("overlap phases = %v", got)
	}
	if got := (&migrationRotation{NoOverlap: true}).phases(); !reflect.DeepEqual(got, []string{phaseCutover}) {
		t.Errorf("no-overlap phases = %v", got)
	}
}
