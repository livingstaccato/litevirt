package pki

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// m2, the other half: once an unreadable superseded.pem can be read again,
// the running node merges it with what it learned meanwhile and writes the
// union back, so neither survives only in memory.
//
// Mutation: drop the persist after a late read in readFileLocked — the
// evidence learned meanwhile is gone after a restart.
func TestSupersession_ALateReadMergesAndSavesBoth(t *testing.T) {
	old := supersededRetryEvery
	supersededRetryEvery = 0
	t.Cleanup(func() { supersededRetryEvery = old })
	dir := setupPKI(t)
	ca, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	obs := observerPKI(t, dir, "obs-host")
	prev, _, err := RenewLocal(ca, caKey, dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	succ, _ := ServedHostCertificate(dir)
	NoteSuccessor(obs, succ)
	path := filepath.Join(obs, supersededFile)
	good, _ := os.ReadFile(path)
	forgetSupersessionsForTests(obs)
	if err := os.WriteFile(path, append(append([]byte(nil), good...), bytes.Repeat([]byte{'\n'}, 17<<20)...), 0o644); err != nil {
		t.Fatal(err)
	}
	other := observerPKI(t, dir, "other-host")
	oprev, _, err := RenewLocal(ca, caKey, other, "other-host")
	if err != nil {
		t.Fatal(err)
	}
	osucc, _ := ServedHostCertificate(other)
	NoteSuccessor(obs, osucc)
	if err := os.WriteFile(path, good, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := SupersededBy(obs, "test-host", prev); !ok { // the late read
		t.Fatal("the record was not read once it could be")
	}
	forgetSupersessionsForTests(obs)
	if _, ok := SupersededBy(obs, "other-host", oprev); !ok {
		t.Fatal("evidence learned while the record was unreadable was not saved once it could be read")
	}
	if _, ok := SupersededBy(obs, "test-host", prev); !ok {
		t.Fatal("the merge lost the record's own evidence")
	}
}
