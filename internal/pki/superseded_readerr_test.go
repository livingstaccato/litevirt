package pki

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// m2 (re-review 3): a superseded.pem this node cannot read is never written
// over. It held the proof that test-host's certificate was replaced; while it
// is unreadable (here: oversized) the node learns another host's renewal. The
// file must come back with the first proof in it — the new evidence is kept
// in memory meanwhile — and not be replaced by a file holding only what the
// node learned since.
//
// Mutation: let persistLocked write while the file has not been read — the
// first proof is gone after a restart.
func TestSupersession_AnUnreadableRecordIsNeverWrittenOver(t *testing.T) {
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
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Restart with the record unreadable.
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
	if _, ok := SupersededBy(obs, "other-host", oprev); !ok {
		t.Fatal("evidence learned while the record was unreadable was not kept in memory")
	}

	// The record becomes readable again (the operator fixed it), and the node
	// restarts: the first proof is still there.
	forgetSupersessionsForTests(obs)
	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.TrimRight(cur, "\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := SupersededBy(obs, "test-host", prev); !ok {
		t.Fatal("an unreadable superseded.pem was written over, and the proof it held was lost")
	}
}
