package pooltrust

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// (re-review rr2 3) An adoption whose ledger write fails, followed by a successful write
// (the daemon recording its own pool), must not mark the adoption as run.
//
// Mutation: keep initialised set when the adoption write fails — red.
func TestRR2Probe_AFailedAdoptionWriteIsNotRecordedByALaterWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores modes")
	}
	f, db := adoptFixture(t)
	ctx := context.Background()
	dir := filepath.Join(f.root, "p")
	disk := filepath.Join(dir, "vm1-root.qcow2")
	writeQcow2(t, disk)
	poolWithDisk(t, db, "h1", "p", dir, "vm1", disk)
	if err := os.MkdirAll(f.data, 0o755); err != nil {
		t.Fatal(err)
	}
	s := f.open(t)
	if err := os.Chmod(f.data, 0o555); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdoptOnUpgrade(ctx, db, "h1"); err == nil {
		t.Fatal("the adoption write did not fail")
	}
	if err := os.Chmod(f.data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.Ensure("isos", Binding{Driver: "dir", Target: filepath.Join(f.data, "pools", "isos")}, HowDaemon); err != nil {
		t.Fatal(err)
	}
	s2 := f.open(t)
	if s2.Initialised() {
		t.Fatal("a failed adoption was recorded as run by the next ledger write")
	}
	if _, err := s2.AdoptOnUpgrade(ctx, db, "h1"); err != nil {
		t.Fatal(err)
	}
	if !adopted(t, s2, "p", dir) {
		t.Fatal("not adopted on the retry")
	}
}
