package pooltrust

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// (re-review rr1 Nit 10) A deleted VM's disk is not evidence: the adoption
// reads only live VM rows.
//
// Mutation: drop `v.deleted_at IS NULL` from the adoption query — red.
func TestAdoptOnUpgrade_ADeletedVMsDiskIsNotEvidence(t *testing.T) {
	f, db := adoptFixture(t)
	ctx := context.Background()
	dir := filepath.Join(f.root, "p")
	disk := filepath.Join(dir, "vm1-root.qcow2")
	writeQcow2(t, disk)
	poolWithDisk(t, db, "h1", "p", dir, "vm1", disk)
	if err := db.Execute(ctx, `UPDATE vms SET deleted_at = ?, updated_at = ? WHERE name = 'vm1'`,
		time.Now().UTC().Format(time.RFC3339), db.NowTS()); err != nil {
		t.Fatal(err)
	}
	s := f.open(t)
	if _, err := s.AdoptOnUpgrade(ctx, db, "h1"); err != nil {
		t.Fatal(err)
	}
	if adopted(t, s, "p", dir) {
		t.Fatal("a deleted VM's disk got the row adopted")
	}
}

// (re-review rr1 N2) A ledger written before the adoption ran — the daemon
// recording its own pools, a create — does not stop the adoption: it runs
// until it has run once, and then never again.
//
// Mutation: count any ledger write as the adoption having run — red.
func TestAdoptOnUpgrade_RunsAfterAnEarlierLedgerWrite(t *testing.T) {
	f, db := adoptFixture(t)
	ctx := context.Background()
	dir := filepath.Join(f.root, "vmpool")
	disk := filepath.Join(dir, "vm1-root.qcow2")
	writeQcow2(t, disk)
	poolWithDisk(t, db, "h1", "vmpool", dir, "vm1", disk)
	s := f.open(t)
	if err := s.Record("isos", Binding{Driver: "dir", Target: filepath.Join(f.data, "pools", "isos")}, HowDaemon); err != nil {
		t.Fatal(err)
	}
	if s.Initialised() || f.open(t).Initialised() {
		t.Fatal("a ledger written before the adoption reads as adopted")
	}
	a, err := f.open(t).AdoptOnUpgrade(ctx, db, "h1")
	if err != nil || !a.Ran {
		t.Fatalf("the adoption did not run after an earlier ledger write: %+v %v", a, err)
	}
	s2 := f.open(t)
	if !adopted(t, s2, "vmpool", dir) || !s2.Initialised() {
		t.Fatalf("after the adoption: vmpool trusted=%t initialised=%t", adopted(t, s2, "vmpool", dir), s2.Initialised())
	}
	if _, ok := s2.Entry("isos"); !ok {
		t.Fatal("the adoption dropped the earlier entry")
	}
	if a, _ := s2.AdoptOnUpgrade(ctx, db, "h1"); a.Ran {
		t.Fatal("the adoption ran a second time")
	}
}

// (re-review rr1 Nit 8) The normalized binding keeps mount(8)'s reading: the
// operator's order, an exact repeat counted where it last takes effect, and a
// quoted value as one option.
//
// Mutations: keep the first of a repeat — "soft,hard,soft" binds as
// "soft,hard", red; split inside quotes — the repeated `y"` of two quoted
// values is dropped, red.
func TestNormalizeMountOptions_KeepsMountsReading(t *testing.T) {
	for in, want := range map[string]string{
		" vers=4.2 , hard ":             "vers=4.2,hard",
		"soft,hard,soft":                "hard,soft",
		"hard,soft,hard":                "soft,hard",
		"vers=3,nosuid,NOEXEC,vers=4.2": "vers=3,vers=4.2",
		`context="a,b",ro`:              `context="a,b",ro`,
		`context="x,y",fscontext="z,y"`: `context="x,y",fscontext="z,y"`,
	} {
		if got := NormalizeMountOptions(in); got != want {
			t.Errorf("NormalizeMountOptions(%q) = %q, want %q", in, got, want)
		}
	}
	if NormalizeMountOptions("soft,hard,soft") == NormalizeMountOptions("soft,hard") {
		t.Error("a repeat that changes the effective option binds equal to its absence")
	}
}
