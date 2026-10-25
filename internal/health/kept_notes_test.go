package health

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// KeptNotes lists each note with its files and the ones under a kept disk,
// and fails on a note that cannot be read rather than skipping it: a release
// that skipped it would not know what that note keeps. ForgetKeptNoted drops
// the released files and the note once it names nothing.
//
// Mutation: skip a note that cannot be read in KeptNotes: red.
func TestKeptNotes_ListsAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := NoteKeptDisks(dir, "old", []string{"/d/old-root.s1"}); err != nil {
		t.Fatal(err)
	}
	if err := NoteKeptBackingFiles(dir, "old", []string{"/d/old-root.qcow2"}); err != nil {
		t.Fatal(err)
	}
	notes, err := KeptNotes(dir)
	if err != nil || len(notes) != 1 || notes[0].VM != "old" ||
		!slices.Equal(notes[0].Paths, []string{"/d/old-root.s1", "/d/old-root.qcow2"}) ||
		!slices.Equal(notes[0].Under, []string{"/d/old-root.qcow2"}) || notes[0].ModTime.IsZero() {
		t.Fatalf("KeptNotes = %+v, %v; want old's note with both files, the base under", notes, err)
	}

	bad := filepath.Join(dir, "kept-disks", "zz.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var ne *KeptDisksNoteError
	if _, err := KeptNotes(dir); !errors.As(err, &ne) || ne.File != bad {
		t.Fatalf("KeptNotes with %s unreadable = %v; want a KeptDisksNoteError naming it", bad, err)
	}
	if err := os.Remove(bad); err != nil {
		t.Fatal(err)
	}

	if err := ForgetKeptNoted(dir, "old", []string{"/d/old-root.s1", "/d/old-root.qcow2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "kept-disks", "old.json")); !os.IsNotExist(err) {
		t.Errorf("old's note is still there once it names nothing (%v)", err)
	}
}

// A note whose last kept disk goes holds nothing more, though the note stays
// for its Recorded paths: a file noted Under that disk is no longer held,
// and a later release of another chain does not name it as kept for this
// VM. The recorded path is still scanned.
//
// Red before: KeptNotedFiles still mapped base to a. Mutation: drop the
// "len(n.Paths) == 0 -> n.Under = nil" in writeKeptDisks: red.
func TestKeptNote_UnderGoesWithTheLastKeptDisk(t *testing.T) {
	dir := t.TempDir()
	top, base, data := "/pool/a-root.qcow2", "/pool/base.qcow2", "/pool/a-data.qcow2"
	if err := writeKeptDisks(dir, "a", keptDisksNote{Paths: []string{top}, Under: []string{base}, Recorded: []string{data}}); err != nil {
		t.Fatal(err)
	}
	if err := forgetKeptDisks(dir, "a", []string{top}); err != nil {
		t.Fatal(err)
	}
	held, err := KeptNotedFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 0 {
		t.Fatalf("KeptNotedFiles = %v after a's last kept disk went; want nothing held", held)
	}
	scanned, err := KeptScanFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if scanned[data] != "a" {
		t.Fatalf("KeptScanFiles = %v; want the recorded %s still scanned for a", scanned, data)
	}
}
