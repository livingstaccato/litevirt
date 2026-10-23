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
