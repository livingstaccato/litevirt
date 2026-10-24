package health

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/safename"
)

// A host's note of the disks it holds of a deleted VM that its delete kept:
// <data_dir>/kept-disks/<vm>.json, a list of paths on this host.
//
// The delete writes it on the host that holds them (`lv rm --keep-disks`, a
// disk recorded delete_with_vm=false, and a disk the delete of a VM with no
// domain kept because a host did not answer), and a failover's old host writes it
// when its pass leaves such a disk at its path (deleted_vm_residue.go). A
// later create of the name on the host reads it before its debris sweep
// clears <vm>-*.qcow2, and moves a noted disk to <path>.kept-<time>
// (SetAsideBeforeCreate). It is the host's own and never replicated, so it
// outlasts the tombstone and the record a create elsewhere or the condition
// retention removes. Every file a kept-disks.json entry of the host names is
// in it too, apart (Recorded), for the scan of the host's disk files alone.

var keptDisksMu sync.Mutex

func keptDisksFile(dataDir, name string) (string, error) {
	if err := safename.ValidateVMName(name); err != nil {
		return "", err
	}
	return filepath.Join(dataDir, "kept-disks", name+".json"), nil
}

type keptDisksNote struct {
	Paths []string `json:"paths"`
	// Under: the noted files a kept disk backs on, below its top (a qcow2
	// backing chain over the VM's own <vm>-<disk>.qcow2). Each is in Paths
	// too, so a build that does not know Under still moves it to a .kept-
	// name rather than removing it. A create of the name refuses while one
	// is at its path (SetAsideBeforeCreate): moving it breaks the chain.
	Under []string `json:"under,omitempty"`
	// Recorded: the files a kept-disks.json entry of this host names
	// (grpcapi's recordKeptDisks: every disk a delete kept, a removal that
	// failed included), noted so that while kept-disks.json cannot be read,
	// even after a restart, the scan of the disk files on this host still
	// reads each one wherever it is (KeptScanFiles). Nothing holds or moves
	// a file for being here alone: a failed removal's retry still frees it.
	Recorded []string `json:"recorded,omitempty"`
}

// KeptDisksNoteError is a note of the disks deletes kept on this host that
// cannot be read: File is the note.
type KeptDisksNoteError struct {
	File string
	Err  error
}

func (e *KeptDisksNoteError) Error() string { return fmt.Sprintf("read %s: %v", e.File, e.Err) }
func (e *KeptDisksNoteError) Unwrap() error { return e.Err }

// keptDisksOf returns the paths noted for name here, each cleaned. A note
// that cannot be read or parsed is a *KeptDisksNoteError.
func keptDisksOf(dataDir, name string) ([]string, error) {
	n, err := keptNoteOf(dataDir, name)
	return n.Paths, err
}

// keptNoteOf is name's note here, every path cleaned; no note is an empty
// one. A note that cannot be read or parsed is a *KeptDisksNoteError.
func keptNoteOf(dataDir, name string) (keptDisksNote, error) {
	if dataDir == "" {
		return keptDisksNote{}, nil
	}
	f, err := keptDisksFile(dataDir, name)
	if err != nil {
		return keptDisksNote{}, err
	}
	b, err := os.ReadFile(f)
	if errors.Is(err, fs.ErrNotExist) {
		return keptDisksNote{}, nil
	}
	if err != nil {
		return keptDisksNote{}, &KeptDisksNoteError{File: f, Err: err}
	}
	var n keptDisksNote
	if err := json.Unmarshal(b, &n); err != nil {
		return keptDisksNote{}, &KeptDisksNoteError{File: f, Err: err}
	}
	for _, l := range [][]string{n.Paths, n.Under, n.Recorded} {
		for i, p := range l {
			l[i] = filepath.Clean(p)
		}
	}
	return n, nil
}

// NoteKeptDisks adds paths to name's note here.
func NoteKeptDisks(dataDir, name string, paths []string) error {
	return noteKept(dataDir, name, paths, false)
}

// NoteKeptBackingFiles adds files to name's note here as files a kept disk
// backs on (keptDisksNote.Under), and as kept disks.
func NoteKeptBackingFiles(dataDir, name string, files []string) error {
	return noteKept(dataDir, name, files, true)
}

func noteKept(dataDir, name string, paths []string, under bool) error {
	if dataDir == "" || len(paths) == 0 {
		return nil
	}
	keptDisksMu.Lock()
	defer keptDisksMu.Unlock()
	n, err := keptNoteOf(dataDir, name)
	if err != nil {
		return err
	}
	for _, p := range paths {
		p = filepath.Clean(p)
		if !slices.Contains(n.Paths, p) {
			n.Paths = append(n.Paths, p)
		}
		if under && !slices.Contains(n.Under, p) {
			n.Under = append(n.Under, p)
		}
	}
	return writeKeptDisks(dataDir, name, n)
}

// NoteKeptRecorded adds paths to name's note here as files a kept-disks.json
// entry names (keptDisksNote.Recorded).
func NoteKeptRecorded(dataDir, name string, paths []string) error {
	if dataDir == "" || len(paths) == 0 {
		return nil
	}
	keptDisksMu.Lock()
	defer keptDisksMu.Unlock()
	n, err := keptNoteOf(dataDir, name)
	if err != nil {
		return err
	}
	for _, p := range paths {
		if p = filepath.Clean(p); !slices.Contains(n.Recorded, p) {
			n.Recorded = append(n.Recorded, p)
		}
	}
	return writeKeptDisks(dataDir, name, n)
}

// ForgetKeptRecorded drops paths from name's note here as files a
// kept-disks.json entry names, and the note once it is empty.
func ForgetKeptRecorded(dataDir, name string, paths []string) error {
	if dataDir == "" || len(paths) == 0 {
		return nil
	}
	keptDisksMu.Lock()
	defer keptDisksMu.Unlock()
	n, err := keptNoteOf(dataDir, name)
	if err != nil || len(n.Recorded) == 0 {
		return err
	}
	n.Recorded = slices.DeleteFunc(n.Recorded, func(p string) bool {
		return slices.ContainsFunc(paths, func(q string) bool { return filepath.Clean(q) == p })
	})
	return writeKeptDisks(dataDir, name, n)
}

// forgetKeptDisks drops paths from name's note here, and the note once it is
// empty.
func forgetKeptDisks(dataDir, name string, paths []string) error {
	if dataDir == "" || len(paths) == 0 {
		return nil
	}
	keptDisksMu.Lock()
	defer keptDisksMu.Unlock()
	n, err := keptNoteOf(dataDir, name)
	if err != nil || len(n.Paths) == 0 && len(n.Recorded) == 0 {
		return err
	}
	gone := func(p string) bool {
		return slices.ContainsFunc(paths, func(q string) bool { return filepath.Clean(q) == p })
	}
	n.Paths = slices.DeleteFunc(n.Paths, gone)
	n.Under = slices.DeleteFunc(n.Under, gone)
	n.Recorded = slices.DeleteFunc(n.Recorded, gone)
	return writeKeptDisks(dataDir, name, n)
}

func writeKeptDisks(dataDir, name string, n keptDisksNote) error {
	f, err := keptDisksFile(dataDir, name)
	if err != nil {
		return err
	}
	if len(n.Paths) == 0 && len(n.Recorded) == 0 {
		if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	dir := filepath.Dir(f)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(n)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(f)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), f); err != nil {
		return err
	}
	return syncDir(dir)
}

// KeptNotedFiles is every file this host's kept-disk notes name, as a kept
// disk or as a file one backs on, cleaned, mapped to the deleted VM whose
// note names it. A note that cannot be read, or a directory of notes that
// cannot be listed, is an error: a caller about to remove a disk file then
// keeps it.
func KeptNotedFiles(dataDir string) (map[string]string, error) {
	return keptNoteFiles(dataDir, false)
}

// KeptScanFiles is KeptNotedFiles and every file a kept-disks.json entry of
// this host names (keptDisksNote.Recorded): every file a delete on this
// host kept, for a scan that cannot read kept-disks.json.
func KeptScanFiles(dataDir string) (map[string]string, error) {
	return keptNoteFiles(dataDir, true)
}

func keptNoteFiles(dataDir string, recorded bool) (map[string]string, error) {
	out := map[string]string{}
	if dataDir == "" {
		return out, nil
	}
	dir := filepath.Join(dataDir, "kept-disks")
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", dir, err)
	}
	keptDisksMu.Lock()
	defer keptDisksMu.Unlock()
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || e.IsDir() {
			continue
		}
		if safename.ValidateVMName(name) != nil {
			continue
		}
		n, err := keptNoteOf(dataDir, name)
		if err != nil {
			return nil, err
		}
		lists := [][]string{n.Paths, n.Under}
		if recorded {
			lists = append(lists, n.Recorded)
		}
		for _, l := range lists {
			for _, p := range l {
				out[p] = name
			}
		}
	}
	return out, nil
}

// KeptNote is one of this host's kept-disk notes.
type KeptNote struct {
	VM      string
	File    string   // the note, <data_dir>/kept-disks/<vm>.json
	Paths   []string // every file it names, cleaned
	Under   []string // of Paths, the files a kept disk backs on
	ModTime time.Time
}

// KeptNotes is every kept-disk note on this host, by VM name. A note that
// cannot be read or parsed (a *KeptDisksNoteError), or a directory of notes
// that cannot be listed, is an error: a release, which removes what a note
// names, then removes nothing. The notes that could be read are returned with
// it: a guard that must refuse on what any readable note names does not lose
// that to another note it cannot read (the first such error is returned).
func KeptNotes(dataDir string) ([]KeptNote, error) {
	if dataDir == "" {
		return nil, nil
	}
	dir := filepath.Join(dataDir, "kept-disks")
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", dir, err)
	}
	keptDisksMu.Lock()
	defer keptDisksMu.Unlock()
	var out []KeptNote
	var first error
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || e.IsDir() || safename.ValidateVMName(name) != nil {
			continue
		}
		n, err := keptNoteOf(dataDir, name)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		f := filepath.Join(dir, e.Name())
		var mod time.Time
		if fi, err := os.Stat(f); err == nil {
			mod = fi.ModTime()
		}
		out = append(out, KeptNote{VM: name, File: f, Paths: n.Paths, Under: n.Under, ModTime: mod})
	}
	return out, first
}

// ForgetKeptNoted drops paths from name's note here, and the note once it
// names nothing else: what an operator's release of a kept chain removed.
func ForgetKeptNoted(dataDir, name string, paths []string) error {
	return forgetKeptDisks(dataDir, name, paths)
}

// KeptBackingFileError is a create refused because a file a kept disk backs
// on is at a path it clears (SetAsideBeforeCreate). It stands until an
// operator moves the kept chain away: a retry on the host does not help.
type KeptBackingFileError struct{ msg string }

func (e *KeptBackingFileError) Error() string { return e.msg }

// NewKeptBackingFileError is a KeptBackingFileError saying msg: a create
// refused because a file it would clear is one a kept disk is, or backs on,
// by a record other than the note (grpcapi's create guard).
func NewKeptBackingFileError(msg string) *KeptBackingFileError {
	return &KeptBackingFileError{msg: msg}
}
