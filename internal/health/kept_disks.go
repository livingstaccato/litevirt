package health

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/litevirt/litevirt/internal/safename"
)

// A host's note of the disks it holds of a deleted VM that its delete kept:
// <data_dir>/kept-disks/<vm>.json, a list of paths on this host.
//
// The delete writes it on the host that holds them (`lv rm --keep-disks`, and
// a disk recorded delete_with_vm=false), and a failover's old host writes it
// when its pass leaves such a disk at its path (deleted_vm_residue.go). A
// later create of the name on the host reads it before its debris sweep
// clears <vm>-*.qcow2, and moves a noted disk to <path>.kept-<time>
// (SetAsideBeforeCreate). It is the host's own and never replicated, so it
// outlasts the tombstone and the record a create elsewhere or the condition
// retention removes.

var keptDisksMu sync.Mutex

func keptDisksFile(dataDir, name string) (string, error) {
	if err := safename.ValidateVMName(name); err != nil {
		return "", err
	}
	return filepath.Join(dataDir, "kept-disks", name+".json"), nil
}

type keptDisksNote struct {
	Paths []string `json:"paths"`
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
	if dataDir == "" {
		return nil, nil
	}
	f, err := keptDisksFile(dataDir, name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(f)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, &KeptDisksNoteError{File: f, Err: err}
	}
	var n keptDisksNote
	if err := json.Unmarshal(b, &n); err != nil {
		return nil, &KeptDisksNoteError{File: f, Err: err}
	}
	for i, p := range n.Paths {
		n.Paths[i] = filepath.Clean(p)
	}
	return n.Paths, nil
}

// NoteKeptDisks adds paths to name's note here.
func NoteKeptDisks(dataDir, name string, paths []string) error {
	if dataDir == "" || len(paths) == 0 {
		return nil
	}
	keptDisksMu.Lock()
	defer keptDisksMu.Unlock()
	have, err := keptDisksOf(dataDir, name)
	if err != nil {
		return err
	}
	for _, p := range paths {
		if p = filepath.Clean(p); !slices.Contains(have, p) {
			have = append(have, p)
		}
	}
	return writeKeptDisks(dataDir, name, have)
}

// forgetKeptDisks drops paths from name's note here, and the note once it is
// empty.
func forgetKeptDisks(dataDir, name string, paths []string) error {
	if dataDir == "" || len(paths) == 0 {
		return nil
	}
	keptDisksMu.Lock()
	defer keptDisksMu.Unlock()
	have, err := keptDisksOf(dataDir, name)
	if err != nil || len(have) == 0 {
		return err
	}
	left := slices.DeleteFunc(have, func(p string) bool {
		return slices.ContainsFunc(paths, func(q string) bool { return filepath.Clean(q) == p })
	})
	return writeKeptDisks(dataDir, name, left)
}

func writeKeptDisks(dataDir, name string, paths []string) error {
	f, err := keptDisksFile(dataDir, name)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	dir := filepath.Dir(f)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(keptDisksNote{Paths: paths})
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
