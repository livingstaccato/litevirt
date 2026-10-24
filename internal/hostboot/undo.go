package hostboot

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// BootFiles is what the files a boot decision (BootState) changes held before
// it: the graceful-stop marker it consumes, the awaiting-serving note it
// leaves and the unclean-boot history it adds to. Undo puts back what that
// decision changed, for a decision whose write the caller then refuses (the
// daemon's own-row reconcile, whose boot report is made only over the state
// it expects): a refused write leaves no trace that it was a boot.
type BootFiles struct {
	marker, awaiting, history fileWas
}

// fileWas is a file's content before, or that it was not there; known=false
// when it could not be read, and it is then left alone.
type fileWas struct {
	path    string
	known   bool
	present bool
	data    []byte
}

func snapshotFile(path string) fileWas {
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		return fileWas{path: path, known: true, present: true, data: b}
	case errors.Is(err, fs.ErrNotExist):
		return fileWas{path: path, known: true}
	}
	return fileWas{path: path}
}

// SnapshotBootFiles records the boot files under dataDir before a decision.
func SnapshotBootFiles(dataDir string) BootFiles {
	if dataDir == "" {
		return BootFiles{}
	}
	return BootFiles{
		marker:   snapshotFile(MarkerPath(dataDir)),
		awaiting: snapshotFile(AwaitingPath(dataDir)),
		history:  snapshotFile(filepath.Join(dataDir, UncleanHistoryName)),
	}
}

// Undo reverts what a decision did to the files since the snapshot, and only
// that: a consumed marker is written back, a note the decision left is
// removed (one that was there before is kept, and one a daemon that serves
// removed since is not put back), and the history gets its content back.
func (b BootFiles) Undo() error {
	var errs []error
	if f := b.marker; f.known && f.present {
		if _, err := os.Lstat(f.path); errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, writeBack(f))
		}
	}
	if f := b.awaiting; f.known && !f.present {
		if err := os.Remove(f.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove %s: %w", f.path, err))
		}
	}
	if f := b.history; f.known {
		if !f.present {
			if err := os.Remove(f.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, fmt.Errorf("remove %s: %w", f.path, err))
			}
		} else if cur, err := os.ReadFile(f.path); err != nil || string(cur) != string(f.data) {
			errs = append(errs, writeBack(f))
		}
	}
	return errors.Join(errs...)
}

func writeBack(f fileWas) error {
	if err := os.WriteFile(f.path, f.data, 0o600); err != nil {
		return fmt.Errorf("restore %s: %w", f.path, err)
	}
	return nil
}
