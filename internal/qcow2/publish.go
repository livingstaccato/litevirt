package qcow2

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/litevirt/litevirt/internal/randid"
)

// publishNoReplace makes the finished temp image visible at path only if
// nothing is there. A hard link fails with EEXIST rather than replace a file
// (or a symlink, which it never follows), so a new image never lands over
// another VM's disk — "<vm>-<disk>.qcow2" is ambiguous across hyphens, and a
// pool can be shared by every project. The error wraps fs.ErrExist. A
// filesystem without hard links is a refusal, not a fallback to rename.
//
// The temp's own name must then go. If it cannot be removed, the published
// name is withdrawn and the call fails: a surviving temp would be a second
// link to what becomes a live disk.
func publishNoReplace(tmpPath, path string) error {
	if err := os.Link(tmpPath, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s already exists; an image is never created over an existing file: %w", path, fs.ErrExist)
		}
		return fmt.Errorf("publish %s: %w", path, err)
	}
	if err := os.Remove(tmpPath); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("remove the temp's second link %s (the publish was withdrawn): %w", tmpPath, err)
	}
	return nil
}

// tempSibling is a fresh, unpredictable temp name beside path, not yet
// created: ".<base>.<random>.tmp". Two creates of one path never share a
// temp, and nothing can be planted at a name nobody can guess.
func tempSibling(path string) string {
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+randid.New()+".tmp")
}
