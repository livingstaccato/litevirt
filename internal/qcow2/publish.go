package qcow2

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// publishNoReplace makes the finished temp image visible at path only if
// nothing is there. A hard link fails with EEXIST rather than replace a file
// (or a symlink, which it never follows), so a new image never lands over
// another VM's disk — "<vm>-<disk>.qcow2" is ambiguous across hyphens, and a
// pool can be shared by every project. The error wraps fs.ErrExist. A
// filesystem without hard links is a refusal, not a fallback to rename.
func publishNoReplace(tmpPath, path string) error {
	if err := os.Link(tmpPath, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s already exists; an image is never created over an existing file: %w", path, fs.ErrExist)
		}
		return fmt.Errorf("publish %s: %w", path, err)
	}
	_ = os.Remove(tmpPath)
	return nil
}

// incompatExternalData is the qcow2 incompatible-feature bit for an external
// data file: the image's clusters live in another file the header names.
const incompatExternalData = 1 << 2

// AssertStandalone refuses a qcow2 image that reads any other file: one with a
// backing file, or with an external data file. Use it on an image built from
// untrusted bytes before it is placed where a VM will open it.
func AssertStandalone(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h, err := readHeader(f)
	if err != nil {
		return err
	}
	if h.BackingFileOffset != 0 || h.BackingFileSize != 0 {
		return fmt.Errorf("%s names a backing file; it is not a standalone image", path)
	}
	if h.IncompatibleFeatures&incompatExternalData != 0 {
		return fmt.Errorf("%s uses an external data file; it is not a standalone image", path)
	}
	return nil
}
