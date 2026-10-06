package grpcapi

import (
	"fmt"
	"path/filepath"

	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/safename"
)

// maxBackingDepth bounds a pre-checked backing chain.
const maxBackingDepth = 16

// precheckQcow2Input judges a qcow2 file's header before qemu-img opens it
// with -f qcow2, then each file of its backing chain the same way:
//   - no external data file: qemu opens that with the image itself, so a
//     conversion would copy whatever file the header names;
//   - at most one backing-format extension: this package reads the first,
//     qemu the last, and the two must not be able to disagree;
//   - a backing file only if allowBacking (nil: none) accepts its path
//     resolved through symlinks, and only declared as qcow2.
//
// It is the pre-check for every qemu-img input that is not a raw image: raw
// is never interpreted, and an image the daemon created still passes here.
func precheckQcow2Input(path string, allowBacking func(resolved string) error) error {
	for depth := 0; ; depth++ {
		if depth > maxBackingDepth {
			return fmt.Errorf("backing chain deeper than %d", maxBackingDepth)
		}
		info, err := qcow2.Info(path)
		if err != nil {
			return fmt.Errorf("%s is not a qcow2 image: %w", path, err)
		}
		if err := qcow2.AssertNoExternalData(path); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		n, err := qcow2.BackingFormatExtensionCount(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if n > 1 {
			return fmt.Errorf("%s declares its backing format %d times", path, n)
		}
		if info.BackingFile == "" {
			return nil
		}
		if allowBacking == nil {
			return fmt.Errorf("%s names backing file %q; a standalone image is required", path, info.BackingFile)
		}
		if info.BackingFormat != "qcow2" {
			return fmt.Errorf("%s names backing file %q with format %q; only a declared qcow2 backing is accepted", path, info.BackingFile, info.BackingFormat)
		}
		b := info.BackingFile
		if !filepath.IsAbs(b) {
			b = filepath.Join(filepath.Dir(path), b)
		}
		resolved, err := filepath.EvalSymlinks(b)
		if err != nil {
			return fmt.Errorf("%s: backing file %q: %w", path, info.BackingFile, err)
		}
		if err := allowBacking(resolved); err != nil {
			return err
		}
		path = resolved
	}
}

// imageStoreBaseOnly accepts a backing file only inside dataDir's image store
// (both sides resolved through symlinks), and only a base that is itself
// standalone — the image a VM was created from.
func imageStoreBaseOnly(dataDir string) func(string) error {
	return func(resolved string) error {
		images, err := filepath.EvalSymlinks(filepath.Join(dataDir, "images"))
		if err != nil {
			return fmt.Errorf("image store: %w", err)
		}
		if !safename.Contains(images, resolved) || resolved == images {
			return fmt.Errorf("backing file %q is not in the image store %s", resolved, images)
		}
		if err := qcow2.AssertStandalone(resolved); err != nil {
			return fmt.Errorf("image-store base %q: %w", resolved, err)
		}
		return nil
	}
}
