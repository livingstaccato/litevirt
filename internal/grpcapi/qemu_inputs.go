package grpcapi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/safename"
)

// maxBackingDepth bounds a pre-checked backing chain.
const maxBackingDepth = 16

// precheckQcow2Input is precheckChain with no raw backing allowed.
func precheckQcow2Input(path string, allowBacking func(resolved string) error) error {
	return precheckChain(path, allowBacking, "")
}

// precheckChain judges a qcow2 file's header before qemu-img opens it with
// -f qcow2, then each file of its backing chain the same way:
//   - no external data file: qemu opens that with the image itself, so a
//     conversion would copy whatever file the header names;
//   - at most one backing-format extension: this package reads the first,
//     qemu the last, and the two must not be able to disagree;
//   - a backing file only if allowBacking (nil: none) accepts its path
//     resolved through symlinks, a protocol-looking name never;
//   - a backing DECLARED qcow2 is judged in turn; one declared raw is
//     accepted only when it is exactly rawBacking (resolved) — the disk
//     record's own backing_disk, a --no-localize promotion's replica — and
//     ends the chain: raw is opened as raw (qemu honours the declared
//     format) and never interpreted. Any other declared format, or none,
//     is refused.
func precheckChain(path string, allowBacking func(resolved string) error, rawBacking string) error {
	for depth := 0; ; depth++ {
		if depth > maxBackingDepth {
			return fmt.Errorf("backing chain deeper than %d", maxBackingDepth)
		}
		if err := precheckQcow2Header(path); err != nil {
			return err
		}
		info, err := qcow2.Info(path)
		if err != nil {
			return fmt.Errorf("%s is not a qcow2 image: %w", path, err)
		}
		if info.BackingFile == "" {
			return nil
		}
		if allowBacking == nil {
			return fmt.Errorf("%s names backing file %q; a standalone image is required", path, info.BackingFile)
		}
		if looksLikeProtocol(info.BackingFile) {
			return fmt.Errorf("%s names backing %q, which is a protocol, not a file", path, info.BackingFile)
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
		switch info.BackingFormat {
		case "qcow2":
			path = resolved
		case "raw":
			if rawBacking == "" || resolved != rawBacking {
				return fmt.Errorf("%s names a raw backing %q that is not this disk's recorded backing", path, resolved)
			}
			if fi, err := os.Lstat(resolved); err != nil || !fi.Mode().IsRegular() {
				return fmt.Errorf("raw backing %q is not a regular file", resolved)
			}
			return nil
		default:
			return fmt.Errorf("%s names backing file %q with format %q; only a declared qcow2 or (this disk's own) raw backing is accepted",
				path, info.BackingFile, info.BackingFormat)
		}
	}
}

// looksLikeProtocol reports a backing name qemu would read as a protocol
// ("json:{...}", "nbd:...", "file:...") rather than a path: a ':' before
// the first '/'.
func looksLikeProtocol(name string) bool {
	c := strings.IndexByte(name, ':')
	sl := strings.IndexByte(name, '/')
	return c >= 0 && (sl < 0 || c < sl)
}

// confineTo accepts resolved only strictly inside one of roots (each
// resolved through symlinks when it exists).
func confineTo(resolved string, roots ...string) error {
	for _, r := range roots {
		if r == "" {
			continue
		}
		if rr, err := filepath.EvalSymlinks(r); err == nil {
			r = rr
		}
		if resolved != r && safename.Contains(r, resolved) {
			return nil
		}
	}
	return fmt.Errorf("backing %q is outside the image store and the disk's pool directory", resolved)
}

// diskRoots are the directories a VM disk's backing chain may live in: the
// image store and the disk's own pool directory (<data_dir>/disks for a
// pool-less disk). Both as this host names them and, under the test root, as
// the files are actually found.
func (s *Server) diskRoots(d corrosion.DiskRecord) []string {
	// The disk's own directory is its pool directory for a pool-less disk
	// (<data_dir>/disks) and for a pool disk alike; it comes from the record.
	roots := []string{filepath.Join(s.dataDir, "images"), filepath.Join(s.dataDir, "disks"), filepath.Dir(d.Path)}
	if d.StorageVolume != "" {
		if ref, ok := s.resolvePool(context.Background(), d.StorageVolume); ok {
			if dir, err := fileBasedPoolDir(s.dataDir, ref); err == nil {
				roots = append(roots, dir)
			}
		}
	}
	if s.hostDiskRoot != "" {
		for _, r := range roots[:len(roots):len(roots)] {
			roots = append(roots, s.hostDiskFile(r))
		}
	}
	return roots
}

// diskChainAllow confines a VM disk's backing chain to diskRoots.
func (s *Server) diskChainAllow(d corrosion.DiskRecord) func(string) error {
	roots := s.diskRoots(d)
	return func(resolved string) error { return confineTo(resolved, roots...) }
}

// diskRawBacking is the one raw backing a VM disk may have: its record's own
// backing_disk (a --no-localize promotion's replica), resolved; "" for none.
func (s *Server) diskRawBacking(d corrosion.DiskRecord) string {
	if d.BackingDisk == "" {
		return ""
	}
	r, err := filepath.EvalSymlinks(s.hostDiskFile(d.BackingDisk))
	if err != nil {
		return ""
	}
	return r
}

// precheckQcow2Header judges one qcow2 header without following its backing
// file: it parses as qcow2, keeps no data in an external file, and declares
// its backing format at most once.
func precheckQcow2Header(path string) error {
	if _, err := qcow2.Info(path); err != nil {
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
	return nil
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
