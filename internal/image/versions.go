package image

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/safename"
)

// Image versions.
//
// An overlay disk holds only its delta over the base it was created on, and
// names that base by path. Writing new content over an image file therefore
// changes every disk built on it, silently. So a file in the store is never
// written over:
//
//   - an image's first content is <name>.qcow2;
//   - a refresh (a re-pull, a re-import) publishes its content as a new file,
//     <name>@<sha256[:12]>.qcow2, and points the name at it with the symlink
//     <name>.current. ImagePath, which every new disk is created from, follows
//     that pointer; disks already built keep naming the file they were built
//     on, which stays where it is;
//   - each published file's sha256 is recorded beside it (<file>.sha256), its
//     identity. The one write a file may take after it is published is a heal:
//     content byte-identical to that recorded identity, put back over a copy
//     whose bytes no longer match it.
//
// '@' is not in the image-name charset (safename), so a version file never
// collides with another image's file.

const versionHexLen = 12

// pointerPath is the symlink naming an image's current version.
func (s *Store) pointerPath(name string) string {
	return filepath.Join(s.imageDir, name+".current")
}

// CanonicalImagePath is the file an image's first content is published at.
func (s *Store) CanonicalImagePath(name string) string {
	return filepath.Join(s.imageDir, name+".qcow2")
}

// currentVersion is the version file the name's pointer names, when it is a
// valid version of name and a regular file.
func (s *Store) currentVersion(name string) (string, bool) {
	t, err := os.Readlink(s.pointerPath(name))
	if err != nil || !isVersionFile(name, t) {
		return "", false
	}
	p := filepath.Join(s.imageDir, t)
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
		return "", false
	}
	return p, true
}

// isVersionFile reports base as a published version file of name.
func isVersionFile(name, base string) bool {
	rest, ok := strings.CutPrefix(base, name+"@")
	if !ok {
		return false
	}
	h, ok := strings.CutSuffix(rest, ".qcow2")
	if !ok || len(h) != versionHexLen {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// IsImageFile reports whether path is one of image name's files in imageDir:
// its first content or a published version. Both sides are compared as given;
// callers pass them resolved.
func IsImageFile(imageDir, name, path string) bool {
	if filepath.Dir(path) != filepath.Clean(imageDir) {
		return false
	}
	b := filepath.Base(path)
	return b == name+".qcow2" || isVersionFile(name, b)
}

// ImageNameOfFile is the image name a store file belongs to: <name>.qcow2 or
// <name>@<hex>.qcow2.
func ImageNameOfFile(path string) (string, bool) {
	b := filepath.Base(path)
	if i := strings.IndexByte(b, '@'); i > 0 {
		name := b[:i]
		return name, isVersionFile(name, b)
	}
	name, ok := strings.CutSuffix(b, ".qcow2")
	return name, ok && safename.ValidateImageName(name) == nil
}

// identityPath is where a published file's sha256 is recorded.
func identityPath(path string) string { return path + ".sha256" }

// RecordedDigest is the sha256 (hex) recorded when path was published; ok is
// false for a file published before identities were recorded.
func RecordedDigest(path string) (string, bool) {
	b, err := os.ReadFile(identityPath(path))
	if err != nil {
		return "", false
	}
	d := strings.TrimSpace(string(b))
	if !validDigest(d) {
		return "", false
	}
	return d, true
}

func validDigest(d string) bool {
	if len(d) != 64 {
		return false
	}
	_, err := hex.DecodeString(d)
	return err == nil && strings.ToLower(d) == d
}

// recordDigest writes path's identity beside it (temp + rename: the record is
// the store's own file, never a disk's).
func recordDigest(path, digest string) error {
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+randid.New()+".tmp")
	if err := os.WriteFile(tmp, []byte(digest+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, identityPath(path)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// FileDigest hashes the file at path (sha256, hex).
func FileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Published says what Publish did.
type Published struct {
	// Path is the image's current file now.
	Path string
	// Superseded is the file that was current before, when this publish
	// made a new version current ("" otherwise). It is left where it is.
	Superseded string
	// Healed lists the files of the image whose bytes had stopped matching
	// their recorded identity — this content — and were put back from it.
	Healed []string
	// Digest is the published content's sha256 (hex).
	Digest string
}

// Publish makes tmp — a file in the image directory whose sha256 is digest —
// the current content of image name. It never writes over a file a disk may
// be built on, with one exception, the heal:
//
//   - every file of the image whose recorded identity is digest but whose
//     bytes no longer match it is healed: a copy of tmp is renamed over it
//     (the directory entry is replaced, nothing is followed), byte-identical
//     to the base every overlay on it was built on;
//   - no current file yet: tmp becomes <name>.qcow2 (no-replace);
//   - the current file's recorded identity is digest: nothing more changes;
//   - otherwise tmp is published as the version <name>@<digest[:12]>.qcow2
//     (no-replace) and the name pointed at it.
//
// tmp is consumed (moved, or removed) on success.
func (s *Store) Publish(name, tmp, digest string) (Published, error) {
	if err := safename.ValidateImageName(name); err != nil {
		return Published{}, err
	}
	if !validDigest(digest) {
		return Published{}, fmt.Errorf("publish image %q: digest %q is not a sha256", name, digest)
	}
	if filepath.Dir(tmp) != filepath.Clean(s.imageDir) {
		return Published{}, fmt.Errorf("publish image %q: %s is not in the image directory", name, tmp)
	}
	var healed []string
	for _, f := range s.ImageFiles(name) {
		rec, ok := RecordedDigest(f)
		if !ok || rec != digest {
			continue
		}
		if got, err := FileDigest(f); err == nil && got == digest {
			continue
		}
		if err := s.healWith(tmp, f); err != nil {
			return Published{}, fmt.Errorf("heal %s: %w", f, err)
		}
		healed = append(healed, f)
	}

	cur := s.ImagePath(name)
	if _, err := os.Lstat(cur); errors.Is(err, fs.ErrNotExist) {
		err := linkNoReplace(tmp, cur)
		if err == nil {
			if rerr := recordDigest(cur, digest); rerr != nil {
				return Published{}, fmt.Errorf("record identity of %s: %w", cur, rerr)
			}
			return Published{Path: cur, Healed: healed, Digest: digest}, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return Published{}, err
		}
		// Published by someone else in between: a refresh of that.
	} else if err != nil {
		return Published{}, err
	}

	if rec, ok := RecordedDigest(cur); ok && rec == digest {
		_ = os.Remove(tmp)
		return Published{Path: cur, Healed: healed, Digest: digest}, nil
	}

	ver := filepath.Join(s.imageDir, name+"@"+digest[:versionHexLen]+".qcow2")
	if err := linkNoReplace(tmp, ver); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return Published{}, err
		}
		// That version is already published: reuse it only if it is this
		// content by its record.
		if rec, ok := RecordedDigest(ver); !ok || rec != digest {
			return Published{}, fmt.Errorf("image %q: %s exists and is not this content; refusing", name, ver)
		}
		_ = os.Remove(tmp)
	} else if err := recordDigest(ver, digest); err != nil {
		return Published{}, fmt.Errorf("record identity of %s: %w", ver, err)
	}
	if err := s.setCurrent(name, filepath.Base(ver)); err != nil {
		return Published{}, err
	}
	return Published{Path: ver, Superseded: cur, Healed: healed, Digest: digest}, nil
}

// healWith puts a copy of src over the image file f, whose recorded identity
// src's content is: written to a fresh temp beside f, synced, then renamed
// over f. f must be a regular file; a rename replaces its directory entry and
// follows nothing.
func (s *Store) healWith(src, f string) error {
	fi, err := os.Lstat(f)
	if err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", f)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := filepath.Join(s.imageDir, "import-heal-"+randid.New()+".tmp")
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, f); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// setCurrent points name at the version file base: a new symlink renamed over
// the pointer (the pointer is the store's own, never a file a disk names).
func (s *Store) setCurrent(name, base string) error {
	tmp := filepath.Join(s.imageDir, "."+name+".current."+randid.New()+".tmp")
	if err := os.Symlink(base, tmp); err != nil {
		return fmt.Errorf("point image %q at %s: %w", name, base, err)
	}
	if err := os.Rename(tmp, s.pointerPath(name)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("point image %q at %s: %w", name, base, err)
	}
	return nil
}

// ImageFiles is every file of image name in the store: its first content and
// each published version.
func (s *Store) ImageFiles(name string) []string {
	var out []string
	if _, err := os.Lstat(s.CanonicalImagePath(name)); err == nil {
		out = append(out, s.CanonicalImagePath(name))
	}
	ents, err := os.ReadDir(s.imageDir)
	if err != nil {
		return out
	}
	for _, e := range ents {
		if isVersionFile(name, e.Name()) {
			out = append(out, filepath.Join(s.imageDir, e.Name()))
		}
	}
	return out
}

// RemoveImageFile removes one superseded file of image name and its identity
// record. The current file is never removed here.
func (s *Store) RemoveImageFile(name, path string) error {
	if !IsImageFile(s.imageDir, name, path) {
		return fmt.Errorf("%s is not a file of image %q", path, name)
	}
	if path == s.ImagePath(name) {
		return fmt.Errorf("%s is image %q's current file", path, name)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	_ = os.Remove(identityPath(path))
	return nil
}

// linkNoReplace makes tmp visible at path only if nothing is there (a hard
// link refuses an existing name), then drops tmp's own name.
func linkNoReplace(tmp, path string) error {
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s already exists: %w", path, fs.ErrExist)
		}
		return fmt.Errorf("publish %s: %w", path, err)
	}
	if err := os.Remove(tmp); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("remove the temp's second link %s (the publish was withdrawn): %w", tmp, err)
	}
	return nil
}
