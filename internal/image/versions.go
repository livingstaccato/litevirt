package image

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/diskmode"
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
//   - content is published as <name>@<sha256[:16]>.qcow2 — named by what it
//     is, so every host that holds the same content names it the same — and
//     the name is pointed at it with the symlink <name>.current. ImagePath,
//     which every new disk is created from, follows that pointer; disks
//     already built keep naming the file they were built on, which stays where
//     it is. A file an earlier build published as <name>.qcow2 stays too;
//   - each file's provenance is recorded beside it (<file>.sha256): its sha256
//     and when it was published here. A file an earlier build left is given
//     one when it is first seen (EnsureProvenance). The one write a file may
//     take after it is published is a heal: content byte-identical to its
//     recorded sha256, put back over a copy whose bytes no longer match it.
//
// '@' is not in the image-name charset (safename), so a version file never
// collides with another image's file.

// versionHexLen is how much of the sha256 a version file is named by.
const versionHexLen = 16

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
	if err != nil {
		return "", false
	}
	if !isVersionFile(name, t) {
		slog.Error("image: the current-version pointer names no version of the image; ignoring it", "image", name, "target", t)
		return "", false
	}
	p := filepath.Join(s.imageDir, t)
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
		slog.Error("image: the current version the pointer names is missing; new disks fall back to the image's first file",
			"image", name, "image_version_path", p)
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
	if !ok || (len(h) != versionHexLen) {
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

// pinPath is where a pin on a store file is recorded.
func pinPath(path string) string { return path + ".pinned" }

// Pin records that something outside the store needs path — a backup taken
// on an overlay of it, wherever its manifest went — so it is never removed
// (RemoveImageFile refuses it). A pin is permanent.
func (s *Store) Pin(path string) error {
	if !sameDir(filepath.Dir(path), s.imageDir) {
		return fmt.Errorf("%s is not in the image store", path)
	}
	if _, ok := ImageNameOfFile(path); !ok {
		return fmt.Errorf("%s is not an image file", path)
	}
	if Pinned(path) {
		return nil
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+randid.New()+".tmp")
	if err := os.WriteFile(tmp, nil, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, pinPath(path)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Pinned reports whether path is pinned. A pin that cannot be read counts as
// one: nothing is removed on a guess.
func Pinned(path string) bool {
	_, err := os.Lstat(pinPath(path))
	return !errors.Is(err, fs.ErrNotExist)
}

// identityPath is where a file's provenance is recorded.
func identityPath(path string) string { return path + ".sha256" }

// Provenance is what the store records about one of its files: its sha256
// and when it was published on this host.
type Provenance struct {
	SHA256      string    `json:"sha256"`
	PublishedAt time.Time `json:"published_at"`
	// RepublishedAt is the last time this same content was published again
	// under the image — a re-import or pull of identical bytes, which reuses
	// the file (Publish) — or zero. PublishedAt stays when the file was
	// written: a restore asks whether the file is unchanged since a backup,
	// and a republish changes nothing in it. A prune asks whether the file
	// belongs to an import since the image's delete, and reads both.
	RepublishedAt time.Time `json:"republished_at,omitempty"`
}

// RecordedProvenance is path's provenance record; ok is false when it has
// none (a file an earlier build published and nothing has seen since).
func RecordedProvenance(path string) (Provenance, bool) {
	b, err := os.ReadFile(identityPath(path))
	if err != nil {
		return Provenance{}, false
	}
	var p Provenance
	if json.Unmarshal(b, &p) != nil {
		return Provenance{}, false
	}
	if !validDigest(p.SHA256) {
		return Provenance{}, false
	}
	return p, true
}

// RecordedDigest is the sha256 (hex) recorded for path.
func RecordedDigest(path string) (string, bool) {
	p, ok := RecordedProvenance(path)
	return p.SHA256, ok
}

func validDigest(d string) bool {
	if len(d) != 64 {
		return false
	}
	_, err := hex.DecodeString(d)
	return err == nil && strings.ToLower(d) == d
}

// recordProvenance writes path's provenance beside it (temp + rename: the
// record is the store's own file, never a disk's).
func recordProvenance(path string, p Provenance) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+randid.New()+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, identityPath(path)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func recordDigest(path, digest string) error {
	return recordProvenance(path, Provenance{SHA256: digest, PublishedAt: time.Now().UTC()})
}

// recordRepublished stamps path's provenance with RepublishedAt now: digest
// was published again under the image and the file reused (review round 1,
// m-2). Its sha256 and PublishedAt stay.
func recordRepublished(path, digest string) error {
	p, ok := RecordedProvenance(path)
	if !ok || p.SHA256 != digest {
		return fmt.Errorf("%s has no provenance record of this content", path)
	}
	p.RepublishedAt = time.Now().UTC()
	return recordProvenance(path, p)
}

// EnsureProvenance gives a store file an earlier build published — one with
// no record — its provenance: its sha256 now, and publishedAt, the latest
// time anything is known to have written it here. A file that has a record
// keeps it. It returns the file's provenance.
func (s *Store) EnsureProvenance(path string, publishedAt time.Time) (Provenance, error) {
	if p, ok := RecordedProvenance(path); ok {
		return p, nil
	}
	if !sameDir(filepath.Dir(path), s.imageDir) {
		return Provenance{}, fmt.Errorf("%s is not in the image store", path)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return Provenance{}, err
	}
	if !fi.Mode().IsRegular() {
		return Provenance{}, fmt.Errorf("%s is not a regular file", path)
	}
	d, err := FileDigest(path)
	if err != nil {
		return Provenance{}, err
	}
	if mt := fi.ModTime().UTC(); mt.After(publishedAt) {
		publishedAt = mt
	}
	p := Provenance{SHA256: d, PublishedAt: publishedAt.UTC()}
	if err := recordProvenance(path, p); err != nil {
		return Provenance{}, err
	}
	return p, nil
}

// StoreFiles is every image file in the store, with the image it belongs to.
// A store whose directory cannot be listed reads as empty: a caller that
// decides anything from what is NOT listed uses ListStoreFiles.
func (s *Store) StoreFiles() map[string]string {
	out, _ := s.ListStoreFiles(os.ReadDir)
	return out
}

// ListStoreFiles is StoreFiles, listing the directory with readDir, and
// reporting a listing that failed (an empty map with the error). A store
// directory that does not exist yet holds no files: that is no error.
func (s *Store) ListStoreFiles(readDir func(string) ([]os.DirEntry, error)) (map[string]string, error) {
	out := map[string]string{}
	ents, err := readDir(s.imageDir)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		p := filepath.Join(s.imageDir, e.Name())
		if name, ok := ImageNameOfFile(p); ok {
			out[p] = name
		}
	}
	return out, nil
}

// ImageDir is the store's image directory.
func (s *Store) ImageDir() string { return s.imageDir }

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
	// Prev is the image's current file as this publish read it, under the
	// name's lock ("" when there was none): what Withdraw points the name
	// back to. It is Path when this publish made nothing current.
	Prev string
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
//   - the current file's recorded identity is digest: nothing more changes;
//   - otherwise tmp is published as the version <name>@<digest[:16]>.qcow2
//     (no-replace) and the name pointed at it — the image's first content
//     too, so that every host names the same content the same.
//
// tmp is consumed (moved, or removed) on success.
func (s *Store) Publish(name, tmp, digest string) (Published, error) {
	pub, _, err := s.publish(name, tmp, digest, false)
	return pub, err
}

// PublishWithdrawable is Publish for an operation that may yet find its
// content stale and Withdraw it: until release is called, RemoveImageFile
// refuses the file it would withdraw to (Published.Prev). release is never
// nil, and is called once the operation has withdrawn or kept its file.
func (s *Store) PublishWithdrawable(name, tmp, digest string) (pub Published, release func(), err error) {
	return s.publish(name, tmp, digest, true)
}

func (s *Store) publish(name, tmp, digest string, withdrawable bool) (Published, func(), error) {
	nop := func() {}
	if err := safename.ValidateImageName(name); err != nil {
		return Published{}, nop, err
	}
	if !validDigest(digest) {
		return Published{}, nop, fmt.Errorf("publish image %q: digest %q is not a sha256", name, digest)
	}
	if filepath.Dir(tmp) != filepath.Clean(s.imageDir) {
		return Published{}, nop, fmt.Errorf("publish image %q: %s is not in the image directory", name, tmp)
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
			return Published{}, nop, fmt.Errorf("heal %s: %w", f, err)
		}
		healed = append(healed, f)
	}

	// From reading the current file to re-pointing the name, one step
	// against a Withdraw of the name (lockName).
	defer s.lockName(name)()
	cur := s.ImagePath(name)
	if _, err := os.Lstat(cur); errors.Is(err, fs.ErrNotExist) {
		cur = "" // the image's first content: nothing is superseded
	} else if err != nil {
		return Published{}, nop, err
	}

	if rec, ok := RecordedDigest(cur); cur != "" && ok && rec == digest {
		_ = os.Remove(tmp)
		if err := recordRepublished(cur, digest); err != nil {
			return Published{}, nop, fmt.Errorf("record the republish of %s: %w", cur, err)
		}
		return Published{Path: cur, Prev: cur, Healed: healed, Digest: digest}, nop, nil
	}

	ver := filepath.Join(s.imageDir, name+"@"+digest[:versionHexLen]+".qcow2")
	if err := linkNoReplace(tmp, ver); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return Published{}, nop, err
		}
		// That version is already published: reuse it only if it is this
		// content by its record.
		if rec, ok := RecordedDigest(ver); !ok || rec != digest {
			return Published{}, nop, fmt.Errorf("image %q: %s exists and is not this content; refusing", name, ver)
		}
		_ = os.Remove(tmp)
		if err := recordRepublished(ver, digest); err != nil {
			return Published{}, nop, fmt.Errorf("record the republish of %s: %w", ver, err)
		}
	} else if err := recordDigest(ver, digest); err != nil {
		return Published{}, nop, fmt.Errorf("record identity of %s: %w", ver, err)
	}
	if err := s.setCurrent(name, filepath.Base(ver)); err != nil {
		return Published{}, nop, err
	}
	prev := cur
	if cur == ver {
		cur = ""
	}
	release := nop
	if withdrawable && prev != "" && prev != ver {
		// Registered under the name's lock, before any RemoveImageFile of
		// the name can look.
		release = s.names.addPending(name, prev)
	}
	return Published{Path: ver, Superseded: cur, Prev: prev, Healed: healed, Digest: digest}, release, nil
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
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, diskmode.File)
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

// Withdraw takes path, a file of image name that Publish has just made its
// current file, back from being current: an image operation that published it
// found it is not the content the image's record names (grpcapi
// staleImageCopyError). The name points again at prev — the publish's
// Published.Prev, the file current as it read it under the name's lock — a
// version, or the image's first file (prev that file, or "" when there was
// none: the pointer is removed). The file itself stays,
// as a superseded version, for the prune to remove once no disk is built on
// it. When path is no longer the current file (another publish since), nothing
// changes.
func (s *Store) Withdraw(name, path, prev string) error {
	if prev == path {
		return nil // Publish made nothing current: the content was already
	}
	// The check that path is still current and the re-point are one step
	// against a Publish of the name (lockName), which a re-point here would
	// otherwise revert.
	defer s.lockName(name)()
	if cur, ok := s.currentVersion(name); !ok || cur != path {
		return nil
	}
	if hook := s.testHooks.withdrawChecked; hook != nil {
		hook()
	}
	if prev != "" && isVersionFile(name, filepath.Base(prev)) && filepath.Dir(prev) == filepath.Clean(s.imageDir) {
		if fi, err := os.Lstat(prev); err == nil && fi.Mode().IsRegular() {
			return s.setCurrent(name, filepath.Base(prev))
		}
	}
	if err := os.Remove(s.pointerPath(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("withdraw image %q's current version %s: %w", name, path, err)
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
// record. The current file is never removed here, nor a file a withdrawal may
// point the name back at (PublishWithdrawable).
func (s *Store) RemoveImageFile(name, path string) error {
	if !IsImageFile(s.imageDir, name, path) {
		return fmt.Errorf("%s is not a file of image %q", path, name)
	}
	// The checks and the removal are one step against a Publish or Withdraw
	// of the name (lockName).
	defer s.lockName(name)()
	if path == s.ImagePath(name) {
		return fmt.Errorf("%s is image %q's current file", path, name)
	}
	if s.names.isPending(name, path) {
		return fmt.Errorf("%s is the file image %q may be withdrawn to (a copy in flight)", path, name)
	}
	if Pinned(path) {
		return fmt.Errorf("%s is pinned: a backup was taken on it", path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	_ = os.Remove(identityPath(path))
	return nil
}

// RemoveDeletedImageFile removes one file of image name — a deleted image,
// so its current file too — and its identity record. A pinned file is never
// removed. When it is the file the name's pointer names, the pointer goes
// first, so no new disk is created on it from here on.
func (s *Store) RemoveDeletedImageFile(name, path string) error {
	if !IsImageFile(s.imageDir, name, path) {
		return fmt.Errorf("%s is not a file of image %q", path, name)
	}
	if Pinned(path) {
		return fmt.Errorf("%s is pinned: a backup was taken on it", path)
	}
	if cur, ok := s.currentVersion(name); ok && cur == path {
		if err := os.Remove(s.pointerPath(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove image %q's current-version pointer: %w", name, err)
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	_ = os.Remove(identityPath(path))
	// A pointer left naming a file that is gone names nothing.
	if t, err := os.Readlink(s.pointerPath(name)); err == nil {
		if _, err := os.Lstat(filepath.Join(s.imageDir, t)); errors.Is(err, fs.ErrNotExist) {
			_ = os.Remove(s.pointerPath(name))
		}
	}
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

// sameDir compares two directories resolved through symlinks.
func sameDir(a, b string) bool {
	ra, err := filepath.EvalSymlinks(a)
	if err != nil {
		ra = filepath.Clean(a)
	}
	rb, err := filepath.EvalSymlinks(b)
	if err != nil {
		rb = filepath.Clean(b)
	}
	return ra == rb
}
