package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/randid"
)

// Each live disk a promotion builds gets a file name no file has had:
// <target>-promoted-<replica stem>-<random>.qcow2. The name without the
// random part, which earlier builds used, is not one a promotion may write:
// a disk kept by `lv rm --keep-disks` after an earlier promotion from the same
// replica can name exactly that path as its missing backing base, and a new
// file there would become that kept overlay's base, which then silently reads
// the wrong data. Every other writer refuses a kept disk's path
// (keptPathRefusal); a promotion, which failover runs, never blocks on one, so
// it builds where nothing ever was instead. It reads the kept-disk records
// only to decide whether an earlier attempt's file may be reused, and builds
// fresh when they cannot be read.
//
// The name is recorded before the file is created, and only while no file
// has it, so a file later found at a recorded name is one this host built. The
// record is a host-local journal beside the promote markers:
// <data_dir>/promote-disks/<target>.json, one entry per disk with the path
// and the full path of the replica it is built from (owner directory and
// file, so two VMs' replicas taken in the same second never match).
//
// The journal belongs to one promotion in progress, and is trusted only
// while that promotion's promote marker is there:
//   - a promotion that starts with no marker for its target drops the
//     journal (an earlier attempt's files in it are left, not reused);
//   - an attempt that ends, finished or failed, clears the journal before it
//     removes the marker (endPromoteAttempt), so a journal is never left
//     beside a marker it outlives.
//
// A file a journal entry names is reused only when it is built from the
// replica chosen now, is a regular file in the pool, no disk row names it,
// and no kept-disk note or kept-disks.json entry names it (keptHolds). A note
// or registry that cannot be read reuses nothing: a fresh disk is built, so a
// promotion never blocks on them. Both ways of building publish the file
// atomically (a temp file placed without replace), so a file at a recorded
// name is complete.

// promotedDiskEntry is the journal's record of one disk's live disk.
type promotedDiskEntry struct {
	Disk string `json:"disk"`
	Path string `json:"path"`
	// Replica is the full path of the replica it is built from.
	Replica string `json:"replica"`
}

// promoteDiskJournalMu serialises the journal's read-modify-write.
var promoteDiskJournalMu sync.Mutex

func (s *Server) promoteDiskJournalPath(target string) string {
	return filepath.Join(s.dataDir, "promote-disks", target+".json")
}

// promoteDisksForAttempt is the journal a promotion of target starting now
// may reuse: target's journal while target's promote marker is there (an
// earlier attempt of the promotion still in progress), else nothing. With no
// marker the journal is dropped; with a marker that cannot be checked it is
// left, and nothing in it is reused.
func (s *Server) promoteDisksForAttempt(target string) map[string]promotedDiskEntry {
	_, err := os.Stat(s.promoteMarkerPath(target))
	switch {
	case err == nil:
		return s.readPromoteDisks(target)
	case errors.Is(err, fs.ErrNotExist):
		s.dropPromoteDisks(target)
	default:
		slog.Warn("promote: whether an earlier attempt is in progress cannot be told; building its live disks under fresh names",
			"vm", target, "marker", s.promoteMarkerPath(target), "error", err)
	}
	return map[string]promotedDiskEntry{}
}

// dropPromoteDisks removes the journal a promotion of target that is no
// longer in progress left, naming each file in it that is still there: it is
// left for an operator, never reused.
func (s *Server) dropPromoteDisks(target string) {
	promoteDiskJournalMu.Lock()
	defer promoteDiskJournalMu.Unlock()
	m, err := s.readPromoteDisksLocked(target)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	for _, e := range m {
		if isRegularFile(e.Path) {
			slog.Warn("promote: a live disk a promotion no longer in progress built is left alone, not reused",
				"vm", target, "disk", e.Disk, "path", e.Path, "built_from", e.Replica)
		}
	}
	if err := os.Remove(s.promoteDiskJournalPath(target)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		// Not read again by this attempt: its first record replaces it.
		slog.Warn("promote: the record of an earlier promotion's live disks was not removed", "vm", target, "error", err)
	}
}

// readPromoteDisks is target's journal by disk name. One that cannot be read
// is logged and read as empty: every name chosen then is a fresh one, which
// collides with nothing, so a promotion never blocks on it.
func (s *Server) readPromoteDisks(target string) map[string]promotedDiskEntry {
	promoteDiskJournalMu.Lock()
	defer promoteDiskJournalMu.Unlock()
	m, err := s.readPromoteDisksLocked(target)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Warn("promote: the record of live disks an earlier attempt built cannot be read; building under fresh names",
			"vm", target, "path", s.promoteDiskJournalPath(target), "error", err)
		return map[string]promotedDiskEntry{}
	}
	return m
}

// readPromoteDisksLocked is target's journal; fs.ErrNotExist (with an empty
// map) when there is none.
func (s *Server) readPromoteDisksLocked(target string) (map[string]promotedDiskEntry, error) {
	m := map[string]promotedDiskEntry{}
	raw, err := os.ReadFile(s.promoteDiskJournalPath(target))
	if err != nil {
		return m, err
	}
	var list []promotedDiskEntry
	if err := json.Unmarshal(raw, &list); err != nil {
		return map[string]promotedDiskEntry{}, err
	}
	for _, e := range list {
		if e.Disk != "" {
			m[e.Disk] = e
		}
	}
	return m, nil
}

// recordPromoteDisk adds e to journal, this attempt's view of target's
// journal, and writes all of it, synced, before e's file is created. What is
// on disk is replaced, never merged: a journal this attempt dropped (or could
// not drop) adds nothing.
func (s *Server) recordPromoteDisk(target string, journal map[string]promotedDiskEntry, e promotedDiskEntry) error {
	promoteDiskJournalMu.Lock()
	defer promoteDiskJournalMu.Unlock()
	journal[e.Disk] = e
	list := make([]promotedDiskEntry, 0, len(journal))
	for _, v := range journal {
		list = append(list, v)
	}
	raw, err := json.Marshal(list)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.promoteDiskJournalPath(target)), 0o700); err != nil {
		return err
	}
	return writeSynced(s.promoteDiskJournalPath(target), raw)
}

// clearPromoteDisks removes target's journal. false when it is still there.
func (s *Server) clearPromoteDisks(target string) bool {
	promoteDiskJournalMu.Lock()
	defer promoteDiskJournalMu.Unlock()
	if err := os.Remove(s.promoteDiskJournalPath(target)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Warn("promote: the record of the live disks built was not removed", "vm", target, "error", err)
		return false
	}
	return true
}

// endPromoteAttempt ends an attempt of a promotion of target, finished (the
// rows name its live disks) or failed: the journal first, then the marker.
// A crash or a failed removal between the two leaves a marker with no journal
// (nothing to reuse), or a journal with no marker, which the next promotion
// drops (promoteDisksForAttempt): never a journal a later promotion trusts.
func (s *Server) endPromoteAttempt(target string) {
	s.clearPromoteDisks(target)
	s.removePromoteMarker(target)
}

// promotedStem is a replica's file name without its format suffix.
func promotedStem(replica string) string {
	return strings.TrimSuffix(strings.TrimSuffix(replica, ".qcow2"), ".raw")
}

// legacyPromotedPath is where an earlier build built target's live disk from
// replica. Never written by this build; looked for only to adopt or reuse what
// an attempt on that build left during a rolling upgrade.
func legacyPromotedPath(poolDir, target, replica string) string {
	return filepath.Join(poolDir, fmt.Sprintf("%s-promoted-%s.qcow2", target, promotedStem(replica)))
}

// freshPromotedPath is a live-disk path in poolDir no file has had. The
// random part has no dot, so the stem a snapshot overlay is named by
// (<stem>.<snapshot>) still ends at it.
func (s *Server) freshPromotedPath(poolDir, target, replica string) string {
	suffix := randid.New()
	if s.promotedDiskSuffix != nil {
		suffix = s.promotedDiskSuffix()
	}
	return filepath.Join(poolDir, fmt.Sprintf("%s-promoted-%s-%s.qcow2", target, promotedStem(replica), suffix))
}

// isRegularFile reports a regular file at path, not following a symlink.
func isRegularFile(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode().IsRegular()
}

// diskRowNames reports whether a disk row names path as its file or a
// backing. A read error counts as named: the file is then not reused.
func (s *Server) diskRowNames(ctx context.Context, path string) bool {
	rows, err := corrosion.DisksReferencingPath(ctx, s.db, path)
	return err != nil || len(rows) > 0
}

// reusablePromotedDisk reports whether p, a file an earlier attempt of this
// promotion recorded or a proof step names, may become a live disk again: a
// regular file in poolDir, named by no disk row, and named by no kept-disk
// note or kept-disks.json entry (keptHolds). Anything that cannot be read
// counts against it, so a fresh disk is built instead. why says what refused
// it.
func (s *Server) reusablePromotedDisk(ctx context.Context, poolDir, p string) (ok bool, why string) {
	switch {
	case p == "" || filepath.Dir(p) != poolDir:
		return false, "not in the target pool"
	case !isRegularFile(p):
		return false, "not a regular file"
	case s.diskRowNames(ctx, p):
		return false, "a disk row names it, or whether one does cannot be read"
	}
	if held, why := s.keptHolds(ctx, p); held {
		return false, why
	}
	return true, ""
}

// planPromotedDisk is where disk's live disk goes, built from the replica at
// replicaPath, for an attempt that has not started a domain: an earlier
// attempt's file to reuse (built true), or a fresh name, recorded in journal
// before it returns (built false). journal is promoteDisksForAttempt's: only
// an entry of the promotion still in progress. legacy, when set, is a file a
// step of this promotion's proof records building from that replica — this
// build's, or an earlier build's during a rolling upgrade — reused the same
// way when the journal has no entry to reuse. An error is the record
// failing; nothing has been created then.
func (s *Server) planPromotedDisk(ctx context.Context, journal map[string]promotedDiskEntry, target, poolDir, disk, replicaPath, legacy string) (path string, built bool, err error) {
	if e, ok := journal[disk]; ok {
		if e.Replica != replicaPath {
			if isRegularFile(e.Path) {
				slog.Warn("promote: an earlier attempt's live disk built from another replica is not reused; left alone, building under a fresh name",
					"vm", target, "disk", disk, "path", e.Path, "built_from", e.Replica, "replica", replicaPath)
			}
		} else if ok, why := s.reusablePromotedDisk(ctx, poolDir, e.Path); ok {
			return e.Path, true, nil
		} else if isRegularFile(e.Path) {
			slog.Warn("promote: an earlier attempt's live disk is not reused; left alone, building under a fresh name",
				"vm", target, "disk", disk, "path", e.Path, "why", why)
		}
	}
	if legacy != "" {
		if ok, why := s.reusablePromotedDisk(ctx, poolDir, legacy); ok {
			return legacy, true, nil
		} else if isRegularFile(legacy) {
			slog.Warn("promote: the live disk a step of this proof names is not reused; left alone, building under a fresh name",
				"vm", target, "disk", disk, "path", legacy, "why", why)
		}
	}
	// A name is recorded only while no file has it, so a file found later
	// at a recorded name is one this host built after recording it. A name
	// a file already has (an accident at 64 random bits) is never recorded:
	// after a few, the last is returned unrecorded and the build refuses it.
	replica := filepath.Base(replicaPath)
	for i := 0; i < 3; i++ {
		path = s.freshPromotedPath(poolDir, target, replica)
		if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := s.recordPromoteDisk(target, journal, promotedDiskEntry{Disk: disk, Path: path, Replica: replicaPath}); err != nil {
			return "", false, err
		}
		return path, false, nil
	}
	return path, false, nil
}

// adoptedPromotedDisk is the live disk of disk, built from the replica at
// replicaPath, that the domain an earlier attempt started runs from.
//
// With the domain's definition read (adoptedXML), it is a disk of that
// domain: the journal's entry, else one with this disk's promoted name (a
// journal dropped or lost), else one of legacy (a proof step's, an earlier
// build's name); only a regular file in poolDir counts.
//
// With the definition unread, what the domain runs from is not known: only
// the journal's entry counts, and only under the rules a reuse is held to
// (reusablePromotedDisk, built from this replica, the promotion still in
// progress). Never the first file found. "" when none is.
func (s *Server) adoptedPromotedDisk(ctx context.Context, journal map[string]promotedDiskEntry, target, poolDir, disk, replicaPath, adoptedXML string, legacy ...string) string {
	e, inJournal := journal[disk]
	if adoptedXML == "" {
		if !inJournal || e.Replica != replicaPath {
			return ""
		}
		if ok, why := s.reusablePromotedDisk(ctx, poolDir, e.Path); !ok {
			slog.Warn("promote: the domain an earlier attempt started cannot be read, and its recorded live disk is not taken",
				"vm", target, "disk", disk, "path", e.Path, "why", why)
			return ""
		}
		return e.Path
	}
	var cands []string
	if inJournal {
		cands = append(cands, e.Path)
	}
	sources, _, _ := domainDiskSourcesFromXML(adoptedXML)
	prefix := fmt.Sprintf("%s-promoted-%s-", target, promotedStem(filepath.Base(replicaPath)))
	for _, p := range sources {
		if b := filepath.Base(p); strings.HasPrefix(b, prefix) && strings.HasSuffix(b, ".qcow2") &&
			!strings.Contains(strings.TrimSuffix(strings.TrimPrefix(b, prefix), ".qcow2"), ".") {
			cands = append(cands, p)
		}
	}
	cands = append(cands, legacy...)
	for _, p := range cands {
		if p == "" || filepath.Dir(p) != poolDir || !isRegularFile(p) {
			continue
		}
		if slices.Contains(sources, p) {
			return p
		}
	}
	return ""
}
