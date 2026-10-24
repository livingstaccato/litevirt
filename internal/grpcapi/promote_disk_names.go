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
// it builds where nothing ever was instead, and never reads kept-disks.json.
//
// The name is recorded before the file is created, and only while no file
// has it, so a file later found at a recorded name is one this host built. The
// record is a host-local journal beside the promote markers:
// <data_dir>/promote-disks/<target>.json, one entry per disk with the path
// and the replica it is built from. Host-local
// and proof-independent for the reason the promote marker is: a retry after a
// crash or a failure may carry the same proof, a fresh one (each failover
// cycle mints one) or none (an operator's promotion), and each of them must
// find what the earlier attempt built. A retry reuses an entry's file when it
// is a regular file built from the replica chosen now and no disk row names
// it; any other entry is left alone and a fresh name is chosen. Both ways of
// building publish the file atomically (a temp file placed without replace),
// so a file at a recorded name is complete. The journal is removed once the
// promoted VM's rows are persisted, when the rows name the files.

// promotedDiskEntry is the journal's record of one disk's live disk.
type promotedDiskEntry struct {
	Disk    string `json:"disk"`
	Path    string `json:"path"`
	Replica string `json:"replica"`
}

// promoteDiskJournalMu serialises the journal's read-modify-write.
var promoteDiskJournalMu sync.Mutex

func (s *Server) promoteDiskJournalPath(target string) string {
	return filepath.Join(s.dataDir, "promote-disks", target+".json")
}

// readPromoteDisks is target's journal by disk name. One that cannot be read
// is logged and read as empty: every name chosen then is a fresh one, which
// collides with nothing, so a promotion never blocks on it.
func (s *Server) readPromoteDisks(target string) map[string]promotedDiskEntry {
	promoteDiskJournalMu.Lock()
	defer promoteDiskJournalMu.Unlock()
	m, err := s.readPromoteDisksLocked(target)
	if err != nil {
		slog.Warn("promote: the record of live disks an earlier attempt built cannot be read; building under fresh names",
			"vm", target, "path", s.promoteDiskJournalPath(target), "error", err)
		return map[string]promotedDiskEntry{}
	}
	return m
}

func (s *Server) readPromoteDisksLocked(target string) (map[string]promotedDiskEntry, error) {
	m := map[string]promotedDiskEntry{}
	raw, err := os.ReadFile(s.promoteDiskJournalPath(target))
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	}
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

// recordPromoteDisk records e in target's journal, synced, before its file is
// created. A journal that cannot be read is replaced.
func (s *Server) recordPromoteDisk(target string, e promotedDiskEntry) error {
	promoteDiskJournalMu.Lock()
	defer promoteDiskJournalMu.Unlock()
	m, _ := s.readPromoteDisksLocked(target)
	m[e.Disk] = e
	list := make([]promotedDiskEntry, 0, len(m))
	for _, v := range m {
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

// clearPromoteDisks removes target's journal once its rows name the files.
func (s *Server) clearPromoteDisks(target string) {
	promoteDiskJournalMu.Lock()
	defer promoteDiskJournalMu.Unlock()
	if err := os.Remove(s.promoteDiskJournalPath(target)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Warn("promote: the record of the live disks built was not removed", "vm", target, "error", err)
	}
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

// planPromotedDisk is where disk's live disk goes, built from replica, for an
// attempt that has not started a domain: an earlier attempt's file to reuse
// (built true), or a fresh name, recorded in the journal before it returns
// (built false). legacy, when set, is a file a step of this promotion's
// proof records building from replica — this build's, or an earlier build's
// during a rolling upgrade — reused the same way when the journal has no
// entry to reuse. An error is the record failing; nothing has been created
// then.
func (s *Server) planPromotedDisk(ctx context.Context, journal map[string]promotedDiskEntry, target, poolDir, disk, replica, legacy string) (path string, built bool, err error) {
	reusable := func(p string) bool {
		return p != "" && filepath.Dir(p) == poolDir && isRegularFile(p) && !s.diskRowNames(ctx, p)
	}
	if e, ok := journal[disk]; ok {
		if e.Replica == replica && reusable(e.Path) {
			return e.Path, true, nil
		}
		if isRegularFile(e.Path) {
			slog.Warn("promote: an earlier attempt's live disk is not reused; left alone, building under a fresh name",
				"vm", target, "disk", disk, "path", e.Path, "built_from", e.Replica, "replica", replica)
		}
	}
	if reusable(legacy) {
		return legacy, true, nil
	}
	// A name is recorded only while no file has it, so a file found later
	// at a recorded name is one this host built after recording it. A name
	// a file already has (an accident at 64 random bits) is never recorded:
	// after a few, the last is returned unrecorded and the build refuses it.
	for i := 0; i < 3; i++ {
		path = s.freshPromotedPath(poolDir, target, replica)
		if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := s.recordPromoteDisk(target, promotedDiskEntry{Disk: disk, Path: path, Replica: replica}); err != nil {
			return "", false, err
		}
		return path, false, nil
	}
	return path, false, nil
}

// adoptedPromotedDisk is the live disk of disk, built from replica, that the
// domain an earlier attempt started runs from: the journal's entry, else a
// disk of that domain with this disk's promoted name (a lost journal), else
// one of legacy (an earlier build's names). Only a regular file in poolDir
// the domain has counts; with the domain's definition unread (adoptedXML
// ""), the first such file there is. "" when none is.
func adoptedPromotedDisk(journal map[string]promotedDiskEntry, target, poolDir, disk, replica, adoptedXML string, legacy ...string) string {
	var cands []string
	if e, ok := journal[disk]; ok {
		cands = append(cands, e.Path)
	}
	var sources []string
	if adoptedXML != "" {
		sources, _, _ = domainDiskSourcesFromXML(adoptedXML)
	}
	prefix := fmt.Sprintf("%s-promoted-%s-", target, promotedStem(replica))
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
		if adoptedXML == "" || slices.Contains(sources, p) {
			return p
		}
	}
	return ""
}
