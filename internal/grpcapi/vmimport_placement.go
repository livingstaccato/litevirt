package grpcapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// A file an import on this host writes into a pool is recorded on this host,
// beside the operation journal: its path, which file it is (its inode), and
// the state the import left it in (size, modification time and, once placed,
// change time), with the import and the daemon process that wrote it. The
// record works on any filesystem; the origin xattr the import also sets is
// extra evidence where the pool keeps user xattrs.
//
// After the daemon restarts, or once the import has ended, a file whose record
// still matches it is that import's leftover and nobody else's: no other flow
// has written it since, because writing it moves its modification time or its
// size (and setting a time back moves its change time), and a file put in its
// place is another inode. A file a later flow rewrote in place (qemu-img
// convert into an existing path reuses the inode, and with it the xattr) no
// longer matches, and is judged like any file whose origin is unknown.
//
// The device number is not part of the match: NFS, btrfs subvolumes and
// device-mapper volumes get a new one at every mount, so binding it would
// unbind every record at a reboot. The record is keyed by path, and a
// different file at that path with the same inode, size and nanosecond times
// is not one any flow makes.
//
// Another host sharing the pool asks this one (ImportLeftoverStatus) whether
// its record shows a file there as its dead import's leftover.
//
// One daemon runs per host. Two daemons under one host name sharing a data
// directory would read each other's running imports as dead; that is not a
// supported setup.
//
// The record directory sits in the data directory, which no pool may target
// once the pool-target confinement merges (that branch's refused data-dir
// targets must include import-placements; see restore-import-rereview-4 NI-2).

// importPlacementDirName is the record's directory under the data directory.
const importPlacementDirName = "import-placements"

// importPlacement is one recorded file.
type importPlacement struct {
	Path    string `json:"path"`
	Dev     uint64 `json:"dev"`
	Ino     uint64 `json:"ino"`
	Size    int64  `json:"size"`
	MtimeNs int64  `json:"mtime_ns"`
	// CtimeNs is the change time once the disk is placed; 0 while it is
	// recorded ahead of placement (placing changes it), or where the
	// platform reports none. It catches a time put back after a rewrite.
	CtimeNs  int64  `json:"ctime_ns,omitempty"`
	ImportID string `json:"import_id"`
	Instance string `json:"daemon_instance"`
	// Scratch is a conversion's scratch file, recorded when it is created and
	// written after: only which file it is binds it. Its random name is no
	// target any other flow writes in place.
	Scratch bool `json:"scratch,omitempty"`
}

// placementOf is the record of fi's file at p, written by the running import
// importID. withCtime binds its change time too (a placed disk).
func placementOf(p string, fi os.FileInfo, importID string, scratch, withCtime bool) (importPlacement, bool) {
	dev, ino, size, mtime, ok := fileState(fi)
	if !ok {
		return importPlacement{}, false
	}
	rec := importPlacement{
		Path: filepath.Clean(p), Dev: dev, Ino: ino, Size: size, MtimeNs: mtime,
		ImportID: importID, Instance: importDaemonInstance, Scratch: scratch,
	}
	if withCtime {
		rec.CtimeNs = fileCtimeNs(fi)
	}
	return rec, true
}

// importPlacementDir is where this host keeps the records, or "" when the
// server has no data directory (then nothing is recorded, and every file is
// judged by age).
func (s *Server) importPlacementDir() string {
	if s.dataDir == "" {
		return ""
	}
	return filepath.Join(s.dataDir, importPlacementDirName)
}

// importPlacementFile is the record file for path p.
func importPlacementFile(dir, p string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(p)))
	return filepath.Join(dir, hex.EncodeToString(sum[:16])+".json")
}

// fileState is the identity and state of the file fi describes.
func fileState(fi os.FileInfo) (dev, ino uint64, size, mtimeNs int64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, 0, false
	}
	return uint64(st.Dev), uint64(st.Ino), fi.Size(), fi.ModTime().UnixNano(), true
}

// matches reports whether fi is still the file, in the state, the record
// names: the same inode, and for a disk the same size and modification time
// to the nanosecond, and the same change time where one was recorded.
func (rec importPlacement) matches(fi os.FileInfo) bool {
	if fi == nil || !fi.Mode().IsRegular() {
		return false
	}
	_, ino, size, mtime, ok := fileState(fi)
	if !ok {
		return false
	}
	return rec.matchesState(ino, size, mtime, fileCtimeNs(fi))
}

// matchesState is matches on a file's state as numbers (as a peer sends it).
func (rec importPlacement) matchesState(ino uint64, size, mtimeNs, ctimeNs int64) bool {
	if ino != rec.Ino {
		return false
	}
	if rec.Scratch {
		return true
	}
	if size != rec.Size || mtimeNs != rec.MtimeNs {
		return false
	}
	return rec.CtimeNs == 0 || ctimeNs == rec.CtimeNs
}

// dead reports whether the record's import is no longer running here.
func (s *Server) importPlacementDead(rec importPlacement) bool {
	return rec.Instance != importDaemonInstance || !s.importRunning(rec.ImportID)
}

// recordImportPlacement records that the running import importID left the
// file fi describes at p, in fi's state. It replaces a record for p, except
// one another import running here holds: two imports whose names collide at
// one disk name (web's disk 3-root, web-3's disk root) never take each
// other's record.
func (s *Server) recordImportPlacement(p string, fi os.FileInfo, importID string, scratch bool) error {
	return s.recordImportPlacementBound(p, fi, importID, scratch, false)
}

func (s *Server) recordImportPlacementBound(p string, fi os.FileInfo, importID string, scratch, withCtime bool) error {
	rec, ok := placementOf(p, fi, importID, scratch, withCtime)
	if !ok {
		return errors.New("no file identity on this platform")
	}
	if old, ok := s.importPlacementOf(p); ok && old.ImportID != importID && !s.importPlacementDead(old) {
		return fmt.Errorf("%s is recorded by import %s, still running here", p, old.ImportID)
	}
	return s.writeImportPlacement(rec)
}

// writeImportPlacement writes rec durably: a crash leaves the old record or
// the new one, never a torn one.
func (s *Server) writeImportPlacement(rec importPlacement) error {
	dir := s.importPlacementDir()
	if dir == "" {
		return nil
	}
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		syncDir(filepath.Dir(dir)) // the new directory itself survives a crash
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".rec-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(b); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, importPlacementFile(dir, rec.Path)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	syncDir(dir)
	return nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// importPlacementOf reads p's record.
func (s *Server) importPlacementOf(p string) (importPlacement, bool) {
	dir := s.importPlacementDir()
	if dir == "" {
		return importPlacement{}, false
	}
	b, err := os.ReadFile(importPlacementFile(dir, p))
	if err != nil {
		return importPlacement{}, false
	}
	var rec importPlacement
	if json.Unmarshal(b, &rec) != nil || rec.Path != filepath.Clean(p) {
		return importPlacement{}, false
	}
	return rec, true
}

// placementLstat stats a recorded path for the prune; a test sets
// placementLstatOverride to make a pool hang.
func (s *Server) placementLstat(p string) (os.FileInfo, error) {
	if s.placementLstatOverride != nil {
		return s.placementLstatOverride(p)
	}
	return os.Lstat(p)
}

// importPlacementPruneBudget bounds one prune pass of one pool.
const importPlacementPruneBudget = 10 * time.Second

// startImportPlacementPrune drops, off the caller's path, the records under
// poolDir that nothing is left for: records of earlier daemon processes whose
// file is gone (removed, or moved aside) or no longer matches (written since,
// so the record can never show it again), and temp files a crash left beside
// the records. A record of this process may name a disk not placed yet, and
// is kept. One pass per pool runs at a time, and it stops at its budget: a
// pool whose mount hangs stalls only its own pass, never an import, and never
// another pool's.
func (s *Server) startImportPlacementPrune(poolDir string) {
	dir := s.importPlacementDir()
	if dir == "" {
		return
	}
	poolDir = filepath.Clean(poolDir)
	if _, busy := s.importPrunes.LoadOrStore(poolDir, struct{}{}); busy {
		return
	}
	go func() {
		defer s.importPrunes.Delete(poolDir)
		s.pruneImportPlacementsIn(poolDir, time.Now().Add(importPlacementPruneBudget))
	}()
}

// pruneImportPlacementsIn is one prune pass over poolDir's records.
func (s *Server) pruneImportPlacementsIn(poolDir string, deadline time.Time) {
	dir := s.importPlacementDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if time.Now().After(deadline) {
			return
		}
		rf := filepath.Join(dir, e.Name())
		if strings.HasPrefix(e.Name(), ".rec-") {
			if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > time.Minute {
				_ = os.Remove(rf) // a record write a crash cut short
			}
			continue
		}
		b, err := os.ReadFile(rf)
		if err != nil {
			continue
		}
		var rec importPlacement
		if json.Unmarshal(b, &rec) != nil || rec.Instance == importDaemonInstance || filepath.Dir(rec.Path) != poolDir {
			continue
		}
		fi, err := s.placementLstat(rec.Path)
		if errors.Is(err, fs.ErrNotExist) || (err == nil && !rec.matches(fi)) {
			_ = os.Remove(rf)
		}
	}
}

// forgetImportPlacement drops p's record if the import importID wrote it ("" drops
// any).
func (s *Server) forgetImportPlacement(p, importID string) {
	dir := s.importPlacementDir()
	if dir == "" {
		return
	}
	rf := importPlacementFile(dir, p)
	if importID != "" {
		b, err := os.ReadFile(rf)
		if err != nil {
			return
		}
		var rec importPlacement
		if json.Unmarshal(b, &rec) == nil && rec.ImportID != importID {
			return
		}
	}
	if err := os.Remove(rf); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Warn("import: could not drop a placement record", "path", p, "error", err)
	}
}
