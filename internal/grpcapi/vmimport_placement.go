package grpcapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
)

// A file an import on this host writes into a pool is recorded on this host,
// beside the operation journal: its path, the file it was (device and inode),
// and the state the import left it in (size and modification time), with the
// import and the daemon process that wrote it. The record works on any
// filesystem; the origin xattr the import also sets is extra evidence where
// the pool keeps user xattrs.
//
// After the daemon restarts, or once the import has ended, a file whose record
// still matches it is that import's leftover and nobody else's: no other flow
// has written it since, because writing it moves its modification time or its
// size, and a file put in its place is another inode. A file a later flow
// rewrote in place (qemu-img convert into an existing path reuses the inode,
// and with it the xattr) no longer matches, and is judged like any file whose
// origin is unknown.
//
// One daemon runs per host. Two daemons under one host name sharing a data
// directory would read each other's running imports as dead; that is not a
// supported setup.

// importPlacementDirName is the record's directory under the data directory.
const importPlacementDirName = "import-placements"

// importPlacement is one recorded file.
type importPlacement struct {
	Path     string `json:"path"`
	Dev      uint64 `json:"dev"`
	Ino      uint64 `json:"ino"`
	Size     int64  `json:"size"`
	MtimeNs  int64  `json:"mtime_ns"`
	ImportID string `json:"import_id"`
	Instance string `json:"daemon_instance"`
	// Scratch is a conversion's scratch file, recorded when it is created and
	// written after: only which file it is binds it. Its random name is no
	// target any other flow writes in place.
	Scratch bool `json:"scratch,omitempty"`
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
// names: the same device and inode, and for a disk the same size and
// modification time to the nanosecond.
func (rec importPlacement) matches(fi os.FileInfo) bool {
	if fi == nil || !fi.Mode().IsRegular() {
		return false
	}
	dev, ino, size, mtime, ok := fileState(fi)
	if !ok || dev != rec.Dev || ino != rec.Ino {
		return false
	}
	return rec.Scratch || (size == rec.Size && mtime == rec.MtimeNs)
}

// recordImportPlacement records that the running import importID left the
// file fi describes at p, in fi's state. It replaces a record for p.
func (s *Server) recordImportPlacement(p string, fi os.FileInfo, importID string, scratch bool) error {
	dev, ino, size, mtime, ok := fileState(fi)
	if !ok {
		return errors.New("no file identity on this platform")
	}
	return s.writeImportPlacement(importPlacement{
		Path: filepath.Clean(p), Dev: dev, Ino: ino, Size: size, MtimeNs: mtime,
		ImportID: importID, Instance: importDaemonInstance, Scratch: scratch,
	})
}

// writeImportPlacement writes rec durably: a crash leaves the old record or
// the new one, never a torn one.
func (s *Server) writeImportPlacement(rec importPlacement) error {
	dir := s.importPlacementDir()
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
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
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
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

// pruneImportPlacements drops the records of earlier daemon processes whose
// file is gone (removed, or moved aside): nothing is left for them to show.
// A record of this process may name a disk not placed yet, and is kept.
func (s *Server) pruneImportPlacements() {
	dir := s.importPlacementDir()
	if dir == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		rf := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(rf)
		if err != nil {
			continue
		}
		var rec importPlacement
		if json.Unmarshal(b, &rec) != nil || rec.Instance == importDaemonInstance {
			continue
		}
		if _, err := os.Lstat(rec.Path); errors.Is(err, fs.ErrNotExist) {
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
