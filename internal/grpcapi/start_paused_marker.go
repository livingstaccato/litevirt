package grpcapi

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A start the guard pauses (NICStartGuard: tap VLANs, or a guarded NIC that
// names no tap) is recorded on this host, durably, before the domain is
// created paused, and the record is removed once that start has ended, the
// guest resumed or the domain destroyed (libvirt.StartGuard.PausedDone). A
// record that outlives its start says exactly one thing: this daemon created
// the domain paused for a start it did not finish. That, and nothing else, is
// what ResumeStrandedStarts acts on: a domain paused for another reason
// (partition pause, a snapshot, an operator, anything added later) carries no
// record, and is never resumed by it (review R2-B1).

const startPausedDir = "start-paused"

// startPausedPath is name's record. The name is hex-encoded, so no VM name can
// leave the directory.
func (s *Server) startPausedPath(name string) string {
	return filepath.Join(s.dataDir, startPausedDir, hex.EncodeToString([]byte(name)))
}

// markStartPaused records, durably (fsynced, then its directory), that a
// start of name is about to create it paused.
func (s *Server) markStartPaused(name string) error {
	if s.dataDir == "" {
		return errors.New("no data directory")
	}
	dir := filepath.Join(s.dataDir, startPausedDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	// The incarnation it pauses: a same-name domain of another uuid is not
	// this start's (startPausedUUID).
	uuid := ""
	if s.virt != nil {
		if x, err := s.virt.DumpXMLInactive(name); err == nil {
			uuid = lv.UUIDFromXML(x)
		}
	}
	if _, err := fmt.Fprintf(tmp, "%s\n%s\nuuid=%s\n", name, time.Now().UTC().Format(time.RFC3339), uuid); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), s.startPausedPath(name)); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// startPausedMarked reports whether a paused start of name is recorded; an
// error when that cannot be read.
func (s *Server) startPausedMarked(name string) (bool, error) {
	_, err := os.Stat(s.startPausedPath(name))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	}
	return false, err
}

// unmarkStartPaused removes name's record (absent is fine).
func (s *Server) unmarkStartPaused(name string) {
	if err := os.Remove(s.startPausedPath(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		// It stays: a later sweep finds the guest running, and drops it.
		slog.Warn("start guard: could not remove the record of a paused start that ended", "vm", name, "error", err)
	}
}

// startPausedUUID is the domain uuid name's record names, "" when it names
// none (it could not be read when the start was recorded).
func (s *Server) startPausedUUID(name string) (string, error) {
	b, err := os.ReadFile(s.startPausedPath(name))
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if u, ok := strings.CutPrefix(l, "uuid="); ok {
			return strings.ToLower(strings.TrimSpace(u)), nil
		}
	}
	return "", nil
}

// removeHalfWrittenStartRecords removes the temporary files of record writes
// a daemon died in (.tmp-*): never a record, and never read.
func (s *Server) removeHalfWrittenStartRecords() {
	dir := filepath.Join(s.dataDir, startPausedDir)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
				slog.Warn("start guard: could not remove a half-written record of a paused start", "file", e.Name(), "error", err)
			}
		}
	}
}
