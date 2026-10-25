package grpcapi

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"
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
	if _, err := fmt.Fprintf(tmp, "%s\n%s\n", name, time.Now().UTC().Format(time.RFC3339)); err != nil {
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
