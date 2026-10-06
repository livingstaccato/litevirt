package grpcapi

import (
	"os"

	"github.com/litevirt/litevirt/internal/randid"
)

// A file an import on this host writes into a pool is recorded with where it
// came from: this host, this daemon process, and the import (the placement
// record, and an xattr where the pool keeps one). A leftover of an import that
// is no longer running here — the daemon restarted, or the import ended
// without cleaning up — that nothing has written since is known to be
// nobody's the moment it is seen, with no need to wait for it to go quiet.

// importOriginXattr names the extended attribute holding a file's origin.
const importOriginXattr = "user.litevirt.import-origin"

// setImportOrigin and getImportOrigin write and read a file's origin xattr;
// variables so a test can take user xattrs away, as some pools do.
var (
	setImportOrigin = setImportOriginXattr
	getImportOrigin = getImportOriginXattr
)

// importDaemonInstance names this daemon process. One daemon runs per host, so
// an origin naming this host and another instance names a process that is gone.
var importDaemonInstance = randid.New()

// importOriginFor is the origin an import with importID records.
func (s *Server) importOriginFor(importID string) string {
	return s.hostName + "/" + importDaemonInstance + "/" + importID
}

// importLeftover reports whether the file fi describes at p is a leftover of
// an import of this host that is no longer running — one under an earlier
// daemon process, or one this process no longer runs — and nothing has
// written since that import left it: its placement record still matches it
// (see vmimport_placement.go). An origin xattr, where the pool keeps one,
// must name the same import.
func (s *Server) importLeftover(p string, fi os.FileInfo) bool {
	rec, ok := s.importPlacementOf(p)
	if !ok || !rec.matches(fi) {
		return false
	}
	if rec.Instance == importDaemonInstance && s.importRunning(rec.ImportID) {
		return false
	}
	if o, ok := getImportOrigin(p); ok && o != s.hostName+"/"+rec.Instance+"/"+rec.ImportID {
		return false
	}
	return true
}

// importRunningFile names the import running in this process that wrote the
// file fi describes at p — its record names it, and it is still that file —
// by its VM name and import id.
func (s *Server) importRunningFile(p string, fi os.FileInfo) (name, importID string, ok bool) {
	rec, ok := s.importPlacementOf(p)
	if !ok || rec.Instance != importDaemonInstance {
		return "", "", false
	}
	dev, ino, _, _, ok := fileState(fi)
	if !ok || !fi.Mode().IsRegular() || dev != rec.Dev || ino != rec.Ino {
		return "", "", false
	}
	name, ok = s.importNameRunning(rec.ImportID)
	return name, rec.ImportID, ok
}
