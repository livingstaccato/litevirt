package grpcapi

import (
	"strings"

	"github.com/litevirt/litevirt/internal/randid"
)

// A file an import on this host writes into a pool records where it came
// from: this host, this daemon process, and the import. A leftover of an
// import that is no longer running here — the daemon restarted, or the import
// ended without cleaning up — is known to be nobody's the moment it is seen,
// with no need to wait for it to go quiet.

// importOriginXattr names the extended attribute holding a file's origin.
const importOriginXattr = "user.litevirt.import-origin"

// importDaemonInstance names this daemon process. One daemon runs per host, so
// an origin naming this host and another instance names a process that is gone.
var importDaemonInstance = randid.New()

// importOriginFor is the origin an import with importID records.
func (s *Server) importOriginFor(importID string) string {
	return s.hostName + "/" + importDaemonInstance + "/" + importID
}

// importOriginOf reads p's origin: the host, the daemon instance and the
// import that wrote it. A file with none, or one unreadable, has none.
func importOriginOf(p string) (host, instance, importID string, ok bool) {
	o, ok := getImportOrigin(p)
	if !ok {
		return "", "", "", false
	}
	parts := strings.SplitN(o, "/", 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// importLeftover reports whether p was written by an import of this host that
// is no longer running: one under an earlier daemon process, or one this
// process no longer runs.
func (s *Server) importLeftover(p string) bool {
	host, instance, id, ok := importOriginOf(p)
	if !ok || host != s.hostName {
		return false
	}
	return instance != importDaemonInstance || !s.importRunning(id)
}

// importOwnFile reports whether p was written by the running import importID.
func (s *Server) importOwnFile(p, importID string) bool {
	host, instance, id, ok := importOriginOf(p)
	return ok && host == s.hostName && instance == importDaemonInstance && id == importID
}
