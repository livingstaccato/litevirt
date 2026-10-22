package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/litevirt/litevirt/internal/health"
)

// keptNoteHolds reports whether path is a file this host's kept-disk notes
// name (health.KeptNotedFiles): a disk a delete kept, or a file one backs on.
// No path that removes a VM's disk files on this host may remove it. A note
// that cannot be read holds every path. why says which.
func (s *Server) keptNoteHolds(path string) (bool, string) {
	files, err := health.KeptNotedFiles(s.dataDir)
	if err != nil {
		return true, fmt.Sprintf("this host's notes of the disks deletes kept cannot be read (%v)", err)
	}
	for _, p := range []string{path, s.hostDiskFile(path)} {
		if vm, ok := files[filepath.Clean(p)]; ok {
			return true, fmt.Sprintf("the deleted VM %s was kept with it (%s)", vm,
				filepath.Join(s.dataDir, "kept-disks", vm+".json"))
		}
	}
	return false, ""
}

// reportKeptNoteHold logs and records, as an event of vmName, a disk file a
// removal of vmName's left because a kept-disk note holds it.
func (s *Server) reportKeptNoteHold(ctx context.Context, vmName, op, path, why string) {
	slog.Warn(op+": a disk file a kept-disk note holds is left", "vm", vmName, "path", path, "why", why)
	s.recordVMEvent(ctx, vmName, "vm.disk.kept", "ok",
		fmt.Sprintf("%s left %s on %s: %s; only an operator removes it", op, path, s.hostName, why))
}
