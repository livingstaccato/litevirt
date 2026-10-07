package grpcapi

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// stagingTempPrefixes are the os.CreateTemp prefixes used by streaming
// operations (replicate / ISO upload / image import / restore). They are
// normally removed by a deferred cleanup on the error/success path — which a
// hard crash (SIGKILL, power loss) of the daemon skips, leaking the temp file
// with nothing to ever remove it. Repeated crashes then fill the pool/image
// dirs. We sweep stale ones on startup.
var stagingTempPrefixes = []string{".repl-", ".upload-", "import-", "restore-", ".promote-"}

// sweepStaleStagingTemps removes leftover staging temp files older than maxAge
// from dir, returning the count removed. The age guard avoids racing a genuinely
// in-flight operation (there shouldn't be one at startup, but it's cheap
// insurance if this is ever called periodically).
func sweepStaleStagingTemps(dir string, maxAge time.Duration, now time.Time) int {
	return sweepStale(dir, maxAge, now, isStagingTemp)
}

func isStagingTemp(name string) bool {
	return strings.HasSuffix(name, ".tmp") && hasStagingPrefix(name)
}

// isLegacyReplicaPartial matches the ".<replica>.partial" temp publishReplica
// staged into before it switched to ".repl-*.tmp": a dot, a replica-shaped
// name (a .qcow2 or .raw), then ".partial". This
// build never creates one, so every match is a leftover of a crash on an older
// one; nothing else collects them.
func isLegacyReplicaPartial(name string) bool {
	inner, ok := strings.CutPrefix(name, ".")
	if !ok {
		return false
	}
	inner, ok = strings.CutSuffix(inner, ".partial")
	if !ok || strings.HasPrefix(inner, ".") {
		return false
	}
	stem, isQcow2 := strings.CutSuffix(inner, ".qcow2")
	if !isQcow2 {
		var isRaw bool
		if stem, isRaw = strings.CutSuffix(inner, ".raw"); !isRaw {
			return false
		}
	}
	return stem != ""
}

// sweepLegacyReplicaPartials removes leftover ".<replica>.partial" files older
// than maxAge from a replica pool directory. Same age guard as the staging
// sweep: a copy still being written keeps a fresh mtime.
func sweepLegacyReplicaPartials(dir string, maxAge time.Duration, now time.Time) int {
	return sweepStale(dir, maxAge, now, isLegacyReplicaPartial)
}

func sweepStale(dir string, maxAge time.Duration, now time.Time, match func(string) bool) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !match(n) {
			continue
		}
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) < maxAge {
			continue
		}
		if os.Remove(filepath.Join(dir, n)) == nil {
			removed++
		}
	}
	return removed
}

func hasStagingPrefix(name string) bool {
	for _, p := range stagingTempPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// SweepStaleStaging removes leaked operation staging temp files from this host's
// pool, image, and disk directories. Called once at startup so a daemon that was
// killed mid-replicate/upload/import/restore doesn't leak staging files forever.
// Pool directories additionally lose any stale ".<replica>.partial" an older
// build's publishReplica left behind (isLegacyReplicaPartial).
//
// It is also where a starting daemon records that this host has begun
// recording pool files (MarkPoolRecords, pool_records.go).
func (s *Server) SweepStaleStaging(ctx context.Context) {
	s.MarkPoolRecords(ctx)
	dirs := map[string]struct{}{
		filepath.Join(s.dataDir, "images"): {},
		filepath.Join(s.dataDir, "disks"):  {},
		// Users' uploads into a pool on <data_dir>/disks stage here.
		filepath.Join(s.dataDir, "disks", poolUploadsSubdir): {},
	}
	// Replicas land only in file-based pool directories (replicateLocalWith),
	// so the legacy replica-temp sweep is confined to those.
	replicaDirs := map[string]struct{}{}
	if pools, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName); err == nil {
		for _, p := range pools {
			if !isFileBasedDriver(p.Driver) {
				continue
			}
			if dir, derr := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: p.Driver, Source: p.Source, Target: p.Target}); derr == nil {
				dirs[dir] = struct{}{}
				replicaDirs[dir] = struct{}{}
			}
		}
	}
	total := 0
	for dir := range dirs {
		total += sweepStaleStagingTemps(dir, time.Hour, time.Now())
	}
	for dir := range replicaDirs {
		total += sweepLegacyReplicaPartials(dir, time.Hour, time.Now())
	}
	if total > 0 {
		slog.Info("startup: swept stale staging temp files (leaked by a prior hard crash)", "removed", total)
	}
}
