package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/storage"
)

// resolveDeepest is p with its symlinks evaluated through the deepest part of
// it that exists; what does not exist yet cannot be a link and is appended
// as written. The path is a file-system path (hostDiskFile applied).
func resolveDeepest(p string) (string, error) {
	p = filepath.Clean(p)
	rest := ""
	for cur := p; ; {
		if _, err := os.Lstat(cur); err == nil {
			r, err := filepath.EvalSymlinks(cur)
			if err != nil {
				return "", err
			}
			return filepath.Join(r, rest), nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// withinMigrationDiskRoot is withinDiskArtifactRoot for a path a migration
// brings onto this host from sourceHost. A host-local disk keeps its recorded
// path across a cold move (the record, the domain and every later operation
// name it), so the path is the SOURCE's pool directory, not necessarily one of
// this host's: a witness founded by a current build keeps its default pool at
// <data_dir>/pools/default, while the workers of an older cluster keep theirs
// at <data_dir>/disks. Judging the path by this host's roots alone refused the
// documented recovery of a VM promoted onto a witness (lv migrate <vm>
// <worker> --cold).
//
// A storage_pools row of sourceHost is replicated state, so it is not trusted
// to name a place this host writes to. A path inside such a pool's directory
// passes only when the directory, with symlinks resolved on this host, is
// BOTH
//
//	(a) inside this host's own disks/, pools/ or mounts/ areas under its data
//	    directory, or inside the directory of a usable pool row of this host's
//	    own (the same resolved directory); and
//	(b) acceptable to storage.CheckWriteRoot, as this host's own pools are: no
//	    system directory, PKI directory, litevirt state or data directory.
//
// The file's own parent directory is held to the same rules after its symlinks
// are resolved, and must stay inside the pool directory, so a link planted
// below it reaches nothing outside.
func (s *Server) withinMigrationDiskRoot(ctx context.Context, p, sourceHost string) bool {
	if s.withinDiskArtifactRoot(p) {
		return true
	}
	if sourceHost == "" || sourceHost == s.hostName || !filepath.IsAbs(p) || s.db == nil || s.dataDir == "" {
		return false
	}
	pools, err := corrosion.ListStoragePoolsForHost(ctx, s.db, sourceHost)
	if err != nil {
		return false
	}
	parent := filepath.Dir(filepath.Clean(p))
	for _, rec := range pools {
		ref := StoragePoolRef{Driver: rec.Driver, Source: rec.Source, Target: rec.Target, Options: rec.Options}
		if !isFileBasedDriver(ref.Driver) || (strings.EqualFold(ref.Driver, "nfs") && ref.Target == "") {
			continue
		}
		dir, derr := fileBasedPoolDir(s.dataDir, ref)
		if derr != nil || !filepath.IsAbs(dir) || !safename.Contains(dir, p) {
			continue
		}
		if s.foreignPoolDirAcceptable(ctx, dir, parent) {
			return true
		}
	}
	return false
}

// foreignPoolDirAcceptable is rules (a) and (b) of withinMigrationDiskRoot for
// the source's pool directory dir and the parent directory of the file in it.
func (s *Server) foreignPoolDirAcceptable(ctx context.Context, dir, parent string) bool {
	if storage.CheckWriteRoot(dir, s.dataDir, s.pkiDir) != nil || storage.CheckWriteRoot(parent, s.dataDir, s.pkiDir) != nil {
		return false
	}
	rd, err := resolveDeepest(s.hostDiskFile(dir))
	if err != nil {
		return false
	}
	rp, err := resolveDeepest(s.hostDiskFile(parent))
	if err != nil || !safename.Contains(rd, rp) {
		return false
	}
	for _, area := range []string{"disks", "pools", "mounts"} {
		ra, err := resolveDeepest(s.hostDiskFile(filepath.Join(s.dataDir, area)))
		if err == nil && safename.Contains(ra, rd) {
			return true
		}
	}
	own, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName)
	if err != nil {
		return false
	}
	for _, rec := range own {
		ref := StoragePoolRef{Driver: rec.Driver, Source: rec.Source, Target: rec.Target, Options: rec.Options}
		if !isFileBasedDriver(ref.Driver) || (strings.EqualFold(ref.Driver, "nfs") && ref.Target == "") {
			continue
		}
		odir, derr := fileBasedPoolDir(s.dataDir, ref)
		if derr != nil || !filepath.IsAbs(odir) || !s.poolUsableForWrite(ctx, rec.Name, ref) {
			continue
		}
		if ro, err := resolveDeepest(s.hostDiskFile(odir)); err == nil && safename.Contains(ro, rd) {
			return true
		}
	}
	return false
}

// coldSourcePathCheck is what the SOURCE of a cold move requires of a disk's
// recorded path before it reads the file to send it, or removes it once the
// move has committed: the path lies in this host's own disk roots or pool
// directories, and its directory, with symlinks resolved, is not a system
// directory, the PKI directory or litevirt state. The target's own checks
// guard what it writes; nothing else stops a crafted disk record from naming a
// file here.
func (s *Server) coldSourcePathCheck(p string) error {
	if !s.withinDiskArtifactRoot(p) {
		return fmt.Errorf("disk path %q is not in a disk-artifact root of %s", p, s.hostName)
	}
	if err := storage.CheckWriteRoot(filepath.Dir(filepath.Clean(p)), s.dataDir, s.pkiDir); err != nil {
		return fmt.Errorf("disk path %q is refused: %w", p, err)
	}
	return nil
}
