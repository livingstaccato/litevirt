package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/storage"
)

// verbStorageHostPath is what it takes to make the daemon use a directory or
// file on the host's own filesystem for storage: a pool or compose volume with
// a target (or a btrfs source, NFS mount options, a Ceph conf or keyring), or a
// compose backup repo path. The daemon writes there as root, so naming one is
// root on that host. It is checked at "/" and no built-in role but Admin holds
// it; an Operator binding, even at "/", does not.
const verbStorageHostPath = "storage.hostpath"

// requireHostPathAuthority refuses a caller without storage.hostpath at the
// cluster root. what names the object, h what it names on the host.
func (s *Server) requireHostPathAuthority(ctx context.Context, what string, h storage.HostPaths) error {
	err := s.RequirePerm(ctx, "/", verbStorageHostPath, "admin")
	if err == nil {
		return nil
	}
	if status.Code(err) != codes.PermissionDenied {
		return err
	}
	return status.Errorf(codes.PermissionDenied,
		"%s names %s on the host; the daemon writes there as root, so it needs %s at the cluster root (the Admin role on /)",
		what, h.Describe(), verbStorageHostPath)
}

// authorizePoolHostPaths is the gate for a pool configuration: cluster-root
// authority for anything it names on the host, then the directories no pool
// may use at all, whoever asks.
func (s *Server) authorizePoolHostPaths(ctx context.Context, what string, cfg storage.Config) error {
	if h := storage.HostPathsOf(cfg); h.Any() {
		if err := s.requireHostPathAuthority(ctx, what, h); err != nil {
			return err
		}
	}
	if err := storage.CheckConfig(cfg, s.dataDir, s.pkiDir); err != nil {
		return status.Errorf(codes.InvalidArgument, "%s: %v", what, err)
	}
	return nil
}

// authorizeComposeHostPaths applies the pool gate to a compose file's volumes
// and backup repos before a deploy does anything. A volume or repo that is
// exactly what is already stored for this stack needs no new authority, so an
// operator can re-deploy a stack an admin wrote; changing or adding one does.
// The protected-directory check applies to every volume, stored or not.
func (s *Server) authorizeComposeHostPaths(ctx context.Context, f *compose.File) error {
	// A stored stack that cannot be read grandfathers nothing.
	stored, err := s.storedStackFile(ctx, f.Name)
	if err != nil {
		stored = nil
	}
	for _, name := range slices.Sorted(maps.Keys(f.Volumes)) {
		vol := f.Volumes[name]
		cfg := storage.Config{Driver: vol.Driver, Source: vol.Source, Target: vol.Target, Options: vol.Options}
		what := fmt.Sprintf("compose volume %q", name)
		if h := storage.HostPathsOf(cfg); h.Any() && !storedVolumeIs(stored, name, vol) {
			if err := s.requireHostPathAuthority(ctx, what, h); err != nil {
				return err
			}
		}
		if err := storage.CheckConfig(cfg, s.dataDir, s.pkiDir); err != nil {
			return status.Errorf(codes.InvalidArgument, "%s: %v", what, err)
		}
	}
	if len(f.BackupRepos) == 0 {
		return nil
	}
	registered, err := corrosion.ListBackupRepos(ctx, s.db)
	if err != nil {
		registered = nil // fail closed: nothing is "already registered"
	}
	for _, name := range slices.Sorted(maps.Keys(f.BackupRepos)) {
		repo := f.BackupRepos[name]
		if repo.Path == "" {
			continue // DeployStack refuses it with its own message
		}
		if slices.ContainsFunc(registered, func(r corrosion.BackupRepo) bool {
			return r.Name == name && r.Path == repo.Path && r.StackName == f.Name
		}) {
			continue
		}
		if err := s.requireHostPathAuthority(ctx, fmt.Sprintf("compose backup repo %q", name),
			storage.HostPaths{WriteRoots: []string{repo.Path}}); err != nil {
			return err
		}
	}
	return nil
}

func storedVolumeIs(stored *compose.File, name string, vol compose.VolumeDef) bool {
	if stored == nil {
		return false
	}
	old, ok := stored.Volumes[name]
	return ok && old.Driver == vol.Driver && old.Source == vol.Source &&
		old.Target == vol.Target && maps.Equal(old.Options, vol.Options)
}

// checkPoolForWrite is the one check every use of a pool goes through —
// CreateVM's disk, move, replicate, the replication runner, promote, replica
// increments, import, upload, content delete and content listing. A pool created before these checks
// may name a directory no pool may use, or a Source in no valid form. It keeps
// listing, but nothing writes into it, mounts it or creates disks on it: each
// attempt is refused and logged so the operator finds out and recreates the
// pool somewhere allowed. Nothing is deleted or rewritten on their behalf.
func (s *Server) checkPoolForWrite(ctx context.Context, name string, ref StoragePoolRef) error {
	cerr, detail := s.poolRefusal(ctx, name, ref)
	if cerr == nil {
		return nil
	}
	slog.Error("storage pool refused: recreate the pool",
		"pool", name, "host", s.hostName, "driver", ref.Driver, "reason", cerr, "detail", detail)
	return status.Errorf(codes.FailedPrecondition,
		"pool %q is refused (%v): nothing lists, reads or writes it — recreate the pool", name, cerr)
}

// poolRefusal is the one predicate behind checkPoolForWrite and
// poolUsableForWrite: why the pool may not be used, or nil. The error is safe
// to show any caller of the pool; detail (another pool's name, its directory)
// is for the log only — the other pool may be another project's.
func (s *Server) poolRefusal(ctx context.Context, name string, ref StoragePoolRef) (error, string) {
	cfg := storage.Config{Driver: ref.Driver, Source: ref.Source, Target: ref.Target, Options: ref.Options}
	if err := storage.CheckConfig(cfg, s.dataDir, s.pkiDir); err != nil {
		return err, ""
	}
	if isFileBasedDriver(ref.Driver) {
		if d, err := fileBasedPoolDir(s.dataDir, ref); err == nil {
			if err := storage.CheckWriteRoot(d, s.dataDir, s.pkiDir); err != nil {
				return err, ""
			}
		}
	}
	// A directory another pool also uses — the same one, an alias, one inside
	// the other, or the same NFS export — is neither pool's own.
	other, why, err := s.poolSharedWith(ctx, name, ref)
	if err != nil {
		return fmt.Errorf("check for a shared directory: %w", err), ""
	}
	if other != "" {
		return fmt.Errorf("its directory overlaps another pool's (%s)", why), fmt.Sprintf("other pool %q", other)
	}
	// An NFS export mounted without nosuid,nodev,noexec,nosymfollow (by hand,
	// or by an earlier build) is not used until litevirt mounts it again.
	if err := storage.CheckNFSMountHardened(s.dataDir, cfg); err != nil {
		return err, ""
	}
	return nil, ""
}

// poolDirForWrite is fileBasedPoolDir for a write: checkPoolForWrite first,
// and for an NFS pool the export mounted (hardened) by its Prepare, so nothing
// is ever written into a bare mount point on the local disk.
func (s *Server) poolDirForWrite(ctx context.Context, name string, ref StoragePoolRef) (string, error) {
	if err := s.checkPoolForWrite(ctx, name, ref); err != nil {
		return "", err
	}
	if strings.EqualFold(ref.Driver, "nfs") {
		drv, err := storage.New(s.dataDir, storage.Config{Driver: ref.Driver, Source: ref.Source, Target: ref.Target, Options: ref.Options})
		if err != nil {
			return "", status.Errorf(codes.FailedPrecondition, "pool %q: %v", name, err)
		}
		if err := drv.Prepare(ctx); err != nil {
			slog.Error("storage pool write refused: its NFS export could not be mounted hardened", "pool", name, "error", err)
			return "", status.Errorf(codes.FailedPrecondition, "pool %q: mount: %v", name, err)
		}
	}
	dir, err := fileBasedPoolDir(s.dataDir, ref)
	if err != nil {
		return "", status.Errorf(codes.FailedPrecondition, "resolve pool dir: %v", err)
	}
	return dir, nil
}

// poolWriteDir is poolDirForWrite for a pool row.
func (s *Server) poolWriteDir(ctx context.Context, rec corrosion.StoragePoolRecord) (string, error) {
	return s.poolDirForWrite(ctx, rec.Name, StoragePoolRef{Driver: rec.Driver, Source: rec.Source, Target: rec.Target, Options: rec.Options})
}

// poolUsableForWrite is checkPoolForWrite without the log, for code that
// enumerates roots (the migration helpers' artifact roots, the scratch sweep)
// rather than acting on one pool. One predicate, not two.
func (s *Server) poolUsableForWrite(ctx context.Context, name string, ref StoragePoolRef) bool {
	err, _ := s.poolRefusal(ctx, name, ref)
	return err == nil
}

// poolUploadExts are the file types a pool holds: disk images, installer ISOs,
// import bundles, and compressed forms of them. Nothing a host executes or
// reads as configuration ends in one of these.
var poolUploadExts = map[string]bool{
	".iso": true, ".img": true, ".qcow2": true, ".qcow": true, ".raw": true,
	".vmdk": true, ".vdi": true, ".vhd": true, ".vhdx": true, ".ova": true, ".ovf": true,
	".gz": true, ".xz": true, ".zst": true, ".bz2": true,
}

// validatePoolUploadName admits a plain base name with an image-like
// extension. A leading dot is refused: no pool content is hidden, and the
// upload's own temp files are dot-files.
func validatePoolUploadName(name string) error {
	if err := safename.ValidateName(name); err != nil {
		return err
	}
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("name %q may not start with '.'", name)
	}
	if !poolUploadExts[strings.ToLower(filepath.Ext(name))] {
		exts := slices.Sorted(maps.Keys(poolUploadExts))
		return fmt.Errorf("name %q must end in one of %s", name, strings.Join(exts, " "))
	}
	return nil
}

// refuseExistingDest reports a name already taken in the pool — by a file, a
// directory or a symlink — so an upload never replaces or writes through it.
func refuseExistingDest(dest, filename string) error {
	fi, err := os.Lstat(dest)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return status.Errorf(codes.Internal, "check destination: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return status.Errorf(codes.AlreadyExists, "%q already exists in the pool as a symlink", filename)
	}
	return status.Errorf(codes.AlreadyExists, "%q already exists in the pool; delete it first", filename)
}

// publishNoClobber makes tmp visible as dest only if dest does not exist. A
// hard link fails with EEXIST rather than replace anything, including a
// symlink, and never follows one. On a filesystem without hard links it falls
// back to check-then-rename.
func publishNoClobber(tmp, dest, filename string) error {
	lerr := os.Link(tmp, dest)
	if lerr == nil {
		return nil
	}
	if err := refuseExistingDest(dest, filename); err != nil {
		return err
	}
	if errors.Is(lerr, fs.ErrExist) {
		// Gone again between the link and the check: still not ours to take.
		return status.Errorf(codes.AlreadyExists, "%q already exists in the pool", filename)
	}
	if err := os.Rename(tmp, dest); err != nil {
		return status.Errorf(codes.Internal, "finalize: %v", err)
	}
	return nil
}

// localPoolDir is where a new target-less local pool keeps its files: a
// directory of its own, never the shared <data_dir>/disks that holds every
// VM's local disks on the host, across projects.
func localPoolDir(dataDir, name string) string {
	return filepath.Join(dataDir, "pools", name)
}

// liveDiskOwners returns the live disks on this host that use path — as their
// own file or as a backing file. A pool directory can hold files that belong to
// VMs outside the pool: a legacy target-less local pool shares <data_dir>/disks
// with every local disk on the host.
func (s *Server) liveDiskOwners(ctx context.Context, host, path string) ([]corrosion.DiskRecord, error) {
	refs, err := corrosion.DisksReferencingPath(ctx, s.db, path)
	if err != nil {
		return nil, err
	}
	out := refs[:0]
	for _, d := range refs {
		if d.HostName == "" || d.HostName == host {
			out = append(out, d)
		}
	}
	return out, nil
}

// dirEntriesSample returns up to n entry names in dir ("" for none, or when
// it does not exist), plus a count of the rest.
func dirEntriesSample(dir string, n int) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for i, e := range ents {
		if i == n {
			out = append(out, fmt.Sprintf("and %d more", len(ents)-n))
			break
		}
		out = append(out, e.Name())
	}
	return out
}

// poolSharedWith returns the name of another live pool row on this host that
// shares ref's storage, and how: the same directory, an alias of it, one
// inside the other, or the same NFS export mounted elsewhere ("" when none).
func (s *Server) poolSharedWith(ctx context.Context, name string, ref StoragePoolRef) (string, string, error) {
	rows, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName)
	if err != nil {
		return "", "", err
	}
	isNFS := strings.EqualFold(ref.Driver, "nfs")
	dir := ""
	if isFileBasedDriver(ref.Driver) {
		dir, _ = fileBasedPoolDir(s.dataDir, ref)
	}
	for _, r := range rows {
		if r.Name == name {
			continue
		}
		if isNFS && strings.EqualFold(r.Driver, "nfs") && storage.NFSExportKey(r.Source) == storage.NFSExportKey(ref.Source) {
			return r.Name, "the same NFS export", nil
		}
		if dir == "" || !isFileBasedDriver(r.Driver) {
			continue
		}
		d, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: r.Driver, Source: r.Source, Target: r.Target})
		if err == nil && storage.DirsOverlap(dir, d) {
			return r.Name, "the same directory, an alias of it, or one inside the other", nil
		}
	}
	return "", "", nil
}

// dirEntryCount is how many entries dir holds (0 when it does not exist).
func dirEntryCount(dir string) int {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	return len(ents)
}
