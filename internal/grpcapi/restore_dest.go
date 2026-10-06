package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/storage"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// Where a restore writes.
//
// <data_dir>/disks holds the pool-less disks of every project on the host, so a
// destination named by the caller was a way to replace another project's disk:
// the restore wrote a temp file and renamed it over whatever the name held. A
// restore now writes only to:
//
//   - a fresh file the daemon names (no target_path) — created no-clobber;
//   - a file an admin names (target_path) — also no-clobber: an existing file is
//     a refusal, for an admin too;
//   - in place, the disk the VM's own record names, for a VM in the backup's
//     project that is stopped on this host. This is the only destination a
//     restore replaces, and its path comes from the record, never the request.

// restoreDest is a resolved restore destination. unlock, when set, releases
// the VM lock an in-place restore holds until the file is placed.
type restoreDest struct {
	path    string
	inPlace bool
	unlock  func()
}

func (d restoreDest) release() {
	if d.unlock != nil {
		d.unlock()
	}
}

// requireAdminTargetPath refuses a caller who names a destination file without
// the host-path authority. Naming one is writing as root wherever it points.
func (s *Server) requireAdminTargetPath(ctx context.Context) error {
	if err := s.RequirePerm(ctx, "/", verbStorageHostPath, "admin"); err != nil {
		return status.Error(codes.PermissionDenied,
			"target_path names a file on the host and requires the admin role; leave it empty and the daemon writes a new file of its own")
	}
	return nil
}

// resolveAdminTarget resolves an admin's target_path (a bare name lands in
// defaultDir) and refuses one that already exists.
func (s *Server) resolveAdminTarget(ctx context.Context, targetPath, defaultDir string) (string, error) {
	if err := s.requireAdminTargetPath(ctx); err != nil {
		return "", err
	}
	target, err := s.resolveRestoreTarget(ctx, targetPath, defaultDir)
	if err != nil {
		return "", err
	}
	if err := refuseExistingFile(target); err != nil {
		return "", err
	}
	return target, nil
}

// refuseExistingFile reports a destination that is already taken — by a file,
// a directory or a symlink.
func refuseExistingFile(path string) error {
	_, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return status.Errorf(codes.Internal, "check destination %q: %v", path, err)
	}
	return status.Errorf(codes.AlreadyExists, "%q already exists; a restore or copy never replaces a file", path)
}

// derivedDiskFile is a fresh, daemon-chosen file name in dir for a restore or
// copy of (vm, disk). The time and random suffix make a collision an accident
// that placeNoClobber still refuses, not a way to aim at a file.
func derivedDiskFile(dir, vm, disk, kind, ext string) (string, error) {
	for _, n := range []string{vm, disk} {
		if err := safename.ValidateName(n); err != nil {
			return "", status.Errorf(codes.InvalidArgument, "%v", err)
		}
	}
	name := fmt.Sprintf("%s-%s-%s-%s-%s%s", vm, disk, kind,
		time.Now().UTC().Format("20060102-150405"), randid.New()[:8], ext)
	return filepath.Join(dir, name), nil
}

// existAsAlreadyExists maps a refused exclusive create (an error wrapping
// fs.ErrExist, as every qcow2.Create* returns for an existing path) to
// AlreadyExists; any other error is returned unchanged.
func existAsAlreadyExists(err error) error {
	if err != nil && errors.Is(err, fs.ErrExist) {
		return status.Errorf(codes.AlreadyExists, "%v", err)
	}
	return err
}

// placeNoClobber makes tmp visible as dst only if nothing is at dst. The
// rename itself refuses (RENAME_NOREPLACE), so a file created between a check
// and the rename is not replaced either.
func placeNoClobber(tmp, dst string) error {
	if err := renameNoReplace(tmp, dst); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return status.Errorf(codes.AlreadyExists, "%q already exists; a restore or copy never replaces a file", dst)
		}
		return status.Errorf(codes.Internal, "place %q: %v", dst, err)
	}
	return nil
}

// place publishes tmp at the destination: over the record's disk for an
// in-place restore, otherwise only where nothing is.
func (d restoreDest) place(tmp string) error {
	if !d.inPlace {
		return placeNoClobber(tmp, d.path)
	}
	if err := refuseSymlinkTarget(d.path); err != nil {
		return err
	}
	if err := os.Rename(tmp, d.path); err != nil {
		return status.Errorf(codes.Internal, "finalize restore: %v", err)
	}
	return nil
}

// stagingTemp creates an empty temp file beside dst for a restore to fill. The
// "restore-" prefix is one SweepStaleStaging collects after a crash.
func stagingTemp(dst string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", status.Errorf(codes.Internal, "mkdir: %v", err)
	}
	f, err := os.CreateTemp(filepath.Dir(dst), "restore-*.tmp")
	if err != nil {
		return "", status.Errorf(codes.Internal, "create restore temp: %v", err)
	}
	name := f.Name()
	_ = f.Close()
	return name, nil
}

// inPlaceRestoreTarget resolves the one destination a restore may replace: the
// disk diskName of VM vmName, from its record. The VM must be in the project
// the restore was authorized against, on this host, and stopped, and the file
// must be that disk's alone. The VM stays locked until the caller releases the
// destination, so it cannot be started underneath the restore.
func (s *Server) inPlaceRestoreTarget(ctx context.Context, vmName, diskName, authProject string) (restoreDest, error) {
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil {
		return restoreDest{}, status.Errorf(codes.Internal, "read vm %q: %v", vmName, err)
	}
	if vm == nil {
		return restoreDest{}, status.Errorf(codes.NotFound, "in_place: vm %q has no record to restore into", vmName)
	}
	if tenancy.NormalizeProject(vm.Project) != tenancy.NormalizeProject(authProject) {
		return restoreDest{}, status.Errorf(codes.PermissionDenied,
			"in_place: the backup belongs to project %q and vm %q to project %q; a restore never replaces another project's disk",
			tenancy.NormalizeProject(authProject), vmName, tenancy.NormalizeProject(vm.Project))
	}
	if vm.HostName != s.hostName {
		return restoreDest{}, status.Errorf(codes.FailedPrecondition,
			"in_place: vm %q lives on %q; run the restore there", vmName, vm.HostName)
	}
	unlock := s.lockVM(vmName)
	d, err := s.inPlaceRestoreLocked(ctx, vmName, diskName)
	if err != nil {
		unlock()
		return restoreDest{}, err
	}
	d.unlock = unlock
	return d, nil
}

func (s *Server) inPlaceRestoreLocked(ctx context.Context, vmName, diskName string) (restoreDest, error) {
	// Re-read under the lock: the state that matters is the one the restore
	// runs against.
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		return restoreDest{}, status.Errorf(codes.Unavailable, "in_place: re-read vm %q: %v", vmName, err)
	}
	if !s.vmDisksClosed(vm) {
		return restoreDest{}, status.Errorf(codes.FailedPrecondition,
			"in_place: vm %q is %s; stop it before restoring over its disk", vmName, vm.State)
	}
	if snaps, serr := corrosion.ListSnapshots(ctx, s.db, vmName); serr != nil {
		return restoreDest{}, status.Errorf(codes.Unavailable, "in_place: list snapshots: %v", serr)
	} else if len(snaps) > 0 {
		return restoreDest{}, status.Errorf(codes.FailedPrecondition,
			"in_place: vm %q has %d snapshot(s); its disk is an overlay a restore would orphan — remove them first", vmName, len(snaps))
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		return restoreDest{}, status.Errorf(codes.Internal, "list disks: %v", err)
	}
	var disk *corrosion.DiskRecord
	for i := range disks {
		if disks[i].DiskName == diskName {
			disk = &disks[i]
			break
		}
	}
	if disk == nil {
		return restoreDest{}, status.Errorf(codes.NotFound, "in_place: vm %q has no disk %q", vmName, diskName)
	}
	if !isFileBasedDriver(disk.StorageType) {
		return restoreDest{}, status.Errorf(codes.FailedPrecondition,
			"in_place: disk %q is on %q storage, not a file a restore can replace", diskName, disk.StorageType)
	}
	if disk.HostName != "" && disk.HostName != s.hostName {
		return restoreDest{}, status.Errorf(codes.FailedPrecondition, "in_place: disk %q is on host %q", diskName, disk.HostName)
	}
	if !filepath.IsAbs(disk.Path) {
		return restoreDest{}, status.Errorf(codes.FailedPrecondition, "in_place: disk %q has no file path on record", diskName)
	}
	// A disk in a pool is written only through the one pool write check —
	// a refused pool (shared, weakly mounted, a legacy area) takes no restore.
	if disk.StorageVolume != "" {
		ref, ok := s.resolvePool(ctx, disk.StorageVolume)
		if !ok {
			return restoreDest{}, status.Errorf(codes.FailedPrecondition, "in_place: disk %q's pool %q is not configured on this host", diskName, disk.StorageVolume)
		}
		if err := s.checkPoolForWrite(ctx, disk.StorageVolume, ref); err != nil {
			return restoreDest{}, err
		}
	}
	fi, err := os.Lstat(disk.Path)
	if err != nil {
		return restoreDest{}, status.Errorf(codes.FailedPrecondition, "in_place: disk file %q: %v", disk.Path, err)
	}
	if !fi.Mode().IsRegular() {
		return restoreDest{}, status.Errorf(codes.FailedPrecondition, "in_place: disk file %q is not a regular file", disk.Path)
	}
	// The file must be this disk's alone: never a base another disk is backed
	// by, on this host or any other (shared storage).
	owners, err := s.diskReferencesAnyHost(ctx, disk.Path)
	if err != nil {
		return restoreDest{}, status.Errorf(codes.Internal, "check disk use: %v", err)
	}
	for _, o := range owners {
		if o.VMName != vmName || o.DiskName != diskName {
			return restoreDest{}, status.Errorf(codes.FailedPrecondition,
				"in_place: %q is also used by vm %q disk %q; a restore never replaces it", disk.Path, o.VMName, o.DiskName)
		}
	}
	return restoreDest{path: disk.Path, inPlace: true}, nil
}

// vmDisksClosed reports whether nothing holds vm's disks open: the record says
// stopped and, when libvirt knows the domain, it is genuinely shut off. With no
// libvirt connection it cannot be established, so it is false.
func (s *Server) vmDisksClosed(vm *corrosion.VMRecord) bool {
	if vm.State != "stopped" || s.virt == nil {
		return false
	}
	if !s.virt.DomainExists(vm.Name) {
		return true
	}
	return s.sourceIsShutOff(vm)
}

// inPlaceContentAccepted refuses, before any byte is restored, an in-place
// restore from a backup whose content format is not recorded: the bytes are
// written back as a VM disk, and what they ARE decides how.
func inPlaceContentAccepted(m *pbsstore.Manifest) error {
	switch m.ContentFormat {
	case pbsstore.ContentGuestRaw, pbsstore.ContentDiskFile:
		return nil
	case "":
		return status.Error(codes.FailedPrecondition,
			"in_place: this backup does not record what its bytes are (it predates content formats); restore it to a new file instead")
	default:
		return status.Errorf(codes.FailedPrecondition, "in_place: unknown backup content format %q", m.ContentFormat)
	}
}

// diskImageFromBackup turns restored backup bytes into a NEW standalone qcow2
// beside dir — the format libvirt opens every file disk as — and returns its
// path. Backup bytes are never placed as a disk directly.
//
// A guest-content backup is raw guest bytes, and the guest controls all of
// them: placed as-is under a disk libvirt opens as qcow2, a guest-written
// qcow2 header with a backing file would make qemu read whatever file the
// guest named (another project's disk). So the bytes are converted with the
// source format NAMED (-f raw, never probed) into a fresh image, and the
// result must name no backing or external data file before it is used.
//
// A disk-file backup is the disk's own image file. It must parse as qcow2;
// a backing file it names must be a qcow2 base in this host's image store
// (a VM created from an image), and it is flattened (-f qcow2) into a fresh
// standalone image the same way.
func (s *Server) diskImageFromBackup(ctx context.Context, contentFormat, restored, dir string) (string, error) {
	var srcFormat string
	switch contentFormat {
	case pbsstore.ContentGuestRaw:
		srcFormat = "raw"
	case pbsstore.ContentDiskFile:
		// The container's header is judged BEFORE qemu-img opens it: no
		// external data file (qemu-img would copy whatever file it names
		// into a perfectly standalone output), one backing format, and a
		// backing file only as a standalone qcow2 base inside this host's
		// image store, resolved through symlinks.
		if err := precheckQcow2Input(restored, imageStoreBaseOnly(s.dataDir)); err != nil {
			return "", status.Errorf(codes.FailedPrecondition, "in_place: the backed-up disk file is refused: %v", err)
		}
		srcFormat = "qcow2"
	default:
		return "", inPlaceContentAccepted(&pbsstore.Manifest{ContentFormat: contentFormat})
	}
	if !qemuImgAvailable() {
		return "", status.Error(codes.FailedPrecondition, "in_place: qemu-img is required to rebuild the disk image")
	}
	f, err := os.CreateTemp(dir, "restore-*.tmp")
	if err != nil {
		return "", status.Errorf(codes.Internal, "create image temp: %v", err)
	}
	out := f.Name()
	_ = f.Close()
	cmd := exec.CommandContext(ctx, "qemu-img", "convert", "-f", srcFormat, "-O", "qcow2", restored, out)
	if msg, err := cmd.CombinedOutput(); err != nil {
		_ = os.Remove(out)
		return "", status.Errorf(codes.Internal, "in_place: qemu-img convert: %v: %s", err, strings.TrimSpace(string(msg)))
	}
	if err := qcow2.AssertStandalone(out); err != nil {
		_ = os.Remove(out)
		return "", status.Errorf(codes.FailedPrecondition, "in_place: the rebuilt image is not standalone: %v", err)
	}
	return out, nil
}

// diskReferencesAnyHost returns every disk row, on ANY host, that uses path —
// as its own file, a backing image or a linked clone's base. vm_disks is
// replicated, so on shared storage a VM another host runs is seen here too;
// liveDiskOwners' this-host filter is right for a host-local directory and
// wrong for a replica or a restore target another host may be reading.
//
// A row matches in either of two ways:
//   - by path: the path as given, or as resolved through symlinks here;
//   - by pool: path lies in one of this host's file-based pools, and the row
//     names the same file relative to the SAME pool as another host has it —
//     a pool on shared storage can be mounted at /mnt/dr on one host and
//     /srv/dr on another (poolIdentity). Where the other host's pool
//     directory cannot be told from its row, the row is taken as a match:
//     a false match keeps a file, a missed one deletes a running VM's disk.
func (s *Server) diskReferencesAnyHost(ctx context.Context, path string) ([]corrosion.DiskRecord, error) {
	paths := []string{filepath.Clean(path)}
	if r, err := filepath.EvalSymlinks(path); err == nil && r != paths[0] {
		paths = append(paths, r)
	}
	var out []corrosion.DiskRecord
	seen := map[string]bool{}
	add := func(d corrosion.DiskRecord) {
		k := d.HostName + "\x00" + d.VMName + "\x00" + d.DiskName
		if !seen[k] {
			seen[k] = true
			out = append(out, d)
		}
	}
	for _, p := range paths {
		rows, err := corrosion.DisksReferencingPath(ctx, s.db, p)
		if err != nil {
			return nil, err
		}
		for _, d := range rows {
			add(d)
		}
	}
	id, rel, ok, err := s.poolRelativePath(ctx, path)
	if err != nil {
		return nil, err
	}
	if !ok {
		return out, nil
	}
	rows, err := corrosion.DisksReferencingPathSuffix(ctx, s.db, rel)
	if err != nil {
		return nil, err
	}
	pools := map[string][]corrosion.StoragePoolRecord{}
	for _, d := range rows {
		if d.HostName == "" || seen[d.HostName+"\x00"+d.VMName+"\x00"+d.DiskName] {
			continue
		}
		hp, have := pools[d.HostName]
		if !have {
			if hp, err = corrosion.ListStoragePoolsForHost(ctx, s.db, d.HostName); err != nil {
				return nil, err
			}
			pools[d.HostName] = hp
		}
		for _, ref := range []string{d.Path, d.BackingImage, d.BackingDisk} {
			prefix, cut := strings.CutSuffix(filepath.Clean(ref), "/"+rel)
			if ref == "" || !cut {
				continue
			}
			if samePoolOnHost(hp, id, prefix) {
				add(d)
				break
			}
		}
	}
	return out, nil
}

// poolIdentity names a pool across hosts: an NFS pool by its export
// (storage.NFSExportKey), any other by its name and project.
func poolIdentity(p corrosion.StoragePoolRecord) string {
	if strings.EqualFold(p.Driver, "nfs") {
		return "nfs:" + storage.NFSExportKey(p.Source)
	}
	return "pool:" + p.Name + "\x00" + tenancy.NormalizeProject(p.Project)
}

// poolRelativePath finds the file-based pool on this host that holds path and
// returns its identity and path's location relative to the pool directory.
func (s *Server) poolRelativePath(ctx context.Context, path string) (id, rel string, ok bool, err error) {
	rows, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName)
	if err != nil {
		return "", "", false, err
	}
	for _, r := range rows {
		if !isFileBasedDriver(r.Driver) {
			continue
		}
		dir, derr := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: r.Driver, Source: r.Source, Target: r.Target})
		if derr != nil {
			continue
		}
		if rl, rerr := filepath.Rel(filepath.Clean(dir), filepath.Clean(path)); rerr == nil && rl != "." && !strings.HasPrefix(rl, "..") {
			return poolIdentity(r), rl, true, nil
		}
	}
	return "", "", false, nil
}

// samePoolOnHost reports whether one of a host's pools is the pool id and
// could be mounted at prefix there. A pool whose directory comes from that
// host's own data_dir (no Target) cannot be told apart, so it matches.
func samePoolOnHost(pools []corrosion.StoragePoolRecord, id, prefix string) bool {
	for _, p := range pools {
		if !isFileBasedDriver(p.Driver) || poolIdentity(p) != id {
			continue
		}
		dir := p.Target
		if strings.EqualFold(p.Driver, "btrfs") {
			dir = p.Source
		}
		if dir == "" || filepath.Clean(dir) == filepath.Clean(prefix) {
			return true
		}
	}
	return false
}
