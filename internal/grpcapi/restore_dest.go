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
	// disk and poolDir describe the disk an in-place restore replaces: its
	// record, and the directory of the pool it lives in (<data_dir>/disks for
	// a pool-less disk). The rebuilt image keeps the disk's OWN backing,
	// taken from these, never from the backup's bytes.
	disk    *corrosion.DiskRecord
	poolDir string
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
	poolDir := filepath.Join(s.dataDir, "disks")
	if disk.StorageVolume != "" {
		ref, _ := s.resolvePool(ctx, disk.StorageVolume)
		if d, derr := fileBasedPoolDir(s.dataDir, ref); derr == nil {
			poolDir = d
		}
	}
	return restoreDest{path: disk.Path, inPlace: true, disk: disk, poolDir: poolDir}, nil
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

// backupContentFormat is what a manifest's bytes are. A manifest written
// since content formats records it. One written before is classified from
// what the daemon itself wrote into it, never from the bytes: a guest-content
// backup (NBD) always establishes a checkpoint and records its BitmapName,
// while a disk-file backup (PushFile of a stopped VM's image) never does. A
// container archive is neither, and is refused.
func backupContentFormat(m *pbsstore.Manifest) (string, error) {
	switch m.ContentFormat {
	case pbsstore.ContentGuestRaw, pbsstore.ContentDiskFile:
		return m.ContentFormat, nil
	case "":
	default:
		return "", status.Errorf(codes.FailedPrecondition, "in_place: unknown backup content format %q", m.ContentFormat)
	}
	switch {
	case m.ContainerSpecJSON != "":
		return "", status.Error(codes.FailedPrecondition,
			"in_place: this is a container backup, not a VM disk; it cannot be restored over a disk")
	case m.BitmapName != "":
		return pbsstore.ContentGuestRaw, nil
	default:
		return pbsstore.ContentDiskFile, nil
	}
}

// inPlaceContentAccepted refuses, before any byte is restored, an in-place
// restore whose bytes cannot be told apart (backupContentFormat).
func inPlaceContentAccepted(m *pbsstore.Manifest) error {
	_, err := backupContentFormat(m)
	return err
}

// diskImageFromBackup turns restored backup bytes into a NEW qcow2 beside
// dir — the format libvirt opens every file disk as — and returns its path.
// Backup bytes are never placed as a disk directly, and qemu-img never probes.
//
// Raw guest content (-f raw) is the whole guest disk: the guest controls every
// byte, a planted qcow2 header included, so it is only ever read as raw, and
// the result is a standalone image.
//
// A disk-file backup is the disk's image file (-f qcow2). Its header is judged
// before qemu-img opens it (no external data file, one backing format). Its
// backing is then decided by the disk being REPLACED, not by the bytes:
//   - if that disk is backed — a linked clone, a --no-localize promotion, a
//     disk created from an image — the restored image is re-pointed to that
//     disk's own backing (originalDiskBacking: from its record, resolved,
//     inside the image store or the disk's pool directory, every layer
//     pre-checked down to a standalone base), and rebuilt as a fresh overlay
//     on it;
//   - if it is standalone, a backing the bytes name is accepted only as a
//     standalone base in the image store, and flattened.
func (s *Server) diskImageFromBackup(ctx context.Context, m *pbsstore.Manifest, restored string, dest restoreDest) (string, error) {
	format, err := backupContentFormat(m)
	if err != nil {
		return "", err
	}
	if !qemuImgAvailable() {
		return "", status.Error(codes.FailedPrecondition, "in_place: qemu-img is required to rebuild the disk image")
	}
	dir := filepath.Dir(dest.path)
	f, err := os.CreateTemp(dir, "restore-*.tmp")
	if err != nil {
		return "", status.Errorf(codes.Internal, "create image temp: %v", err)
	}
	out := f.Name()
	_ = f.Close()
	fail := func(code codes.Code, format string, a ...any) (string, error) {
		_ = os.Remove(out)
		return "", status.Errorf(code, format, a...)
	}

	if format == pbsstore.ContentGuestRaw {
		if msg, err := exec.CommandContext(ctx, "qemu-img", "convert", "-f", "raw", "-O", "qcow2", restored, out).CombinedOutput(); err != nil {
			return fail(codes.Internal, "in_place: qemu-img convert: %v: %s", err, strings.TrimSpace(string(msg)))
		}
		if err := qcow2.AssertStandalone(out); err != nil {
			return fail(codes.FailedPrecondition, "in_place: the rebuilt image is not standalone: %v", err)
		}
		return out, nil
	}

	// Disk file. Judge the bytes' own header first — without following the
	// backing file it names, which is not trusted.
	if err := precheckQcow2Header(restored); err != nil {
		return fail(codes.FailedPrecondition, "in_place: the backed-up disk file is refused: %v", err)
	}
	backing, backingFmt, err := s.originalDiskBacking(dest)
	if err != nil {
		return fail(codes.FailedPrecondition, "in_place: %v", err)
	}
	if backing == "" {
		if err := precheckQcow2Input(restored, imageStoreBaseOnly(s.dataDir)); err != nil {
			return fail(codes.FailedPrecondition, "in_place: the backed-up disk file is refused: %v", err)
		}
		if msg, err := exec.CommandContext(ctx, "qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", restored, out).CombinedOutput(); err != nil {
			return fail(codes.Internal, "in_place: qemu-img convert: %v: %s", err, strings.TrimSpace(string(msg)))
		}
		if err := qcow2.AssertStandalone(out); err != nil {
			return fail(codes.FailedPrecondition, "in_place: the rebuilt image is not standalone: %v", err)
		}
		return out, nil
	}
	// Re-point the bytes' header to the disk's own backing WITHOUT opening
	// what the header named (-u), confirm the header now names exactly that,
	// and only then let qemu-img read the chain.
	if msg, err := exec.CommandContext(ctx, "qemu-img", "rebase", "-u", "-f", "qcow2", "-b", backing, "-F", backingFmt, restored).CombinedOutput(); err != nil {
		return fail(codes.Internal, "in_place: qemu-img rebase: %v: %s", err, strings.TrimSpace(string(msg)))
	}
	if err := namesExactly(restored, backing, backingFmt); err != nil {
		return fail(codes.FailedPrecondition, "in_place: the re-pointed disk file is refused: %v", err)
	}
	if msg, err := exec.CommandContext(ctx, "qemu-img", "convert", "-f", "qcow2", "-O", "qcow2",
		"-B", backing, "-F", backingFmt, restored, out).CombinedOutput(); err != nil {
		return fail(codes.Internal, "in_place: qemu-img convert: %v: %s", err, strings.TrimSpace(string(msg)))
	}
	// The rebuilt overlay names exactly the disk's own backing, nothing else.
	if err := namesExactly(out, backing, backingFmt); err != nil {
		return fail(codes.FailedPrecondition, "in_place: the rebuilt image is refused: %v", err)
	}
	return out, nil
}

// namesExactly checks a qcow2 header that should name exactly backing (in
// backingFmt) and nothing else: no external data file, one backing format.
func namesExactly(path, backing, backingFmt string) error {
	if err := precheckQcow2Header(path); err != nil {
		return err
	}
	info, err := qcow2.Info(path)
	if err != nil {
		return err
	}
	if info.BackingFile != backing || info.BackingFormat != backingFmt {
		return fmt.Errorf("%s names backing %q (%q), want %q (%q)", path, info.BackingFile, info.BackingFormat, backing, backingFmt)
	}
	return nil
}

// originalDiskBacking returns the backing of the disk an in-place restore
// replaces and its format — "" for a standalone disk. It comes from the disk's
// RECORD (backing_disk: a linked clone's base or a --no-localize promotion's
// replica; backing_image: the image a disk was created from), else from the
// current file's own header — never from the backup. The format is the one the
// current disk declares (daemon-written; a raw replica is "raw"). The path is
// resolved through symlinks and must be inside the image store or the disk's
// own pool directory. A qcow2 backing's whole chain is pre-checked, every
// layer inside those directories, down to a standalone base; a raw backing is
// a leaf and is never interpreted.
func (s *Server) originalDiskBacking(dest restoreDest) (string, string, error) {
	d := dest.disk
	if d == nil {
		return "", "", fmt.Errorf("no disk record")
	}
	// The disk being replaced may be damaged — that is often why it is being
	// restored — so its header is consulted only when it still parses, and
	// only after the record.
	cur, _ := qcow2.Info(d.Path)
	if cur == nil {
		cur = &qcow2.ImageInfo{}
	}
	images := filepath.Join(s.dataDir, "images")
	var cand string
	switch {
	case d.BackingDisk != "":
		cand = d.BackingDisk
	case d.BackingImage != "":
		cand = d.BackingImage
		if !filepath.IsAbs(cand) {
			cand = filepath.Join(images, strings.TrimSuffix(cand, ".qcow2")+".qcow2")
		}
	case cur.BackingFile != "":
		cand = cur.BackingFile
		if !filepath.IsAbs(cand) {
			cand = filepath.Join(filepath.Dir(d.Path), cand)
		}
	default:
		return "", "", nil
	}
	format := cur.BackingFormat
	if format == "" {
		// No header to say (a damaged disk, or none declared): a backing the
		// daemon made in an allowed directory is qcow2 if it parses as one
		// (this package's parser, not a qemu-img probe), else raw.
		format = "raw"
		if r, err := filepath.EvalSymlinks(cand); err == nil {
			if _, err := qcow2.Info(r); err == nil {
				format = "qcow2"
			}
		}
	}
	if format != "qcow2" && format != "raw" {
		return "", "", fmt.Errorf("the disk's backing format %q is not qcow2 or raw", format)
	}
	var roots []string
	for _, r := range []string{images, dest.poolDir} {
		if rr, err := filepath.EvalSymlinks(r); err == nil {
			roots = append(roots, rr)
		}
	}
	within := func(resolved string) error {
		for _, r := range roots {
			if resolved != r && safename.Contains(r, resolved) {
				return nil
			}
		}
		return fmt.Errorf("backing %q is outside the image store and the disk's pool directory", resolved)
	}
	resolved, err := filepath.EvalSymlinks(cand)
	if err != nil {
		return "", "", fmt.Errorf("the disk's backing %q: %w", cand, err)
	}
	if err := within(resolved); err != nil {
		return "", "", err
	}
	if format == "qcow2" {
		if err := precheckQcow2Input(resolved, within); err != nil {
			return "", "", fmt.Errorf("the disk's backing chain is refused: %w", err)
		}
	} else if fi, err := os.Lstat(resolved); err != nil || !fi.Mode().IsRegular() {
		return "", "", fmt.Errorf("the disk's raw backing %q is not a regular file", resolved)
	}
	return resolved, format, nil
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
