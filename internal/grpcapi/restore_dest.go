package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/cmdbound"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/diskmode"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/pitoverlay"
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
//     a refusal, for an admin too, unless it is exactly the destination VM's
//     own recorded disk file, which RestoreFromBackup restores as in_place;
//   - in place, the disk the VM's own record names, for a VM in the backup's
//     project that is stopped on this host. This is the only destination a
//     restore replaces, and its path comes from the record, never the request.

// restoreDest is a resolved restore destination. unlock, when set, releases
// the VM lock an in-place restore holds until the file is placed.
type restoreDest struct {
	path    string
	inPlace bool
	unlock  func()
	// disk is the record of the disk an in-place restore replaces. The
	// rebuilt image keeps the disk's OWN backing, judged by the disk's chain
	// rule, never taken from the backup's bytes.
	disk *corrosion.DiskRecord
	// setAside, for an in-place restore over a disk held on an overlay that
	// cannot be verified, sets that overlay aside AFTER the restored image
	// has been placed over the disk, and returns the report to make — the
	// hold cleared, the event, the notification. Placing first means no
	// moment exists, crash or not, at which the overlay is gone while the
	// old disk is still there: a restore that fails before placement, or a
	// crash between the placement and the set-aside, leaves the overlay
	// beside the disk, and the VM held (P1, and m1 of the switch review: the
	// overlay was taken of another file than the restored one, so it is never
	// committed into it; it is only set aside).
	setAside func() (done func(), err error)
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

// resolveRestoreFromTarget is resolveAdminTarget for RestoreFromBackup: an
// admin's target_path that already exists is refused, except when it is
// exactly the recorded file of disk diskName of VM vmName on this host —
// main (3e4ba50b) restored over a named file, and the VM's own disk is the
// one file a restore may replace. ownDisk reports that case, which the
// caller restores as in_place does, with all of its checks.
func (s *Server) resolveRestoreFromTarget(ctx context.Context, targetPath, defaultDir, vmName, diskName string) (target string, ownDisk bool, err error) {
	if err := s.requireAdminTargetPath(ctx); err != nil {
		return "", false, err
	}
	if target, err = s.resolveRestoreTarget(ctx, targetPath, defaultDir); err != nil {
		return "", false, err
	}
	eerr := refuseExistingFile(target)
	if eerr == nil || status.Code(eerr) != codes.AlreadyExists {
		return target, false, eerr
	}
	disks, derr := corrosion.GetVMDisks(ctx, s.db, vmName)
	if derr != nil {
		return "", false, status.Errorf(codes.Internal, "list disks: %v", derr)
	}
	for _, d := range disks {
		if d.DiskName == diskName && (d.HostName == "" || d.HostName == s.hostName) &&
			filepath.IsAbs(d.Path) && filepath.Clean(d.Path) == filepath.Clean(target) {
			return target, true, nil
		}
	}
	return "", false, existingTargetRefusal(target)
}

// existingTargetRefusal is the refusal of a restore target_path that already
// exists and is not the VM's own disk.
func existingTargetRefusal(path string) error {
	return status.Errorf(codes.AlreadyExists,
		"%q already exists; a restore never replaces a file it is merely given — to restore over the VM's own disk, use --in-place (in_place), which takes the file from the VM's record", path)
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
// placement itself refuses (noReplacePlace: renameat2 RENAME_NOREPLACE, or a
// hard link where the filesystem cannot do the flag, as on NFS), so a file
// created between a check and the placement is not replaced either.
func placeNoClobber(tmp, dst string) error {
	unsupported, err := noReplacePlace(tmp, dst, false, "placed a file by a hard link but could not remove its temporary name")
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrExist):
		return status.Errorf(codes.AlreadyExists, "%q already exists; a restore or copy never replaces a file", dst)
	case unsupported:
		return status.Errorf(codes.FailedPrecondition, "place %q: %v; a file is never placed with a rename that could overwrite one", dst, err)
	}
	return status.Errorf(codes.Internal, "place %q: %v", dst, err)
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
	if d.setAside != nil {
		// The placement is durable before the overlay moves: a crash can
		// never leave the overlay moved and the old disk still in place.
		syncDir(filepath.Dir(d.path))
		restorePlaceStep("placed")
		done, err := d.setAside()
		if err != nil {
			// The restore is in place; the overlay stays beside it, bound
			// to the file it replaced, so the VM stays held (never
			// committed into the restored disk) until it is set aside.
			slog.Error("restore: the restored disk is in place, but its old point-in-time overlay could not be set aside; the VM stays held", "disk", d.path, "error", err)
			return &placedButHeldError{disk: d.path, err: err}
		}
		done()
	}
	return nil
}

// placedButHeldError is an in-place placement that succeeded while the old
// point-in-time overlay beside the disk could not be set aside: the restored
// disk is in place, and the VM stays held on that overlay (N5 of the switch
// re-review). The restore reports it instead of "restore complete".
type placedButHeldError struct {
	disk string
	err  error
}

func (e *placedButHeldError) Error() string {
	return fmt.Sprintf("restored in place over %s, but its old point-in-time overlay %s could not be set aside (%v): the VM stays held on it. Re-run the restore, or decide the overlay with `lv resolve-pit-overlay <vm> <disk>` (normally --discard: it was taken of the file the restore replaced)",
		e.disk, pitoverlay.Path(e.disk), e.err)
}

// pitSetAside is pitoverlay.SetAside; a test makes it fail.
var pitSetAside = pitoverlay.SetAside

// restorePlaceStep marks a step of an in-place placement; a test makes it
// crash there.
var restorePlaceStep = func(string) {}

// stagingTemp creates an empty temp file beside dst for a restore to fill. The
// "restore-" prefix is one SweepStaleStaging collects after a crash.
func stagingTemp(dst string) (string, error) {
	if err := diskmode.MkdirAll(filepath.Dir(dst)); err != nil {
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
	// The disk is replaced before its backing record is cleared, which a
	// host in write quarantine cannot record (quarantine_lifecycle.go).
	if err := s.quarantinedLifecycleRefusal("restore over", fmt.Sprintf("disk %q of VM %q", diskName, vmName),
		"the disk would be replaced while the cluster keeps the backing record of the old one",
		"lv backup restore-from --in-place", false); err != nil {
		return restoreDest{}, err
	}
	unlock := s.lockVMAs(vmName, "restore")
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
	// A point-in-time overlay beside the disk is settled before the restore
	// writes over the disk: committed if it is this disk's as it is, else set
	// aside — never committed later over the restored contents.
	dest := restoreDest{path: disk.Path, inPlace: true, disk: disk}
	if err := s.healPITOverlay(ctx, vm, disk); err != nil {
		// A held overlay cannot be committed, and the restore is about to
		// replace the disk it was taken of: it is set aside (kept, never
		// deleted) so it can never meet the restored disk. That is the
		// advice a hold gives for a disk that cannot be trusted. It happens
		// at place time, when the restored image is ready: a restore that
		// fails before then (a missing chunk, a cancel) leaves the overlay
		// where it is and the VM held (P1).
		if serr := s.heldOverlayCanBeSetAside(vm, disk, err); serr != nil {
			return restoreDest{}, status.Errorf(codes.FailedPrecondition, "in_place: %v", serr)
		}
		dest.setAside = func() (func(), error) {
			return s.setAsideHeldOverlayForRestore(ctx, vm, disk, err)
		}
	}
	return dest, nil
}

// heldOverlayCanBeSetAside reports whether an in-place restore may set
// disk's overlay aside: heal failed with a hold, an overlay is there, and the
// VM is not running. Anything else is refused (heldErr).
func (s *Server) heldOverlayCanBeSetAside(vm *corrosion.VMRecord, disk *corrosion.DiskRecord, heldErr error) error {
	if status.Code(heldErr) != codes.FailedPrecondition || !pitoverlay.Present(s.hostDiskFile(disk.Path)) || s.domainActivity(vm) != activityInactive {
		return heldErr
	}
	return nil
}

// setAsideHeldOverlayForRestore sets aside disk's overlay that held the VM
// (heal failed with held), once an in-place restore has placed its image over
// the disk. It returns the report to make — the hold cleared, the event and
// the notification. The checks are made again here (heldOverlayCanBeSetAside).
func (s *Server) setAsideHeldOverlayForRestore(ctx context.Context, vm *corrosion.VMRecord, disk *corrosion.DiskRecord, heldErr error) (done func(), err error) {
	if err := s.heldOverlayCanBeSetAside(vm, disk, heldErr); err != nil {
		return nil, err
	}
	// The definition is pointed at the restored disk BEFORE the overlay
	// moves (P-1 of lab 2 run c2: without it the VM could not start). A
	// crash between the two leaves the overlay beside the disk, still bound
	// to the file the restore replaced: the VM stays held, the overlay is
	// never committed into the restored disk, and re-running the restore
	// sets it aside. The other order would leave, on a crash, a definition
	// naming a missing overlay and no hold (repointDanglingPITDefinition
	// still recovers that on the next start).
	if err := s.pointPITDefinitionAtDisk(vm, disk); err != nil {
		return nil, fmt.Errorf("%v; and pointing the definition back at the restored disk: %w", heldErr, err)
	}
	restorePlaceStep("repointed")
	path := s.hostDiskFile(disk.Path)
	to, err := pitSetAside(path, time.Now().UTC().Format("20060102-150405"))
	if err != nil {
		if to != "" {
			// The overlay moved, its binding did not: put it back, so the
			// pair stays together beside the disk (and the VM held).
			if perr := pitoverlay.PutBack(path, to); perr != nil {
				return nil, fmt.Errorf("%v; and setting the overlay aside for the restore: %v; and putting it back: %w", heldErr, err, perr)
			}
		}
		return nil, fmt.Errorf("%v; and setting the overlay aside for the restore: %w", heldErr, err)
	}
	return func() {
		detail := fmt.Sprintf("%s: the in-place restore replaced the disk %s; its point-in-time overlay, which could not be verified, was set aside as %s (with its binding as %s.id), kept, so it never meets the restored disk. Inspect it, then delete it",
			disk.DiskName, path, to, to)
		slog.Warn("restore: point-in-time overlay set aside", "vm", vm.Name, "detail", detail)
		s.ClearPITOverlayHold(ctx, vm.Name, disk.DiskName)
		s.recordVMEventSeverity(ctx, vm.Name, "disk.pit_overlay_set_aside", "warning", "warn", detail)
		s.notify(ctx, notify.Notification{Kind: "replication.pit_overlay_set_aside", Severity: notify.SevWarn, Subject: vm.Name, Detail: detail})
	}, nil
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
		if msg, err := cmdbound.CombinedOutput(ctx, cmdbound.Command(ctx, "qemu-img", "convert", "-f", "raw", "-O", "qcow2", restored, out)); err != nil {
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
	// Backed or not is the backup's own header: a standalone backup is
	// restored standalone, an overlay onto the disk's own (verified) base.
	rinfo, err := qcow2.Info(restored)
	if err != nil {
		return fail(codes.FailedPrecondition, "in_place: the backed-up disk file is refused: %v", err)
	}
	if rinfo.BackingFile == "" {
		if msg, err := cmdbound.CombinedOutput(ctx, cmdbound.Command(ctx, "qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", restored, out)); err != nil {
			return fail(codes.Internal, "in_place: qemu-img convert: %v: %s", err, strings.TrimSpace(string(msg)))
		}
		if err := qcow2.AssertStandalone(out); err != nil {
			return fail(codes.FailedPrecondition, "in_place: the rebuilt image is not standalone: %v", err)
		}
		return out, nil
	}
	// An overlay backup of a disk that is standalone now (a move flattened it
	// since): rebuild the disk FLAT from the backup and the base it was taken
	// on, when that base is recorded, still there and unchanged.
	if cur, cerr := qcow2.Info(dest.disk.Path); cerr == nil && cur.BackingFile == "" {
		base, baseFmt, err := s.recordedBackupBase(ctx, dest, m)
		if err != nil {
			return fail(codes.FailedPrecondition, "in_place: %v; restoring it to a new file still works", err)
		}
		if msg, err := cmdbound.CombinedOutput(ctx, cmdbound.Command(ctx, "qemu-img", "rebase", "-u", "-f", "qcow2", "-b", base, "-F", baseFmt, restored)); err != nil {
			return fail(codes.Internal, "in_place: qemu-img rebase: %v: %s", err, strings.TrimSpace(string(msg)))
		}
		if err := namesExactly(restored, base, baseFmt); err != nil {
			return fail(codes.FailedPrecondition, "in_place: the re-pointed disk file is refused: %v", err)
		}
		if err := s.judgeRepointedChain(ctx, restored, base, baseFmt, *dest.disk); err != nil {
			code := codes.FailedPrecondition
			if storage.IsFSNoAnswer(err) {
				code = codes.Unavailable
			}
			return fail(code, "in_place: the re-pointed disk file is refused: %v", err)
		}
		if msg, err := cmdbound.CombinedOutput(ctx, cmdbound.Command(ctx, "qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", restored, out)); err != nil {
			return fail(codes.Internal, "in_place: qemu-img convert: %v: %s", err, strings.TrimSpace(string(msg)))
		}
		if err := qcow2.AssertStandalone(out); err != nil {
			return fail(codes.FailedPrecondition, "in_place: the rebuilt image is not standalone: %v", err)
		}
		return out, nil
	}
	backing, backingFmt, err := s.originalDiskBacking(ctx, dest, m)
	if err != nil {
		return fail(codes.FailedPrecondition, "in_place: %v", err)
	}
	// Re-point the bytes' header to the disk's own backing WITHOUT opening
	// what the header named (-u), confirm the header now names exactly that,
	// and only then let qemu-img read the chain.
	if msg, err := cmdbound.CombinedOutput(ctx, cmdbound.Command(ctx, "qemu-img", "rebase", "-u", "-f", "qcow2", "-b", backing, "-F", backingFmt, restored)); err != nil {
		return fail(codes.Internal, "in_place: qemu-img rebase: %v: %s", err, strings.TrimSpace(string(msg)))
	}
	if err := namesExactly(restored, backing, backingFmt); err != nil {
		return fail(codes.FailedPrecondition, "in_place: the re-pointed disk file is refused: %v", err)
	}
	if msg, err := cmdbound.CombinedOutput(ctx, cmdbound.Command(ctx, "qemu-img", "convert", "-f", "qcow2", "-O", "qcow2",
		"-B", backing, "-F", backingFmt, restored, out)); err != nil {
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

// originalDiskBacking returns the backing, and its format, that an in-place
// restore of an overlay backup rebuilds onto. Nothing of it comes from the
// backup, and nothing from guest bytes:
//   - the path is the CURRENT disk's own header's backing, resolved through
//     symlinks and accepted by the disk's chain rule (diskChainRule): the
//     image store, a pool the VM's project may use, the backing_disk the
//     record names, or a file the project owns by record;
//   - the disk record, where it names a backing (backing_disk, backing_image),
//     must agree with it — a record a move left stale is a refusal, not a
//     choice;
//   - the format comes from a record: a recorded replica's own format, qcow2
//     for an image-store image or another VM's disk (a linked clone's base).
//     Anything else is unknown and refused; the current header must declare
//     the same format;
//   - the base must be the one the backup was taken on (m.BaseIdentity:
//     path, size, sha256). A backup that predates that record is accepted on
//     a base that cannot change under its name — a recorded replica or
//     another VM's disk — and on an image only when the image's own records
//     show it has not been replaced since the backup (imageUnchangedSince).
//
// A qcow2 base's own chain is pre-checked by the same rule down to a
// standalone base; a raw base is a leaf and is never interpreted.
func (s *Server) originalDiskBacking(ctx context.Context, dest restoreDest, m *pbsstore.Manifest) (string, string, error) {
	d := dest.disk
	if d == nil {
		return "", "", fmt.Errorf("no disk record")
	}
	cur, err := qcow2.Info(d.Path)
	if err != nil {
		return "", "", fmt.Errorf("the disk's current image %s cannot be read to find its backing: %w", d.Path, err)
	}
	if cur.BackingFile == "" {
		return "", "", fmt.Errorf("the backup is an overlay but disk %s is now standalone (flattened since); restore it to a new file instead", d.Path)
	}
	if looksLikeProtocol(cur.BackingFile) {
		return "", "", fmt.Errorf("the disk's backing %q is a protocol, not a file", cur.BackingFile)
	}
	cand := cur.BackingFile
	if !filepath.IsAbs(cand) {
		cand = filepath.Join(filepath.Dir(d.Path), cand)
	}
	resolved, err := filepath.EvalSymlinks(cand)
	if err != nil {
		return "", "", fmt.Errorf("the disk's backing %q: %w", cand, err)
	}
	images := filepath.Join(s.dataDir, "images")
	rule := s.diskChainRule(ctx, *d)
	self := resolvedOr(d.Path)

	// The record must agree — with what lies below the disk's own layers (the
	// bases a snapshot of it left), which is what the record names.
	agree := s.belowOwnLayers(ctx, *d, self, resolved)
	for what, rec := range map[string]string{"backing_disk": d.BackingDisk, "backing_image": d.BackingImage} {
		if rec == "" {
			continue
		}
		p := rec
		if what == "backing_image" && !filepath.IsAbs(p) {
			// An image name: any version of it the store has published (a
			// refresh never replaces the file a disk was built on).
			if image.IsImageFile(resolvedOr(images), strings.TrimSuffix(p, ".qcow2"), agree) {
				continue
			}
			p = filepath.Join(images, strings.TrimSuffix(p, ".qcow2")+".qcow2")
		}
		if r, err := filepath.EvalSymlinks(p); err != nil || r != agree {
			return "", "", fmt.Errorf("the disk's record (%s %q) disagrees with its image's backing %q; refusing to guess", what, rec, agree)
		}
	}

	// The format, from a record — or, for the replica under a VM an earlier
	// build promoted with --no-localize (no record of either), from the
	// daemon-made layout that ties it to this VM (legacyPromotedReplica).
	format, immutable, err := s.recordedBackingFormat(resolved, images)
	if err != nil && cur.BackingFormat == "qcow2" && s.newDiskChain(ctx, *d).snapshotBase(self, resolved) {
		// The base an external snapshot of this VM left (its own earlier
		// file, qcow2 as libvirt wrote the overlay on it).
		format, immutable, err = "qcow2", true, nil
	}
	if err != nil && (cur.BackingFormat == "raw" || cur.BackingFormat == "qcow2") && d.BackingDisk == "" &&
		s.newDiskChain(ctx, *d).legacyPromoted(self, resolved, cur.BackingFormat) {
		// The replica, raw or qcow2, under a VM main promoted with
		// --no-localize, on the bounds its start accepts it on
		// (diskChain.legacyPromoted). A replica is a point-in-time file: it
		// does not change under its name.
		format, immutable, err = cur.BackingFormat, true, nil
	}
	if err != nil {
		return "", "", err
	}
	if cur.BackingFormat != format {
		return "", "", fmt.Errorf("the disk declares its backing %q as %q, but its record says %q; refusing", resolved, cur.BackingFormat, format)
	}
	if err := rule(self, resolved, format); err != nil {
		return "", "", err
	}

	// The base must be the one the backup was taken on.
	if id := m.BaseIdentity; id != nil {
		got, err := baseFileIdentity(resolved)
		if err != nil {
			return "", "", fmt.Errorf("the disk's base %s: %w", resolved, err)
		}
		if got.Path != id.Path || got.Size != id.Size || got.SHA256 != id.SHA256 {
			return "", "", fmt.Errorf("the base the backup was taken on (%s, %d bytes, sha256 %s) is not the disk's base now (%s, %d bytes, sha256 %s); the backup's delta would sit on different data",
				id.Path, id.Size, id.SHA256, got.Path, got.Size, got.SHA256)
		}
	} else if !immutable {
		if err := s.imageUnchangedSince(ctx, d, resolved, m.Timestamp); err != nil {
			return "", "", fmt.Errorf("this backup does not record the identity of its base %s, and %v; restore it to a new file instead", resolved, err)
		}
	}

	if format == "qcow2" {
		if _, err := precheckChain(resolved, rule); err != nil {
			return "", "", fmt.Errorf("the disk's backing chain is refused: %w", err)
		}
	} else if fi, err := os.Lstat(resolved); err != nil || !fi.Mode().IsRegular() {
		return "", "", fmt.Errorf("the disk's raw backing %q is not a regular file", resolved)
	}
	return resolved, format, nil
}

// judgeRepointedChain judges the chain of restored, re-pointed at exactly
// the recorded base (base, baseFmt): its top layer must name exactly that
// base, and every layer below is judged by disk's own rule. Which layer is
// the top is resolved strictly (resolvedStrict): a form taken as given on no
// answer would route the top to the disk's broader rule, which may admit
// more than exactly the recorded base (re-review 4, R4-M1). A resolution
// that does not answer is the error.
func (s *Server) judgeRepointedChain(ctx context.Context, restored, base, baseFmt string, disk corrosion.DiskRecord) error {
	top, err := resolvedStrict(restored)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", restored, err)
	}
	rule := s.diskChainRule(ctx, disk)
	_, err = precheckChain(restored, func(layer, resolved, format string) error {
		if layer == top {
			if resolved != base || format != baseFmt {
				return fmt.Errorf("%s names %q (%s), not the recorded base %q (%s)", layer, resolved, format, base, baseFmt)
			}
			return nil
		}
		return rule(layer, resolved, format)
	})
	return err
}

// belowOwnLayers follows resolved, the backing of d's file self, down through
// d's own layers — the bases a snapshot of d's VM left (snapshotBase), each a
// regular qcow2 file — and returns the first backing that is not one: the
// file d's record names. A layer whose header cannot be read ends the walk
// there (the record is then compared with it, and disagrees).
func (s *Server) belowOwnLayers(ctx context.Context, d corrosion.DiskRecord, self, resolved string) string {
	c := s.newDiskChain(ctx, d)
	cur := resolved
	for i := 0; i < maxBackingDepth && c.snapshotBase(self, cur); i++ {
		fi, err := os.Lstat(cur)
		if err != nil || !fi.Mode().IsRegular() {
			return cur
		}
		info, err := qcow2.Info(cur)
		if err != nil || info.BackingFile == "" || looksLikeProtocol(info.BackingFile) {
			return cur
		}
		next := info.BackingFile
		if !filepath.IsAbs(next) {
			next = filepath.Join(filepath.Dir(cur), next)
		}
		r, err := filepath.EvalSymlinks(next)
		if err != nil {
			return cur
		}
		cur = r
	}
	return cur
}

// recordedBackupBase is the base an overlay backup was taken on, for
// rebuilding a disk that has been flattened since: the manifest's
// BaseIdentity, never the backup's header — and the manifest's path is never
// trusted on its own: the base must still exist, be accepted by the disk's
// chain rule (the image store, a pool the VM's project may use, a file the
// project owns by record), and match the recorded size and sha256; its format
// comes from a record (recordedBackingFormat); a qcow2 base's own chain is
// pre-checked by the same rule.
func (s *Server) recordedBackupBase(ctx context.Context, dest restoreDest, m *pbsstore.Manifest) (string, string, error) {
	id := m.BaseIdentity
	if id == nil {
		return "", "", fmt.Errorf("the backup is an overlay, disk %s is now standalone (flattened since), and the backup does not record the base it was taken on", dest.disk.Path)
	}
	resolved, err := filepath.EvalSymlinks(id.Path)
	if err != nil {
		return "", "", fmt.Errorf("the base the backup was taken on (%s) is gone: %w", id.Path, err)
	}
	got, err := baseFileIdentity(resolved)
	if err != nil {
		return "", "", fmt.Errorf("the base the backup was taken on (%s): %w", resolved, err)
	}
	if got.Path != id.Path || got.Size != id.Size || got.SHA256 != id.SHA256 {
		return "", "", fmt.Errorf("the base the backup was taken on (%s, %d bytes, sha256 %s) has changed (%s, %d bytes, sha256 %s)",
			id.Path, id.Size, id.SHA256, got.Path, got.Size, got.SHA256)
	}
	// Where it is first: the disk's chain rule, as for a qcow2 layer (a
	// flattened disk's record names no backing_disk any more, so no record
	// link applies).
	rule := s.diskChainRule(ctx, *dest.disk)
	if err := rule(resolvedOr(dest.disk.Path), resolved, "qcow2"); err != nil {
		return "", "", err
	}
	format, _, err := s.recordedBackingFormat(resolved, filepath.Join(s.dataDir, "images"))
	if err != nil {
		return "", "", err
	}
	if format == "raw" {
		// Raw only as the VM's own project's recorded replica: guest content
		// of that project, read as raw.
		rec, ok := replicaRecordFor(resolved)
		vm, verr := corrosion.GetVM(ctx, s.db, dest.disk.VMName)
		if !ok || verr != nil || vm == nil || tenancy.NormalizeProject(rec.Project) != tenancy.NormalizeProject(vm.Project) {
			return "", "", fmt.Errorf("the raw base the backup was taken on (%s) is not a replica of this VM's project", resolved)
		}
	}
	if format == "qcow2" {
		if _, err := precheckChain(resolved, rule); err != nil {
			return "", "", fmt.Errorf("the base's own chain is refused: %w", err)
		}
	}
	return resolved, format, nil
}

// imageUnchangedSince accepts, for a backup that does not record its base's
// identity (taken before manifests recorded it), the image-store base resolved
// of disk d only when THAT FILE's own provenance shows it unchanged since the
// backup (backupTS): it was published on this host no later than the backup,
// and its bytes still have the sha256 recorded for it. Since this build no
// store file is ever written over (only healed to its own recorded sha256), so
// the one way it can differ from the backup's base is an earlier build's
// overwrite after the backup, which moved its publish time. Refreshes of the
// image name — here or on any host — publish other files and change nothing
// here. An earlier build's file gets its provenance when first seen
// (imageFileProvenance). Any other case is an error saying why.
func (s *Server) imageUnchangedSince(ctx context.Context, d *corrosion.DiskRecord, resolved, backupTS string) error {
	images := resolvedOr(s.imageStore().ImageDir())
	name, ok := image.ImageNameOfFile(resolved)
	if !ok || !image.IsImageFile(images, name, resolved) {
		return fmt.Errorf("its base is not a file of any image in the store")
	}
	backup, err := time.Parse(time.RFC3339, backupTS)
	if err != nil {
		return fmt.Errorf("the backup's time %q cannot be read", backupTS)
	}
	prov, err := s.imageFileProvenance(ctx, name, resolved)
	if err != nil {
		return fmt.Errorf("image %q: the provenance of %s: %v", name, resolved, err)
	}
	if prov.PublishedAt.IsZero() {
		return fmt.Errorf("image %q's file %s has no recorded publish time", name, resolved)
	}
	if prov.PublishedAt.After(backup) {
		return fmt.Errorf("image %q's file %s was written here at %s, after the backup (%s), so it may have been replaced since",
			name, resolved, prov.PublishedAt.Format(time.RFC3339), backupTS)
	}
	got, err := image.FileDigest(resolved)
	if err != nil {
		return fmt.Errorf("image %q: %v", name, err)
	}
	if got != prov.SHA256 {
		return fmt.Errorf("image %q's file %s no longer matches its recorded sha256 (sha256 %s, recorded %s)", name, resolved, got, prov.SHA256)
	}
	return nil
}

// recordedBackingFormat is a base file's format from a RECORD, never from its
// bytes: a recorded replica's own format; qcow2 for an image in the image
// store or for a file a VM disk row names as its own disk (a linked clone's
// base). immutable reports a base that cannot be replaced under its name (a
// recorded replica, a VM's disk); an image can be.
func (s *Server) recordedBackingFormat(resolved, images string) (format string, immutable bool, err error) {
	if r, ok := replicaRecordFor(resolved); ok {
		return r.Format, true, nil
	}
	if confineTo(resolved, images) == nil {
		return "qcow2", false, nil
	}
	rows, rerr := corrosion.DisksReferencingPath(context.Background(), s.db, resolved)
	if rerr != nil {
		return "", false, rerr
	}
	for _, r := range rows {
		if p, e := filepath.EvalSymlinks(r.Path); e == nil && p == resolved {
			return "qcow2", true, nil
		}
	}
	return "", false, fmt.Errorf("the format of the disk's backing %q is not recorded anywhere (not a recorded replica, an image, or a VM disk); refusing to guess", resolved)
}

// baseFileIdentity is a file's resolved path, size and sha256.
func baseFileIdentity(path string) (*pbsstore.BaseIdentity, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return nil, err
	}
	return &pbsstore.BaseIdentity{Path: resolved, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// overlayBaseIdentity is the identity of the base an overlay disk file is on,
// for a disk-file backup's manifest; nil for a standalone disk (or one whose
// base cannot be read — the restore then treats it as unrecorded).
func overlayBaseIdentity(path string) *pbsstore.BaseIdentity {
	info, err := qcow2.Info(path)
	if err != nil || info.BackingFile == "" || looksLikeProtocol(info.BackingFile) {
		return nil
	}
	b := info.BackingFile
	if !filepath.IsAbs(b) {
		b = filepath.Join(filepath.Dir(path), b)
	}
	id, err := baseFileIdentity(b)
	if err != nil {
		return nil
	}
	return id
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
