package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/notify"
)

// SupersededNamedOnlySec is the older_than_sec a client sends with purge set
// alongside remove_paths or restore_path (service.proto, SupersededDisksRequest):
// about 285 years, so no copy is that old, and short enough that
// older_than_sec seconds still fit a time.Duration. An older host that does
// not know the named fields then requires admin and purges nothing.
const SupersededNamedOnlySec = 9_000_000_000

// supersededVMDeleted is a SupersededDisk's vm_state when the VM whose disk
// it was set aside from was deleted.
const supersededVMDeleted = "deleted"

// keptHeld is a .kept- file's held reason in a SupersededDisks answer.
const keptHeld = "a disk a deleted VM was kept with; only an operator removes it, by hand"

// keptSeedHeld is a .kept- seed's held reason in a SupersededDisks answer.
const keptSeedHeld = "a cloud-init seed a deleted VM was kept with, which can hold user-data; only an operator removes it, by hand"

// supersededVarsHeld is a set-aside UEFI vars file's held reason in a
// SupersededDisks answer.
const supersededVarsHeld = "the UEFI vars of a deleted VM's superseded definition; only an operator removes it, by hand " +
	"(rename it back to its path to use it again)"

// SetSupersededDiskRetentionDays records superseded_disk_retention_days, which
// a SupersededDisks answer reports (the sweep itself runs in the daemon).
func (s *Server) SetSupersededDiskRetentionDays(days int) { s.supersededRetentionDays = days }

// SupersededDisks is `lv host superseded-disks <host>`: the disk copies a
// failover set aside on a host (health/superseded_retention.go); with purge,
// the removal of every one neither retained nor held; with remove_paths, the
// removal of exactly the named copies; with restore_path, the named copy put
// back as its VM's disk. The copies are files on that host, so the request is
// answered there.
func (s *Server) SupersededDisks(ctx context.Context, req *pb.SupersededDisksRequest) (*pb.SupersededDisksResponse, error) {
	named := len(req.RemovePaths) > 0 || req.RestorePath != ""
	role := "viewer"
	if req.Purge || named {
		role = "admin" // it deletes or replaces disk data
	}
	if err := RequireRole(ctx, role); err != nil {
		return nil, err
	}
	if req.Host != "" && req.Host != s.hostName {
		client, conn, err := s.peerClient(ctx, req.Host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", req.Host, err)
		}
		defer conn.Close()
		return client.SupersededDisks(ctx, req)
	}
	if req.OlderThanSec < 0 {
		return nil, status.Error(codes.InvalidArgument, "older_than_sec must not be negative")
	}
	if len(req.RemovePaths) > 0 && req.RestorePath != "" {
		return nil, status.Error(codes.InvalidArgument, "remove and restore are separate requests")
	}

	copies, err := health.ListSupersededDisks(ctx, s.db, s.dataDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list superseded disk copies: %v", err)
	}
	// The reconciler's firmware quarantines are listed, purged and removed by
	// name beside the disk copies, under the same retention rule
	// (health/reconciled_quarantine.go).
	quarantines, err := health.ListReconciledQuarantines(ctx, s.db, s.dataDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list reconciled firmware quarantines: %v", err)
	}
	resp := &pb.SupersededDisksResponse{Host: s.hostName, RetentionDays: int32(s.supersededRetentionDays)}
	removed := map[string]bool{}
	switch {
	case req.RestorePath != "" && health.IsReconciledQuarantinePath(s.dataDir, req.RestorePath):
		vm, setAside, rerr := s.restoreReconciledQuarantine(ctx, req.RestorePath)
		if rerr != nil {
			return nil, rerr
		}
		resp.Restored, resp.RestoredTo, resp.SetAside = filepath.Clean(req.RestorePath), "the firmware state (NVRAM, vTPM) of VM "+vm, setAside
		if quarantines, err = health.ListReconciledQuarantines(ctx, s.db, s.dataDir); err != nil {
			quarantines = nil
		}
	case req.RestorePath != "":
		got, rerr := s.restoreSupersededDisk(ctx, req.RestorePath)
		if rerr != nil {
			return nil, rerr
		}
		resp.Restored, resp.RestoredTo, resp.SetAside = got.Restored, got.DiskPath, got.SetAside
		// The restore is done (and audited): a listing that fails now (a
		// directory whose storage stopped answering meanwhile) must not
		// report it as failed. The answer carries the restore with no list.
		if copies, err = supersededRelist(ctx, s.db, s.dataDir); err != nil {
			slog.Warn("superseded disks: restored, but the copies could not be listed again; the answer has no list",
				"restored", got.Restored, "to", got.DiskPath, "error", err)
			copies = nil
		}
	case len(req.RemovePaths) > 0:
		// Named copies only: the purge flag a client sends beside them is for
		// older hosts (SupersededNamedOnlySec), never a bulk purge here.
		var diskPaths, fwPaths []string
		for _, p := range req.RemovePaths {
			if health.IsReconciledQuarantinePath(s.dataDir, p) {
				fwPaths = append(fwPaths, p)
			} else {
				diskPaths = append(diskPaths, p)
			}
		}
		var bytes int64
		var names []string
		gone, rerr := health.RemoveSupersededDisks(ctx, s.db, s.dataDir, diskPaths)
		for _, c := range gone {
			removed[c.Path] = true
			bytes += c.SizeBytes
			names = append(names, c.Path)
		}
		if rerr == nil && len(fwPaths) > 0 {
			var fwGone []health.ReconciledQuarantine
			fwGone, rerr = health.RemoveReconciledQuarantines(ctx, s.db, s.dataDir, fwPaths)
			for _, q := range fwGone {
				removed[q.Path] = true
				bytes += q.SizeBytes
				names = append(names, q.Path)
			}
		}
		result, detail := "ok", fmt.Sprintf("removed %d named superseded disk copies and firmware quarantines (%d bytes) on %s: %s",
			len(names), bytes, s.hostName, strings.Join(names, ", "))
		if rerr != nil {
			result, detail = "error", detail+": "+rerr.Error()
		}
		s.audit(ctx, "host.superseded_disks.remove", s.hostName, detail, result)
		if rerr != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "%s", detail)
		}
	case req.Purge:
		gone, perr := health.PurgeSupersededDisks(ctx, s.db, s.dataDir, time.Duration(req.OlderThanSec)*time.Second, time.Now(), s.keptHolds)
		var bytes int64
		for _, c := range gone {
			removed[c.Path] = true
			bytes += c.SizeBytes
		}
		fwGone, qerr := health.PurgeReconciledQuarantines(ctx, s.db, s.dataDir, time.Duration(req.OlderThanSec)*time.Second, time.Now())
		for _, q := range fwGone {
			removed[q.Path] = true
			bytes += q.SizeBytes
		}
		if perr == nil {
			perr = qerr
		}
		result, detail := "ok", fmt.Sprintf("removed %d superseded disk copies and %d reconciled firmware quarantines (%d bytes) on %s", len(gone), len(fwGone), bytes, s.hostName)
		if perr != nil {
			result, detail = "error", detail+": "+perr.Error()
		}
		s.audit(ctx, "host.superseded_disks.purge", s.hostName, detail, result)
		if perr != nil {
			return nil, status.Errorf(codes.Internal, "%s", detail)
		}
	}

	for _, c := range copies {
		vm, vmState := c.VM, c.VMState
		if vm == "" && c.DeletedVM != "" {
			// Its VM was deleted: named, and shown as deleted.
			vm, vmState = c.DeletedVM, supersededVMDeleted
		}
		resp.Disks = append(resp.Disks, &pb.SupersededDisk{
			Path: c.Path, DiskPath: c.DiskPath, SetAsideAt: c.SetAsideAt.UTC().Format(time.RFC3339),
			SizeBytes: c.SizeBytes, VmName: vm, VmState: vmState, Held: c.Held, Removed: removed[c.Path],
			Retained: c.Retained,
		})
	}
	for _, q := range quarantines {
		vm := ""
		if q.Retained != "" {
			vm = q.VM // a VM of the name exists
		}
		resp.Disks = append(resp.Disks, &pb.SupersededDisk{
			Path: q.Path, DiskPath: "firmware state of VM " + q.VM, SetAsideAt: q.SetAsideAt.UTC().Format(time.RFC3339),
			SizeBytes: q.SizeBytes, VmName: vm, VmState: q.VMState, Held: q.Held, Removed: removed[q.Path],
			Retained: q.Retained,
		})
	}
	// The disks deleted VMs were kept with, which a create moved to .kept-
	// names: listed only. Held, for a client that predates kept: no named
	// removal takes one.
	kept, err := health.ListKeptDisks(ctx, s.db, s.dataDir)
	if err != nil {
		if !req.Purge && !named {
			return nil, status.Errorf(codes.Internal, "list kept disks: %v", err)
		}
		slog.Warn("superseded disks: the kept disks could not be listed; the answer has none", "error", err)
	}
	for _, k := range kept {
		held := keptHeld
		if k.Seed {
			held = keptSeedHeld
		}
		d := &pb.SupersededDisk{
			Path: k.Path, DiskPath: k.DiskPath, SetAsideAt: k.MovedAt.UTC().Format(time.RFC3339), SizeBytes: k.SizeBytes,
			Held: held, Kept: true, Seed: k.Seed,
		}
		s.nameKeptCopy(ctx, k, d)
		resp.Disks = append(resp.Disks, d)
	}
	// The UEFI vars of deleted VMs' superseded definitions this host
	// undefined (health.ReapSupersededStoppedLeftover): listed only, like a
	// kept disk, with the VM they were by name.
	vars, err := health.ListSupersededVars(s.dataDir)
	if err != nil {
		if !req.Purge && !named {
			return nil, status.Errorf(codes.Internal, "list set-aside UEFI vars: %v", err)
		}
		slog.Warn("superseded disks: the set-aside UEFI vars could not be listed; the answer has none", "error", err)
	}
	for _, v := range vars {
		d := &pb.SupersededDisk{
			Path: v.Path, DiskPath: v.VarsPath, SetAsideAt: v.SetAsideAt.UTC().Format(time.RFC3339), SizeBytes: v.SizeBytes,
			VmName: v.VM, Held: supersededVarsHeld, Kept: true, UefiVars: true,
		}
		if vm, err := corrosion.GetVM(ctx, s.db, v.VM); err == nil && vm != nil {
			d.VmState = vm.State
		}
		resp.Disks = append(resp.Disks, d)
	}
	return resp, nil
}

// restoreSupersededDisk is the restore half of SupersededDisks, under the
// VM's lock so a start cannot land between the checks and the swap.
func (s *Server) restoreSupersededDisk(ctx context.Context, copyPath string) (health.RestoredCopy, error) {
	copies, err := health.ListSupersededDisks(ctx, s.db, s.dataDir)
	if err != nil {
		return health.RestoredCopy{}, status.Errorf(codes.Internal, "list superseded disk copies: %v", err)
	}
	vmName := ""
	for _, c := range copies {
		if c.Path == filepath.Clean(copyPath) {
			vmName = c.VM
		}
	}
	if vmName != "" {
		defer s.lockVMAs(vmName, "superseded-disk restore")()
	}
	running := func(name string) bool {
		if s.virt == nil || !s.virt.DomainExists(name) {
			return false
		}
		// libvirt's own activity question: DomainState reports a paused
		// domain, whose disk is open, as "stopped".
		active, err := s.virt.DomainIsActive(name)
		return err != nil || active
	}
	got, err := health.RestoreSupersededDisk(ctx, s.db, s.dataDir, s.hostName, copyPath, running, time.Now())
	detail := fmt.Sprintf("restore %s on %s", copyPath, s.hostName)
	if err != nil {
		s.audit(ctx, "host.superseded_disks.restore", s.hostName, detail+": "+err.Error(), "error")
		if errors.Is(err, health.ErrRestoreRefused) {
			return got, status.Errorf(codes.FailedPrecondition, "%v", err)
		}
		return got, status.Errorf(codes.Internal, "%v", err)
	}
	detail = fmt.Sprintf("restored %s as disk %s of VM %s at %s on %s", got.Restored, got.Disk, got.VM, got.DiskPath, s.hostName)
	if got.SetAside != "" {
		detail += "; the disk it replaced is kept as " + got.SetAside
	}
	s.audit(ctx, "host.superseded_disks.restore", s.hostName, detail, "ok")
	s.recordVMEvent(ctx, got.VM, "vm.disk.restored", "ok", detail)
	return got, nil
}

// NotifyVMDiskStranded is the failover coordinator's and the reconciler's
// callback for a VM disk left on, or set aside on, a host
// (health/stranded_disk.go): a vm.disk.stranded notification.
func (s *Server) NotifyVMDiskStranded(vm, host, detail string) {
	s.notify(context.Background(), notify.Notification{
		Kind: "vm.disk.stranded", Severity: notify.SevWarn, Subject: vm,
		Detail: host + ": " + detail,
	})
}

// NotifyCTRootfsStranded is the coordinator's callback for a container
// relocation that left the container's own rootfs on its failed host
// (health/stranded_rootfs.go): a ct.rootfs.stranded notification.
func (s *Server) NotifyCTRootfsStranded(ct, host, detail string) {
	s.notify(context.Background(), notify.Notification{
		Kind: "ct.rootfs.stranded", Severity: notify.SevWarn, Subject: ct,
		Detail: host + ": " + detail,
	})
}

// supersededRelist lists the copies again after a restore; tests make it fail.
var supersededRelist = health.ListSupersededDisks

var reconciledDirRe = regexp.MustCompile(`^(.+)-reconciled-[0-9]+$`)

// restoreReconciledQuarantine puts a reconciler firmware quarantine (a
// finished <vm>-reconciled-<unix>, an unfinished <vm>-reconciling-<uuid>, or
// an interrupted <vm>-restoring-<uuid>) back as the VM's own NVRAM and vTPM
// state on this host (D2-18 re-review 4, I-1, m-2), under the VM's lock: the
// VM's row names this host, its incarnation's uuid is the quarantine's, and
// its domain is not active. The state in place is set aside as another
// reconciled quarantine first (FirmwareStore.RestoreFirmwareQuarantine).
// It returns the VM and where the replaced state went ("" when there was none).
func (s *Server) restoreReconciledQuarantine(ctx context.Context, path string) (string, string, error) {
	p := filepath.Clean(path)
	base := filepath.Base(p)
	vm, uuid := "", ""
	if svm, _, su, ok := fwmig.ParseStageName(base); ok {
		vm, uuid = svm, su
	} else if m := reconciledDirRe.FindStringSubmatch(base); m != nil {
		vm = m[1]
		b, err := os.ReadFile(filepath.Join(p, "reason.txt"))
		if err != nil {
			return "", "", status.Errorf(codes.FailedPrecondition, "%s: its reason.txt cannot be read (%v), so whose state it is is not known", p, err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "uuid: "); ok && lv.ValidFirmwareUUID(strings.TrimSpace(v)) {
				uuid = strings.TrimSpace(v)
			}
		}
	}
	refuse := func(format string, a ...any) error {
		err := status.Errorf(codes.FailedPrecondition, "restore %s: "+format, append([]any{p}, a...)...)
		s.audit(ctx, "host.superseded_disks.restore", s.hostName, err.Error(), "error")
		return err
	}
	if vm == "" {
		return "", "", refuse("not a reconciler firmware quarantine")
	}
	if fi, err := os.Lstat(p); err != nil || !fi.IsDir() {
		return "", "", refuse("no such directory on %s (%v)", s.hostName, err)
	}
	defer s.lockVM(vm)()
	row, err := corrosion.GetVM(ctx, s.db, vm)
	if err != nil {
		return "", "", status.Errorf(codes.Unavailable, "restore %s: VM %s's row cannot be read: %v", p, vm, err)
	}
	if row == nil {
		return "", "", refuse("VM %s does not exist; nothing restores state for it", vm)
	}
	if row.HostName != s.hostName {
		return "", "", refuse("VM %s is placed on %s, not %s: stop it, move it here with `lv migrate %s %s --cold`, then restore", vm, row.HostName, s.hostName, vm, s.hostName)
	}
	rowUUID := parseFirmwareSpec(row.Spec).UUID
	if uuid != "" && !strings.EqualFold(uuid, rowUUID) {
		return "", "", refuse("its state is of uuid %s, and VM %s's incarnation has uuid %s", uuid, vm, rowUUID)
	}
	switch row.State {
	case "running", "starting", "migrating", "pending":
		return "", "", refuse("VM %s is %s; stop it first", vm, row.State)
	}
	if s.virt != nil {
		active, err := s.virt.DomainIsActive(vm)
		if err != nil && !lv.IsNoDomain(err) {
			return "", "", status.Errorf(codes.Unavailable, "restore %s: VM %s's domain state cannot be read: %v", p, vm, err)
		}
		if err == nil && active {
			return "", "", refuse("VM %s's domain is active on %s; stop it first", vm, s.hostName)
		}
	}
	qdir := filepath.Dir(p)
	now := time.Now()
	final := ""
	for i := int64(0); ; i++ {
		final = filepath.Join(qdir, fmt.Sprintf("%s-reconciled-%d", vm, now.Unix()+i))
		if _, err := os.Lstat(final); os.IsNotExist(err) && final != p {
			break
		}
	}
	reason := fmt.Sprintf("vm: %s\nuuid: %s\nhost: %s\nquarantined_at: %s\n"+
		"reason: the state VM %s had in place when an operator restored %s (lv host superseded-disks --restore)\n"+
		"retention: kept while VM %s exists; once it is gone, removed after superseded_disk_retention_days (lv host superseded-disks lists it)\n",
		vm, uuidOrNoneGRPC(uuid), s.hostName, now.UTC().Format(time.RFC3339), vm, p, vm)
	restoring := filepath.Join(qdir, fwmig.StageName(vm, fwmig.StageRestoring, uuid))
	stage := filepath.Join(qdir, fwmig.StageName(vm, fwmig.StageReconciling, uuid))
	if err := s.fw().RestoreFirmwareQuarantine(vm, uuid, p, restoring, stage, final, []byte(reason)); err != nil {
		s.audit(ctx, "host.superseded_disks.restore", s.hostName, fmt.Sprintf("restore %s: %v", p, err), "error")
		return "", "", status.Errorf(codes.FailedPrecondition, "restore %s: %v", p, err)
	}
	setAside := ""
	if _, err := os.Lstat(final); err == nil {
		setAside = final
	}
	detail := fmt.Sprintf("restored %s as the firmware state of VM %s on %s", p, vm, s.hostName)
	if setAside != "" {
		detail += "; the state it replaced is kept as " + setAside
	}
	s.audit(ctx, "host.superseded_disks.restore", s.hostName, detail, "ok")
	s.recordVMEvent(ctx, vm, "vm.firmware.restored", "ok", detail)
	return vm, setAside, nil
}

func uuidOrNoneGRPC(u string) string {
	if u == "" {
		return "(none: NVRAM only)"
	}
	return u
}

// nameKeptCopy fills in the VM a kept file belongs to by name, when that is
// known (lab 2, abort proof, surprise 3): a seed's from its file name
// (<data_dir>/cloudinit/<vm>.iso), a disk's from the disk rows of this host
// that record its path, a live one first. When a VM of that name exists, its
// state is filled in too, and EarlierVm says whether the file is an earlier
// VM's of that name rather than that VM's: a kept disk always is (a create
// of the name moved it off the path), a seed is unless it is stamped for the
// VM that exists now. A name that cannot be told, or a read that fails,
// leaves the VM column empty, as before.
func (s *Server) nameKeptCopy(ctx context.Context, k health.KeptCopy, d *pb.SupersededDisk) {
	name := ""
	if k.Seed {
		name = strings.TrimSuffix(filepath.Base(k.DiskPath), ".iso")
	} else {
		rows, err := s.db.Query(ctx, `SELECT vm_name FROM vm_disks WHERE path = ? AND host_name = ?
			ORDER BY CASE WHEN deleted_at IS NULL THEN 0 ELSE 1 END LIMIT 1`, k.DiskPath, s.hostName)
		if err != nil || len(rows) == 0 {
			return
		}
		name = rows[0].String("vm_name")
	}
	if name == "" {
		return
	}
	d.VmName = name
	vm, err := corrosion.GetVM(ctx, s.db, name)
	if err != nil || vm == nil {
		return
	}
	d.VmState = vm.State
	if !k.Seed {
		d.EarlierVm = true
		return
	}
	stamp, stamped, serr := cloudinit.SeedOwner(k.Path)
	d.EarlierVm = serr != nil || !stamped || stamp == "" || stamp != cloudinit.SpecUUID(vm.Spec)
}
