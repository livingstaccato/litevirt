package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/diskmode"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/storage"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// CloneVM creates a new VM from a template or a stopped source VM. Linked clones
// (qcow2 overlay) are instant + space-efficient; full clones (qcow2 convert)
// are independent. The clone is created on — and (v1) runs on — the source's
// host, since the source disks live there; it gets a fresh identity (new MACs +
// regenerated cloud-init instance-id/hostname → clean first boot, new SSH host
// keys). Storage-aware default: linked on shared storage, full on local.
func (s *Server) CloneVM(ctx context.Context, req *pb.CloneVMRequest) (*pb.VM, error) {
	if req.Source == "" || req.Target == "" {
		return nil, status.Error(codes.InvalidArgument, "source and target are required")
	}
	if !validResourceName(req.Target) {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid target name %q: only letters, digits, '_', '.', '-' are allowed", req.Target)
	}
	// Path-independent precheck BEFORE the source is resolved. The real
	// per-path check is below, once the source's project is known -- but
	// resolving first and authorizing second turns the handler into an
	// existence oracle: NotFound means the name is free, PermissionDenied
	// means another tenant owns a VM by that name, and VM names routinely
	// encode customer and service identity. Same shape as CloneContainer and
	// the other fetch-then-authorize handlers.
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	src, err := corrosion.GetVM(ctx, s.db, req.Source)
	if err != nil {
		src = nil
	}
	// Authorize the SOURCE as well as the destination. A clone READS the source
	// VM's disks and writes a full copy into the caller's project, so checking
	// only the destination authorizes the write and leaves the read unguarded —
	// a tenant who may create VMs in their own project could otherwise lift
	// another tenant's data into it. Same rule and same verb as BuildImage
	// (imageops.go), which calls this out as "a cross-project data-exposure
	// surface"; cloning is that operation with a VM as the destination instead
	// of an image.
	//
	// requirePermResolved, not RequirePerm: the precheck above lets every
	// binding-holder through, so a tenant with a grant on their own project
	// reached this point either way. A plain NotFound for an absent source and
	// RequirePerm's PermissionDenied (naming the source's project) for a
	// foreign one was the oracle the precheck was meant to close. The resolved
	// form answers both with one PermissionDenied, and a NotFound only to a
	// caller who could have seen the name anyway.
	var srcPath string
	if src != nil {
		srcPath = vmRBACPath(src)
	}
	if err := s.requirePermResolved(ctx, src != nil, srcPath, vmRBACPathFor("", req.Source),
		"backup.create", "operator", "vm "+strconv.Quote(req.Source)); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, status.Errorf(codes.NotFound, "source %q not found", req.Source)
	}
	project := tenancy.NormalizeProject(req.Project)
	if req.Project == "" {
		project = tenancy.NormalizeProject(src.Project)
	}
	if err := s.RequirePerm(ctx, vmRBACPathFor(project, req.Target), "vm.create", "operator"); err != nil {
		return nil, err
	}
	if existing, _ := corrosion.GetVM(ctx, s.db, req.Target); existing != nil {
		return nil, status.Errorf(codes.AlreadyExists, "VM %q already exists", req.Target)
	}
	if err := s.validateCloneTarget(ctx, req, src, project); err != nil {
		return nil, err
	}
	// The clone is created where the source's disks live.
	if src.HostName != s.hostName {
		client, conn, perr := s.peerClient(ctx, src.HostName)
		if perr != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach source host %s: %v", src.HostName, perr)
		}
		defer conn.Close()
		var hdr metadata.MD
		vm, err := client.CloneVM(ctx, req, grpc.Header(&hdr))
		if m := hdr.Get(CloneModeHeader); len(m) > 0 {
			_ = grpc.SetHeader(ctx, metadata.Pairs(CloneModeHeader, m[0]))
		}
		// A source on an older release does not know destination_host or
		// target_pool: it makes a plain same-host clone and answers success. Say
		// so, rather than let the clone sit where it was not asked to be.
		if err == nil && vm != nil {
			if ierr := cloneTargetIgnored(req, vm, src.HostName); ierr != nil {
				// The clone exists, complete, where the older source made it: on
				// its events too, as a failed step of a cross-host clone is.
				s.recordVMEvent(ctx, req.Target, "vm.clone", "error", status.Convert(ierr).Message())
				return nil, ierr
			}
		}
		return vm, err
	}
	if s.cloneAsOlderBuildForTest {
		// What a source on a release before destination_host does with the
		// request: the fields are unknown to it and the clone is made here.
		req = proto.Clone(req).(*pb.CloneVMRequest)
		req.DestinationHost, req.TargetPool = "", ""
	}
	// A clone to another host is made here, where the source's disks are, as
	// an ordinary full clone, and then moved to its host as `lv migrate --cold`
	// moves any stopped VM: its disks streamed over the peer connection, its
	// domain defined there, the staged copy removed once the handoff commits.
	crossHost := req.DestinationHost != "" && req.DestinationHost != s.hostName
	if !crossHost {
		return s.cloneVMOnSource(ctx, req, src, project, false)
	}
	// The move, the pool step and the start run as the caller. A request that
	// reached this host forwarded by a peer carries the caller only where
	// forwarded identity is enforced; where it is not, every step here would run
	// as the peer (admin), which no permission check of the caller's has judged
	// at this host. Refused, with the way out, rather than run as admin.
	if kind, _ := ctx.Value(ctxKeyPrincipalKind).(string); kind == principalKindPeer && fwdBearerFromCtx(ctx) != "" && !s.forwardedIdentityEnforced(ctx) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"a clone onto another host entered at a node other than %s, where it is made, would run its move as a cluster peer, not as you, "+
				"because forwarded identity is not enforced: send the request to %s (LV_HOST=%s), or enforce forwarded identity",
			s.hostName, s.hostName, s.hostName)
	}
	staged := proto.Clone(req).(*pb.CloneVMRequest)
	staged.Start, staged.DestinationHost, staged.TargetPool, staged.Mode = false, "", "", "full"
	if _, err := s.cloneVMOnSource(ctx, staged, src, project, true); err != nil {
		return nil, err
	}
	return s.finishCrossHostClone(ctx, req)
}

// cloneTargetIgnored reports a clone that a source on an older release made as
// a plain same-host clone, ignoring destination_host and target_pool, which it
// does not know: the clone is on another host than the one asked for, or one of
// its disks is not in the pool asked for. The answer it is judged by is the
// clone as its final host reads it back (a cross-host clone's InspectVM there),
// so a clone this release made where it was asked is never refused.
func cloneTargetIgnored(req *pb.CloneVMRequest, vm *pb.VM, srcHost string) error {
	if req.DestinationHost != "" && vm.GetHostName() != req.DestinationHost {
		return status.Errorf(codes.FailedPrecondition,
			"%s, where the clone is made, is on an older release that ignores destination_host and target_pool: "+
				"the clone %q was made on %s instead of %s. Move it with `lv migrate %s %s --cold` or remove it with `lv rm %s`; "+
				"finish upgrading %s to clone onto another host",
			srcHost, req.Target, vm.GetHostName(), req.DestinationHost, req.Target, req.DestinationHost, req.Target, srcHost)
	}
	if req.TargetPool == "" {
		return nil
	}
	for _, d := range vm.GetDisks() {
		// A ceph disk is copied inside its own pool, wherever the clone is made.
		if strings.HasPrefix(d.GetPath(), "rbd:") {
			continue
		}
		if d.GetStorageVolume() != req.TargetPool {
			return status.Errorf(codes.FailedPrecondition,
				"%s, where the clone is made, is on an older release that ignores target_pool: "+
					"the clone %q was made on %s with its disk %q in the default directory, not in pool %q. "+
					"Move it with `lv move-volume %s %s %s` or remove it with `lv rm %s`; "+
					"finish upgrading %s to clone into a pool",
				srcHost, req.Target, vm.GetHostName(), d.GetName(), req.TargetPool,
				req.Target, d.GetName(), req.TargetPool, req.Target, srcHost)
		}
	}
	return nil
}

// cloneVMOnSource is CloneVM on the host that holds the source's disks, with
// every permission check made and the target name known to be free. On the
// source's host it places the disks in req.TargetPool when one is named.
func (s *Server) cloneVMOnSource(ctx context.Context, req *pb.CloneVMRequest, src *corrosion.VMRecord, project string, staging bool) (_ *pb.VM, cloneErr error) {
	var err error
	// The clone makes a VM of the name here: no create of the name runs on
	// this host while it does (beginCreate), and the name is checked again
	// under the flight.
	endFlight, setFlightUUID, err := s.beginCreate(req.Target)
	if err != nil {
		return nil, err
	}
	defer endFlight()
	if existing, _ := corrosion.GetVM(ctx, s.db, req.Target); existing != nil {
		return nil, status.Errorf(codes.AlreadyExists, "VM %q already exists", req.Target)
	}
	// The source's lock, held until the clone's row exists (review M-1): a
	// linked clone backs on the source's current layer before anything
	// records that. A snapshot delete or restore of the source holds this
	// lock, and asks which VMs back on its files only by their rows and the
	// headers of their disk files, neither of which exists for this clone
	// until it is made. The source is judged again under it.
	unlockSrc := s.lockVMAs(req.Source, "clone")
	defer unlockSrc()
	if fresh, gErr := corrosion.GetVM(ctx, s.db, req.Source); gErr != nil || fresh == nil {
		return nil, status.Errorf(codes.NotFound, "source %q not found", req.Source)
	} else if fresh.HostName != s.hostName {
		return nil, status.Errorf(codes.FailedPrecondition, "source %q moved to host %s while the clone started; retry", req.Source, fresh.HostName)
	} else {
		src = fresh
	}
	// A clone reads the source's disks and firmware state, and takes the
	// target's name for a new domain and NVRAM: neither may be named by a
	// live firmware move's record here (spec §6.9).
	if err := s.firmwareMoveRefusal("clone", src); err != nil {
		return nil, err
	}
	if err := s.firmwareMoveNameRefusal("clone", req.Target); err != nil {
		return nil, err
	}
	// Consistent disk state: clone a template or a stopped VM (a running VM's
	// disk isn't crash-consistent). Snapshot-based clone is a follow-up.
	if !src.IsTemplate && src.State != "stopped" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"source %q must be a template or stopped to clone (current: %s); stop it or convert it to a template first",
			req.Source, src.State)
	}
	if req.Snapshot != "" {
		return nil, status.Error(codes.Unimplemented, "clone-from-snapshot is not supported yet; clone from the template/VM directly")
	}
	if s.virt == nil {
		return nil, status.Errorf(codes.Internal, "libvirt not connected on host %s", s.hostName)
	}

	// A point-in-time overlay an earlier copy left holds writes the source's
	// disk lacks: settle it before the clone reads or backs on the disk.
	if err := s.settlePITOverlays(ctx, src); err != nil {
		return nil, err
	}
	// A volume move left unresolved: the rows name the file holding the
	// guest's writes before one is copied (move_unresolved.go).
	if err := s.resolveUnresolvedMovesFor(ctx, req.Source, health.MoveUseReadsRunning); err != nil {
		return nil, err
	}
	srcDisks, err := corrosion.GetVMDisks(ctx, s.db, req.Source)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load source disks: %v", err)
	}
	if len(srcDisks) == 0 {
		return nil, status.Errorf(codes.FailedPrecondition, "source %q has no disks to clone", req.Source)
	}

	var srcSpec pb.VMSpec
	if src.Spec != "" {
		_ = json.Unmarshal([]byte(src.Spec), &srcSpec)
	}
	// The clone carries the source's limits; judge them as a create's are.
	if err := s.checkCopiedSpecLimits(ctx, &srcSpec); err != nil {
		return nil, err
	}

	// A clone does not claim. It rebuilds the source's NIC list with fresh MACs
	// and persists it directly, so on a NetBox-bound network it would either
	// copy the source's address onto a second VM or leave the clone addressless
	// on a network where nothing hands out addresses but NetBox. Refused before
	// admission, so nothing is reserved and no disk is written.
	if err := s.refuseIfBound(ctx, "clone", specNetworkNames(srcSpec.Network)); err != nil {
		return nil, err
	}
	// Project isolation: the clone's NICs land in the TARGET project, which may
	// differ from the source's. Refused before admission and any disk write.
	if err := s.admitCopiedNetworks(ctx, "clone", project, src.Project, specNetworkNames(srcSpec.Network)); err != nil {
		return nil, err
	}
	if err := s.admitSecurityGroupRefs(ctx, project, nicSecurityGroupNames(srcSpec.Network)); err != nil {
		return nil, status.Errorf(status.Code(err), "clone: %s", status.Convert(err).Message())
	}

	// Capacity + quota admission. A clone is a full-sized VM — same vCPU, same
	// memory, its own disks — so it consumes exactly what CreateVM would, and
	// skipping this let a clone walk past both the host's capacity and the
	// project's quota. Cloning a template in a loop was an unbounded way to
	// overfill a host with every other create path refusing correctly.
	//
	// It runs HERE, after the forward to the source's host, for the same reason
	// CreateVM admits only on the owning node: reserving on both nodes counts one
	// clone twice and the forwarded half then refuses itself. It is also before
	// any disk is written, so a refusal costs no I/O.
	//
	// The figures come from srcSpec, which is what the clone's VM record will
	// report as its usage — admitting a different number than the row we go on to
	// write would leave the accounting permanently off by the difference.
	lease, aerr := s.admitWithReservation(
		ctx, "CloneVM", s.hostName, project, "vm:"+req.Target,
		int(srcSpec.Cpu), int(srcSpec.MemoryMib), vmSpecQuotaAmount(&srcSpec), intentVMResident)
	if aerr != nil {
		return nil, aerr
	}
	defer lease.release(ctx)

	mode, modeWhy := s.cloneModeFor(ctx, req.Mode, srcDisks)
	// A clone placed in a pool is its own copy: a linked one is an overlay on
	// its source's file, which no other pool holds.
	var tpool *cloneTargetPool
	if req.TargetPool != "" {
		if req.Mode == "linked" {
			return nil, status.Error(codes.InvalidArgument,
				"a linked clone cannot be placed in a storage pool: it is an overlay on its source's disk; use --mode full")
		}
		mode, modeWhy = "full", "a clone placed in pool "+req.TargetPool+" is a full copy"
		if tpool, err = s.cloneTargetPoolFor(ctx, project, req.TargetPool, srcDisks); err != nil {
			return nil, err
		}
	}
	// A ceph disk is copied inside its pool (rbd deep cp); there is no file a
	// linked clone's qcow2 overlay could back on. A target pool does not move
	// it: only the file disks are placed there, so its space is admitted in
	// its own pool, as a create's disk is.
	cephNeed := map[string]int64{}
	for _, d := range srcDisks {
		if mode == "linked" && isRBDDisk(d) {
			return nil, status.Errorf(codes.FailedPrecondition,
				"disk %s of %q is on ceph, which has no linked clone; clone it with --mode full (an rbd copy inside the pool)", d.DiskName, req.Source)
		}
		// The copy lands in the source disk's pool, which the clone's project
		// must be allowed to use.
		if isRBDDisk(d) {
			if err := s.admitPoolAttach(ctx, project, s.hostName, d.StorageVolume); err != nil {
				return nil, err
			}
			cephNeed[d.StorageVolume] += d.SizeBytes
		}
	}
	for pool, need := range cephNeed {
		if err := s.admitPoolCapacity(ctx, s.hostName, pool, need); err != nil {
			return nil, err
		}
	}
	// Said to the caller (lv clone prints it), as auto may pick either.
	_ = grpc.SetHeader(ctx, metadata.Pairs(CloneModeHeader, mode+": "+modeWhy))

	// Preserve disk bus + SCSI controller model from the source spec (a Windows
	// scsi/lsisas guest cloned as virtio wouldn't boot — and would falsify
	// "BitLocker survives clone"). Cross-cutting G1 fix.
	diskSpecByName := map[string]*pb.DiskSpec{}
	for _, ds := range srcSpec.Disks {
		diskSpecByName[ds.Name] = ds
	}

	// ── Clone the disks ──────────────────────────────────────────────────
	var diskConfigs []lv.DiskConfig
	var diskRecords []corrosion.DiskRecord
	var created []string
	createdBy := map[string]storage.Driver{} // an rbd copy is removed by its driver
	// createdFile is the file each copy this clone wrote is, held open from
	// right after it was written until the clone returns (pinnedFile): a
	// failed clone removes a path only while that file is still there, never
	// another's that took the path since, even one given the copy's inode.
	createdFile := map[string]*pinnedFile{}
	// createdPinErr is why a copy could not be held open: a failed clone
	// leaves it (it cannot be told from another file at the path).
	createdPinErr := map[string]error{}
	defer func() {
		for _, pf := range createdFile {
			pf.release()
		}
	}()
	// cloneLeft is what a failed clone's cleanup leaves of what it made; the
	// clone's error names each (withLeftovers), not only the daemon log.
	var cloneLeft []string
	noteLeft := func(what string) { cloneLeft = append(cloneLeft, what) }
	defer func() { cloneErr = withLeftovers(cloneErr, "clone", cloneLeft) }()
	// cloneSeed is the cloud-init seed this clone wrote, once it has, and
	// cloneSeedFile that file, held open until the clone returns
	// (pinnedFile): a failed clone removes the seed only while it is still
	// the file at that name, never another's placed there since.
	var cloneSeed string
	var cloneSeedFile *pinnedFile
	var cloneSeedPinErr error
	defer func() { cloneSeedFile.release() }()
	removeCloneSeed := func() {
		if cloneSeed == "" {
			return
		}
		if cloneSeedPinErr != nil {
			slog.Warn("clone cleanup: seed left, it could not be held open when it was written", "path", cloneSeed, "error", cloneSeedPinErr)
			noteLeft(fmt.Sprintf("seed %s (it could not be held open to tell it from another file there: %v)", cloneSeed, cloneSeedPinErr))
			return
		}
		if !cloneSeedFile.stillAt(cloneSeed) {
			slog.Warn("clone cleanup: seed left, it is no longer the file this clone wrote", "path", cloneSeed)
			return
		}
		// RemoveSeed also removes the seed's sidecars (.owner, .stale,
		// .removed), as a failed create's cleanup does. This clone wrote
		// .owner (StampSeed). The other two record a seed of a VM of this
		// name that moved away or went stale; the clone holds the name (its
		// flight, and no VM row of it), so they describe no VM that is
		// still here, and they are metadata only, never a disk.
		if e := cloudinit.RemoveSeed(cloneSeed); e != nil {
			slog.Warn("clone cleanup: remove cloud-init seed", "path", cloneSeed, "error", e)
			noteLeft(fmt.Sprintf("seed %s (not removed: %v)", cloneSeed, e))
			return
		}
		cloneSeedFile.release()
		cloneSeed, cloneSeedFile = "", nil
	}
	cleanup := func() {
		removeCloneSeed()
		for _, p := range created {
			if drv := createdBy[p]; drv != nil {
				rmCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
				if e := drv.DeleteDisk(rmCtx, p); e != nil {
					slog.Warn("clone cleanup: remove disk", "path", p, "error", e)
					noteLeft(fmt.Sprintf("disk %s (not removed: %v)", p, e))
				}
				cancel()
				continue
			}
			if perr := createdPinErr[p]; perr != nil {
				if _, serr := os.Lstat(p); serr != nil && os.IsNotExist(serr) {
					continue
				}
				slog.Warn("clone cleanup: disk left, it could not be held open when it was written", "path", p, "error", perr)
				noteLeft(fmt.Sprintf("disk %s (it could not be held open to tell it from another file there: %v)", p, perr))
				continue
			}
			if !createdFile[p].stillAt(p) {
				slog.Warn("clone cleanup: disk left, it is no longer the file this clone wrote", "path", p)
				continue
			}
			if e := os.Remove(p); e != nil && !os.IsNotExist(e) {
				slog.Warn("clone cleanup: remove disk", "path", p, "error", e)
				noteLeft(fmt.Sprintf("disk %s (not removed: %v)", p, e))
				continue
			}
			createdFile[p].release()
			delete(createdFile, p)
		}
		if s.cleanedUpHook != nil {
			s.cleanedUpHook()
		}
	}
	// Only a copy that is not where main puts a clone is admitted for space with
	// headroom: the staged copy of a clone onto another host, and a copy into a
	// pool. A same-host clone into the default directory is as on main.
	if mode == "full" && (staging || tpool != nil) {
		spaceDir, why := filepath.Dir(s.images.DiskPath(req.Target, "root")), "the staged copy"
		if tpool != nil {
			spaceDir, why = tpool.dir, "the copy in pool "+tpool.name
		}
		if err := s.requireCloneSpace(ctx, spaceDir, srcDisks, why); err != nil {
			return nil, err
		}
	}
	// A clone's disk file is a new disk, as a create's is: one at the path a
	// kept overlay names as its missing base would become that base. The
	// same check as a create's, before a byte is written: refused when a
	// kept overlay names one of these paths, and judged as a create is while
	// kept-disks.json or a kept chain cannot be read (keptCollisionOnDisk).
	// A clone with no file disk here (ceph only), or into a shared pool
	// elsewhere, writes nothing a kept overlay on this host can back on.
	if tpool == nil || !s.sharedPoolElsewhere(tpool.ref.Driver, tpool.ref.Target) {
		var planned []string
		for _, d := range srcDisks {
			if isRBDDisk(d) {
				continue
			}
			p, perr := s.images.SafeDiskPath(req.Target, d.DiskName)
			if tpool != nil {
				p, perr = tpool.diskPath(req.Target, d.DiskName)
			}
			if perr != nil {
				continue // refused, InvalidArgument, by the loop below
			}
			planned = append(planned, s.hostDiskFile(p))
		}
		if err := s.keptPathRefusal(ctx, fmt.Sprintf("clone %s", req.Target), planned...); err != nil {
			return nil, err
		}
	}
	for _, d := range srcDisks {
		if isRBDDisk(d) {
			// Copied inside the pool, never through this host.
			bus, controller := "virtio", ""
			if ds := diskSpecByName[d.DiskName]; ds != nil {
				if ds.Bus != "" {
					bus = ds.Bus
				}
				controller = ds.ControllerModel
			}
			clonePath, drv, cerr := s.cloneCephDisk(ctx, src.StackName, d, req.Target)
			if cerr != nil {
				cleanup()
				return nil, cerr
			}
			created = append(created, clonePath)
			createdBy[clonePath] = drv
			diskConfigs = append(diskConfigs, lv.DiskConfig{Name: d.DiskName, Path: clonePath, Bus: bus, ControllerModel: controller})
			diskRecords = append(diskRecords, corrosion.DiskRecord{
				VMName: req.Target, DiskName: d.DiskName, HostName: s.hostName, Path: clonePath,
				SizeBytes: d.SizeBytes, StorageType: "ceph", StorageVolume: d.StorageVolume,
				TargetDev: lv.DiskDevName(bus, len(diskRecords)), Bus: bus,
			})
			continue
		}
		clonePath, err := s.images.SafeDiskPath(req.Target, d.DiskName)
		if tpool != nil {
			clonePath, err = tpool.diskPath(req.Target, d.DiskName)
		}
		if err != nil {
			cleanup()
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		if tpool != nil {
			// Never onto a file that is already there: in a shared pool the
			// derived "<vm>-<disk>.qcow2" can be another VM's disk.
			if _, lerr := os.Lstat(s.hostDiskFile(clonePath)); lerr == nil {
				cleanup()
				return nil, status.Errorf(codes.AlreadyExists, "%s already exists in pool %q", clonePath, tpool.name)
			}
			if rerr := refuseSymlinkTarget(s.hostDiskFile(clonePath)); rerr != nil {
				cleanup()
				return nil, rerr
			}
		}
		// hostFile is where this host's copy of the clone's disk file is: the
		// recorded path itself, except under the hostDiskRoot test seam.
		hostFile := s.hostDiskFile(clonePath)
		if err := diskmode.MkdirAll(filepath.Dir(hostFile)); err != nil {
			cleanup()
			return nil, status.Errorf(codes.Internal, "prepare disk dir: %v", err)
		}
		size := uint64(d.SizeBytes)
		var backing string
		if mode == "linked" {
			if err := qcow2.CreateWithBacking(hostFile, d.Path, size, nil); err != nil {
				cleanup()
				return nil, cloneDiskErr("create linked clone disk", d.DiskName, err)
			}
			backing = d.Path
		} else {
			// Uncompressed flatten: fast to write and fast for the clone's guest
			// to read (a compressed convert would be CPU-bound here and inflate
			// on every guest read). Pure-Go — no qemu-img dependency.
			//
			// The chain is read by each layer's DECLARED backing format, every
			// backing judged by diskChainRule first and the reader confined to
			// exactly those: a raw backing (a promoted VM's replica, guest
			// content) is read as raw, never parsed for a header the guest may
			// have written.
			accepted, err := precheckChain(s.hostDiskFile(d.Path), s.diskChainRule(ctx, d))
			if err != nil {
				cleanup()
				return nil, status.Errorf(codes.FailedPrecondition, "full-clone disk %s: %v", d.DiskName, err)
			}
			if err := qcow2.ConvertConfined(ctx, s.hostDiskFile(d.Path), hostFile, &qcow2.Options{Uncompressed: true}, onlyAccepted(accepted)); err != nil {
				cleanup()
				return nil, cloneDiskErr("full-clone disk", d.DiskName, err)
			}
		}
		created = append(created, hostFile)
		if pf, perr := s.pinMade(hostFile); perr != nil {
			createdPinErr[hostFile] = perr
		} else {
			delete(createdPinErr, hostFile)
			createdFile[hostFile].release()
			createdFile[hostFile] = pf
		}
		bus, controller := "virtio", ""
		if ds := diskSpecByName[d.DiskName]; ds != nil {
			if ds.Bus != "" {
				bus = ds.Bus
			}
			controller = ds.ControllerModel
		}
		diskConfigs = append(diskConfigs, lv.DiskConfig{Name: d.DiskName, Path: clonePath, Bus: bus, ControllerModel: controller})
		// The clone's own file is <data_dir>/disks on this host whatever the
		// source's storage (SafeDiskPath): recorded as that, so no host
		// takes a local file for shared storage (review I-3).
		storageType, storageVolume := "local", ""
		if tpool != nil {
			storageType, storageVolume = tpool.storageType(), tpool.name
		}
		diskRecords = append(diskRecords, corrosion.DiskRecord{
			VMName: req.Target, DiskName: d.DiskName, HostName: s.hostName, Path: clonePath,
			SizeBytes: d.SizeBytes, StorageType: storageType, StorageVolume: storageVolume, BackingDisk: backing,
			TargetDev: lv.DiskDevName(bus, len(diskRecords)), Bus: bus,
		})
	}

	if req.Ip != "" && len(srcSpec.Network) > 0 {
		if err := s.checkNICIdentities(ctx, project, []*pb.NetworkAttachment{{Name: srcSpec.Network[0].Name, Ip: req.Ip}}, req.Target); err != nil {
			cleanup()
			return nil, err
		}
	}

	// ── Networks: fresh MACs (don't duplicate the source's) ──────────────
	var netConfigs []lv.NetworkConfig
	var ifaceRecords []corrosion.InterfaceRecord
	var nicRecords []corrosion.NICRecord // v42 dual-write alongside ifaceRecords (vm_nics)
	var guardRecords []corrosion.NICGuardRecord
	cloneUUID := uuid.NewString() // the clone's incarnation; its guard records carry it
	setFlightUUID(cloneUUID)
	// The clone's seed network-config inputs, one per NIC (cloudinit.NIC),
	// and its host-isolated picks, in flight until this returns.
	var seedNICs []cloudinit.NIC
	var isoPicks []isoPick
	defer func() { s.releaseHostIsolatedPicks(isoPicks) }()
	macs := s.newMACAllocator()
	for i, n := range srcSpec.Network {
		mac, merr := macs.next(ctx)
		if merr != nil {
			cleanup()
			return nil, merr
		}
		bridge := network.FlatBridgeName(n.Name)
		if pb, perr := s.provisionForVM(ctx, n.Name); perr == nil && pb != "" {
			bridge = pb
		}
		ip := ""
		if i == 0 {
			ip = req.Ip // optional static IP for the first NIC
		}
		if def, _ := lookupNetworkDef(ctx, s.db, n.Name); ip == "" && !strings.HasPrefix(bridge, "direct:") &&
			s.dhcpReservable(&pb.NetworkAttachment{Name: n.Name}, def) {
			// The clone's NIC is guarded by default: give it an exact,
			// reserved address (nic_identity.go).
			rip, rerr := s.reserveDHCPAddress(ctx, n.Name, def.Subnet, bridge, mac)
			if rerr != nil {
				cleanup()
				return nil, status.Errorf(codes.ResourceExhausted, "reserve a DHCP address on %q: %v", n.Name, rerr)
			}
			ip = rip
		} else if ip == "" && cloudinit.HostIsolatedAddressable(def) {
			// A host-isolated network serves no DHCP: the clone's NIC is
			// given its own address, as a created VM's is.
			var vips []string
			if lb := srcSpec.GetLoadbalancer(); lb != nil && lb.GetVip() != "" {
				vips = append(vips, lb.GetVip())
			}
			if hip, herr := s.hostIsolatedAddress(ctx, n.Name, def, vips); herr != nil {
				slog.Warn("host-isolated network: no address for the clone's NIC; the guest gets none",
					"vm", req.Target, "network", n.Name, "error", herr)
			} else {
				ip = hip
				isoPicks = append(isoPicks, isoPick{network: n.Name, ip: hip})
			}
		}
		{
			def, _ := lookupNetworkDef(ctx, s.db, n.Name)
			in := cloudinit.NIC{Ordinal: i, MAC: mac, RecordedIP: ip, Net: def}
			if i == 0 {
				in.IP = req.Ip
			}
			seedNICs = append(seedNICs, in)
		}
		if strings.HasPrefix(bridge, "direct:") {
			netConfigs = append(netConfigs, lv.NetworkConfig{Direct: strings.TrimPrefix(bridge, "direct:"), Model: n.Model, MAC: mac, RateMBps: n.RateMbSec})
		} else {
			if e := s.ensureBridge(bridge); e != nil {
				cleanup()
				return nil, status.Errorf(codes.FailedPrecondition, "bridge %q unavailable: %v", bridge, e)
			}
			netConfigs = append(netConfigs, lv.NetworkConfig{Bridge: bridge, Model: n.Model, MAC: mac, RateMBps: n.RateMbSec})
		}
		// The groups go on the legacy row as well as the vm_nics one: a peer on
		// an older build renders this NIC's chain from vm_interfaces alone.
		ifaceRecords = append(ifaceRecords, corrosion.InterfaceRecord{
			VMName: req.Target, NetworkName: n.Name, Ordinal: i, MAC: mac, IP: ip,
			SecurityGroups: n.SecurityGroups,
		})
		nicRecords = append(nicRecords, corrosion.NICRecord{
			VMName:         req.Target,
			ID:             corrosion.DeterministicNICID(req.Target, mac),
			NetworkName:    n.Name,
			Model:          n.Model,
			MAC:            mac,
			Ordinal:        i,
			IP:             ip,
			TapDevice:      "",
			SecurityGroups: encodeSecurityGroups(n.SecurityGroups),
		})
		// A clone's NICs are new NICs: each gets the default guard. The
		// source's relaxations are not copied — relaxing a guard needs
		// cluster-root network authority the cloning caller may not hold —
		// and are set on the clone with `lv firewall nic-guard set`.
		// A NIC on the `trunk:` feature is guarded like any other new NIC,
		// its VLANs its network's to allow (guardDecision.record, re-review
		// R2-I1, R3-I1).
		// A macvtap or SR-IOV NIC bypasses the bridge where guards are
		// enforced: no record, rather than one that claims a protection it
		// lacks (guardUnenforcedOnNetwork, as create decides).
		if !strings.HasPrefix(bridge, "direct:") && guardUnenforcedOnNetwork(ctx, s.db, n.Name) == "" {
			guardRecords = append(guardRecords, corrosion.NICGuardRecord{VMName: req.Target, MAC: mac, Mode: corrosion.NICGuardOn,
				VMUUID: cloneUUID, Network: n.Name, Ordinal: i})
		}
	}
	if err := s.writeNewNICGuards(ctx, guardRecords); err != nil {
		cleanup()
		return nil, err
	}

	// ── Fresh cloud-init identity (new instance-id ⇒ clean first boot) ───
	cloudInitISO := ""
	if srcSpec.Image != "" || srcSpec.CloudInit != nil {
		userData := "#cloud-config\n{}\n"
		if srcSpec.CloudInit != nil && srcSpec.CloudInit.Userdata != "" {
			userData = srcSpec.CloudInit.Userdata
		}
		isoPath, perr := lv.SafeCloudInitISOPath(s.dataDir, req.Target)
		if perr != nil {
			cleanup()
			return nil, status.Errorf(codes.InvalidArgument, "%v", perr)
		}
		// The clone's own NICs' network-config, derived as a create derives
		// it. A network-config the source's spec names is the source's —
		// its addresses — and is not the clone's (nor kept on its spec
		// below).
		netCfg := cloudinit.NetworkConfig(seedNICs)
		if err := cloudinit.GenerateISO(cloudinit.Config{
			InstanceID:    req.Target, // NEW id forces first-boot (regen SSH host keys, machine-id)
			LocalHostname: req.Target,
			UserData:      userData,
			NetworkConfig: netCfg,
			// The clone's network-config is always litevirt's (above).
			VendorData: cloudinit.SeedVendorData(nil, netCfg),
		}, isoPath); err != nil {
			cleanup()
			return nil, status.Errorf(codes.Internal, "generate cloud-init ISO: %v", err)
		}
		if err := cloudinit.StampSeed(isoPath, cloneUUID); err != nil {
			slog.Warn("clone: could not stamp the cloud-init seed with its VM; a later start writes it again",
				"vm", req.Target, "error", err)
		}
		cloudInitISO = isoPath
		cloneSeed = isoPath
		cloneSeedFile, cloneSeedPinErr = s.pinMade(isoPath)
	}

	// ── Derive the clone's spec + domain ─────────────────────────────────
	// Mutate srcSpec in place for the clone's identity (it's our local copy,
	// unmarshalled fresh above) — copying a proto message by value would copy
	// its internal mutex.
	cpu := int(srcSpec.Cpu)
	mem := int(srcSpec.MemoryMib)
	srcSpec.Name = req.Target
	srcSpec.Project = project
	srcSpec.Devices = nil    // v1: don't clone PCI passthrough (device may be in use)
	srcSpec.UsbDevices = nil // nor USB: a device passes to one guest, and a raw one is the source host's
	srcSpec.Uuid = cloneUUID // fresh identity ⇒ fresh vTPM (never copy the source TPM secret) (G1)
	for i := range srcSpec.Network {
		if i < len(ifaceRecords) {
			srcSpec.Network[i].Mac = ifaceRecords[i].MAC
			srcSpec.Network[i].Ip = ifaceRecords[i].IP
		}
		// The source's static IPv6 address and gateways are the source's:
		// a seed rebuilt from the clone's spec must not give them to the
		// clone (the clone's own seed above has none).
		srcSpec.Network[i].Ipv6 = ""
		srcSpec.Network[i].Ipv6Gateway = ""
		srcSpec.Network[i].Gateway = ""
	}
	// Nor the source's own network-config, which names the source's
	// addresses: the clone's seed is derived from its own NICs.
	if srcSpec.CloudInit != nil {
		srcSpec.CloudInit.Networkconfig = ""
	}
	specJSON, _ := json.Marshal(&srcSpec)

	machine := srcSpec.Machine
	if machine == "" {
		machine = "q35"
	}
	firmware := srcSpec.Firmware
	if firmware == "" {
		firmware = "uefi"
	}
	// A clone DEFINES a brand-new domain, so it takes the node's cpu_mode default
	// when the source names none — the same reasoning as the machine-type pin
	// below: a clone must not start life carrying the hazard its source had. An
	// empty mode defines the guest with no <cpu> element, i.e. QEMU's qemu64,
	// which has no SSE4.2/AVX/AVX2 whatever the host can do. A source that DOES
	// name a mode is reproduced exactly.
	if srcSpec.CpuMode == "" && srcSpec.CpuModel == "" {
		srcSpec.CpuMode = s.effectiveDefaultCPUMode()
		specJSON, _ = json.Marshal(&srcSpec)
	}
	// The clone keeps the source's disk tuning and NIC queues (its NICs are
	// matched by position: the MACs are fresh).
	compose.ApplyDiskTuning(diskConfigs, &srcSpec)
	compose.ApplyNICTuningByPosition(netConfigs, &srcSpec)
	vmCfg := lv.VMConfig{
		Name: req.Target, UUID: srcSpec.Uuid, CPU: cpu, CPUMode: srcSpec.CpuMode, CPUModel: srcSpec.CpuModel, MemoryMiB: mem,
		Machine: machine, Firmware: firmware, GuestAgent: srcSpec.GuestAgent,
		EnableVNC: !srcSpec.DisableVnc, EnableSPICE: srcSpec.EnableSpice,
		Disks: diskConfigs, Networks: netConfigs, CloudInitISO: cloudInitISO, Boot: srcSpec.Boot,
		// Memory hot-add carried: the clone's spec copies the band.
		HotplugBaseMiB: int(srcSpec.MemoryHotplugBaseMib), HotplugMaxMiB: int(srcSpec.MemoryHotplugMaxMib),
		CPULimit: srcSpec.CpuLimit, CPUShares: int(srcSpec.CpuShares),
	}
	// Thread Secure Boot + vTPM (fresh vTPM at the new UUID; fresh NVRAM from
	// template) into the clone domain (G1).
	if err := s.applyFirmwareConfig(&vmCfg, &srcSpec); err != nil {
		cleanup()
		return nil, err
	}
	s.withNICMTU(&vmCfg)
	domXML, err := lv.GenerateDomainXML(vmCfg)
	if err != nil {
		cleanup()
		return nil, renderStatus("generate domain XML", err)
	}
	// The release gates for what the clone's spec carries, immediately before
	// the domain that holds them is defined; the row is written through the
	// one writer that checks every grant taken (M9). Limits are gated as a
	// create's are. Disk/NIC tuning and memory hot-add (USB devices are not
	// cloned) are copied from the source as the io and passthrough branches
	// copy them: once the release token has latched their grants are taken
	// (recording a first use, refusing as a create would); before it, the
	// clone keeps its source's settings ungated, as those branches do.
	var gs vmSpecGrants
	if gs.limits, err = s.recordLimitedSpec(ctx, &srcSpec); err != nil {
		cleanup()
		return nil, err
	}
	cloneNeeds := corrosion.VMSpecFeatures{Limits: specSetsLimits(&srcSpec)}
	if specSetsDiskNICIO(&srcSpec) && s.ReleaseFeatureAvailable(capabilities.FeatureVMDiskNICIO) {
		if gs.tuning, err = s.ioGrant(ctx); err != nil {
			cleanup()
			return nil, err
		}
		cloneNeeds.Tuning = true
	}
	if specSetsNICMTU(&srcSpec) && s.ReleaseFeatureAvailable(capabilities.FeatureNICMTU) {
		if gs.mtu, err = s.nicMTUGrant(ctx); err != nil {
			cleanup()
			return nil, err
		}
		cloneNeeds.MTU = true
	}
	if vmSpecSetsPassthrough(&srcSpec) && s.ReleaseFeatureAvailable(capabilities.FeatureUSBMountsMemory) {
		if gs.passthrough, err = s.passthroughGrant(ctx); err != nil {
			cleanup()
			return nil, err
		}
		cloneNeeds.Passthrough = true
	}
	// A new domain starts from a fresh template, never from vars an earlier VM
	// of the name left in libvirt's directory.
	if err := s.setAsideStaleLibvirtVars(req.Target); err != nil {
		cleanup()
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	if err := s.virt.DefineDomain(domXML); err != nil {
		cleanup()
		return nil, status.Errorf(codes.Internal, "define clone domain: %v", err)
	}
	s.ensureSparePCIeRootPorts(req.Target)
	// specJSON above was marshalled BEFORE the define, so it carries whatever
	// the source spec had — an alias if the source was never pinned. The define
	// just resolved it against this host's qemu; persist that concrete value
	// instead, or the clone starts life with the ABI hazard its source had.
	// Re-marshal, since the pre-pin JSON is what would otherwise be stored.
	if before := srcSpec.Machine; true {
		s.pinMachineFromDomain(&srcSpec)
		if srcSpec.Machine != before {
			specJSON, _ = json.Marshal(&srcSpec)
		}
	}

	// Roll back everything the clone built until the DB row lands — including the
	// fresh UUID-keyed swtpm + name-keyed NVRAM, so a failed clone strands nothing (G1).
	rollbackClone := func(running bool) {
		if running {
			s.virt.DestroyDomain(req.Target)
		}
		s.virt.UndefineDomain(req.Target, false)
		cleanup()
		s.fw().WipeFirmwareState(req.Target, srcSpec.Uuid)
	}

	state := "stopped"
	if req.Start {
		// The clone's rows are written once it runs; until then the firewall
		// renders its NICs from here (nic_firewall_arming.go).
		trunks := map[int][]int{}
		for i, n := range srcSpec.Network {
			if len(n.Trunk) > 1 {
				for _, v := range n.Trunk {
					trunks[i] = append(trunks[i], int(v))
				}
			}
		}
		defer s.pendingNICs(req.Target, cloneUUID, ifaceRecords, trunks)()
		if err := s.virt.StartDomain(req.Target); err != nil {
			rollbackClone(false)
			return nil, status.Errorf(codes.Internal, "start clone: %v", err)
		}
		state = "running"
	}

	// FENCE, immediately before the durable write (see allowCommit). Disk
	// copying, cloud-init materialisation, and the optional start all sit
	// between admission and here — one of the widest grant-to-commit gaps of
	// any create-shaped path — so the project's quota authority can genuinely
	// move mid-clone. Refusing tears the clone down exactly like any other
	// pre-persist failure: nothing durable exists yet, so it costs a retry.
	s.fireCommitFenceHook("CloneVM")
	if ferr := lease.allowCommit(ctx); ferr != nil {
		rollbackClone(state == "running")
		return nil, ferr
	}

	// adopt=false: the clone best-effort-populates vm_nics from its fresh network
	// attachments, but (like every producer besides CreateVM) does not
	// self-certify adoption — hardware_adoption_state stays at its schema
	// default 'pending' for the Phase-6 backfill audit to confirm/reconcile.
	// pciIntents is always nil: srcSpec.Devices was dropped above (v1 clones
	// never carry PCI passthrough).
	//
	// A started clone is inserted "creating": assignOwnerEpochAtCreate publishes
	// it running only once it holds a positive epoch and a marker names it.
	insertState := state
	if state == "running" {
		insertState = "creating"
	}
	if err := corrosion.InsertVMWithReleaseFeatures(ctx, s.db, gs.tuning, gs.passthrough, gs.limits, gs.mtu, cloneNeeds, corrosion.VMRecord{
		Name: req.Target, StackName: src.StackName, HostName: s.hostName, Spec: string(specJSON),
		State: insertState, CPUActual: cpu, MemActual: mem, Project: project,
	}, ifaceRecords, diskRecords, nicRecords, nil, false); err != nil {
		rollbackClone(state == "running")
		return nil, status.Errorf(codes.Internal, "persist clone: %v", err)
	}
	// UNCONDITIONAL, with the runtime markers gated on the state. The earlier
	// version skipped a stopped clone entirely on the grounds that "a stopped one
	// is graduated by whatever later starts it" — which is not true of anything:
	// GraduateVMOwnerEpoch has one non-backfill caller, and StartVM's publish
	// hits the epoch < 1 skip and merely logs "pre-epoch … unprovable". A stopped
	// clone therefore sat at 0 until someone enabled the default-off backfill,
	// and became running-and-unprovable the moment it started.
	s.assignOwnerEpochAtCreate(ctx, req.Target, state == "running")
	if len(guardRecords) > 0 {
		s.reconcileLocal(ctx)
	}

	slog.Info("VM cloned", "source", req.Source, "target", req.Target, "mode", mode, "why", modeWhy, "host", s.hostName)
	s.audit(ctx, "vm.clone", req.Target, fmt.Sprintf("source=%s mode=%s", req.Source, mode), "ok")
	s.recordVMEvent(ctx, req.Target, "vm.cloned", "ok", "source="+req.Source+" mode="+mode)
	s.publish("vm.cloned", req.Target, "source="+req.Source)
	return s.vmToProto(ctx, req.Target)
}

// ConvertToTemplate marks a stopped VM as a template (Proxmox-style): a VM that
// can no longer start, whose disks become immutable clone sources. With
// req.Revert it turns a template back into a normal VM.
//
// The is_template flag lives in the replicated vms table, so this is a pure
// state mutation — no per-host action — and any node can serve it; the change
// replicates to the owning host.
func (s *Server) ConvertToTemplate(ctx context.Context, req *pb.ConvertToTemplateRequest) (*pb.VM, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	vm, err := corrosion.GetVM(ctx, s.db, req.Name)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.Name)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.update", "operator"); err != nil {
		return nil, err
	}

	if req.Revert {
		if !vm.IsTemplate {
			return nil, status.Errorf(codes.FailedPrecondition, "%q is not a template", req.Name)
		}
		// Reverting makes the VM startable again — but if its disks still back
		// live linked clones, starting it would corrupt them. Refuse until the
		// clones are gone (or were full-cloned).
		if clones, gErr := s.linkedClonesOf(ctx, req.Name); gErr != nil {
			return nil, status.Errorf(codes.Internal, "check linked clones: %v", gErr)
		} else if len(clones) > 0 {
			return nil, status.Errorf(codes.FailedPrecondition,
				"cannot revert %q to a VM: %d linked clone(s) still depend on its disks (%s); delete or full-clone them first",
				req.Name, len(clones), strings.Join(clones, ", "))
		}
		if err := corrosion.SetVMTemplate(ctx, s.db, req.Name, false); err != nil {
			return nil, status.Errorf(codes.Internal, "revert template: %v", err)
		}
		s.audit(ctx, "vm.template.revert", req.Name, "", "ok")
		s.publish("vm.template.revert", req.Name, "")
		return s.InspectVM(ctx, &pb.InspectVMRequest{Name: req.Name})
	}

	if vm.IsTemplate {
		return nil, status.Errorf(codes.FailedPrecondition, "%q is already a template", req.Name)
	}
	// Before the stopped check, and before anything is written: a VM holding a
	// NetBox address becomes invisible to the inventory mirror the moment this
	// flag is set, and the address it leaves behind is reclaimable by neither the
	// mirror nor the orphan sweep. See refuseTemplateIfBound. Placed here rather
	// than after the state check so an operator is not made to stop a VM only to
	// be told the conversion was never available.
	if err := s.refuseTemplateIfBound(ctx, req.Name); err != nil {
		return nil, err
	}
	// A template must not be running (its disks are about to become immutable
	// clone sources). Require it stopped.
	if vm.State != "stopped" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q must be stopped to convert to a template (current: %s)", req.Name, vm.State)
	}
	if err := corrosion.SetVMTemplate(ctx, s.db, req.Name, true); err != nil {
		return nil, status.Errorf(codes.Internal, "convert to template: %v", err)
	}
	s.audit(ctx, "vm.template.convert", req.Name, "", "ok")
	s.publish("vm.template.convert", req.Name, "")
	return s.InspectVM(ctx, &pb.InspectVMRequest{Name: req.Name})
}

// linkedClonesOf returns the names of VMs whose disks are linked-clone overlays
// backed by any disk of the named source VM/template. Used to guard template
// revert and (later) template/snapshot deletion.
func (s *Server) linkedClonesOf(ctx context.Context, sourceVM string) ([]string, error) {
	disks, err := corrosion.GetVMDisks(ctx, s.db, sourceVM)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var clones []string
	for _, d := range disks {
		names, err := corrosion.LinkedCloneNames(ctx, s.db, d.Path)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			if n != sourceVM && !seen[n] {
				seen[n] = true
				clones = append(clones, n)
			}
		}
	}
	return clones, nil
}

// cloneMode resolves the effective clone mode given the requested mode and
// whether the source's disks all live on shared storage. Storage-aware auto
// (the default): linked when every disk is on shared storage (instant, freely
// placeable), full otherwise (so a local-storage clone isn't host-pinned).
func cloneMode(requested string, allShared bool) string {
	switch requested {
	case "linked", "full":
		return requested
	default: // "" / auto
		if allShared {
			return "linked"
		}
		return "full"
	}
}

// CloneModeHeader is the response header CloneVM says the mode it used in,
// and why ("linked: ..." / "full: ...").
const CloneModeHeader = "x-litevirt-clone-mode"

// cloneModeFor resolves the clone mode and says why. A requested mode is
// used as asked. Auto keeps main 3e4ba50b's choice — linked when every
// source disk is on shared storage (templates.go:162 cloneMode(req.Mode,
// allDisksShared(srcDisks))) — and counts as shared, as main did, a clone
// of a shared disk: main recorded a clone with its source's storage type
// (templates.go:221 StorageType: d.StorageType), so a clone of an NFS VM's
// clone was linked. This build records such a clone "local" (its file is),
// and judges it by what it is a clone of. The new clone records its
// backing_disk, which a snapshot delete of the source checks before it lets
// libvirt merge or remove a file the clone backs on. Auto falls back to a full copy only where a
// linked clone cannot back on the disk (no file path), and says so.
func (s *Server) cloneModeFor(ctx context.Context, requested string, disks []corrosion.DiskRecord) (string, string) {
	switch requested {
	case "linked", "full":
		return requested, "requested"
	}
	if len(disks) == 0 {
		return "full", "auto: the source has no disks to link to"
	}
	for _, d := range disks {
		if isRBDDisk(d) {
			return "full", fmt.Sprintf("auto: disk %s is on ceph, so it is copied inside its pool (rbd deep cp)", d.DiskName)
		}
	}
	for _, d := range disks {
		if !s.sharedAsOnMain(ctx, d, 0) {
			return "full", fmt.Sprintf("auto: disk %s is on host-local storage, so a full copy keeps the clone independent of its source's host", d.DiskName)
		}
	}
	for _, d := range disks {
		if !filepath.IsAbs(d.Path) {
			return "full", fmt.Sprintf("auto: disk %s (%s) is not a file a linked clone can back on, so it is copied in full", d.DiskName, d.Path)
		}
	}
	return "linked", "auto: every disk is on shared storage, or a clone of a disk that is"
}

// sharedAsOnMain is DiskIsShared, or — for a clone (a backing_disk, no
// pool) — whether the disk it is a clone of is.
func (s *Server) sharedAsOnMain(ctx context.Context, d corrosion.DiskRecord, depth int) bool {
	if corrosion.DiskIsShared(d) {
		return true
	}
	if d.BackingDisk == "" || d.StorageVolume != "" || depth >= 8 {
		return false
	}
	rows, err := corrosion.DisksReferencingPath(ctx, s.db, d.BackingDisk)
	if err != nil {
		return false
	}
	for _, r := range rows {
		if r.Path == d.BackingDisk && s.sharedAsOnMain(ctx, r, depth+1) {
			return true
		}
	}
	return false
}

// diskIsShared reports whether a disk lives on cluster-shared storage (so a
// linked clone backed by it can run on any host). Local/dir/btrfs/lvm are
// host-local; nfs/ceph/iscsi are shared. Delegates to corrosion.DiskIsShared —
// the single shared definition the failover coordinator + reconciler also use.
func diskIsShared(d corrosion.DiskRecord) bool {
	return corrosion.DiskIsShared(d)
}

// allDisksShared reports whether every disk is on shared storage.
func allDisksShared(disks []corrosion.DiskRecord) bool {
	if len(disks) == 0 {
		return false
	}
	for _, d := range disks {
		if !diskIsShared(d) {
			return false
		}
	}
	return true
}

// cloneDiskErr reports a failed clone disk. The clone's "<target>-<disk>.qcow2"
// can be another VM's disk (VM "a" disk "b-root" is VM "a-b" disk "root");
// qcow2 refuses to create over it, and that refusal is FailedPrecondition, not
// an internal error.
func cloneDiskErr(what, disk string, err error) error {
	if errors.Is(err, fs.ErrExist) {
		return status.Errorf(codes.FailedPrecondition, "%s %s: %v — choose another target name", what, disk, err)
	}
	return status.Errorf(codes.Internal, "%s %s: %v", what, disk, err)
}

// isRBDDisk reports whether a disk is an rbd image on a ceph pool.
func isRBDDisk(d corrosion.DiskRecord) bool { return strings.HasPrefix(d.Path, "rbd:") }

// cloneCephDisk copies a ceph disk of a VM into a new image of the clone
// target in the same pool, with the pool's driver (rbd deep cp), and returns
// the copy's locator and the driver that removes it on a rollback.
func (s *Server) cloneCephDisk(ctx context.Context, stackName string, d corrosion.DiskRecord, target string) (string, storage.Driver, error) {
	if d.StorageVolume == "" {
		return "", nil, status.Errorf(codes.FailedPrecondition, "disk %s (%s) names no ceph pool to copy it in", d.DiskName, d.Path)
	}
	cfg, err := s.resolveVolume(ctx, stackName, d.StorageVolume)
	if err != nil {
		return "", nil, status.Errorf(codes.FailedPrecondition, "disk %s: storage %q: %v", d.DiskName, d.StorageVolume, err)
	}
	if !strings.EqualFold(cfg.Driver, "ceph") {
		return "", nil, status.Errorf(codes.FailedPrecondition, "disk %s: storage %q is not a ceph pool", d.DiskName, d.StorageVolume)
	}
	if _, err := s.ensureCephSecret(cfg); err != nil {
		return "", nil, status.Errorf(codes.FailedPrecondition, "disk %s: %v", d.DiskName, err)
	}
	drv, err := storage.New(s.dataDir, cfg)
	if err != nil {
		return "", nil, status.Errorf(codes.Internal, "storage driver %q: %v", d.StorageVolume, err)
	}
	cloner := storage.AsDiskCloner(drv)
	if cloner == nil {
		return "", nil, status.Errorf(codes.Internal, "storage %q cannot copy a disk", d.StorageVolume)
	}
	p, err := cloner.CloneDisk(ctx, d.Path, storage.DiskOptions{VMName: target, DiskName: d.DiskName, SizeBytes: d.SizeBytes})
	if err != nil {
		return "", nil, cloneDiskErr("ceph clone disk", d.DiskName, err)
	}
	return p, drv, nil
}
