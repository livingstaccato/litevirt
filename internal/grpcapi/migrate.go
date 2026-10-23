package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/dns"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/hooks"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/obs"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/vfio"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// authorizeMigrationHelper is the REAL authorization for the target-side
// migration helper RPCs (EnsureCloudInit/EnsureDisks/EnsureFirmwareState/
// CleanupMigrationArtifacts). requirePermPrecheck is NOT an auth grant (any
// binding-holder passes it), so these helpers — which create/remove host files
// and can define a domain — must additionally require vm.migrate on the VM
// being migrated. The VM record is replicated cluster-wide during migration, so
// it resolves on the target even though the source still owns it.
func (s *Server) authorizeMigrationHelper(ctx context.Context, vmName string) (*corrosion.VMRecord, error) {
	if err := safename.ValidateVMName(vmName); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", vmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.migrate", "operator"); err != nil {
		return nil, err
	}
	return vm, nil
}

// authorizeMigrationTarget is authorizeMigrationHelper for the helper RPCs
// that STAGE a migration on this host (disks, cloud-init, domain, firmware): it
// also refuses when this host is a witness, whatever the source checked. Cleanup
// and rollback keep authorizeMigrationHelper.
func (s *Server) authorizeMigrationTarget(ctx context.Context, vmName string) (*corrosion.VMRecord, error) {
	vm, err := s.authorizeMigrationHelper(ctx, vmName)
	if err != nil {
		return nil, err
	}
	if err := s.refuseSelfWitnessTarget(ctx, fmt.Sprintf("migration of VM %q to this host", vmName)); err != nil {
		return nil, err
	}
	return vm, nil
}

// withinDiskArtifactRoot reports whether p is inside a directory where VM disk
// artifacts legitimately live — the default disks dir or a file-backed storage
// pool's directory. The migration helpers bound their create/remove to these
// roots so they can never touch e.g. {dataDir}/state.db just because it's under
// the data dir.
func (s *Server) withinDiskArtifactRoot(p string) bool {
	_, ok := s.diskArtifactRootOf(p)
	return ok
}

// diskArtifactRootOf is withinDiskArtifactRoot that also returns the root
// directory p was found in.
func (s *Server) diskArtifactRootOf(p string) (string, bool) {
	if root := filepath.Join(s.dataDir, "disks"); safename.Contains(root, p) {
		return root, true
	}
	s.storagePoolsMu.RLock()
	pools := make(map[string]StoragePoolRef, len(s.storagePools))
	for n, pr := range s.storagePools {
		pools[n] = pr
	}
	s.storagePoolsMu.RUnlock()
	for n, pr := range pools {
		if !isFileBasedDriver(pr.Driver) || !s.poolUsableForWrite(context.Background(), n, pr) {
			continue
		}
		if dir, derr := fileBasedPoolDir(s.dataDir, pr); derr == nil && safename.Contains(dir, p) {
			return dir, true
		}
	}
	return "", false
}

// migrationSourceHost is the host a migration of vm brings its disks from: the
// host its row names, which does not change until the move is done.
func migrationSourceHost(vm *corrosion.VMRecord) string {
	if vm == nil {
		return ""
	}
	return vm.HostName
}

// errLibvirtCallUnanswered is the answer of a libvirt call whose goroutine
// ended without one: what waits on the call's result is never left waiting.
var errLibvirtCallUnanswered = errors.New("the libvirt call ended without an answer")

// answerLibvirtCall runs call in a goroutine of its own and returns the
// channel its answer arrives on. The answer is sent however the goroutine
// ends but by a panic, so what waits on it always gets one: what call
// returned, or errLibvirtCallUnanswered when it ended without returning
// (runtime.Goexit below it). A panic answers nothing: it goes on, and the
// process with it.
func answerLibvirtCall(call func() error) <-chan error {
	answered := make(chan error, 1)
	go func() {
		err := errLibvirtCallUnanswered
		defer func() {
			if p := recover(); p != nil {
				panic(p)
			}
			answered <- err
		}()
		err = call()
	}()
	return answered
}

// MigrateVM performs a live migration of a VM to a target host.
// It streams MigrateProgress messages back to the caller.
func (s *Server) MigrateVM(req *pb.MigrateVMRequest, stream grpc.ServerStreamingServer[pb.MigrateProgress]) error {
	ctx := stream.Context()
	// Named span for the whole migration; child peer RPCs (define/copy/cutover on
	// the target daemon) hang off this via the otelgrpc handlers, so a migration
	// renders as one trace across both hosts. No-op when tracing is off.
	ctx, span := obs.Span(ctx, "vm.migrate")
	span.SetAttribute("vm.name", req.GetVmName())
	span.SetAttribute("vm.target_host", req.GetTargetHost())
	defer span.End()
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return err
	}

	// Per-VM lock prevents concurrent snapshot/migrate/delete (#27). It is
	// released here UNLESS the migration outlives this request, in which case it
	// travels with the adopter — dropping it while libvirt is still moving the
	// guest is what lets a snapshot or delete run against a VM mid-flight.
	unlock := releaseOnce(s.lockVMAs(req.VmName, "migration"))
	adopted := false
	defer func() {
		if !adopted {
			unlock()
		}
	}()

	send := func(phase pb.MigratePhase, memPct, diskPct float32) error {
		return stream.Send(&pb.MigrateProgress{
			Phase:     phase,
			MemoryPct: memPct,
			DiskPct:   diskPct,
		})
	}

	// Validate
	if err := send(pb.MigratePhase_MIGRATE_VALIDATING, 0, 0); err != nil {
		return err
	}

	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "VM %q not found", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.migrate", "operator"); err != nil {
		s.audit(ctx, "vm.migrate", req.VmName, "permission denied: → "+req.TargetHost, "denied")
		return err
	}
	if vm.HostName != s.hostName {
		// Released BEFORE the forward: the lock must not be held across a peer
		// RPC. See releaseOnce.
		unlock()

		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		remote, err := client.MigrateVM(ctx, req)
		if err != nil {
			return err
		}
		for {
			msg, err := remote.Recv()
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}
	return s.migrateOwnedVM(ctx, req, vm, send, unlock, &adopted, ownedMigrateOpts{})
}

// ownedMigrateOpts is what a caller other than MigrateVM adds to
// migrateOwnedVM.
type ownedMigrateOpts struct {
	// beforeMove runs once every check of the migration has passed and the
	// destination's capacity lease is held, before anything is done on the
	// target or to the VM. An error from it ends the migration with nothing
	// done. Host drain uses it to cold-move a RUNNING VM: it runs the cold
	// path's remaining checks and only then shuts the VM down
	// (drainRunningVMCold), under the one lease this migration holds.
	beforeMove func(ctx context.Context) error
}

// sourceGateRefused is the split-brain gate for the source of a migration of
// vm to target. A VM LEAVING this host — this host owns it and the target is
// another host — takes the drain gate, which also passes a `draining` host:
// moving a VM away is what draining is for, whether the drain or an operator
// moves it. Decided from the VM's row (read under its lock) and the resolved
// target, never from a request field. Anything else takes ExecutionGate. A
// move onto a draining host is refused before this, by the target-is-active
// check.
func (s *Server) sourceGateRefused(ctx context.Context, vm *corrosion.VMRecord, target string) (string, bool) {
	if vm.HostName == s.hostName && target != s.hostName {
		return s.drainGateRefused(ctx)
	}
	return s.execGateRefused(ctx)
}

// migrateOwnedVM is MigrateVM on the host that owns the VM, called with the
// VM's lock held and the caller's permission already checked. unlock and
// adopted let a live migration that outlives the request carry the lock to
// its adopter (adoptAbandonedMigration): it sets *adopted and the caller must
// then not release the lock itself. Host drain, which holds the VM's lock for
// its whole step, calls this directly for its cold moves (drainColdMove), with
// the same lock discipline.
func (s *Server) migrateOwnedVM(ctx context.Context, req *pb.MigrateVMRequest, vm *corrosion.VMRecord, send func(pb.MigratePhase, float32, float32) error, unlock func(), adopted *bool, opts ownedMigrateOpts) error {
	// A move out ends in an ownership commit this host writes, after a
	// cut-over that cannot be undone, and starts with a `migrating` row this
	// host writes. Under write quarantine both are refused: the guest would
	// run on the target while every row names this host, and failover of
	// this host would then start a second copy. Refused before anything is
	// done anywhere.
	if err := s.moveOutQuarantineRefusal(fmt.Sprintf("VM %q", vm.Name), req.TargetHost); err != nil {
		return err
	}
	// A volume move left unresolved: the rows name the file holding the
	// guest's writes before anything reads them for the migration
	// (move_unresolved.go).
	// Without storage a running domain migrates live with the files it has
	// open, so a forked history it cannot get wrong does not hold it.
	use := health.MoveUseBoots
	if !req.WithStorage {
		use = health.MoveUseMigratesRunning
	}
	if err := s.resolveUnresolvedMovesFor(ctx, vm.Name, use); err != nil {
		return err
	}
	// The VM leaves this host: the next admission here reads the runtime
	// afresh, not a cached inventory that still charges the VM's memory as
	// runtime-only load (invalidateInventoryCache; P-3 of lab 2 run c2). An
	// adopted migration drops it again when it finishes.
	defer s.invalidateInventoryCache()
	// A VM a live firmware move's record names here is not moved, by any
	// strategy (spec §6.9, §9). A live move is refused again by stage A
	// item 5; a cold one would hand the row to a third host, away from the
	// parked move's records and the start veto they hold. Drain's cold
	// moves enter here too. A move in progress writes its marker below this
	// point, and the adopter and recovery never re-enter here.
	if err := s.firmwareMoveRefusal("migrate", vm); err != nil {
		return err
	}
	// A failback move is conditional on the VM still being where the drain left
	// it, judged here, by its owner under its lock (failback.go).
	if req.GetExpectDrainRecord() {
		if err := s.checkDrainExpectation(ctx, req, vm); err != nil {
			return err
		}
	}
	// A point-in-time overlay an earlier copy left holds writes the disk's
	// file lacks: a migration must carry them, so settle it first.
	if err := s.settlePITOverlays(ctx, vm); err != nil {
		return err
	}
	// Secure Boot / vTPM firmware-state travel (G1). A firmware VM's NVRAM + swtpm
	// are host-local and bind BitLocker, so they need a CONSISTENT capture:
	//   - LIVE (fwLive) is the live firmware move (migrate_firmware_live.go): the
	//     target guest arrives paused, and runs only once its TPM state verified
	//     against the source's final state and the commit landed; the source's
	//     copy is kept until then. Stage A below decides whether this VM may.
	//   - COLD (fwCold) requires the VM STOPPED: its firmware can't be captured at
	//     a single instant while the guest keeps mutating TPM state, so we copy it
	//     quiescent.
	fwSpec := parseFirmwareSpec(vm.Spec)
	fwVM := fwSpec.SecureBoot || fwSpec.Tpm
	fwLive := fwVM && req.Strategy != pb.MigrateStrategy_MIGRATE_COLD
	fwCold := fwVM && !fwLive
	// coldStopped: a STOPPED VM migrated cold. Nothing runs, so there is nothing
	// for libvirt to migrate: the VM is moved as the firmware VM is
	// (coldMigrateStoppedVM) — its host-local disks streamed to the target, its
	// domain defined there, and its ownership handed over in one transaction.
	coldStopped := req.Strategy == pb.MigrateStrategy_MIGRATE_COLD && vm.State == "stopped"
	switch {
	case fwLive && vm.State == "stopped":
		return status.Errorf(codes.FailedPrecondition,
			"Secure Boot / vTPM VM %q is stopped; a live migration needs it running — "+
				"`lv migrate %s %s --cold`", req.VmName, req.VmName, req.TargetHost)
	case fwLive && vm.State != "running":
		return liveFirmwareRefusal(req.VmName, req.TargetHost, "it is %s, not running", vm.State)
	case fwCold && vm.State != "stopped":
		return status.Errorf(codes.FailedPrecondition,
			"stop Secure Boot / vTPM VM %q before migrating it — its firmware state can't be captured consistently while running: "+
				"`lv stop %s`, then `lv migrate %s %s --cold`", req.VmName, req.VmName, req.VmName, req.TargetHost)
	case !fwVM && !coldStopped && vm.State != "running":
		if vm.State == "stopped" {
			return status.Errorf(codes.FailedPrecondition,
				"VM %q is stopped; live migration needs a running VM — migrate it with --cold", req.VmName)
		}
		return status.Errorf(codes.FailedPrecondition,
			"VM %q must be running to live-migrate, or stopped to migrate with --cold (state: %s)", req.VmName, vm.State)
	}
	// Resolve target host
	targetHost, err := corrosion.GetHost(ctx, s.db, req.TargetHost)
	if err != nil || targetHost == nil {
		return status.Errorf(codes.NotFound, "target host %q not found", req.TargetHost)
	}
	// A witness runs no workloads and a host that is not active takes none:
	// refused before anything moves, naming the host and why
	// (migrate_target_role.go).
	if err := nonWorkloadTargetError(targetHost); err != nil {
		return err
	}

	// CPU compatibility, SOURCE-side, before ANY target-side provisioning: a guest
	// whose CPU is derived from its host (host-model / host-passthrough) may be
	// executing instructions the destination does not have, and libvirt only says
	// so once the migration is already underway. Advisory and fail-open — it
	// refuses only on a positive "cannot run" from the target that the source,
	// running the guest, does not also give about itself (see
	// preflightTargetCPU), never on a peer that is old or cannot answer.
	//
	// Only for a move that carries a RUNNING guest. A cold move (a stopped VM, a
	// firmware VM, and drain's cold move of a running VM, which shuts it down
	// first) boots the guest fresh on the target, where host-model and
	// host-passthrough expand to the target's own CPU: what the source's guest
	// is running on now is not a requirement there, and asking it refused moves
	// between different CPU generations for nothing. A target that cannot run
	// the guest's machine type still refuses, at the define.
	if !coldStopped && !fwCold {
		if err := s.preflightTargetCPU(ctx, vm, req.TargetHost); err != nil {
			return err
		}
	}

	// USB passthrough: live is refused while a device is attached; cold needs
	// every device mapped and the target to hold each mapping. Before any
	// target-side work, so a refusal wastes none. A spec that cannot be read
	// refuses rather than migrating a VM whose devices are unknown.
	if vm.Spec != "" {
		usbSpec := &pb.VMSpec{}
		if err := json.Unmarshal([]byte(vm.Spec), usbSpec); err != nil {
			return status.Errorf(codes.Internal, "parse spec of %q: %v", vm.Name, err)
		}
		if err := s.refuseUSBMigration(ctx, vm, usbSpec, targetHost.Name, req.Strategy == pb.MigrateStrategy_MIGRATE_COLD); err != nil {
			return err
		}
	}

	// PCI passthrough cannot be re-realized cross-host in this release, so refuse
	// migrating any VM that holds PCI intent — but only once hardware_v2 is latched,
	// so pre-latch migration behavior (incl. the legacy VF/PF/target-availability
	// guards below) is unchanged. Fail CLOSED on a read error: if we cannot tell
	// whether the VM holds intent, refuse rather than risk migrating a PCI VM.
	if s.hardwareV2Latched(ctx) {
		intents, err := corrosion.ListVMPCIIntents(ctx, s.db, vm.Name)
		if err != nil {
			return status.Errorf(codes.Internal, "check PCI intent for %q: %v", vm.Name, err)
		}
		if len(intents) > 0 {
			addr := "<pci-address>"
			if intents[0].ExclusiveKey != nil {
				addr = *intents[0].ExclusiveKey
			}
			return status.Errorf(codes.FailedPrecondition,
				"VM %q holds PCI passthrough intent; cross-host migration of PCI devices is not supported in this release; %s",
				vm.Name, s.pciMoveRoute(ctx, vm.Name, addr, req.TargetHost))
		}
	}

	// Split-brain gate (Phase 1), SOURCE-side: a migration is a runtime-ownership
	// move, so the source must hold local quorum. This runs ON THE SOURCE (a
	// non-source caller forwarded above and returned) and re-checks quorum HERE — not
	// just at schedule time — closing the loss-of-quorum window between the rebalance
	// executor / health-checker's DECISION and the actual move, AND covering an
	// explicit operator MigrateVM that has no earlier gate. Placed before any
	// target-side setup (PCI/network/disk provisioning) so a refusal wastes no work.
	// Fail-open until split_brain_gate_v1 is cluster-wide.
	if reason, refused := s.sourceGateRefused(ctx, vm, targetHost.Name); refused {
		s.noteGateRefused(corrosion.ActionReschedule, reason)
		return status.Error(codes.FailedPrecondition, s.gateRefusal(ctx, "migration", reason, returnToServiceHint))
	}

	// Gate the explicit target on the matching host capability (mirrors what
	// placement does for auto placement) — a firmware VM that lands on a
	// non-capable host can't define. A live firmware move's stage A checks them
	// with its own refusal text.
	if fwCold {
		if fwSpec.Tpm && targetHost.Labels[corrosion.LabelTPMCapable] != "true" {
			return status.Errorf(codes.FailedPrecondition,
				"target host %q is not vTPM-capable (no swtpm); cannot migrate vTPM VM %q there", req.TargetHost, req.VmName)
		}
		if fwSpec.SecureBoot && targetHost.Labels[corrosion.LabelSecureBootCapable] != "true" {
			return status.Errorf(codes.FailedPrecondition,
				"target host %q is not Secure-Boot-capable (no secboot OVMF); cannot migrate VM %q there", req.TargetHost, req.VmName)
		}
	}

	// Snapshot + local-disk preconditions. A VM running on a snapshot overlay
	// keeps its data in a qcow2 whose backing (base) file is NOT part of a
	// storage copy, so migrating its local storage leaves the backing chain
	// behind and qemu on the target cannot open the disk — the migration fails
	// mid-copy. Block it up-front with a clear, actionable error instead of that
	// confusing late failure. Shared storage (nfs/ceph/iscsi/...) is unaffected
	// because the whole chain stays in place and reachable from the target.
	disks, err := corrosion.GetVMDisks(ctx, s.db, req.VmName)
	if err != nil {
		return status.Errorf(codes.Internal, "query VM disks: %v", err)
	}
	hasLocal := false
	for _, d := range disks {
		// Both local and dir keep the disk as a host-local file (same path = two
		// distinct files on two hosts) — match the source-cleanup predicate so a
		// dir-pool VM isn't mistaken for shared storage and migrated without its
		// disk (G1 #3 / pre-existing for dir pools). An untyped legacy row is
		// host-local, as the storage copy takes it (isHostLocalDisk).
		if isHostLocalDisk(d) {
			hasLocal = true
			break
		}
	}
	snaps, _ := corrosion.ListSnapshots(ctx, s.db, req.VmName)
	if hasLocal && len(snaps) > 0 {
		return status.Errorf(codes.FailedPrecondition,
			"VM %q has %d snapshot(s) on local storage — a snapshotted VM cannot be migrated "+
				"(its disk overlay's backing chain would be left behind). Remove them first: "+
				"`lv snapshot rm %s <name>` for each, then migrate.",
			req.VmName, len(snaps), req.VmName)
	}

	// A live firmware move: stage A (spec §3.2 items 1–7), source-local and
	// writing nothing; a refusal names the cold move.
	var fwElig *liveFirmwareEligible
	if fwLive {
		if fwElig, err = s.liveFirmwareStageA(ctx, liveFirmwareMove{vm: vm, target: targetHost, withStorage: req.WithStorage, disks: disks}); err != nil {
			return err
		}
	}

	// Moving a RUNNING VM with a local disk needs --with-storage, cold or live:
	// libvirt moves the guest, and without a storage copy the target has no disk
	// for it. A stopped VM's cold move streams its host-local disks itself, so
	// --with-storage (a libvirt storage copy of a running guest) does not apply
	// to it; neither does it to a firmware VM moved cold, which moves stopped.
	withStorage := req.WithStorage && !coldStopped && !fwCold
	if !coldStopped && !fwCold && hasLocal && !withStorage {
		return status.Errorf(codes.FailedPrecondition,
			"VM %q has a local disk — use --with-storage to migrate it running, or stop it and migrate it with --cold", req.VmName)
	}
	// The disks the copy mirrors: the host-local ones, never a shared one,
	// which is the same file on the target and would be mirrored onto itself.
	var diskTargets []string
	if withStorage {
		if diskTargets, err = storageMigrationTargets(req.VmName, disks); err != nil {
			return err
		}
		if len(diskTargets) == 0 {
			// Nothing to copy: an empty migrate_disks would make libvirt copy
			// EVERY writable disk, the shared ones included.
			slog.Info("migrate: --with-storage requested but the VM has no host-local disk; migrating without a storage copy",
				"vm", req.VmName)
			withStorage = false
		}
	}
	// A storage copy cannot be tunnelled through libvirt's TLS connection: QEMU
	// opens its own migration stream and NBD channel to the target. They are
	// encrypted (VIR_MIGRATE_TLS) only when BOTH hosts have migration-TLS
	// credentials installed for QEMU, from the migration CA, never the cluster
	// CA, whose key a guest escaping into QEMU would otherwise hold. This host's
	// side is settled here, before any work; the target's comes back from
	// EnsureDisks.
	srcTLS := false
	if withStorage {
		var tlsErr error
		srcTLS, tlsErr = s.migrationTLSState()
		if errors.Is(tlsErr, pki.ErrInvalidMigrationCredentials) {
			// This host holds credentials it cannot use: a fault to fix, refused
			// whatever the plaintext opt-in says.
			return unusableMigrationCredentialsRefusal(req.VmName, s.hostName, tlsErr.Error())
		}
		if !srcTLS && !s.allowPlaintextStorageMigration {
			return plaintextStorageRefusal(req.VmName, s.hostName, req.TargetHost, s.hostName)
		}
	} else if s.migrationNetwork != "" {
		// A memory-only migration rides libvirt's tunnel on the cluster
		// address; it can use the migration network only on QEMU's own stream,
		// which needs this host's credentials too (migration_network.go). Not
		// being ready is not a refusal here: the move stays in the tunnel.
		srcTLS = s.migrationTLSReady()
	}
	// The disks the copy needs on the target, checked against their records
	// here, before any work on the target.
	var diskStubs []*pb.DiskStub
	if withStorage {
		if diskStubs, err = s.storageMigrationStubs(ctx, req.VmName); err != nil {
			return err
		}
	}

	// NUMA topology pre-flight: warn if source and target have different NUMA
	// layouts when the VM has CPU pinning configured (#55).
	if vm.Spec != "" {
		var specCheck struct {
			Resources *struct {
				CpuPinning []int32 `json:"cpu_pinning"`
			} `json:"resources"`
		}
		if json.Unmarshal([]byte(vm.Spec), &specCheck) == nil &&
			specCheck.Resources != nil && len(specCheck.Resources.CpuPinning) > 0 {
			// Log a warning — the target host may have different NUMA topology.
			slog.Warn("migration pre-flight: VM has CPU pinning — verify NUMA topology on target host",
				"vm", vm.Name, "target", req.TargetHost,
				"pinning", specCheck.Resources.CpuPinning)
			if err := send(pb.MigratePhase_MIGRATE_VALIDATING, 0, 0); err != nil {
				return err
			}
		}
	}

	// PCI passthrough guard: classify assigned devices as VFs (hot-unplug OK) vs PFs (block live).
	assignedDevices, _ := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	var detachedVFs []corrosion.PCIDeviceRecord
	for _, d := range assignedDevices {
		if d.VMName != req.VmName {
			continue
		}
		if vfio.IsVF(d.Address) {
			// SR-IOV VFs can be hot-unplugged before migration.
			detachedVFs = append(detachedVFs, d)
		} else if req.Strategy == pb.MigrateStrategy_MIGRATE_LIVE {
			return status.Errorf(codes.FailedPrecondition,
				"VM %q has PCI passthrough device %s (%s) — live migration is not possible; %s",
				req.VmName, d.Address, d.Type, s.pciMoveRoute(ctx, req.VmName, d.Address, req.TargetHost))
		} else if req.Strategy == pb.MigrateStrategy_MIGRATE_COLD && !coldStopped {
			// --cold moves a STOPPED VM. A running one would still go through
			// libvirt's migration, which cannot move a PF, and would fail only
			// after the target had been prepared.
			return status.Errorf(codes.FailedPrecondition,
				"VM %q is running and has PCI passthrough device %s (%s), which cannot be moved while the guest runs; %s",
				req.VmName, d.Address, d.Type, s.pciMoveRoute(ctx, req.VmName, d.Address, req.TargetHost))
		}
	}
	// A live firmware move detaches its VFs only under a durable lease, which
	// its restart recovery rebuilds them from: with no operation journal there
	// is none, so it is refused before anything is detached or asked of the
	// target (review D2-13 N-6). Main never live-moved a firmware VM.
	if fwLive && len(detachedVFs) > 0 && s.opJournal == nil {
		return liveFirmwareRefusal(req.VmName, req.TargetHost,
			"it has SR-IOV VFs, and this host's operation journal did not open, so their detach could not be recorded; repair <data_dir>/opjournal (see the daemon log) and restart the daemon")
	}

	// PCI pre-flight: verify target host has compatible devices for any PCI
	// devices the VM spec requires (covers both VF reattach and cold migration).
	if vm.Spec != "" {
		var specDevices struct {
			Devices []struct {
				Type   string `json:"type"`
				Vendor string `json:"vendor"`
				Count  int32  `json:"count"`
			} `json:"devices"`
		}
		if json.Unmarshal([]byte(vm.Spec), &specDevices) == nil && len(specDevices.Devices) > 0 {
			for _, ds := range specDevices.Devices {
				if ds.Count == 0 {
					continue
				}
				targetDevices, err := corrosion.ListPCIDevices(ctx, s.db, req.TargetHost, ds.Type)
				if err != nil {
					return status.Errorf(codes.Internal, "query target host PCI devices: %v", err)
				}
				freeCount := int32(0)
				for _, d := range targetDevices {
					if d.VMName == "" {
						freeCount++
					}
				}
				if freeCount < ds.Count {
					return status.Errorf(codes.FailedPrecondition,
						"target host %q has %d free %s devices but VM %q requires %d",
						req.TargetHost, freeCount, ds.Type, req.VmName, ds.Count)
				}
			}
		}
	}

	// Capacity admission on the TARGET. A migration puts a full-sized RUNNING VM
	// onto another host — the same consumption a create of that VM would have — and
	// nothing admitted it, so an operator (or the health checker's automatic
	// re-home, which drives this same handler) could pack a target past the point
	// where `lv run` refuses a VM of exactly that size, with nothing logged because
	// nothing checked.
	//
	// HOST-only, deliberately (no project quota): a migration MOVES an allocation
	// the project's quota already counts — it does not grow it — so charging quota
	// again would refuse the migration of any workload occupying more than half
	// its quota. That is the exact double-count the host-only admission exists for
	// (see the start paths).
	//
	// The DECISION runs on the DESTINATION (acquireDestinationHostLease): only the
	// target daemon can probe its own runtime inventory, and the replicated
	// observation this side would otherwise lean on degrades to DB-only arithmetic
	// exactly when it is missing, stale, or unreadable. The source asks once, holds
	// the returned destination-local lease across the whole transfer, and releases
	// it on every return path. It sits after the free source-local preflights
	// (which need no peer round trip to refuse) and before ALL target-side setup
	// (network provisioning, cloud-init, disk stubs) and the transfer itself, so a
	// refusal still wastes no work and changes no state anywhere. The figures are
	// the VM's ACTUAL allocation, which is what the target's usage will report
	// once the VM lands there.
	// No libvirt, no migration — said here, before the first thing this attempt
	// does on the target. It used to be checked after the row was written
	// `migrating`, and returned with the row stranded there.
	if s.virt == nil {
		return status.Errorf(codes.Internal, "libvirt not connected on host %s", s.hostName)
	}

	migLease, err := s.acquireDestinationHostLease(ctx, "MigrateVM", targetHost.Name, vm.Project, "vm:"+vm.Name, vm.CPUActual, vm.MemActual, intentVMResident)
	if err != nil {
		return err
	}
	// The target's capacity lease is held until libvirt ends the move: an
	// adopted migration (adoptAbandonedMigration) takes it with it, and
	// releases it when the move ends.
	leaseHeld := true
	// fwl is the live firmware move once the target may hold it: an exit
	// before libvirt has the guest aborts it there first (§7 P2), and drops
	// its marker once the target answered.
	var fwl *liveFirmwareRun
	defer func() {
		if !leaseHeld {
			return // the adopter releases it, and clears the marker's lease
		}
		// Released, it leaves the marker: a marker that still names the
		// lease is a dead process's, or one whose release failed, which
		// every recovery pass releases (review m4).
		if migLease.released(ctx) && fwl != nil {
			s.clearMarkerLease(fwl.marker.VM, fwl.marker.Attempt)
		}
	}()

	if opts.beforeMove != nil {
		if err := opts.beforeMove(ctx); err != nil {
			return err
		}
	}

	// From here until libvirt is handed the guest, every exit undoes what this
	// attempt did: the row goes back to the state the guest is actually in, and
	// whatever was pre-created on the target is removed. Without it, a client
	// that went away (a Ctrl-C fails the next progress Send) returned with the
	// row `migrating` — which the reconciler and owner-assert skip, snapshot
	// refuses, and a retry refuses as not running — and leaked the target's
	// stubs and cloud-init ISO. Disarmed when libvirt takes over (its failure
	// branch and the adopter own the outcome from then) and for the firmware
	// cold move, which owns its own.
	abort := &migrationAbort{armed: true}
	defer func() {
		if abort.armed {
			var park fwmig.Phase
			var why string
			if fwl != nil {
				park, why = s.abortLiveFirmwareBeforeCutover(ctx, fwl, false)
			}
			s.undoMigrationAttempt(ctx, vm.Name, req.TargetHost, abort)
			if fwl != nil {
				s.settleLiveFirmwareAbort(ctx, fwl, park, why)
			}
		}
	}()

	// §6.1 steps 2 and 3: the marker, the target's hold (Prepare), stage B.
	if fwLive {
		// The marker records the admission lease, which a recovery releases
		// if this process dies holding it (lab2-D2-proof F8).
		if migLease != nil {
			fwElig.lease, fwElig.leaseHolder = migLease.id, migLease.hostHolder
			if fwElig.leaseHolder == "" && migLease.id != "" {
				fwElig.leaseHolder = s.hostName
			}
		}
		if fwl, err = s.beginLiveFirmwareMove(ctx, vm, targetHost, fwElig); err != nil {
			return err
		}
	}

	// The VM's networks and its cloud-init ISO on the target, before anything
	// else is asked of it (prepareMigrationTarget).
	s.prepareMigrationTarget(ctx, vm, req.TargetHost)

	// Ensure disk files exist on target before --with-storage migration.
	// libvirt validates all file paths in the domain XML before block copy starts.
	// createdStubs is what THIS attempt created there — all a failed attempt
	// may remove.
	var createdStubs []string
	// cdromSources: the target's own file for each installer CD-ROM that names
	// another file there (a link, a library directory); the destination
	// definition carries those (MigrateParams.CDROMSources).
	var cdromSources map[string]string
	// targetCgroup: the target's cgroup version when it reported one.
	var targetCgroup string
	// stripVNC: the target cannot do VNC passwords (MigrateParams.StripVNCPassword).
	var stripVNC bool
	// targetNetDevs: the device the target serves each of the VM's managed
	// networks on, when it said (MigrateParams.NICBridges).
	var targetNetDevs map[string]string
	useTLS := false
	// route is where the migration's data goes: the cluster address, or the
	// target's address in migration.network (migration_network.go).
	route := migrationRoute{addr: targetHost.Address}
	if withStorage {
		var dstTLS bool
		var ens ensureOutcome
		if ens, err = s.ensureDisksOnTargetNet(ctx, req.TargetHost, vm.Name, diskStubs, srcTLS, !(fwCold || coldStopped)); err != nil {
			// EnsureDisks removed whatever it had created; the cloud-init ISO
			// pre-created above is the only leftover, and the abort removes it.
			return err
		}
		createdStubs, dstTLS, cdromSources, targetCgroup = ens.created, ens.tlsReady, ens.remap, ens.cgroupMode
		stripVNC, targetNetDevs = ens.vncPasswordUnavailable, ens.netDevices
		abort.createdStubs = createdStubs
		useTLS = srcTLS && dstTLS
		// Both ready is not enough: their credentials must chain to one
		// migration CA. A mismatch is refused, never sent in plaintext
		// instead. The abort undoes the stubs.
		if useTLS {
			localCA, caErr := s.localMigrationCA()
			if caErr != nil {
				// This host knows it is not an older build: an unreadable CA is
				// a fault to fix, not a reason to skip the comparison.
				return status.Errorf(codes.FailedPrecondition,
					"refusing to migrate VM %q with a storage copy: %s cannot read its own migration CA (%v), so it cannot "+
						"tell whether %s's migration-TLS credentials come from the same CA. Reissue its credentials with "+
						"`lv host install-migration-tls --reissue` (run where the cluster's migration CA lives)",
					req.VmName, s.hostName, caErr, req.TargetHost)
			}
			if err := migrationCAMismatch(req.VmName, s.hostName, localCA, s.localMigrationCAList(), req.TargetHost, ens.migrationCA, ens.migrationCAs); err != nil {
				return err
			}
		}
		kind := routeStorage
		if fwCold || coldStopped {
			kind = routeCold
		}
		if fwl != nil {
			route = s.chooseLiveFirmwareRoute(ctx, vm.Name, *targetHost, ens.migAddr, kind, storageTLSGap(srcTLS, dstTLS, s.hostName, req.TargetHost))
		} else {
			route = s.chooseMigrationRoute(ctx, vm.Name, *targetHost, ens.migAddr, kind, storageTLSGap(srcTLS, dstTLS, s.hostName, req.TargetHost))
		}
		if !dstTLS && ens.tlsUnusable != "" {
			// The target holds credentials it cannot use. Refused before the
			// copy, whatever the plaintext opt-in says; the abort undoes the
			// stubs.
			return unusableMigrationCredentialsRefusal(req.VmName, req.TargetHost, ens.tlsUnusable)
		}
		if !useTLS && !s.allowPlaintextStorageMigration {
			// This host could encrypt; the target cannot (no credentials, or an
			// older build that never answers). The abort undoes the stubs.
			return plaintextStorageRefusal(req.VmName, s.hostName, req.TargetHost, req.TargetHost)
		}
		if !useTLS {
			slog.Warn("storage migration is NOT encrypted: a host has no migration TLS and "+
				"migration.allow_unencrypted_storage is set", "vm", req.VmName,
				"source_tls", srcTLS, "target_tls", dstTLS, "target", req.TargetHost)
		}
	} else {
		// No disks to stub, but the target's qemu opens the installer ISO from
		// its own filesystem: the target judges that file before the migration
		// (EnsureDisks with no stubs does only that).
		ens, eerr := s.ensureDisksOnTargetNet(ctx, req.TargetHost, vm.Name, nil, srcTLS, !(fwCold || coldStopped))
		if eerr != nil {
			return eerr
		}
		cdromSources, targetCgroup = ens.remap, ens.cgroupMode
		stripVNC, targetNetDevs = ens.vncPasswordUnavailable, ens.netDevices
		switch {
		case fwCold || coldStopped:
			route = s.chooseMigrationRoute(ctx, vm.Name, *targetHost, ens.migAddr, routeCold, "")
		case fwl != nil:
			// QEMU's TLS stream only with both hosts ready and their
			// migration CAs agreeing (memoryTLSReady).
			gap := s.memoryTLSGap(srcTLS, ens, req.TargetHost)
			useTLS = gap == ""
			route = s.chooseLiveFirmwareRoute(ctx, vm.Name, *targetHost, ens.migAddr, routeMemory, gap)
		default:
			route = s.chooseMigrationRoute(ctx, vm.Name, *targetHost, ens.migAddr, routeMemory, s.memoryTLSGap(srcTLS, ens, req.TargetHost))
		}
	}
	if fwl != nil {
		// Stage C (spec §3.2 item 11): the resolved route and both hosts'
		// TLS; then the marker records it, with the stubs the target made.
		fwRoute, cerr := liveFirmwareStageC(vm.Name, *targetHost, withStorage, route, useTLS)
		if cerr != nil {
			return cerr
		}
		if err := s.recordLiveFirmwareRoute(fwl, fwRoute, createdStubs); err != nil {
			return err
		}
	}
	if route.onNetwork {
		// A cold move's disk stream (and the clone copy, which is one) is dialed
		// at this address; a live move's data is not (migration_network.go).
		abort.diskAddr = route.addr
	}

	// A STOPPED VM — every Secure-Boot/vTPM VM, and any other VM migrated with
	// --cold while stopped — moves WITHOUT libvirt runtime migration: there is no
	// running guest to migrate, and that path can't carry the host-local
	// NVRAM/swtpm. Its host-local disks are streamed to the target, its quiescent
	// firmware pushed, its domain defined there, the VM handed over with its
	// stopped state preserved, and the source cleaned up. Returns early — the
	// runtime-migration machinery below is for running VMs only. The abort stays
	// armed until the handoff commits, so a failure before it removes what this
	// attempt left on the target (the copied disks and the cloud-init ISO).
	if fwCold || coldStopped {
		return s.coldMigrateStoppedVM(ctx, vm, targetHost, fwSpec, abort, send)
	}

	// pre_migrate hook
	hspec := vmHooks(vm)
	pbVM := &pb.VM{Name: vm.Name, HostName: vm.HostName, State: pb.VMState_VM_RUNNING}
	hooks.Run(ctx, hooks.PreMigrate, pbVM, hspec)

	// Preparing
	if err := send(pb.MigratePhase_MIGRATE_PREPARING, 0, 0); err != nil {
		return err
	}

	// Default (zero value) and MIGRATE_LIVE both mean live migration.
	live := req.Strategy != pb.MigrateStrategy_MIGRATE_COLD
	strategyLabel := "live"
	if !live {
		strategyLabel = "cold"
	}

	// The VM's migration policy: its tuning, and its timeout below.
	tuning := migrationTuningFor(vm, live)
	migratePolicy := tuning.policy

	// Build destination URI: use TLS transport with our existing PKI certs.
	// Combined with MigrateTunnelled, all data flows over the single libvirt
	// TLS port (16514) — no SSH or extra ports required.
	// URIHost brackets an IPv6 literal — an unbracketed one makes this an
	// unparseable authority and libvirt connects nowhere useful.
	dconnuri := fmt.Sprintf("qemu+tls://%s/system", corrosion.URIHost(targetHost.Address))

	// Announced before the row is written `migrating`: a client that has gone
	// away fails this Send, and that is cheaper to find out while there is no
	// state to restore.
	if err := send(pb.MigratePhase_MIGRATE_COPYING, 0, 0); err != nil {
		return err
	}

	// The target puts the guest's NIC firewall — its guards above all — in
	// force before the guest arrives, under the tap names its MACs fix
	// (re-review I-10). Before anything is written, so a refusal changes
	// nothing. A guard record an earlier build left for a NIC the VM no
	// longer has is retired first: no target could put it in force.
	s.retireOrphanNICGuards(ctx, vm.Name, "")
	armed, aerr := s.armMigrationTarget(ctx, targetHost, vm.Name)
	if aerr != nil {
		return aerr
	}

	// Split-brain gate, LATE re-check: the early gate (after target validation) is a
	// fail-fast, but preflight/provisioning ran since then. Re-check quorum on the
	// source IMMEDIATELY before the irreversible step (state → migrating, then
	// MigrateToTarget), so a quorum loss during setup still stops the move. Fail-open
	// until split_brain_gate_v1 is cluster-wide.
	if reason, refused := s.sourceGateRefused(ctx, vm, targetHost.Name); refused {
		s.noteGateRefused(corrosion.ActionReschedule, reason)
		return status.Error(codes.FailedPrecondition, s.gateRefusal(ctx, "migration", reason, returnToServiceHint))
	}

	// Hot-detach SR-IOV VFs, after the late gate and every progress send — the
	// last step before the row is written `migrating` — so that as few exits as
	// possible can follow it. Each VF is recorded in the abort as soon as it has
	// left the guest: one a later VF's failure strands goes back into the guest.
	//
	// The VM keeps owning each VF until the cutover commits
	// (releaseSourceVFsAfterCutover), so no allocation can take one while it is
	// out of the guest, and a durable lease names them first, so a restart in
	// the window puts them back (RecoverDeviceLeases).
	// Ungated on operation_protocol, on purpose: this move does not change the
	// VM's replicated hardware, and the host-local lease is something no peer
	// relies on (TestMigrateVM_TheVFLeaseAndItsRecoveryWorkWithTheProtocolOff).
	if err := s.beginMigrationVFLease(req.VmName, pciAddresses(detachedVFs)); err != nil {
		return status.Errorf(codes.FailedPrecondition, "record the VFs detached for migration: %v", err)
	}
	// beginMigrationVFLease writes nothing for a VM with no VF to detach.
	abort.leaseWritten = len(detachedVFs) > 0
	for _, vf := range detachedVFs {
		// Membership-aware (idempotent) guest detach so a retried migration converges: if a
		// prior attempt already live-detached the VF but its release failed, the VF is gone
		// from the guest and a bare DetachHostdev would error ("device not found") and abort
		// before re-attempting the release. detachHostdevIfPresent skips the already-gone
		// detach so control falls through to the idempotent release. A DumpXML error still
		// aborts the migration (fail closed — membership cannot be confirmed).
		if err := s.detachHostdevIfPresent(ctx, req.VmName, vf.Address); err != nil {
			return status.Errorf(codes.Internal, "detach VF %s before migration: %v", vf.Address, err)
		}
		abort.detachedVFs = append(abort.detachedVFs, vf)
		slog.Info("VF detached for migration", "vm", req.VmName, "address", vf.Address)
	}

	// Mark as migrating in state store. Recorded first, so a write that errored
	// after landing is still restored by the abort.
	abort.stateWritten = true
	if err := corrosion.UpdateVMState(ctx, s.db, vm.Name, "migrating", migratingDetailPrefix+req.TargetHost); err != nil {
		s.noteStateWriteFail(corrosion.OpVMState, err)
	}
	// §6.1 step 5: the marker migrating, last before libvirt has the guest.
	if fwl != nil {
		fwl.vfs = detachedVFs
		if err := s.startLiveFirmwareMigration(fwl); err != nil {
			return err
		}
	}
	migrationStart := time.Now()
	sharesWeight := s.vmSharesWeight(ctx, vm.Name)

	// Apply migration timeout if configured.
	migrateCtx := ctx
	if migratePolicy.GetTimeoutSec() > 0 {
		var cancel context.CancelFunc
		migrateCtx, cancel = context.WithTimeout(ctx, time.Duration(migratePolicy.GetTimeoutSec())*time.Second)
		defer cancel()
	}

	// Run migration in background; poll progress. From here the failure branch
	// below and the adopter own the outcome, so the abort stands down.
	abort.armed = false
	// The request or the adopter waiting on done always gets an answer
	// (answerLibvirtCall).
	done := answerLibvirtCall(func() error {
		params := lv.MigrateParams{
			Live:          live,
			WithStorage:   withStorage,
			BandwidthMiB:  tuning.bandwidthMiB,
			AutoConverge:  tuning.autoConverge,
			MaxDowntimeMS: tuning.maxDowntimeMS,
			// Bracketed here, not in internal/libvirt: that package renders it
			// into a tcp:// migrate_uri authority but must not import corrosion.
			// The data channel's address: the cluster address, or the target's
			// address in migration.network (migration_network.go).
			TargetAddress: corrosion.URIHost(route.addr),
			DiskTargets:   diskTargets,
			// The target's migration certificate carries its CLUSTER address as
			// an IP SAN (`lv host init`/`add` issue it for the same address
			// peers dial). The name it is checked against stays that address
			// even when the data goes to another one, which is in no SAN.
			TLS:              useTLS || route.direct,
			TLSDestination:   targetHost.Address,
			Direct:           route.direct,
			CDROMSources:     cdromSources,
			SharesWeight:     sharesWeight,
			TargetCgroup:     targetCgroup,
			StripVNCPassword: stripVNC,
			// The destination definition carries each rbd disk's monitors as
			// its pool resolves them now (a re-addressed cluster's).
			RBDLocators: s.rbdLocatorsOf(ctx, vm.Name),
			// A live firmware move: the guest arrives paused, and the source
			// stays defined with its state (spec §6.3).
			FirmwareLive: fwl != nil,
			// Each NIC lands on the device the target serves its network on.
			NICBridges: s.migrationNICBridges(ctx, vm.Name, targetNetDevs),
		}
		armed.apply(&params)
		logVNCPasswordStrip(vm.Name, req.TargetHost, params.StripVNCPassword)
		return s.virt.MigrateToTarget(vm.Name, dconnuri, params)
	})

	// failedOnSource ends a migration that left the guest on this host.
	failedOnSource := func(migrateErr error) error {
		// Migration failed — VM is still on the source host.
		// Check if the domain is still alive; if so, restore to "running"
		// instead of leaving it in "error" (#21).
		//
		// Bounded and detached from the request: a client that goes
		// away now must not drop the restore and strand the row
		// `migrating`, which nothing else heals.
		fctx, fcancel := detachedMigrateCleanupCtx(ctx)
		defer fcancel()
		// A live firmware move is aborted (or parked) on the target first,
		// and a paused source guest resumed (§7 M1, M1p), so the VFs below
		// go into a guest that runs; its marker goes only after the row is
		// restored. A park whose source guest is not running keeps the row
		// migrating.
		var unmark func()
		keepRow := false
		if fwl != nil {
			unmark, keepRow = s.liveFirmwareMigrateFailed(fctx, fwl, migrateErr)
		}
		// The VFs go back before the row says running: the guest stayed.
		s.reattachVFsOnSource(fctx, vm.Name, detachedVFs, len(detachedVFs) > 0)
		if !keepRow && s.restoreSourceStateAfterFailedMigration(fctx, vm.Name,
			fmt.Sprintf("migration to %s failed: %v", req.TargetHost, migrateErr), migrateErr.Error()) {
			slog.Warn("migration failed but VM still running on source",
				"vm", vm.Name, "target", req.TargetHost, "error", migrateErr)
		}
		if unmark != nil {
			unmark()
		}
		// A parked firmware move keeps everything on the target ("kept":
		// nothing deleted anywhere), its stubs included.
		if fwl == nil || unmark != nil {
			s.cleanupFailedMigrationTarget(fctx, vm.Name, req.TargetHost, createdStubs)
		}
		send(pb.MigratePhase_MIGRATE_FAILED, 0, 0) //nolint:errcheck
		s.recordMigrationMetrics(strategyLabel, "failure", time.Since(migrationStart), 0, 0)
		return status.Errorf(codes.Internal, "migration failed: %v", migrateErr)
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

poll:
	for {
		select {
		case <-migrateCtx.Done():
			timedOut := s.abortOnMigrateTimeout(ctx, migrateCtx, vm.Name)
			if timedOut {
				// The policy timeout aborted the job: libvirt's answer says
				// what happened, and the request reports that (lab2-drain
				// anomaly 5). An error is the abort taken, the guest still
				// here; nil is a cut-over that won the race. Either goes on
				// as libvirt's answer does below.
				grace := time.NewTimer(s.drainAbortGraceOrDefault())
				select {
				case migrateErr := <-done:
					grace.Stop()
					if migrateErr != nil {
						migrateErr = fmt.Errorf("it reached its migration policy timeout_sec (%ds) and its libvirt job was aborted; %s stays on %s: %w",
							migratePolicy.GetTimeoutSec(), vm.Name, s.hostName, migrateErr)
					}
					answered := make(chan error, 1)
					answered <- migrateErr
					done = answered
					migrateCtx = context.WithoutCancel(ctx) // the loop now reads libvirt's answer
					continue poll
				case <-grace.C:
				}
			}
			// libvirt is still migrating. MigrateToTarget takes no context, so
			// cancelling this request does not stop the guest moving — it only
			// stops us watching. Returning bare here left the VM at
			// host_name=source/state=migrating while it ran on the target, and
			// the reconciler skips `migrating`, so nothing ever healed it.
			*adopted = true
			leaseHeld = false
			s.adoptAbandonedMigration(context.WithoutCancel(ctx), vm, req.TargetHost,
				withStorage, disks, done, unlock, migrationFinish{
					target: targetHost, detachedVFs: detachedVFs, pbVM: pbVM, hspec: hspec, armed: armed,
					createdStubs: createdStubs, lease: migLease, fwLive: fwl,
				})
			if timedOut {
				return status.Errorf(codes.DeadlineExceeded,
					"the migration of %q to %s reached its migration policy timeout_sec (%ds) and its libvirt job was aborted, "+
						"but libvirt did not answer the abort within %s; the move is left to finish in the background, and %s ends "+
						"running on %s or on %s, never on both — watch `lv events %s`",
					vm.Name, req.TargetHost, migratePolicy.GetTimeoutSec(), s.drainAbortGraceOrDefault(), vm.Name, s.hostName, req.TargetHost, vm.Name)
			}
			return status.Errorf(codes.DeadlineExceeded,
				"stopped waiting for the migration of %q to %s (%v); it is still running in "+
					"libvirt and will be completed in the background — watch `lv events %s`",
				vm.Name, req.TargetHost, migrateCtx.Err(), vm.Name)
		case migrateErr := <-done:
			if fwl != nil {
				if !s.liveFirmwareSourceActive(vm.Name) {
					// The source domain is not known to be active: the guest
					// may have left it (a failure after the target took it,
					// §7 M1b). The move goes on to cutover, which confirms the
					// domain inactive before Verify decides.
					if migrateErr != nil {
						slog.Warn("migrate: the migration call failed, but the source domain is not active; verifying the target",
							"vm", vm.Name, "target", req.TargetHost, "error", migrateErr)
					}
					break poll
				}
				if migrateErr == nil {
					// The guest did not leave: never a cutover (§7 M1, M1p).
					migrateErr = errLiveFirmwareSourceActive
				}
			}
			if migrateErr != nil {
				return failedOnSource(migrateErr)
			}
			break poll
		case <-ticker.C:
			memPct, diskPct := s.virt.DomainJobProgress(vm.Name)
			if memPct >= 0 {
				send(pb.MigratePhase_MIGRATE_CONVERGING, memPct, diskPct) //nolint:errcheck
			}
		}
	}

	// Cutover / completing
	cutoverStart := time.Now()
	send(pb.MigratePhase_MIGRATE_CUTOVER, 100, 0)    //nolint:errcheck
	send(pb.MigratePhase_MIGRATE_COMPLETING, 100, 0) //nolint:errcheck

	// A live firmware move commits only once the target's paused guest
	// verified against the source's final state (§6.1 steps 7 and 8); any
	// other outcome parks it, both copies kept.
	if fwl != nil {
		if err := s.liveFirmwareCutover(ctx, fwl); err != nil {
			if errors.Is(err, errLiveFirmwareSourceActive) {
				return failedOnSource(err)
			}
			s.recordMigrationMetrics(strategyLabel, "failure", time.Since(migrationStart), 0, 0)
			return err
		}
	}

	// The libvirt cutover has happened and cannot be rolled back. Commit the
	// VM+disk ownership move to the target atomically BEFORE any destructive
	// source cleanup or success signal — a failed commit is loud divergence, never
	// silent success. `disks` is the pre-cutover snapshot captured above.
	if err := s.finalizeMigrationOwnership(ctx, vm, req.TargetHost, withStorage, disks); err != nil {
		if fwl == nil {
			// A firmware move's target keeps its verified guest paused under
			// its hold; the marker stays verified, and recovery commits it.
			armed.uncommitted(ctx)
		}
		s.recordMigrationMetrics(strategyLabel, "failure", time.Since(migrationStart), 0, 0)
		s.recordVMEvent(context.WithoutCancel(ctx), vm.Name, "vm.migrated", "error",
			"cut over to "+req.TargetHost+" but ownership commit failed: "+err.Error())
		s.audit(context.WithoutCancel(ctx), "vm.migrate", vm.Name, "from="+s.hostName+" to="+req.TargetHost, "error")
		return status.Errorf(codes.Internal,
			"VM %q cut over to %s but committing ownership failed: %v", vm.Name, req.TargetHost, err)
	}
	if fwl != nil {
		if err := s.liveFirmwareCommitted(fwl); err != nil {
			return err
		}
	}
	s.releaseSourceVFsAfterCutover(context.WithoutCancel(ctx), vm.Name, detachedVFs)

	downtimeMs := float64(time.Since(cutoverStart).Milliseconds())
	s.recordMigrationMetrics(strategyLabel, "success", time.Since(migrationStart), downtimeMs, 0)
	slog.Info("migration complete", "vm", vm.Name, "from", s.hostName, "to", req.TargetHost)
	s.recordVMEvent(context.WithoutCancel(ctx), vm.Name, "vm.migrated", "ok", "from="+s.hostName+" to="+req.TargetHost)
	s.audit(context.WithoutCancel(ctx), "vm.migrate", vm.Name, "from="+s.hostName+" to="+req.TargetHost, "ok")

	// A cold firmware move's state is handled in coldMigrateStoppedVM (the early
	// return above); a live one's is released and cleaned up by the finish.
	if err := s.finishMigrationOnTarget(ctx, vm, migrationFinish{
		target: targetHost, detachedVFs: detachedVFs, pbVM: pbVM, hspec: hspec, armed: armed, fwLive: fwl,
	}); err != nil {
		return status.Errorf(codes.FailedPrecondition, "VM %q migrated to %s, but finishing the move failed: %s", vm.Name, req.TargetHost, status.Convert(err).Message())
	}

	return send(pb.MigratePhase_MIGRATE_DONE, 100, 0)
}

// finalizeMigrationOwnership commits the VM + disk ownership move to targetHost and
// only then removes orphaned source disks for a --with-storage host-local migration.
// disks is the placement snapshot captured before cutover.
//
// The libvirt cutover has already happened and cannot be rolled back, so:
//   - The ownership move (VM row + all disk rows) is one atomic guarded commit
//     (corrosion.CommitMigrationOwnership), so a failure can't leave some disks on
//     the target while the VM still points at the source.
//   - It runs on a bounded DETACHED context with a short retry, because the request
//     context may already be cancelled after cutover — losing the commit to a
//     cancelled ctx would recreate the very divergence we are closing.
//   - A source disk is deleted ONLY after the commit lands. A failed commit returns
//     an error (loud divergence) and deletes nothing.
//
// adoptAbandonedMigration takes over a live migration the request context
// stopped waiting for.
//
// MigrateToTarget takes no context and blocks in libvirt regardless, so a
// cancelled request or an expired migrate timeout does not stop the migration —
// it only stops us watching. The handler used to return bare at that point: no
// state update, no artifact cleanup, no ownership finalize, and the per-VM lock
// dropped mid-flight. libvirt then completed with
// MigratePersistDest|MigrateUndefineSource, so the guest ran on the TARGET
// while corrosion still said host_name=source, state=migrating — and nothing
// heals that, because the reconciler explicitly skips `migrating`.
//
// Abandoning the WAIT is fine. Abandoning the OUTCOME is not. The lock travels
// with the adoption: releasing it while libvirt is still moving the guest is
// what lets a concurrent snapshot or delete run against a VM mid-flight.
func (s *Server) adoptAbandonedMigration(
	ctx context.Context,
	vm *corrosion.VMRecord,
	targetHost string,
	withStorage bool,
	disks []corrosion.DiskRecord,
	done <-chan error,
	unlock func(),
	finish migrationFinish,
) {
	go func() {
		defer unlock()
		// The target keeps counting the guest's room until libvirt ends the
		// move: the adopter releases the lease, under the lock, and a live
		// firmware move's marker then no longer names it. One whose release
		// failed stays named, and the recovery releases it (re-review 2, m-A).
		defer func() {
			if finish.lease.released(ctx) && finish.fwLive != nil {
				s.clearMarkerLease(finish.fwLive.marker.VM, finish.fwLive.marker.Attempt)
			}
		}()
		defer s.invalidateInventoryCache()
		defer func() {
			if p := recover(); p != nil {
				slog.Error("migrate: adopted migration panicked", "vm", vm.Name, "panic", p)
			}
		}()

		var err error
		select {
		case err = <-done:
		case <-time.After(adoptedMigrationCeiling):
			// MigrateToTarget takes no context, so a migration that will not
			// converge runs for as long as libvirt lets it — with this VM's lock
			// held, blocking every later operation on it. Past the ceiling it is
			// aborted; libvirt then returns an error and the guest stays on the
			// source, which the failure branch below records.
			slog.Warn("migrate: adopted migration exceeded its ceiling; aborting it",
				"vm", vm.Name, "target", targetHost, "ceiling", adoptedMigrationCeiling)
			if aerr := s.virt.AbortMigration(vm.Name); aerr != nil {
				slog.Error("migrate: could not abort the adopted migration", "vm", vm.Name, "error", aerr)
			}
			err = <-done
		}
		if finish.fwLive != nil {
			if !s.liveFirmwareSourceActive(vm.Name) {
				// The guest may have left the source (§7 M1b): cutover and
				// Verify decide, below.
				if err != nil {
					slog.Warn("migrate: adopted firmware migration failed with the source domain not active; verifying the target",
						"vm", vm.Name, "target", targetHost, "error", err)
				}
				err = nil
			} else if err == nil {
				err = errLiveFirmwareSourceActive
			}
		}
		failed := func(err error) {
			// The migration failed after we stopped watching; the guest is still
			// on the source. Anything but `migrating` — that is the state nothing
			// heals.
			// The guest stayed, so it gets back the VFs detached for the move,
			// as a watched failure does: after a live firmware move's abort
			// (and a paused source guest's resume, §7 M1p).
			var unmark func()
			keepRow := false
			if finish.fwLive != nil {
				unmark, keepRow = s.liveFirmwareMigrateFailed(ctx, finish.fwLive, err)
			}
			s.reattachVFsOnSource(ctx, vm.Name, finish.detachedVFs, len(finish.detachedVFs) > 0)
			state, detail := "error", fmt.Sprintf("migration to %s failed after the request was abandoned: %v", targetHost, err)
			if st, sErr := s.virt.DomainState(vm.Name); sErr == nil && st == "running" {
				state, detail = "running", fmt.Sprintf("migration to %s failed after the request was abandoned; VM still running on %s: %v", targetHost, s.hostName, err)
			}
			// A LOCAL publish: the migration failed, so the guest and its domain
			// are still on THIS host. state is "error" or "running" depending on
			// what libvirt reports, so it can publish a running VM and has to be
			// routed — this function was added after the chokepoint landed and so
			// was never routed with the rest. A parked firmware move whose
			// source guest is not running keeps the row migrating.
			if !keepRow {
				if werr := s.publishRunning(ctx, vm.Name, state, func(ctx context.Context) error {
					return corrosion.UpdateVMState(ctx, s.db, vm.Name, state, detail)
				}); werr != nil {
					s.noteStateWriteFail(corrosion.OpVMState, werr)
				}
			}
			if unmark != nil {
				unmark()
			}
			if finish.fwLive == nil || unmark != nil {
				s.cleanupFailedMigrationTarget(ctx, vm.Name, targetHost, finish.createdStubs)
			}
			if finish.drainFrom != "" && finish.pbVM != nil {
				// The drain ran pre_migrate; post_migrate names where the VM is.
				finish.pbVM.HostName, finish.pbVM.State = s.hostName, vmStateToPB(state)
				hooks.Run(ctx, hooks.PostMigrate, finish.pbVM, finish.hspec)
			}
			slog.Warn("migrate: adopted migration failed", "vm", vm.Name, "target", targetHost, "error", err)
			s.recordVMEvent(ctx, vm.Name, "vm.migrated", "error", "abandoned request; migration failed: "+err.Error())
		}
		if err != nil {
			failed(err)
			return
		}

		// A live firmware move commits only on Verify's MATCH, adopted or not.
		if finish.fwLive != nil {
			if cerr := s.liveFirmwareCutover(ctx, finish.fwLive); cerr != nil {
				if errors.Is(cerr, errLiveFirmwareSourceActive) {
					failed(cerr)
					return
				}
				s.recordVMEvent(ctx, vm.Name, "vm.migrated", "error", "abandoned request; "+cerr.Error())
				return
			}
		}
		// libvirt cut over. The commit is the only thing that makes the cluster
		// agree with reality, and it cannot be skipped just because nobody is
		// listening any more.
		ferr := s.finalizeMigrationOwnership(ctx, vm, targetHost, withStorage, disks)
		if finish.drainFrom != "" {
			// The guest has left the drained host, whatever the commit did. After
			// the commit, so a judgement reading the row in between cannot find
			// it still migrating on the source and name it again.
			if drainForgetHookForTest != nil {
				drainForgetHookForTest()
			}
			s.forgetDrainTimeout(ctx, finish.drainFrom, vm.Name)
		}
		if ferr != nil {
			if finish.fwLive == nil {
				finish.armed.uncommitted(ctx)
			}
			if finish.drainFrom != "" && finish.pbVM != nil {
				// libvirt reported the cut-over: the guest runs on the target,
				// whatever the row says. post_migrate names it, as the watched
				// drain's commit failure does.
				finish.pbVM.HostName, finish.pbVM.State = targetHost, pb.VMState_VM_RUNNING
				hooks.Run(ctx, hooks.PostMigrate, finish.pbVM, finish.hspec)
			}
			slog.Error("migrate: adopted migration cut over but ownership commit FAILED — "+
				"the guest is on the target and the cluster does not know",
				"vm", vm.Name, "target", targetHost, "error", ferr)
			s.recordVMEvent(ctx, vm.Name, "vm.migrated", "error",
				"abandoned request; cut over to "+targetHost+" but ownership commit failed: "+ferr.Error())
			return
		}
		if finish.fwLive != nil {
			if cerr := s.liveFirmwareCommitted(finish.fwLive); cerr != nil {
				slog.Error("migrate: adopted firmware migration committed, but its marker could not record it", "vm", vm.Name, "error", cerr)
				return
			}
		}
		s.releaseSourceVFsAfterCutover(ctx, vm.Name, finish.detachedVFs)
		slog.Info("migrate: adopted migration completed", "vm", vm.Name, "target", targetHost)
		if finish.drainFrom != "" {
			// As a watched drain move: so that undrain can move it back.
			s.recordDrainOriginBounded(ctx, s.drainRecordJobFor(ctx, vm.Name, finish.drainFrom, targetHost))
		}
		s.recordVMEvent(ctx, vm.Name, "vm.migrated", "ok",
			"abandoned request; completed to "+targetHost)
		// The same finish a watched migration gets. Committing ownership and
		// stopping here left the guest without its SR-IOV VFs, its FDB entries
		// on the old VTEP, its LB backends and DNS stale, and the source's files
		// orphaned.
		if finish.target != nil {
			if err := s.finishMigrationOnTarget(ctx, vm, finish); err != nil {
				slog.Error("adopted migration: the guest is held paused on its target", "vm", vm.Name, "error", err)
			}
		} else {
			s.enqueueMirrorSync(ctx, vm.Name, mirrorOpUpsert)
		}
	}()
}

func (s *Server) finalizeMigrationOwnership(ctx context.Context, vm *corrosion.VMRecord, targetHost string, withStorage bool, disks []corrosion.DiskRecord) error {
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	var lastErr error
	committed := false
	for attempt := 0; attempt < 3; attempt++ {
		//runningcheck:allow ownership handoff — this runs on the SOURCE after cutover, whose
		// domain libvirt has already undefined (MigrateToTarget sets MigrateUndefineSource).
		// Routing it through the mark-then-commit helper would fail the marker write and
		// REFUSE this commit on every successful migration, leaving the row naming the
		// source while the guest runs on the target — the exact split-ownership state this
		// call site exists to prevent. The destination's convergence marks its own runtime.
		ok, err := corrosion.CommitMigrationOwnership(fctx, s.db, vm.Name, s.hostName, targetHost, "running", disks)
		if err != nil {
			lastErr = err
			slog.Error("post-migration: ownership commit failed, retrying",
				"vm", vm.Name, "to", targetHost, "attempt", attempt, "error", err)
			time.Sleep(time.Duration(attempt+1) * 250 * time.Millisecond)
			continue
		}
		if !ok {
			// Preconditions no longer hold (VM/disks changed during migration) —
			// a hard abort, never silent success. The guest is on the target all
			// the same, so the VM row is moved there if it is still this
			// migration's: a row left `migrating` on the source is one nothing
			// heals (owner-assert skips `migrating`), and the cluster would go on
			// naming a host that no longer runs the guest.
			//runningcheck:allow ownership handoff after cutover, as CommitMigrationOwnership above: the source's
			// domain is gone, and the destination's convergence marks its own runtime.
			moved, rerr := corrosion.RepointMigratedVM(fctx, s.db, vm.Name, s.hostName, targetHost, "running")
			switch {
			case rerr != nil:
				return fmt.Errorf("ownership commit precondition failed: VM %q or its disks changed during migration, "+
					"and the VM row could not be moved to %s: %v", vm.Name, targetHost, rerr)
			case moved:
				slog.Error("post-migration: disk rows changed during migration; moved the VM row to the target "+
					"and left the disk rows as they are", "vm", vm.Name, "to", targetHost)
				return fmt.Errorf("ownership commit precondition failed: VM %q's disks changed during migration; "+
					"the VM row now names %s, where it runs, and its disk rows were left unchanged", vm.Name, targetHost)
			}
			return fmt.Errorf("ownership commit precondition failed: VM %q or its disks changed during migration", vm.Name)
		}
		committed = true
		break
	}
	if !committed {
		return fmt.Errorf("ownership commit for VM %q did not land after retries: %w", vm.Name, lastErr)
	}

	// A --with-storage migration COPIES each host-local disk to the target's own
	// filesystem, leaving the source copy orphaned. Remove it (we run on the source
	// host) — but ONLY now that ownership is committed, and never a disk still
	// referenced by a linked clone or another VM (bug-sweep #1). Shared pools
	// (nfs/ceph/iscsi) share the file with the target, so they are left untouched.
	if !withStorage {
		return nil
	}
	for _, d := range disks {
		if !isHostLocalDiskDriver(d.StorageType) || d.Path == "" {
			continue
		}
		if referenced, reason, _ := s.pathStillReferenced(fctx, d.Path, vm.Name, d.DiskName); referenced {
			slog.Warn("post-migration: source disk still referenced — NOT deleting",
				"vm", vm.Name, "path", d.Path, "referenced_by", reason)
		} else if rmErr := os.Remove(d.Path); rmErr != nil && !os.IsNotExist(rmErr) {
			slog.Warn("post-migration: could not remove orphaned source disk",
				"vm", vm.Name, "path", d.Path, "error", rmErr)
		} else if rmErr == nil {
			slog.Info("post-migration: removed orphaned source disk",
				"vm", vm.Name, "path", d.Path)
		}
	}
	return nil
}

// cleanupPostMigration removes the source host's cloud-init ISO after migration.
//
// It deliberately does NOT touch disk files: for --with-storage migrations the
// orphaned source disks are already removed, per-disk and storage-type-aware,
// at the migration site above (only for host-local local/dir drivers, at each
// disk's RECORDED path). The previous os.RemoveAll(<dataDir>/disks/<vm>) here
// assumed a per-VM subdirectory that the flat <vm>-<disk>.qcow2 naming never
// uses — at best a no-op, at worst a path-wrong removal — so it's gone.
//
// Two things stay on the source on purpose, until the VM is deleted (DeleteVM
// then has each host it left remove them: deleted_vm_leftovers.go):
//
//   - a disk DETACHED while the VM ran here. The migration did not move it —
//     only live disks are copied — and detach preserves the file; its
//     soft-deleted row still names this host, which is how the delete finds it.
//   - the owner-epoch marker. It is this host's statement that its runtime
//     belonged to the old generation, and runtimeSuperseded reads an ABSENT
//     marker as "not superseded": removing it would turn a refused self-heal
//     restart from a stale replica into a permitted one, the dual-run the
//     marker exists to stop (finishVMReplaceRuntime keeps a stale marker for
//     the same reason). Once the row is tombstoned it fences nothing.
func (s *Server) cleanupPostMigration(vmName string) {
	// Always clean up cloud-init ISO — target regenerates from stored spec if needed.
	isoPath := filepath.Join(s.dataDir, "cloudinit", vmName+".iso")
	if _, err := os.Stat(isoPath); err == nil {
		// The instance-id the guest booted with is kept beside the path, for
		// a seed written again here when the VM comes back
		// (writeMissingSeedForStart).
		owner, _, _ := cloudinit.SeedOwner(isoPath)
		id := ""
		if sd, rerr := cloudinit.ReadSeed(isoPath); rerr == nil {
			id = sd.InstanceID()
		}
		if err := cloudinit.RemoveSeed(isoPath); err == nil {
			slog.Info("post-migration: removed cloud-init ISO", "vm", vmName, "path", isoPath)
			if rerr := cloudinit.RecordRemovedSeed(isoPath, owner, id); rerr != nil {
				slog.Warn("post-migration: the removed seed's instance-id was not kept", "vm", vmName, "error", rerr)
			}
		}
	}
}

// MigrateVMForHealthCheck is an exported wrapper for use by the health checker.
// It calls the full MigrateVM path (with all post-migration steps) using a
// discard stream that drops progress updates. Injects admin auth context.
func (s *Server) MigrateVMForHealthCheck(ctx context.Context, vmName, targetHost string) error {
	req := &pb.MigrateVMRequest{
		VmName:     vmName,
		TargetHost: targetHost,
		Strategy:   pb.MigrateStrategy_MIGRATE_LIVE,
	}
	// Inject an admin principal so RequirePerm/RequireRole pass for this
	// internal (health-checker-driven) call. Both username and role must
	// be present — RequirePerm rejects an empty principal before reaching
	// the role fallback.
	// The health-check migrate action does not live-move a Secure Boot /
	// vTPM VM (spec §1, §12).
	if err := s.migrateVMForHealthCheckRefusal(ctx, vmName); err != nil {
		return err
	}
	authCtx := context.WithValue(ctx, ctxKeyRole, "admin")
	authCtx = context.WithValue(authCtx, ctxKeyUsername, "system:healthcheck")
	return s.MigrateVM(req, &discardMigrateStream{ctx: authCtx})
}

// discardMigrateStream implements grpc.ServerStreamingServer[pb.MigrateProgress]
// by discarding all progress messages. Used for internal migration calls.
type discardMigrateStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (d *discardMigrateStream) Send(*pb.MigrateProgress) error { return nil }
func (d *discardMigrateStream) Context() context.Context       { return d.ctx }

// recordMigrationMetrics records duration, downtime, and transfer metrics if available.
func (s *Server) recordMigrationMetrics(strategy, result string, duration time.Duration, downtimeMs, transferBytes float64) {
	if s.migrationMetrics == nil {
		return
	}
	s.migrationMetrics.Duration.WithLabelValues(strategy, result).Observe(duration.Seconds())
	if downtimeMs > 0 {
		s.migrationMetrics.Downtime.WithLabelValues(strategy).Observe(downtimeMs)
	}
	if transferBytes > 0 {
		s.migrationMetrics.Transfer.WithLabelValues(strategy).Observe(transferBytes)
	}
}

// reattachVFTimeout bounds the whole post-cutover VF-reattach fan of
// AttachDevice calls, so a hung target can't block the migrate path forever.
const reattachVFTimeout = 60 * time.Second

// reattachVFsOnTarget sends AttachDevice RPCs to the target host for each VF
// that was detached before migration. The target allocates equivalent VFs from its own pool.
func (s *Server) reattachVFsOnTarget(ctx context.Context, targetHostName, addr string, grpcPort int, vmName string, vfs []corrosion.PCIDeviceRecord) (failed []string) {
	if h := reattachVFsOnTargetHook; h != nil {
		return h(targetHostName, vmName, vfs)
	}
	conn, err := s.dialPeerAddr(peerTarget(addr, grpcPort))
	if err != nil {
		slog.Warn("reattach VFs: dial target", "host", targetHostName, "error", err)
		return pciAddresses(vfs)
	}
	defer conn.Close()
	return s.sendReattachVFs(ctx, pb.NewLiteVirtClient(conn), targetHostName, vmName, vfs)
}

// reattachVFsOnTargetHook, when set, answers reattachVFsOnTarget in place of
// the target. Test-only.
var reattachVFsOnTargetHook func(target, vm string, vfs []corrosion.PCIDeviceRecord) (failed []string)

// sendReattachVFs issues an AttachDevice to the target for each pre-migration
// detached VF. It runs on a context detached from the inbound RPC — same
// rationale as notifyDetachedContext (finding 6): a long migration (large disk
// copy) can outlive the entry-node user's forwarded bearer, and under
// ForwardedIdentityV1 the owning target has no peer-identity fallback, so a
// stale bearer copied onto these RPCs would be rejected Unauthenticated and the
// migrated VM would come up without its passthrough devices. Detaching makes
// this a plain peer/system call; the span survives (via ctx's value chain) so
// the reattach still links into the vm.migrate trace. The client is a parameter
// so a test can capture the exact outbound context.
func (s *Server) sendReattachVFs(ctx context.Context, client pb.LiteVirtClient, targetHostName, vmName string, vfs []corrosion.PCIDeviceRecord) (failed []string) {
	ctx, cancel := notifyDetachedContext(ctx, reattachVFTimeout)
	defer cancel()
	for _, vf := range vfs {
		_, err := client.AttachDevice(ctx, &pb.AttachDeviceRequest{
			VmName: vmName,
			PciDevice: &pb.DeviceSpec{
				Type:   vf.Type,
				Vendor: vf.VendorID,
				Count:  1,
				Sriov:  true,
			},
		})
		if err != nil {
			failed = append(failed, vf.Address)
			slog.Warn("reattach VF on target failed", "vm", vmName, "type", vf.Type,
				"vendor", vf.VendorID, "target", targetHostName, "error", err)
		} else {
			slog.Info("VF reattached on target", "vm", vmName, "type", vf.Type, "target", targetHostName)
		}
	}
	return failed
}

// EnsureCloudInit generates a cloud-init ISO on this host for a VM migrating
// in. Called by the source host before migration so the target has the ISO
// ready. A seed here of another VM of the name — one deleted while this host
// kept its seed — is written again (cloudinit/seed_owner.go). A seed here that
// is already this VM's is a copy from an earlier stay, which NICs attached or
// detached since are not in, and the guest applies a seed's network-config
// on every boot: its network-config and vendor-data are replaced by the
// source's, and its meta-data and user-data are kept byte for byte. A source
// from before it sent vendor-data derives its network-config another way, and
// the seed is then kept as it is.
//
// It writes a seed — user-data and vendor-data the guest runs as root — and
// stamps it as the VM's, so it is the target half of a migration a source
// daemon drives, as EnsureFirmwareState is: a peer call (every source calls it
// through its peer client), and vm.migrate on the VM for the identity the peer
// forwards.
func (s *Server) EnsureCloudInit(ctx context.Context, req *pb.EnsureCloudInitRequest) (*emptypb.Empty, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	vm, err := s.authorizeMigrationTarget(ctx, req.VmName)
	if err != nil {
		return nil, err
	}
	isoPath, err := lv.SafeCloudInitISOPath(s.dataDir, req.VmName)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	owner := cloudinit.SpecUUID(vm.Spec)
	if cloudinit.SeedIsFor(isoPath, owner) {
		if req.Vendordata == nil {
			return &emptypb.Empty{}, nil
		}
		changed, err := cloudinit.RebuildISO(isoPath, req.Networkconfig, *req.Vendordata)
		if err != nil {
			detail := fmt.Sprintf("the VM's seed at %s on %s could not take the migration source's network-config: %v; the VM arrives on it as it is, so a NIC attached or detached since the seed was written may lose its configuration in the guest at its next boot; the next start or NIC attach or detach of the VM on %s tries again", isoPath, s.hostName, err, s.hostName)
			slog.Warn("cloud-init ISO for migration: "+detail, "vm", req.VmName)
			if merr := cloudinit.MarkSeedStale(isoPath); merr != nil {
				slog.Warn("cloud-init ISO for migration: could not mark the seed stale", "vm", req.VmName, "error", merr)
			}
			s.recordVMEventSeverity(ctx, req.VmName, "seed.rebuild_failed", "error", "warning", detail)
			return nil, status.Errorf(codes.Internal, "rewrite the network-config of the VM's cloud-init ISO: %v", err)
		}
		if changed {
			slog.Info("cloud-init ISO for migration: the VM's seed here takes the source's network-config", "vm", req.VmName, "path", isoPath)
		}
		return &emptypb.Empty{}, nil
	}
	// A file already at the path is written over, but it was not created
	// for this migration: a failed migration's cleanup leaves the path alone,
	// as it does a seed that was this VM's.
	_, statErr := os.Lstat(isoPath)
	existed := statErr == nil

	if err := writeVMSeed(vm, req, isoPath, req.VmName); err != nil {
		return nil, status.Errorf(codes.Internal, "generate cloud-init ISO: %v", err)
	}
	if !existed {
		s.recordMade(ctx, &s.migrationISOs, req.VmName, isoPath)
	}
	slog.Info("cloud-init ISO generated for migration", "vm", req.VmName, "path", isoPath, "replaced", existed)
	return &emptypb.Empty{}, nil
}

// writeVMSeed writes vm's seed at isoPath from req (ensureCloudInitRequest)
// and stamps it as the VM's: hostname the VM's name and instanceID its
// instance-id, the one the guest booted with, so it is not a new instance.
func writeVMSeed(vm *corrosion.VMRecord, req *pb.EnsureCloudInitRequest, isoPath, instanceID string) error {
	userData := req.Userdata
	if userData == "" {
		userData = "#cloud-config\n{}\n"
	}
	// The vendor-data the source decided. A source from before the field
	// sends none, and the target derives it from the VM's spec; a spec that
	// cannot be read gets none.
	vendorData := ""
	if req.Vendordata != nil {
		vendorData = *req.Vendordata
	} else {
		var spec pb.VMSpec
		if json.Unmarshal([]byte(vm.Spec), &spec) == nil {
			vendorData = cloudinit.SeedVendorData(&spec, req.Networkconfig)
		}
	}
	if err := cloudinit.GenerateISO(cloudinit.Config{
		InstanceID:    instanceID,
		LocalHostname: req.VmName,
		UserData:      userData,
		NetworkConfig: req.Networkconfig,
		VendorData:    vendorData,
	}, isoPath); err != nil {
		return err
	}
	if err := cloudinit.StampSeed(isoPath, cloudinit.SpecUUID(vm.Spec)); err != nil {
		slog.Warn("cloud-init ISO: could not stamp it with its VM; a later start writes it again",
			"vm", req.VmName, "error", err)
	}
	return nil
}

// EnsureDisks creates empty qcow2 images at the requested paths so that
// libvirt's domain XML validation passes before block copy starts.
// Called by the source host before --with-storage migration.
//
// It reports the stubs it created and records them (migrationStubs). The copy
// mirrors each source disk into the file at its path here, and a failed attempt
// removes what was created, so a file this host did not create for this VM
// takes part in neither. Such a file is refused, not skipped: it may be the
// VM's disk from an earlier stay here — drill D1's was a copy partition settle
// kept — and the mirror overwrites it whenever the sizes match. Refused rather
// than overwritten on an operator's say-so, because only someone looking at
// the file on this host can tell whether it is still needed, and once they
// have, moving it aside is the whole remedy. A stub this host created for the
// VM in an earlier attempt is its own and is reused.
//
// Every path is checked before any is created, and a failure part-way removes
// the stubs this call created, so a refused or failed call leaves nothing.
func (s *Server) EnsureDisks(ctx context.Context, req *pb.EnsureDisksRequest) (*pb.EnsureDisksResponse, error) {
	if _, err := s.authorizeMigrationTarget(ctx, req.VmName); err != nil {
		return nil, err
	}
	// Whether this host's QEMU can take an encrypted copy, settled once.
	var tlsReady bool
	var tlsErr error
	if req.WantMigrationTls {
		tlsReady, tlsErr = s.migrationTLSState()
	}
	// A storage copy (disk stubs) that asks for TLS while this host's own
	// credentials are unusable is refused, before anything is created: an
	// older source reads only migration_tls_ready, and with its plaintext
	// opt-in it would send the copy in plaintext to a host that is merely
	// misconfigured. A memory-only ask is answered "not ready" below, and
	// that move stays in libvirt's tunnel.
	if len(req.Disks) > 0 && errors.Is(tlsErr, pki.ErrInvalidMigrationCredentials) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s holds migration-TLS credentials it cannot use (%s), so a storage copy to it cannot be encrypted. "+
				"Reissue its credentials with `lv host install-migration-tls --reissue` (run where the cluster's migration CA lives)",
			s.hostName, headerValue(tlsErr.Error()))
	}
	// A NIC whose MTU this host's bridge does not equal: answered before
	// anything is created here, and the source refuses the move.
	if p := s.nicMTUProblem(ctx, req.GetNicMtu()); p != "" {
		return &pb.EnsureDisksResponse{NicMtuProblem: p}, nil
	}
	isoWarning := ""
	var isoResolved map[string]string
	// The domain lands here with its installer ISO; qemu on THIS host opens
	// it, so this host judges it before the migration may proceed, and for a
	// runtime move names the file here the destination definition is to carry.
	if rec, gErr := corrosion.GetVM(ctx, s.db, req.VmName); gErr == nil && rec != nil {
		w, resolved, err := s.verifyIncomingVMISO(ctx, rec, req)
		if err != nil {
			return nil, err
		}
		isoWarning, isoResolved = w, resolved
		// The incoming domain names its ceph disks' secrets: defined here
		// now, from this host's pool, or the migration is refused with the
		// reason before libvirt is asked (libvirtd drops the secrets on a
		// restart, and this host's keyring may hold another key).
		if err := s.prepareIncomingCephDisks(ctx, rec); err != nil {
			return nil, err
		}
	}
	for _, stub := range req.Disks {
		// Only ever create stubs in a real disk-artifact root (the disks dir or a
		// file-backed pool dir) — never an arbitrary path under the data dir such
		// as state.db.
		if !s.withinDiskArtifactRoot(stub.Path) {
			return nil, status.Errorf(codes.InvalidArgument, "disk stub path %q is not in a disk-artifact root", stub.Path)
		}
		if _, err := os.Lstat(stub.Path); err == nil {
			if !s.madeHere(ctx, &s.migrationStubs, req.VmName, stub.Path) {
				return nil, status.Errorf(codes.FailedPrecondition,
					"disk %s of VM %q already exists on %s, and this migration did not create it. "+
						"It may be the VM's disk from an earlier stay on %s (a copy partition settle kept, or one a "+
						"rolled-back move placed after it gave up, say), and copying the disk there would overwrite it. "+
						"It may be the only copy of the VM's data from before a failover: do not delete it. %s, "+
						"then migrate again",
					stub.Path, req.VmName, s.hostName, s.hostName, moveAsideAdvice(s.hostName, stub.Path))
			}
		} else if !os.IsNotExist(err) {
			return nil, status.Errorf(codes.Internal, "stat disk stub %s: %v", stub.Path, err)
		}
	}
	if s.isoResolvedWithheld {
		isoResolved = nil
	}
	resp := &pb.EnsureDisksResponse{InstallerIsoWarning: isoWarning, InstallerIsoResolved: isoResolved, CgroupMode: lv.CgroupMode(),
		// A live migration onto this host moves a guest without its VNC
		// password when this QEMU cannot do one (docs/ui.md "Console passwords").
		VncPasswordUnavailable: s.vncPasswordUnavailableForMigration() != ""}
	if req.GetWantNetworkDevices() {
		resp.NetworkDevices = s.servedNetworkDevices(ctx, req.GetVmName())
	}
	var made []string // created by this call: removed again if a later one fails
	undo := func() {
		for _, p := range made {
			if err := s.removeDiskFileBeneath(p, false); err != nil {
				slog.Warn("disk stub: remove after a failed EnsureDisks", "vm", req.VmName, "path", p, "error", err)
			}
			s.migrationStubs.forget(p)
		}
	}
	for _, stub := range req.Disks {
		// Create a valid qcow2 image — QEMU validates the format header
		// before block copy starts. Use a minimal size; migration overwrites it.
		sizeBytes := uint64(1024 * 1024 * 1024) // 1G default
		if stub.SizeBytes > 0 {
			sizeBytes = uint64(stub.SizeBytes)
		}
		// The stub's directory is opened once, by descriptor, beneath its disk
		// root with no link followed (the root judged, missing directories made
		// through it), and the exists check, the replace and the create all go
		// through that held directory: a link planted on the way is refused,
		// never followed to create a stub somewhere else.
		root, rootOK := s.diskArtifactRootOf(stub.Path)
		if !rootOK {
			undo()
			return nil, status.Errorf(codes.InvalidArgument, "disk stub path %q is not in a disk-artifact root", stub.Path)
		}
		pd, derr := s.openDiskDir(root, relUnder(root, filepath.Dir(stub.Path)), true, false)
		if derr != nil {
			undo()
			return nil, status.Errorf(codes.Internal, "create disk dir %s: %v", filepath.Dir(stub.Path), derr)
		}
		base := filepath.Base(stub.Path)
		file := pd.path(base)
		reused, stubErr := func() (bool, error) {
			defer pd.close()
			if fi, err := os.Lstat(file); err == nil {
				// This host's own stub from an earlier attempt for this VM (checked
				// above). Reuse it at the size asked for now: the mirror needs the
				// sizes to agree, and a stub holds nothing worth keeping. Only a
				// regular file is reused: a link (or anything else) at the name is
				// replaced, never taken for the stub.
				if info, ierr := qcow2.Info(file); fi.Mode().IsRegular() && ierr == nil && info.VirtualSize == sizeBytes {
					return true, nil
				}
				if err := pd.unlink(base); err != nil {
					return false, status.Errorf(codes.Internal, "replace stub %s: %v", stub.Path, err)
				}
				s.migrationStubs.forget(stub.Path)
			}
			if err := qcow2.Create(file, sizeBytes, nil); err != nil {
				return false, status.Errorf(codes.Internal, "create stub %s: %v", stub.Path, err)
			}
			return false, nil
		}()
		if stubErr != nil {
			undo()
			return nil, stubErr
		}
		if reused {
			resp.CreatedPaths = append(resp.CreatedPaths, stub.Path)
			slog.Info("disk stub reused for migration", "vm", req.VmName, "path", stub.Path)
			continue
		}
		made = append(made, stub.Path)
		if s.ensureStubCreatedHook != nil {
			s.ensureStubCreatedHook()
		}
		s.recordMade(ctx, &s.migrationStubs, req.VmName, stub.Path)
		resp.CreatedPaths = append(resp.CreatedPaths, stub.Path)
		slog.Info("disk stub created for migration", "vm", req.VmName, "path", stub.Path, "size_bytes", stub.SizeBytes)
	}
	if req.WantMigrationTls {
		// The source can encrypt the copy; tell it whether this host's QEMU can
		// take the other end, and, in a response header, which migration CA
		// its credentials chain to, so the source can refuse a mismatch
		// before the copy rather than at QEMU's TLS handshake.
		resp.MigrationTlsReady = tlsReady
		if fp, _ := s.localMigrationCA(); resp.MigrationTlsReady && fp != "" {
			md := metadata.Pairs(MigrationCAMD, fp)
			if list := s.localMigrationCAList(); len(list) > 0 {
				packed, dropped := packMigrationCAList(list)
				md.Append(MigrationCAsMD, packed)
				if dropped > 0 {
					md.Append(MigrationCAsMoreMD, strconv.Itoa(dropped))
				}
			}
			_ = grpc.SetHeader(ctx, md)
		}
		if errors.Is(tlsErr, pki.ErrInvalidMigrationCredentials) {
			// Not ready because the credentials here are unusable: say why, so
			// the source can refuse with the fix rather than "no credentials".
			_ = grpc.SetHeader(ctx, metadata.Pairs(MigrationTLSUnusableMD, headerValue(tlsErr.Error())))
		}
	}
	s.answerMigrationNetwork(ctx, req, resp)
	return resp, nil
}

// EnsureFirmwareState materializes a Secure-Boot/vTPM VM's firmware-state bundle
// (NVRAM + swtpm) pushed by a cold-migration source, so libvirt can define the
// domain here with its BitLocker-binding state intact (G1). Mirrors EnsureDisks.
//
// A stopped VM without firmware state is cold-migrated through it too, with no
// bundle: the call then only defines the domain, under the same attempt record
// and rollback. A VM whose recorded spec has firmware state is refused without
// its bundle, so it can never be defined here with a fresh TPM.
func (s *Server) EnsureFirmwareState(ctx context.Context, req *pb.EnsureFirmwareStateRequest) (*pb.EnsureFirmwareStateResponse, error) {
	if req.VmName == "" || (len(req.Bundle) == 0 && req.DomainXml == "") {
		return nil, status.Error(codes.InvalidArgument, "vm_name and a non-empty firmware bundle or domain definition are required")
	}
	// The target half of a cold migration its SOURCE DAEMON drives, as
	// ReceiveMigrationDisk is: it defines caller-supplied domain XML (only its
	// name and uuid are checked), so a user holding vm.migrate must not reach
	// it directly. requirePeerCert also admits a promoted forwarded peer, so
	// the source's own call is unaffected.
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	vm, err := s.authorizeMigrationTarget(ctx, req.VmName)
	if err != nil {
		return nil, err
	}
	// A VM whose row names this host lives here: a domain defined for it is
	// the one `lv start` boots, and a migration TO this host never names it.
	if vm.HostName == s.hostName {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q lives on %s; its domain is not defined here by a migration to it", vm.Name, s.hostName)
	}
	hasBundle := len(req.Bundle) > 0
	if !hasBundle && usesFirmwareState(vm.Spec) {
		return nil, status.Errorf(codes.InvalidArgument,
			"VM %q has Secure Boot / vTPM firmware state; it is not defined here without its firmware bundle", req.VmName)
	}
	// Only firmware this call materialized is wiped on a refusal below: with no
	// bundle there is none, and the name-keyed files here may be another VM's
	// (a same-name VM deleted with --keep-disks keeps its marker).
	wipe := func() {
		if hasBundle {
			s.fw().WipeFirmwareState(req.VmName, req.Uuid)
		}
	}
	// The uuid keys the swtpm tree this restores into (and wipes on a refusal
	// below), and the permission was checked on vm_name alone: it must be this
	// VM's own recorded uuid — what the source sends (fwSpec.UUID) — or
	// vm.migrate on one VM would overwrite or erase another VM's TPM.
	if req.Uuid != "" && (!lv.ValidFirmwareUUID(req.Uuid) ||
		!strings.EqualFold(parseFirmwareSpec(vm.Spec).UUID, req.Uuid)) {
		return nil, status.Errorf(codes.InvalidArgument,
			"firmware uuid %q is not the recorded uuid of VM %q", req.Uuid, req.VmName)
	}
	// vm_name + uuid index into on-disk firmware paths, so validate them to a safe
	// charset (no path traversal). And refuse to materialize state under a domain
	// that already exists here — this RPC is for a migration TARGET that hasn't
	// defined the VM yet; clobbering a live VM's firmware would be destructive (G1).
	if !validRestoreName(req.VmName) || (req.Uuid != "" && !validRestoreName(req.Uuid)) {
		return nil, status.Error(codes.InvalidArgument, "invalid vm_name or uuid")
	}
	// Held until the domain is defined and recorded, so a concurrent
	// RollbackFirmwareState cannot wipe the firmware materialized below.
	s.firmwareTargets.op.Lock()
	defer s.firmwareTargets.op.Unlock()
	// A live firmware move's record of the VM here (spec §6.9): its state is
	// that move's, and only the move writes or removes it.
	if err := s.firmwareMoveRecordRefusal("materialise firmware state", req.VmName, req.Uuid); err != nil {
		return nil, err
	}
	if s.virt != nil && s.virt.DomainExists(req.VmName) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"refusing to materialize firmware over already-defined domain %q", req.VmName)
	}
	if hasBundle {
		if err := s.fw().ReadFirmwareBundle(bytes.NewReader(req.Bundle), req.VmName, req.Uuid); err != nil {
			return nil, status.Errorf(codes.Internal, "materialize firmware state for %q: %v", req.VmName, err)
		}
	}
	// Define (shut off) the domain from the source's own XML now that its firmware
	// is materialized, so the migrated VM is immediately startable here (a plain
	// reassigned-stopped VM is otherwise undefined on this host, and StartDomain /
	// the reconciler won't rebuild it). DefineDomain does NOT start it — the VM
	// stays stopped as intended (G1).
	resp := &pb.EnsureFirmwareStateResponse{}
	if req.DomainXml != "" && s.virt != nil {
		// The XML embeds the SOURCE's absolute firmware paths (loader / VARS
		// template / NVRAM). It's only portable to a host with an identical layout,
		// so refuse a fingerprint mismatch rather than define a domain pointing at
		// the source host's paths.
		if req.SourceFirmwareFingerprint != "" && req.SourceFirmwareFingerprint != s.firmwareLayoutFingerprint() {
			wipe()
			return nil, status.Errorf(codes.FailedPrecondition,
				"firmware path layout differs between source and target (dataDir/OVMF paths); cold firmware migration requires an identical layout on both hosts")
		}
		// Validate the XML identity matches the request — never define a mismatched
		// or unrelated domain via this RPC. A uuid compares without case: libvirt
		// reports lower case, and a stored spec uuid is never overwritten.
		if xn, xu := domainIdentity(req.DomainXml); xn != req.VmName || (req.Uuid != "" && !strings.EqualFold(xu, req.Uuid)) {
			wipe()
			return nil, status.Errorf(codes.InvalidArgument,
				"domain XML identity (name=%q uuid=%q) does not match request (name=%q uuid=%q)", xn, xu, req.VmName, req.Uuid)
		}
		// USB passthrough: the source's definition names the SOURCE's device.
		// Re-resolve each one here — its mapping's row for this host, a
		// bus-port from this host's sysfs — so the VM is defined with the device
		// this host has, or not at all.
		domXML := req.DomainXml
		if usbSpec := parseSpecOrNil(vm.Spec); len(usbSpec.GetUsbDevices()) > 0 {
			usb, uerr := s.resolveUSBHostdevs(ctx, usbSpec)
			if uerr != nil {
				wipe()
				return nil, uerr
			}
			rewritten, rerr := lv.ReplaceUSBHostdevs(domXML, usb)
			if rerr != nil {
				wipe()
				return nil, status.Errorf(codes.Internal, "re-resolve USB devices of %q on %s: %v", req.VmName, s.hostName, rerr)
			}
			domXML = rewritten
		}
		// The source rendered <shares> for ITS cgroup version and says which
		// weight that was (a cleared weight arrives as the default); this host
		// defines the domain at its own scale. No weight sent: unchanged.
		domXML = lv.RetargetCPUShares(domXML, int(req.SharesWeight), lv.CgroupMode() == "v2")
		// A plain UEFI VM's libvirt-managed vars: the source's bytes, hashed
		// after the write, or none and a file of an earlier VM of the name set
		// aside, so the VM never boots from vars that are not its own.
		varsWritten := false
		switch {
		case usesFirmwareState(vm.Spec):
			if len(req.LibvirtVars) > 0 {
				wipe()
				return nil, status.Errorf(codes.InvalidArgument, "VM %q uses Secure Boot / vTPM; its UEFI vars are the firmware bundle's", req.VmName)
			}
		case len(req.LibvirtVars) > 0:
			sum, werr := s.writeTargetLibvirtVars(req.VmName, domXML, req.LibvirtVars, req.LibvirtVarsSha256)
			if werr != nil {
				wipe()
				return nil, werr
			}
			resp.LibvirtVarsSha256, varsWritten = sum, true
		default:
			if serr := s.setAsideStaleLibvirtVars(req.VmName); serr != nil {
				wipe()
				return nil, status.Errorf(codes.Internal, "%v", serr)
			}
		}
		if err := s.virt.DefineDomain(domXML); err != nil {
			// Roll back the firmware we just materialized so a retry is clean.
			wipe()
			if varsWritten {
				_ = os.Remove(s.libvirtVarsPath(req.VmName))
			}
			return nil, status.Errorf(codes.Internal, "define migrated domain %q: %v", req.VmName, err)
		}
		// This call materialized the firmware and defined the domain: record
		// them as the attempt's, the only thing its rollback may remove, and
		// say so to the source.
		s.firmwareTargets.add(req.VmName, req.AttemptId, req.Uuid)
		if varsWritten {
			s.firmwareTargets.markVars(req.VmName)
		}
		resp.DomainDefined = true
	}
	slog.Info("firmware state received for migration", "vm", req.VmName, "bytes", len(req.Bundle),
		"defined", resp.DomainDefined, "attempt", req.AttemptId)
	return resp, nil
}

// ensureFirmwareStateOnTarget defines a cold migration's domain on the target
// from the source's own XML (EnsureFirmwareState), so the stopped VM is
// startable there. For a Secure-Boot/vTPM VM it first captures this host's
// firmware-state bundle and pushes it with the XML, so the target defines the
// domain with the BitLocker-binding state present. Unlike disks, the firmware is
// NOT best-effort — a firmware VM that migrates without its state would boot a
// fresh TPM, so a failure aborts (G1). A VM without firmware state sends no
// bundle and no firmware layout fingerprint: its XML is carried as a live
// migration carries it.
//
// It reports what the call left on the target, for the rollback of a failure
// before the handoff commits (abandonFirmwareTarget). attempt names this
// migration attempt to the target, which records the domain it defines under it.
func (s *Server) ensureFirmwareStateOnTarget(ctx context.Context, targetHost, vmName string, fs firmwareSpec, domainXML, attempt string, vars []byte) (firmwareTargetOutcome, string, error) {
	req := &pb.EnsureFirmwareStateRequest{VmName: vmName, DomainXml: domainXML, AttemptId: attempt,
		SharesWeight: int32(s.vmSharesWeight(ctx, vmName))}
	// The VM's uuid names the attempt's record on the target whatever the
	// firmware: its rollback is addressed by it, and a plain VM's (no uuid sent)
	// never matched, leaving the domain and the vars it wrote behind.
	req.Uuid = fs.UUID
	// A plain UEFI VM's libvirt vars: the target holds them, verified by hash,
	// or the move does not go on (the source's copy is removed only after).
	if len(vars) > 0 {
		req.LibvirtVars, req.LibvirtVarsSha256 = vars, varsSHA256(vars)
	}
	if fs.SecureBoot || fs.Tpm {
		// Per-component preflight: never push a PARTIAL bundle (WriteFirmwareBundle
		// alone would accept NVRAM-only or swtpm-only) — that restores a fresh TPM.
		if err := s.firmwarePresent(vmName, fs); err != nil {
			return fwTargetUntouched, "", err
		}
		var buf bytes.Buffer
		has, err := s.fw().WriteFirmwareBundle(vmName, fs.UUID, &buf)
		if err != nil {
			return fwTargetUntouched, "", status.Errorf(codes.Internal, "capture firmware state for %q: %v", vmName, err)
		}
		if !has {
			return fwTargetUntouched, "", status.Errorf(codes.FailedPrecondition,
				"firmware state for %q is not present on this host; cannot migrate it consistently", vmName)
		}
		req.Bundle = buf.Bytes()
		req.SourceFirmwareFingerprint = s.firmwareLayoutFingerprint()
	}
	client, closeConn, err := s.dialPeer(ctx, targetHost)
	if err != nil {
		return fwTargetUntouched, "", status.Errorf(codes.Unavailable, "cannot reach target host %s to define the VM: %v", targetHost, err)
	}
	defer closeConn()
	resp, err := client.EnsureFirmwareState(ctx, req)
	if err != nil && len(req.Bundle) == 0 && status.Code(err) == codes.InvalidArgument &&
		strings.Contains(status.Convert(err).Message(), oldTargetBundleRequired) {
		// An older target's first check: it refused before defining anything.
		return fwTargetUntouched, "", targetTooOldForColdMigration(targetHost, vmName)
	}
	if err != nil {
		// The target may have defined the domain before the call failed: a
		// cancelled request loses the answer, not the define.
		return fwTargetUnknown, "", status.Errorf(codes.Internal, "define VM %q on %s: %v", vmName, targetHost, err)
	}
	if len(vars) > 0 && resp.GetLibvirtVarsSha256() != varsSHA256(vars) {
		// An older target ignores the field and answers none: the VM would
		// boot there from a fresh template. Nothing was committed; the
		// caller rolls back what the call defined.
		out := fwTargetUnreported
		if resp.GetDomainDefined() {
			out = fwTargetDefined
		}
		return out, "", status.Errorf(codes.FailedPrecondition,
			"%s did not confirm it holds the UEFI vars of VM %q (it answered %q; an older build ignores them); nothing was changed. "+
				"Upgrade %s, or start the VM and migrate it live", targetHost, vmName, resp.GetLibvirtVarsSha256(), targetHost)
	}
	if !resp.GetDomainDefined() {
		return fwTargetUnreported, resp.GetLibvirtVarsSha256(), nil
	}
	return fwTargetDefined, resp.GetLibvirtVarsSha256(), nil
}

// pciMoveRoute is the route that moves a VM holding a PCI passthrough device:
// no migration, live or cold, carries the device, so it is released from the VM
// first and a device is attached again on the target. A stopped VM's detach and
// attach need hardware_v2, so before it is active no route is advised. Proven
// by TestFleet_PCIMoveRouteTheRefusalsAdviseWorks and
// TestFleet_PCIMoveRouteIsNotAdvisedBeforeHardwareV2.
func (s *Server) pciMoveRoute(ctx context.Context, vm, addr, target string) string {
	if !s.hardwareV2Latched(ctx) {
		return "no migration carries a passthrough device, and releasing and re-attaching one on a stopped VM needs hardware_v2, which is not active yet, so there is no supported way to move this VM until it is"
	}
	return fmt.Sprintf("no migration carries a passthrough device, so stop the VM, `lv detach-pci %s %s`, `lv migrate %s %s --cold`, then `lv attach-pci %s --address <a free PCI address on %s>` (see `lv host devices %s`); the target needs its own free device, the source's address is not reused, and ROM, multifunction and vGPU settings are not carried over",
		vm, addr, vm, target, vm, target, target)
}

// coldMoveDisks reads the VM's disk records and applies the cold path's
// refusals that need no domain: a VM holding a PCI passthrough device, and a
// VM with no domain defined here.
//
// A Secure-Boot/vTPM VM with a host-local disk is not refused. It was, from
// before this path copied host-local disks at all; it now moves as any stopped
// VM does, its disks streamed first and its firmware bundle carried with the
// domain's define, and a failure before the handoff takes both back.
func (s *Server) coldMoveDisks(ctx context.Context, vm *corrosion.VMRecord, target string) ([]corrosion.DiskRecord, error) {
	// A volume move left unresolved here: the rows name the file the persistent
	// config names before one is streamed (move_unresolved.go).
	if err := s.resolveUnresolvedMoves(ctx, vm.Name); err != nil {
		return nil, err
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query disks for %q: %v", vm.Name, err)
	}
	// PCI/hostdev passthrough isn't carried by this path — the source XML embeds
	// source host PCI addresses that won't be valid (or assigned) on the target.
	// Refuse for now rather than define a domain with stale hostdevs (G1).
	if assigned, _ := corrosion.ListPCIDevices(ctx, s.db, s.hostName, ""); len(assigned) > 0 {
		for _, d := range assigned {
			if d.VMName == vm.Name {
				return nil, status.Errorf(codes.FailedPrecondition,
					"VM %q has PCI passthrough device %s — migrating a stopped VM with hostdevs is not supported yet; %s",
					vm.Name, d.Address, s.pciMoveRoute(ctx, vm.Name, d.Address, target))
			}
		}
	}
	// The domain is what the target is defined from, and its definition is
	// what names each disk's format. A VM recorded here with no domain was
	// most likely moved here by an older drain, which moved only its record:
	// its disk files never left the host it came from.
	if !s.virt.DomainExists(vm.Name) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q has no domain defined on %s, so there is nothing here to migrate cold. "+
				"A drain by an older build moved only its record here; its host-local disks, if any, are still on the host it came from. "+
				"See \"A VM with no domain\" in docs/migration-failover.md", vm.Name, s.hostName)
	}
	return disks, nil
}

// coldMovePreflight runs, for a VM that is still RUNNING, every check of its
// cold move that needs neither the domain shut off nor anything written: the
// refusals of coldMoveDisks, a disk missing from the domain definition, each
// host-local disk's source-side checks (coldDiskSourceCheck: readable, and an
// overlay flattenable with room for the flatten) and the target's checks of
// each copy (ReceiveMigrationDisk check_only: path, record, a file already
// there, free space). A drain runs it before it shuts the VM down, so a VM the
// cold move would refuse is left running. vm is the VM's record; its State is
// not read.
func (s *Server) coldMovePreflight(ctx context.Context, vm *corrosion.VMRecord, targetHost string) error {
	if s.virt == nil {
		return status.Errorf(codes.Internal, "libvirt not connected on host %s", s.hostName)
	}
	if err := s.nicMTUPreflight(ctx, vm, targetHost); err != nil {
		return err
	}
	if err := s.refuseColdMoveOnSharedMAC(ctx, vm.Name); err != nil {
		return err
	}
	disks, err := s.coldMoveDisks(ctx, vm, targetHost)
	if err != nil {
		return err
	}
	domXML, err := s.virt.DumpXML(vm.Name)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "cannot dump domain XML for %q: %v", vm.Name, err)
	}
	formats, err := domainDiskFormats(domXML)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "read the disks of VM %q from its domain definition: %v", vm.Name, err)
	}
	var client pb.LiteVirtClient
	for _, d := range disks {
		if !copiedByStorageMigration(d) {
			continue
		}
		if formats[d.Path] == "" {
			return status.Errorf(codes.FailedPrecondition,
				"disk %q of VM %q (%s) is not in its domain definition on %s, so its format is unknown; "+
					"repair the VM's disks before migrating it", d.DiskName, vm.Name, d.Path, s.hostName)
		}
		flatten, err := s.coldDiskSourceCheck(d, formats[d.Path])
		if err != nil {
			return err
		}
		if client == nil {
			c, closeConn, derr := s.dialPeer(ctx, targetHost)
			if derr != nil {
				return status.Errorf(codes.Unavailable, "cannot reach %s to check the disks of VM %q: %v", targetHost, vm.Name, derr)
			}
			defer closeConn()
			client = c
		}
		if err := s.checkColdDiskOnTarget(ctx, client, vm.Name, d, flatten); err != nil {
			if status.Code(err) == codes.Unimplemented {
				return targetTooOldForColdMigration(targetHost, vm.Name)
			}
			return status.Errorf(status.Code(err), "%s would not take disk %q of VM %q: %s",
				targetHost, d.DiskName, vm.Name, status.Convert(err).Message())
		}
	}
	return nil
}

// coldMigrateStoppedVM moves a STOPPED VM to targetHost WITHOUT libvirt runtime
// migration — a Secure-Boot/vTPM VM, which is always migrated this way, or any
// other VM migrated with --cold while stopped. In order:
//
//  1. each host-local disk file is streamed to the target (ReceiveMigrationDisk),
//     a Secure-Boot/vTPM VM's included;
//  2. the domain is defined on the target from this host's XML, with the
//     quiescent firmware bundle of a firmware VM (EnsureFirmwareState);
//  3. the VM and every one of its disk records move to the target in ONE
//     guarded transaction that keeps the stopped state (handOffColdFirmwareVM);
//  4. only then is the source cleaned up: its domain undefined, a firmware VM's
//     firmware wiped, and the copied disk files removed.
//
// A failure before the handoff commits leaves the source untouched and owning
// the VM. What this attempt defined on the target is taken back here
// (abandonFirmwareTarget); the disks it copied there and the cloud-init ISO are
// removed by MigrateVM's abort, which stays armed until the commit and is
// disarmed by it.
func (s *Server) coldMigrateStoppedVM(ctx context.Context, vm *corrosion.VMRecord, targetHost *corrosion.HostRecord, fwSpec firmwareSpec, abort *migrationAbort, send func(pb.MigratePhase, float32, float32) error) error {
	start := time.Now()
	fwVM := fwSpec.SecureBoot || fwSpec.Tpm
	if s.virt == nil {
		return status.Errorf(codes.Internal, "libvirt not connected on host %s", s.hostName)
	}
	// Must read disks successfully — proceeding on an error would skip the
	// host-local refusal AND the disk-ownership updates, diverging VM/disk records.
	disks, err := s.coldMoveDisks(ctx, vm, targetHost.Name)
	if err != nil {
		return err
	}
	// Hold the VM's start lease for the whole move, so neither the restart
	// policy nor the reconciler starts it here while its disks are copied
	// (migrate_cold_fence.go). Taken before the check below, so nothing can
	// start it between the two.
	releaseLease, err := s.holdColdMoveStartLease(ctx, vm.Name)
	if err != nil {
		return err
	}
	defer releaseLease()
	// The row says stopped; the move goes ahead only if libvirt agrees. An
	// active guest — paused counts, which DomainState reports as stopped —
	// could write into a disk while it is being copied.
	if err := s.coldSourceShutOff(vm.Name); err != nil {
		return err
	}
	// Dump the source's (shut-off) domain XML so the target can DEFINE the same
	// domain — a plain reassigned-stopped VM would otherwise be undefined on the
	// target and unstartable. Disk paths are the recorded ones on both hosts,
	// and a firmware VM's dataDir-relative NVRAM + UUID-keyed swtpm dir are
	// identical across hosts, so the XML is portable.
	domXML, err := s.virt.DumpXML(vm.Name)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition,
			"cannot dump domain XML for %q (it must be defined to migrate it cold): %v", vm.Name, err)
	}
	// The VM's installer ISO goes as the path as written (a host path as the
	// VM was given it, a pool's file through the pool's directory as the
	// target names it), not as the file it resolved to on this host: a target
	// on this build resolves and judges it at its start (and points the domain
	// at its own file); a target on an older build has its qemu follow the
	// link there, as before.
	if remap := s.olderTargetISORemap(ctx, vm.Name, targetHost.Name, s.domainInstallerISOs(vm.Name, domXML)); len(remap) > 0 {
		rewritten, _, rerr := lv.RewriteCDROMSources(domXML, remap)
		if rerr != nil {
			return status.Errorf(codes.FailedPrecondition, "point the installer CD-ROM of VM %q back at the path it was given: %v", vm.Name, rerr)
		}
		domXML = rewritten
	}
	_ = send(pb.MigratePhase_MIGRATE_COPYING, 0, 0)

	// Host-local disks first: the source keeps its own copy until the handoff
	// commits, so a failure here, or anywhere before the commit, loses nothing.
	formats, err := domainDiskFormats(domXML)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "read the disks of VM %q from its domain definition: %v", vm.Name, err)
	}
	copied, err := s.copyColdDisksToTarget(ctx, targetHost.Name, vm.Name, disks, formats, abort, send)
	if err != nil {
		return err
	}

	// Push the quiescent firmware (a firmware VM's) to the target AND define the
	// domain there (the handler materializes firmware then DefineDomain — shut
	// off, not started). Per-component preflight is inside. Source is untouched
	// on failure.
	//
	// Any failure from here until the handoff commits — a cancelled request
	// included — rolls back what THIS attempt created on the target, and only
	// that: the target records the domain it defines under attempt, and
	// leaves a domain it found there (abandonFirmwareTarget).
	attempt := uuid.NewString()
	// A plain UEFI VM's libvirt-managed vars ride with the definition: libvirt
	// keeps them outside the firmware store, and the source's file is the only
	// copy until the target has confirmed its own by hash.
	var sentVars []byte
	// Only a VM whose current definition is plain UEFI has libvirt-managed
	// vars: a BIOS VM's stale file is not its state and is neither sent nor
	// a reason for an older target to refuse.
	if !fwSpec.SecureBoot && !fwSpec.Tpm && fwSpec.hasNvram() {
		if sentVars, err = s.readSourceLibvirtVars(vm.Name, domXML); err != nil {
			return err
		}
	}
	outcome, confirmedVarsSHA, err := s.ensureFirmwareStateOnTarget(ctx, targetHost.Name, vm.Name, fwSpec, domXML, attempt, sentVars)
	if err != nil {
		return s.abandonFirmwareTarget(ctx, targetHost.Name, vm.Name, fwSpec.UUID, attempt, outcome, err)
	}

	// Once more, immediately before the handoff: a domain started since the
	// first check — by hand, or by anything the start lease does not fence —
	// may have written to a disk while it was copied, and that copy must not
	// become the VM's disk.
	if err := s.coldSourceShutOff(vm.Name); err != nil {
		return s.abandonFirmwareTarget(ctx, targetHost.Name, vm.Name, fwSpec.UUID, attempt, outcome, err)
	}
	if err := s.handOffColdFirmwareVM(ctx, vm, targetHost); err != nil {
		return s.abandonFirmwareTarget(ctx, targetHost.Name, vm.Name, fwSpec.UUID, attempt, outcome, err)
	}
	// The handoff is committed: the target owns the VM, and what this attempt
	// put there is the VM's now, not something to take back.
	abort.armed = false
	// What follows is cleanup and bookkeeping for a migration that has
	// happened, so it must not die with a client that went away.
	ctx = context.WithoutCancel(ctx)
	if s.coldMoveAfterHandoff != nil {
		s.coldMoveAfterHandoff(vm.Name)
	}
	// And before the source is touched: an active domain here is using these
	// disks, so neither it nor they are removed. The move is reported failed —
	// a drain must not start the VM on the target as well.
	if err := s.coldSourceShutOff(vm.Name); err != nil {
		msg := fmt.Sprintf("VM %q was handed off to %s, but its domain on %s is not confirmed shut off (%s); "+
			"the domain and disks on %s are kept and the VM is not started anywhere by this migration — "+
			"stop it on %s and check which copy of its disks is current",
			vm.Name, targetHost.Name, s.hostName, status.Convert(err).Message(), s.hostName, s.hostName)
		slog.Error("cold migration: "+msg, "vm", vm.Name, "from", s.hostName, "to", targetHost.Name)
		s.recordVMEvent(ctx, vm.Name, "vm.migrated", "error", msg)
		s.recordMigrationMetrics("cold", "failure", time.Since(start), 0, 0)
		return status.Error(codes.Aborted, msg)
	}

	// Clean up the source ONLY after a fully successful handoff: undefine the
	// shut-off domain, then wipe the now-orphaned firmware. Do NOT wipe firmware
	// if the undefine fails — keep the source copy as a recoverable fallback and
	// surface the leftover (the VM is already correctly owned by the target).
	if s.virt.DomainExists(vm.Name) {
		if err := s.virt.UndefineDomainPreservingState(vm.Name); err != nil {
			slog.Error("cold migration: source domain undefine failed — leaving source firmware as a fallback; clean up manually",
				"vm", vm.Name, "host", s.hostName, "error", err)
			s.recordVMEvent(ctx, vm.Name, "vm.migrated", "warn", "migrated to "+targetHost.Name+" but source domain undefine failed (firmware retained on source)")
		} else if fwVM {
			s.fw().WipeFirmwareState(vm.Name, fwSpec.UUID)
		}
	} else if fwVM {
		s.fw().WipeFirmwareState(vm.Name, fwSpec.UUID)
	}
	// The copies on the target are the VM's disks now; the source's are orphans.
	s.removeColdMigratedSourceDisks(ctx, vm.Name, copied)
	s.cleanupPostMigration(vm.Name)
	// The hash the target answered, not the one sent: the file goes only while
	// it is still what the target confirmed it holds.
	if len(sentVars) > 0 && confirmedVarsSHA != "" {
		s.removeMigratedSourceVars(ctx, vm.Name, confirmedVarsSHA)
	}

	_ = send(pb.MigratePhase_MIGRATE_CUTOVER, 100, 0)
	_ = send(pb.MigratePhase_MIGRATE_COMPLETING, 100, 0)
	// The same host-link catch-up as the runtime path above. This is the OTHER
	// migration — a stopped VM takes it instead — and the ownership move it
	// commits is just as invisible to NetBox.
	s.enqueueMirrorSync(ctx, vm.Name, mirrorOpUpsert)
	s.recordMigrationMetrics("cold", "success", time.Since(start), 0, 0)
	kind := "cold"
	if fwVM {
		kind = "cold firmware"
	}
	slog.Info("cold migration complete", "vm", vm.Name, "from", s.hostName, "to", targetHost.Name,
		"state", vm.State, "firmware", fwVM, "disks_copied", len(copied))
	s.recordVMEvent(ctx, vm.Name, "vm.migrated", "ok", "from="+s.hostName+" to="+targetHost.Name+" ("+kind+", "+vm.State+")")
	s.audit(ctx, "vm.migrate", vm.Name, "from="+s.hostName+" to="+targetHost.Name+" ("+kind+")", "ok")
	// The migration has happened; a client that went away does not undo it.
	_ = send(pb.MigratePhase_MIGRATE_DONE, 100, 100)
	return nil
}

// coldFirmwareHandoffTimeout bounds the cold firmware migration's ownership
// commit once it runs detached from the request (handOffColdFirmwareVM).
const coldFirmwareHandoffTimeout = 30 * time.Second

// handOffColdFirmwareVM commits a cold firmware migration's ownership handoff:
// the VM and every one of its disk records move to targetHost in ONE guarded
// transaction (corrosion.TransferVMOwnerWithDisks), which CASes on the VM's
// owner epoch, advances it once, and keeps the VM's (stopped) state. On failure
// the source still owns the VM and all of its disks, and the caller rolls back
// what the attempt created on the target (abandonFirmwareTarget).
//
// It used to commit each disk record, then the VM row, as separate writes,
// rolling them back one by one on the request context. A client that went away
// part-way cancelled that context, so every later write — the rollback's
// included — failed, and a daemon crash between the commits had no rollback at
// all: either way the VM still belonged to the source while disk records named
// the target. One transaction leaves no intermediate state to strand.
//
// The commit runs on a context detached from the request, bounded by
// coldFirmwareHandoffTimeout: once it starts, it and the cleanup that follows
// it are one unit, not something a disconnecting client can cut in half. A
// request already cancelled before that point aborts instead.
func (s *Server) handOffColdFirmwareVM(ctx context.Context, vm *corrosion.VMRecord, targetHost *corrosion.HostRecord) error {
	if err := ctx.Err(); err != nil {
		return status.FromContextError(err).Err()
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), coldFirmwareHandoffTimeout)
	defer cancel()

	// Phase 4: migration commit is an ownership transition (fresh-read CAS + increment).
	// The CAS is on the epoch read here, as TransferVMOwnerFresh does: a concurrent
	// transition between this read and the commit makes the commit lose cleanly.
	cur, err := corrosion.GetVM(cctx, s.db, vm.Name)
	if err == nil && cur == nil {
		err = corrosion.ErrNoRowsAffected
	}
	if err == nil {
		//runningcheck:allow ownership handoff — the cold firmware migration hands the VM to
		// targetHost while running on the source. Same reason as the cutover commit above.
		err = corrosion.TransferVMOwnerWithDisks(cctx, s.db, vm.Name, targetHost.Name, vm.State, cur.OwnerEpoch)
	}
	if err != nil {
		return status.Errorf(codes.Internal, "reassign VM %q and its disks to %s: %v", vm.Name, targetHost.Name, err)
	}
	s.reverseReplicationAfterMove(cctx, "vm", vm.Name, "", s.hostName, targetHost.Name)
	return nil
}

// CleanupMigrationArtifacts removes the stub disks + cloud-init ISO that this
// host pre-created as a migration target, after the migration failed. The VM
// was never defined here (PersistDest only persists on success), so the files
// are orphaned; leaving them leaks space and shadows a later retry. Best-effort
// per file — a missing file is not an error. Only files this host recorded
// creating for the VM are removed, and none while the VM lives here; a
// recorded stub the source does not name is removed too, while nothing has
// written to it since it was made.
//
// With vm_deleted it instead removes a DELETED VM's leftovers on a host the VM
// left — its owner-epoch marker and the disks detached from it here — by this
// host's own records (removeDeletedVMLeftoversHere).
func (s *Server) CleanupMigrationArtifacts(ctx context.Context, req *pb.CleanupMigrationArtifactsRequest) (*emptypb.Empty, error) {
	if err := safename.ValidateVMName(req.VmName); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	// A deleted VM's leftovers on a host it left are a different request with
	// its own rules: nothing below (RBAC, stub ledger, firmware, undefine)
	// applies. Only the deleting owner may send it (requireSystemPeer).
	if req.VmDeleted {
		if err := s.requireSystemPeer(ctx); err != nil {
			return nil, err
		}
		vm, _ := corrosion.GetVM(ctx, s.db, req.VmName)
		return s.removeDeletedVMLeftoversHere(ctx, req, vm)
	}
	// Require vm.migrate on the VM being cleaned up. A failed migration leaves the
	// VM record intact (the source still owns it); only when the VM has truly
	// vanished do we fall back to admin (orphan cleanup), so a binding-holder
	// can't drive this RPC against a VM they don't control.
	vm, _ := corrosion.GetVM(ctx, s.db, req.VmName)
	if vm != nil {
		if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.migrate", "operator"); err != nil {
			return nil, err
		}
	} else if err := RequireRole(ctx, "admin"); err != nil {
		return nil, status.Error(codes.PermissionDenied,
			"cleaning up artifacts of a vanished VM requires the admin role")
	}
	// The firmware UUID keys a RemoveAll under the swtpm root, and the
	// permission above was checked on VmName alone. So it must be a real UUID
	// (".." would name /var/lib/libvirt) and it must be THIS VM's own, as the
	// replicated row records it — the value the source sends (fwSpec.UUID) —
	// or vm.migrate on one VM would wipe another VM's TPM. A vanished VM has
	// no row to bind against, so its swtpm tree is not wiped through here.
	if req.FirmwareUuid != "" {
		if !lv.ValidFirmwareUUID(req.FirmwareUuid) {
			return nil, status.Errorf(codes.InvalidArgument, "invalid firmware uuid %q", req.FirmwareUuid)
		}
		if vm == nil || !strings.EqualFold(parseFirmwareSpec(vm.Spec).UUID, req.FirmwareUuid) {
			return nil, status.Errorf(codes.InvalidArgument,
				"firmware uuid %q is not the recorded uuid of VM %q", req.FirmwareUuid, req.VmName)
		}
	}
	// A VM that lives here — its row names this host, or its domain is defined
	// here — has its real disks at these paths; a failed migration TO this host
	// never got that far.
	rowNamesHere := vm != nil && vm.HostName == s.hostName
	vmLivesHere := rowNamesHere || (s.virt != nil && s.virt.DomainExists(req.VmName))
	// The paths the source names, and the stubs this host recorded making for
	// the VM that it does not name. The source names only what EnsureDisks
	// reported, and a source whose EnsureDisks call was cut — its client went
	// away while this host was making the stubs — never got the report. Such a
	// stub is taken only while nothing has written to it since it was made: a
	// copy that ran, or a guest using it as its disk, has, and a record that
	// outlived the migration that made it must not reach a disk.
	paths := append([]string(nil), req.DiskPaths...)
	named := make(map[string]bool, len(paths))
	for _, p := range paths {
		named[p] = true
	}
	for p, at := range s.madeHereFor(ctx, &s.migrationStubs, req.VmName) {
		if named[p] {
			continue
		}
		// The file the removal below would take: hostDiskFile(p), as the
		// cold copy wrote it.
		if fi, err := os.Lstat(s.hostDiskFile(p)); err != nil || fi.ModTime().After(at) {
			continue
		}
		paths = append(paths, p)
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		// Only ever remove paths in a real disk-artifact root (disks dir or a
		// file-backed pool dir) — never an arbitrary file under the data dir such
		// as state.db.
		root, rootOK := s.migrationRootOf(ctx, p, migrationSourceHost(vm))
		if !rootOK {
			slog.Warn("cleanup migration artifacts: refusing to remove path outside a disk-artifact root", "vm", req.VmName, "path", p)
			continue
		}
		// Only a stub THIS host created for the VM (EnsureDisks). The source's
		// list is not trusted for it: a source built before EnsureDisks reported
		// what it created names every disk path, including a disk that was here
		// already, and removing that by name deleted it (drill D1).
		if vmLivesHere || !s.madeHere(ctx, &s.migrationStubs, req.VmName, p) {
			slog.Warn("cleanup migration artifacts: leaving a disk file this host did not create as a migration stub",
				"vm", req.VmName, "path", p, "vm_lives_here", vmLivesHere)
			continue
		}
		// Through the directory held open beneath its root, never a link
		if err := s.removeUnderRoot(root, p, true); err != nil {
			slog.Warn("cleanup migration artifacts: remove disk stub", "vm", req.VmName, "path", p, "error", err)
			continue
		}
		s.migrationStubs.forget(p)
	}
	// The cloud-init ISO by the same rule as the stubs: never one of a VM that
	// lives here — the guest boots from it — and only one EnsureCloudInit
	// generated here for the VM. One it found already there, or made before a
	// restart forgot the record, is left in place.
	if req.RemoveCloudInit {
		if iso, perr := lv.SafeCloudInitISOPath(s.dataDir, req.VmName); perr != nil {
			slog.Warn("cleanup migration artifacts: invalid vm name for cloud-init path", "vm", req.VmName, "error", perr)
		} else if vmLivesHere || !s.madeHere(ctx, &s.migrationISOs, req.VmName, iso) {
			slog.Warn("cleanup migration artifacts: leaving a cloud-init ISO this host did not create for the migration",
				"vm", req.VmName, "path", iso, "vm_lives_here", vmLivesHere)
		} else if err := cloudinit.RemoveSeed(iso); err != nil {
			slog.Warn("cleanup migration artifacts: remove cloud-init iso", "vm", req.VmName, "path", iso, "error", err)
		} else {
			s.migrationISOs.forget(iso)
		}
	}
	// Undefine a domain this host pre-defined for a failed firmware migration,
	// BEFORE wiping its firmware (so we never wipe firmware out from under a still-
	// defined domain). If the undefine FAILS, keep the firmware as a recoverable
	// fallback and surface the error rather than stranding a defined domain whose
	// firmware we erased (G1).
	// A VM whose row names this host owns the domain here; it is never a
	// migration leftover, so neither it nor its firmware is touched.
	// A live firmware move's record of the VM here (spec §6.9): the domain
	// and firmware are that move's, and only its own steps remove them.
	if held := s.firmwareMoveRecordRefusal("cleanup of migration artifacts", req.VmName, req.FirmwareUuid); held != nil {
		slog.Warn("cleanup migration artifacts: leaving the domain and firmware of a live firmware move",
			"vm", req.VmName, "detail", status.Convert(held).Message())
		return &emptypb.Empty{}, nil
	}
	if req.UndefineDomain && rowNamesHere {
		slog.Warn("cleanup migration artifacts: VM lives on this host; leaving its domain and firmware",
			"vm", req.VmName)
	} else if req.UndefineDomain && req.VmName != "" && s.virt != nil && s.virt.DomainExists(req.VmName) {
		if err := s.virt.UndefineDomainPreservingState(req.VmName); err != nil {
			slog.Warn("cleanup migration artifacts: undefine pre-defined domain", "vm", req.VmName, "error", err)
			return nil, status.Errorf(codes.Internal,
				"undefine domain %q failed; left firmware in place (recoverable): %v", req.VmName, err)
		}
	}
	// Wipe firmware state we pushed to this (failed) target so it can't be
	// adopted by a retry / orphan the swtpm tree (G1).
	// Never the firmware of a VM that lives here — an adopted or live workload,
	// judged the same way as the disk stubs above but AFTER the undefine, so a
	// domain this host pre-defined for the failed migration no longer counts.
	if req.FirmwareUuid != "" {
		if rowNamesHere || (s.virt != nil && s.virt.DomainExists(req.VmName)) {
			slog.Warn("cleanup migration artifacts: VM lives on this host; leaving its firmware state",
				"vm", req.VmName, "row_names_here", rowNamesHere)
		} else {
			s.fw().WipeFirmwareState(req.VmName, req.FirmwareUuid)
		}
	}
	return &emptypb.Empty{}, nil
}

// cleanupMigrationArtifactsOnTarget best-effort removes the stubs + ISO the
// target pre-created, after a failed migration. Never blocks/fails the caller.
func (s *Server) cleanupMigrationArtifactsOnTarget(ctx context.Context, targetHost, vmName string, diskPaths []string, firmwareUUID string) {
	client, closeConn, err := s.dialPeer(ctx, targetHost)
	if err != nil {
		slog.Warn("cleanupMigrationArtifactsOnTarget: cannot reach host", "host", targetHost, "error", err)
		return
	}
	defer closeConn()
	if _, err := client.CleanupMigrationArtifacts(ctx, &pb.CleanupMigrationArtifactsRequest{
		VmName:          vmName,
		DiskPaths:       diskPaths,
		RemoveCloudInit: true,
		FirmwareUuid:    firmwareUUID,
	}); err != nil {
		slog.Warn("cleanupMigrationArtifactsOnTarget: cleanup failed", "host", targetHost, "vm", vmName, "error", err)
	}
}

// isHostLocalDiskDriver reports whether a disk's storage driver keeps the disk
// as a host-local file, so the same path on two hosts is two distinct files.
// Deliberately conservative: only the plain-file local/dir drivers qualify, so
// the post-migration source-disk cleanup never touches shared (nfs/ceph/iscsi)
// or volume-manager (zfs/lvm/btrfs) backends, where deleting "the source" could
// destroy the live disk.
func isHostLocalDiskDriver(t string) bool {
	return t == "local" || t == "dir"
}

// diskVirtualSize returns the virtual size of a qcow2 image.
func diskVirtualSize(_ context.Context, path string) (int64, error) {
	info, err := qcow2.Info(path)
	if err != nil {
		return 0, err
	}
	return int64(info.VirtualSize), nil
}

// plaintextStorageRefusal is the error for a storage copy that cannot be
// encrypted (lacking names the host without migration TLS) while the source does
// not allow plaintext. It names both ways out.
func plaintextStorageRefusal(vmName, source, target, lacking string) error {
	return status.Errorf(codes.FailedPrecondition,
		"refusing to migrate VM %q with a storage copy: %s has no migration-TLS credentials, "+
			"so the guest's memory and disk contents would cross the network between %s and %s "+
			"in plaintext. Provision them with `lv host install-migration-tls` (run where the "+
			"cluster CA lives), or, if the network between them is trusted, set "+
			"`migration.allow_unencrypted_storage: true` in %s's config.yaml and restart its daemon",
		vmName, lacking, source, target, source)
}

// storageMigrationStubs is the source-side preflight of a --with-storage
// migration: the stub each of the VM's disk files needs on the target, sized at
// the source disk's virtual size, which the block mirror requires the target
// image to match.
//
// It refuses a disk whose virtual size differs from its recorded size. The
// record is what placement, quota and the target's own rebuilds go by, so a
// disk that disagrees with it is a fault to repair, not to carry to another
// host — and when the target already holds a file of the recorded size, the
// copy fails deep in drive-mirror with "Source and target image have different
// sizes" (drill D1: an overlay rebuilt at its 112 MiB backing size for a disk
// recorded at 20 GiB). A disk with no recorded size, or whose size cannot be
// read here (not a qcow2), is sent at what can be known, as before.
//
// Disks on a storage driver that is not a host-local file (nfs, ceph, a volume
// manager) are not stubbed: there is no per-host file to create.
func (s *Server) storageMigrationStubs(ctx context.Context, vmName string) ([]*pb.DiskStub, error) {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the disks of VM %q: %v", vmName, err)
	}
	var stubs []*pb.DiskStub
	for _, d := range disks {
		if !copiedByStorageMigration(d) {
			continue
		}
		size, err := diskVirtualSize(ctx, d.Path)
		if err != nil {
			slog.Warn("storage migration: cannot read the disk's virtual size, using the recorded size",
				"vm", vmName, "path", d.Path, "db_size", d.SizeBytes, "error", err)
			size = d.SizeBytes
		} else if d.SizeBytes > 0 && size != d.SizeBytes {
			return nil, status.Errorf(codes.FailedPrecondition,
				"disk %q of VM %q is %d bytes on %s, but its record says %d bytes; a storage migration "+
					"would carry that disagreement to the target, or fail in the copy with \"Source and target "+
					"image have different sizes\". Grow the disk to its recorded size or correct the record, "+
					"then migrate again",
				d.DiskName, vmName, size, s.hostName, d.SizeBytes)
		}
		stubs = append(stubs, &pb.DiskStub{Path: d.Path, SizeBytes: size})
	}
	return stubs, nil
}

// copiedByStorageMigration reports whether a --with-storage migration copies
// this disk: a host-local file (a row with no storage type is taken as one, as
// it always was). A shared disk (nfs, ceph, iscsi, a volume manager) is the same
// disk on the target already, and copying it would mirror it onto itself.
func copiedByStorageMigration(d corrosion.DiskRecord) bool {
	return d.Path != "" && isHostLocalDisk(d)
}

// isHostLocalDisk is the one answer to "does this VM disk live on this host
// only", for every decision about moving a VM: a host-local driver, or a row
// with no storage type, which predates the column and has always been copied
// as host-local. Drain's choice between a live and a cold move, the snapshot
// refusal and the copy itself must agree, or an untyped disk is left behind by
// a move that copies none. Removal paths keep the stricter
// isHostLocalDiskDriver: they delete, and an untyped row proves less.
//
// It agrees with corrosion.DiskIsShared, which is the cluster's definition of
// shared storage, on every driver whose disk is a plain file a move can copy:
// btrfs is host-local there, so it is here too (a clone or MoveVolume into a
// btrfs pool makes such a disk). TestIsHostLocalDiskAgreesWithDiskIsShared pins
// the two together. zfs and lvm are not shared either, but their disks are
// volumes, not files, so no move here copies them; they stay as they were.
func isHostLocalDisk(d corrosion.DiskRecord) bool {
	return d.StorageType == "" || isHostLocalDiskDriver(d.StorageType) || strings.EqualFold(d.StorageType, "btrfs")
}

// storageMigrationTargets is the migrate_disks list of a --with-storage
// migration: the target device of every disk it copies, and nothing else.
// libvirt reads an EMPTY list as "copy every writable disk", so a copied disk
// with no recorded target device is refused rather than left out, which would
// leave it behind, or the list emptied, which would copy the shared disks too.
func storageMigrationTargets(vmName string, disks []corrosion.DiskRecord) ([]string, error) {
	var targets []string
	for _, d := range disks {
		if !copiedByStorageMigration(d) {
			continue
		}
		if d.TargetDev == "" {
			return nil, status.Errorf(codes.FailedPrecondition,
				"disk %q of VM %q has no recorded target device, so a storage migration cannot name it to libvirt; "+
					"stop the VM and migrate it with --cold, or repair its record", d.DiskName, vmName)
		}
		targets = append(targets, d.TargetDev)
	}
	return targets, nil
}

// ensureDisksOnTarget has the target create the stub files the copy needs, so
// libvirt accepts the domain XML before block copy starts, and returns the
// paths the target reports it created — all a failed attempt may remove there.
//
// A failure stops the migration. It used to be logged and the migration went
// ahead, against a target missing disks libvirt would then trip over — or
// holding a file the copy would overwrite (EnsureDisks refuses that).
//
// With wantTLS it also has the target install its migration-TLS credentials
// for QEMU and returns whether it could. An older target never answers that,
// which reads as false.
//
// It also sends the installer CD-ROM paths the domain here carries, so the
// target judges the ISO it would open; runtime says the domain moves by
// libvirt runtime migration (ensureDisksOnTargetISO).
func (s *Server) ensureDisksOnTarget(ctx context.Context, targetHost, vmName string, stubs []*pb.DiskStub, wantTLS, runtime bool) ([]string, bool, error) {
	created, tls, _, _, err := s.ensureDisksOnTargetISO(ctx, targetHost, vmName, stubs, wantTLS, runtime)
	return created, tls, err
}

// ensureDisksOnTargetISO is ensureDisksOnTarget that also returns, for a
// runtime move, the target's resolution of each installer CD-ROM that names
// another file there (source path → target path), for
// MigrateParams.CDROMSources. With the ISO paths it sends the sha256 of the
// file this host judged for the VM's ISO, so a target where another project's
// pool maps the directory admits that very content on the VM's first arrival.
func (s *Server) ensureDisksOnTargetISO(ctx context.Context, targetHost, vmName string, stubs []*pb.DiskStub, wantTLS, runtime bool) ([]string, bool, map[string]string, string, error) {
	o, err := s.ensureDisksOnTargetNet(ctx, targetHost, vmName, stubs, wantTLS, runtime)
	return o.created, o.tlsReady, o.remap, o.cgroupMode, err
}

// MigrationCAMD is the EnsureDisks response header in which a target that is
// ready for migration TLS names the SHA-256 fingerprint of the migration CA
// its credentials chain to. An older target sends none.
const MigrationCAMD = "x-litevirt-migration-ca-sha256"

// MigrationCAsMD is the EnsureDisks response header in which a target that
// sends MigrationCAMD also lists the fingerprint of each CA in its migration
// CA file, comma-separated, so a refusal can name the CAs lv doctor
// migration-tls shows. Shown only, never compared; an older target sends none.
const MigrationCAsMD = "x-litevirt-migration-cas-sha256"

// MigrationCAsMoreMD accompanies MigrationCAsMD when the sender had more CA
// fingerprints than fit in the header: it carries how many were left out, so
// the reader can say the list is incomplete. Shown only.
const MigrationCAsMoreMD = "x-litevirt-migration-cas-more"

// maxMigrationCAsShown caps how many fingerprints a reader keeps from a peer's
// MigrationCAsMD.
const maxMigrationCAsShown = 16

// migrationHeaderLimit is the longest value headerValue lets through.
const migrationHeaderLimit = 512

// packMigrationCAList joins whole fingerprints, comma-separated, into one
// header value of at most migrationHeaderLimit bytes. A fingerprint that does
// not fit whole is left out, never cut; dropped counts those left out.
func packMigrationCAList(list []string) (packed string, dropped int) {
	var b strings.Builder
	for i, fp := range list {
		fp = headerValue(fp)
		add := len(fp)
		if b.Len() > 0 {
			add++
		}
		if b.Len()+add > migrationHeaderLimit {
			return b.String(), len(list) - i
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(fp)
	}
	return b.String(), 0
}

// isSHA256Hex reports whether s is a SHA-256 fingerprint as pki.CertFingerprint
// writes it: 64 lower-case hex digits.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// readMigrationCA is the read side of MigrationCAMD, whose sender is a peer we
// do not control. A value that is not a SHA-256 fingerprint reads as "", which
// is what an older peer that sends none reads as: migrationCAsAgree compares
// nothing then, so a bad value neither makes agreement succeed nor refuse any
// differently than an absent header.
func readMigrationCA(v []string) string {
	if len(v) > 0 && isSHA256Hex(v[0]) {
		return v[0]
	}
	return ""
}

// migrationCAsUnreadable stands for a list header that was present but held no
// fingerprint, as the only element readMigrationCAList then returns.
const migrationCAsUnreadable = "(unreadable)"

// readMigrationCAList is the read side of MigrationCAsMD, whose sender is a
// peer we do not control: it keeps only well-formed fingerprints, at most
// maxMigrationCAsShown of them, and drops the rest before they reach an error
// or an event. more is the peer's MigrationCAsMoreMD; the result ends with a
// "+N more" marker when the list was incomplete (left out by the sender or by
// the cap). nil when no valid fingerprint came.
func readMigrationCAList(list, more []string) []string {
	if len(list) == 0 {
		return nil
	}
	var out []string
	extra := 0
	for _, fp := range strings.Split(list[0], ",") {
		if !isSHA256Hex(fp) {
			continue
		}
		if len(out) >= maxMigrationCAsShown {
			extra++
			continue
		}
		out = append(out, fp)
	}
	if len(out) == 0 {
		return []string{migrationCAsUnreadable}
	}
	if len(more) > 0 {
		if n, err := strconv.Atoi(more[0]); err == nil && n > 0 {
			extra += min(n, 1<<20)
		}
	}
	if extra > 0 {
		out = append(out, fmt.Sprintf("+%d more (list incomplete)", extra))
	}
	return out
}

// sanitizeMigrationTLSUnusable bounds a peer-supplied reason to one line of at
// most 512 printable ASCII bytes before it reaches an error.
func sanitizeMigrationTLSUnusable(v string) string { return headerValue(v) }

// MigrationTLSUnusableMD is the EnsureDisks response header in which a
// target that is not ready for migration TLS because its credentials are
// unusable (pki.ErrInvalidMigrationCredentials) says why. An older target, or
// one that simply has none, sends none.
const MigrationTLSUnusableMD = "x-litevirt-migration-tls-unusable"

// headerValue makes text a valid gRPC (HTTP/2) header value: one line of
// printable ASCII, at most 512 bytes. Anything else becomes '?'.
func headerValue(text string) string {
	const limit = 512
	b := make([]byte, 0, min(len(text), limit))
	for _, r := range text {
		if len(b) >= limit {
			break
		}
		if r < 0x20 || r > 0x7e {
			r = '?'
		}
		b = append(b, byte(r))
	}
	return string(b)
}

// unusableMigrationCredentialsRefusal refuses a storage copy because host's
// migration-TLS credentials are unusable (why), with both fixes: an
// incomplete set is usually a push still in flight, a damaged one is reissued.
func unusableMigrationCredentialsRefusal(vmName, host, why string) error {
	return status.Errorf(codes.FailedPrecondition,
		"refusing to migrate VM %q with a storage copy: %s holds migration-TLS credentials it cannot use (%s), so the copy "+
			"could not be encrypted. If its set is incomplete (some of ca.crt, host.crt and host.key missing), a credential "+
			"push is in flight or was cut short: let it finish, or re-run `lv host install-migration-tls`. If the set is "+
			"damaged, reissue it with `lv host install-migration-tls --reissue`. Run either where the cluster's migration "+
			"CA lives", vmName, host, why)
}

// migrationCAMismatch refuses a storage copy between hosts whose migration
// credentials chain to different migration CAs: QEMU's TLS handshake would
// fail mid-copy. sourceCA and targetCA are the compared set digests, either
// unknown (an older build, or none could be read) comparing nothing;
// sourceCAs and targetCAs are what the refusal shows.
func migrationCAMismatch(vmName, source, sourceCA string, sourceCAs []string, target, targetCA string, targetCAs []string) error {
	if migrationCAsAgree(sourceCA, targetCA) {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"refusing to migrate VM %q with a storage copy: the migration-TLS credentials of %s and %s come from "+
			"different migration CAs (%s), so QEMU's TLS handshake between them would fail. "+
			"While `lv host rotate-migration-ca` runs, hosts hold different CA files until it finishes its current "+
			"phase: retry once it has. Otherwise reissue every host's credentials from one migration CA with "+
			"`lv host install-migration-tls --reissue` (run where the cluster's migration CA lives)",
		vmName, source, target, migrationCAsShown(source, sourceCA, sourceCAs, target, targetCA, targetCAs))
}

// migrationCAsShown names each host's migration CAs for an operator: the
// fingerprints lv doctor migration-tls lists, or, from a build that does not
// list them, the set digest, marked as one.
func migrationCAsShown(source, sourceCA string, sourceCAs []string, target, targetCA string, targetCAs []string) string {
	one := func(host, digest string, list []string) string {
		if len(list) == 1 && list[0] == migrationCAsUnreadable {
			return host + ": " + digest + " (digest of its CA set; its CA list could not be read)"
		}
		if len(list) > 0 {
			return host + ": " + strings.Join(list, ", ")
		}
		return host + ": " + digest + " (digest of its CA set; its build does not list the CAs)"
	}
	return one(source, sourceCA, sourceCAs) + "; " + one(target, targetCA, targetCAs)
}

// migrationCAsAgree reports whether two hosts' migration CAs (fingerprints,
// "" when unknown) may be used together for QEMU's TLS stream: the same CA,
// or either one unknown (an older build), which compares nothing.
func migrationCAsAgree(a, b string) bool {
	return a == "" || b == "" || a == b
}

// memoryTLSReady is whether a memory-only move to the target that answered
// ens may use QEMU's own TLS stream: memoryTLSGap has nothing to say.
func (s *Server) memoryTLSReady(srcTLS bool, ens ensureOutcome) bool {
	return s.memoryTLSGap(srcTLS, ens, "the target") == ""
}

// memoryTLSGap says why a memory-only move to target, which answered ens,
// may not use QEMU's own TLS stream, or "" when it may: both hosts ready
// (srcTLS, ens.tlsReady) and their migration CAs agreeing. A mismatch is not
// ready, so the move stays in libvirt's tunnel instead of failing QEMU's
// handshake.
func (s *Server) memoryTLSGap(srcTLS bool, ens ensureOutcome, target string) string {
	if !srcTLS {
		return "this host (" + s.hostName + ") has no usable migration-TLS credentials (`lv host install-migration-tls`)"
	}
	if !ens.tlsReady {
		return target + " has no usable migration-TLS credentials (`lv host install-migration-tls`)"
	}
	localCA, err := s.localMigrationCA()
	if err != nil {
		return fmt.Sprintf("this host (%s) cannot read its own migration CA (%v)", s.hostName, err)
	}
	if !migrationCAsAgree(localCA, ens.migrationCA) {
		return "the two hosts' migration-TLS credentials come from different migration CAs (" +
			migrationCAsShown(s.hostName, localCA, s.localMigrationCAList(), target, ens.migrationCA, ens.migrationCAs) +
			"), as while `lv host rotate-migration-ca` finishes a phase; see `lv doctor migration-tls`"
	}
	return ""
}

// ensureOutcome is what the target's EnsureDisks answered.
type ensureOutcome struct {
	created  []string // disk stubs this call made
	tlsReady bool     // wantTLS and the target has migration-TLS credentials
	// migrationCA is the fingerprint of the migration CA the target's
	// credentials chain to (MigrationCAMD), "" when it did not say.
	migrationCA string
	// migrationCAs lists the fingerprint of each CA in the target's CA file
	// (MigrationCAsMD), nil when it did not say. Shown, never compared.
	migrationCAs []string
	// tlsUnusable is why the target's migration-TLS credentials are unusable
	// (MigrationTLSUnusableMD), "" when it did not say.
	tlsUnusable string
	remap       map[string]string // installer CD-ROM source path -> the target's file
	// migAddr is the target's address inside migration.network, "" when none
	// was asked for or the target gave none (migration_network.go).
	migAddr string
	// cgroupMode is the target's cgroup version ("v2"/"v1"), "" when it did
	// not say (an older target, or no call was made).
	cgroupMode string
	// vncPasswordUnavailable: the target's QEMU cannot do VNC password
	// authentication (FIPS), so a live migration strips the guest's VNC
	// password (MigrateParams.StripVNCPassword). False when it did not say.
	vncPasswordUnavailable bool
	// netDevices: the device the target serves each of the VM's managed
	// networks on (EnsureDisksResponse.network_devices); nil when it did not
	// say (an older target, or no call was made).
	netDevices map[string]string
}

// ensureDisksOnTargetNet is ensureDisksOnTargetISO that also asks for the
// target's address in migration.network when one is configured, which makes
// the call even where it would otherwise have nothing to send.
func (s *Server) ensureDisksOnTargetNet(ctx context.Context, targetHost, vmName string, stubs []*pb.DiskStub, wantTLS, runtime bool) (ensureOutcome, error) {
	s.endMoveRecords(vmName)
	isoPaths, err := s.domainInstallerISOPaths(vmName, runtime)
	if err != nil {
		return ensureOutcome{}, err
	}
	// A VM with an rbd disk always asks: the target defines (or refuses) the
	// ceph secrets the domain names (prepareIncomingCephDisks). A runtime move
	// of a VM with a cpu-shares weight also asks the target for its cgroup
	// version, so the destination definition carries the target's scale
	// (MigrateParams.SharesWeight). That ask alone is best effort: an
	// unanswered one leaves the domain as it is, as before.
	hasRBD := s.vmHasRBDDisk(ctx, vmName)
	// A runtime move of a guest whose VNC console has a password also asks:
	// a target whose QEMU cannot do one (FIPS) must get the guest without it,
	// or the guest fails to start there. Best effort, like the cgroup ask.
	hasVNCPassword := runtime && s.vmHasVNCPassword(vmName)
	// A NIC MTU always asks too: the target's bridge must equal it.
	mtus, err := s.nicMTUExpectations(ctx, vmName)
	if err != nil {
		return ensureOutcome{}, err
	}
	// A runtime move of a VM with a NIC on a managed network asks which device
	// the target serves each such network on. Best effort, like the cgroup ask.
	wantNetDevs := runtime && s.vmHasManagedNIC(ctx, vmName)
	shareOnly := runtime && (s.vmSharesWeight(ctx, vmName) > 0 || hasVNCPassword || wantNetDevs) && len(stubs) == 0 && !wantTLS && len(isoPaths) == 0 &&
		s.migrationNetwork == "" && !hasRBD && len(mtus) == 0
	if len(stubs) == 0 && !wantTLS && len(isoPaths) == 0 && s.migrationNetwork == "" && !shareOnly && !hasRBD && len(mtus) == 0 {
		return ensureOutcome{}, nil
	}
	client, closer, err := s.dialPeer(ctx, targetHost)
	if err != nil {
		if shareOnly {
			return ensureOutcome{}, nil
		}
		return ensureOutcome{}, status.Errorf(codes.Unavailable,
			"cannot reach %s to prepare the disks of VM %q for the copy: %v", targetHost, vmName, err)
	}
	defer closer()

	var hdr metadata.MD
	resp, err := client.EnsureDisks(ctx, &pb.EnsureDisksRequest{
		VmName: vmName, Disks: stubs, WantMigrationTls: wantTLS,
		InstallerIsoListed: true, InstallerIsoPaths: isoPaths, InstallerIsoRuntime: runtime && len(isoPaths) > 0,
		InstallerIsoSha256: s.judgedISOSHA256(ctx, vmName, isoPaths),
		MigrationNetwork:   s.migrationNetwork,
		NicMtu:             mtus,
		WantNetworkDevices: wantNetDevs,
	}, grpc.Header(&hdr))
	if err != nil && shareOnly {
		slog.Warn("migration: the target did not answer the migration preflight; cpu-shares, VNC password and NICs move as defined",
			"vm", vmName, "target", targetHost, "error", err)
		return ensureOutcome{}, nil
	}
	if err != nil {
		code := status.Code(err)
		if code == codes.Unknown {
			code = codes.Internal
		}
		return ensureOutcome{}, status.Errorf(code, "could not prepare the disks of VM %q on %s for the copy: %s",
			vmName, targetHost, status.Convert(err).Message())
	}
	if err := nicMTURefusal(vmName, targetHost, resp.GetNicMtuProblem()); err != nil {
		return ensureOutcome{}, err
	}
	if w := resp.GetInstallerIsoWarning(); w != "" {
		slog.Warn("migration: "+w, "vm", vmName, "target", targetHost)
		s.recordVMEvent(ctx, vmName, "vm.migrate.iso_warning", "warn", w)
	}
	var remap map[string]string
	if runtime && len(isoPaths) > 0 && len(resp.GetInstallerIsoResolved()) == 0 {
		// A target on this build answers every listed path. None: a target
		// older than that, whose qemu opens the paths it is handed, unjudged,
		// as on main. Hand it what main handed it — the path the VM was given —
		// so a link that names another file there is followed there.
		remap = s.olderTargetISORemap(ctx, vmName, targetHost, isoPaths)
	}
	if runtime {
		for from, to := range resp.GetInstallerIsoResolved() {
			if from == to || to == "" {
				continue
			}
			if remap == nil {
				remap = map[string]string{}
			}
			remap[from] = to
			slog.Info("migration: the target opens the installer ISO at its own file", "vm", vmName, "target", targetHost, "here", from, "there", to)
		}
	}
	targetCA := readMigrationCA(hdr.Get(MigrationCAMD))
	var unusable string
	targetCAs := readMigrationCAList(hdr.Get(MigrationCAsMD), hdr.Get(MigrationCAsMoreMD))
	if v := hdr.Get(MigrationTLSUnusableMD); len(v) > 0 {
		unusable = sanitizeMigrationTLSUnusable(v[0])
	}
	return ensureOutcome{created: resp.GetCreatedPaths(), tlsReady: wantTLS && resp.GetMigrationTlsReady(), migrationCA: targetCA, migrationCAs: targetCAs, tlsUnusable: unusable, remap: remap, migAddr: resp.GetMigrationAddress(), cgroupMode: resp.GetCgroupMode(), vncPasswordUnavailable: resp.GetVncPasswordUnavailable(), netDevices: resp.GetNetworkDevices()}, nil
}

// olderTargetISORemap points, for a move to an older target, the CD-ROM that
// is the VM's installer ISO back at the path as written, which this host's
// start had pointed at the file it resolved to here. A target on main opens
// the path it is handed, following its own links, as main to main did:
//
//   - a host path ISO (an Admin's, or a VM's from before iso_scope): the path
//     the VM was given (spec.Iso);
//   - a pool ISO named by its absolute path: that path;
//   - a pool reference: the file in the pool's directory as the target's row
//     for that pool names it (this host's, when the target has none).
//
// A pool ISO is remapped only from the file it resolved to here through its
// directory: a pool directory that is a link naming another directory on
// each host (/var/lib/libvirt/images on a data disk) is then followed on the
// target. A target on this build re-resolves either path itself.
func (s *Server) olderTargetISORemap(ctx context.Context, vmName, targetHost string, isoPaths []string) map[string]string {
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		return nil
	}
	spec := vmSpecFor(vm)
	iso, scope := spec.GetIso(), spec.GetIsoScope()
	if iso == "" {
		return nil
	}
	var remap map[string]string
	add := func(from, to string) {
		if remap == nil {
			remap = map[string]string{}
		}
		remap[from] = to
		slog.Info("migration: an older target opens the installer ISO by the path as written, as before",
			"vm", vmName, "here", from, "there", to)
	}
	if filepath.IsAbs(iso) && (scope == "" || scope == isoScopeHostPath) {
		resolved, _ := filepath.EvalSymlinks(iso)
		for _, p := range isoPaths {
			if p == iso || (len(isoPaths) > 1 && p != resolved) {
				continue
			}
			add(p, iso)
		}
		return remap
	}
	here, written := iso, iso
	if !filepath.IsAbs(iso) {
		pool, file, ok := parseISORef(iso)
		if !ok {
			return nil
		}
		if here, ok = s.lexicalPoolFile(ctx, s.hostName, pool, file); !ok {
			return nil
		}
		written = here
		if there, ok := s.lexicalPoolFile(ctx, targetHost, pool, file); ok {
			written = there
		}
	}
	rdir, err := filepath.EvalSymlinks(filepath.Dir(here))
	if err != nil {
		return nil
	}
	resolvedHere := filepath.Join(rdir, filepath.Base(here))
	for _, p := range isoPaths {
		if p == written || p != resolvedHere {
			continue
		}
		add(p, written)
	}
	return remap
}

// lexicalPoolFile is file in pool's directory on host as the pool's row
// names it, links and all.
func (s *Server) lexicalPoolFile(ctx context.Context, host, pool, file string) (string, bool) {
	if host == "" {
		return "", false
	}
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, host, pool)
	if err != nil || !ok || !isFileBasedDriver(rec.Driver) {
		return "", false
	}
	pd, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: rec.Driver, Source: rec.Source, Target: rec.Target})
	if err != nil || pd == "" {
		return "", false
	}
	return filepath.Join(filepath.Clean(pd), file), true
}

// judgedISOSHA256 is, for the installer CD-ROM path that is the VM's pool ISO
// as this host resolves and judges it now, that file's sha256 (cached per
// file version). Nothing for a host path ISO (no ownership rule applies), or
// when this host's judgement does not pass.
func (s *Server) judgedISOSHA256(ctx context.Context, vmName string, isoPaths []string) map[string]string {
	if len(isoPaths) == 0 {
		return nil
	}
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		return nil
	}
	spec := vmSpecFor(vm)
	if spec.GetIso() == "" {
		return nil
	}
	path, viaPool, err := s.resolveSpecISO(ctx, vm.Name, vm.Project, spec)
	if err != nil || !viaPool {
		return nil
	}
	for _, p := range isoPaths {
		if p != path {
			continue
		}
		sum, err := s.isoFileSHA256(path)
		if err != nil {
			return nil
		}
		return map[string]string{p: sum}
	}
	return nil
}

// prepareMigrationTarget puts on the target what libvirt checks for on the
// destination before it moves a domain there: the bridges, DHCP, NAT, VXLAN
// tunnels and IRB gateways of the VM's networks (#38), and its cloud-init ISO,
// whose CD-ROM path libvirt refuses to find missing (#62). Both are
// best-effort, as they always were for `lv migrate`: a target that cannot
// make one fails the migration itself, with libvirt's reason.
//
// Shared by every move that hands libvirt a domain for the target —
// migrateOwnedVM (`lv migrate`, live or cold, and a drain's cold move through
// it) and a drain's live move (drainOneVM), which had neither and so never
// moved a cloud-init VM live (lab2c-report.md, bug 2). A failed attempt takes
// back the ISO with cleanupFailedMigrationTarget.
func (s *Server) prepareMigrationTarget(ctx context.Context, vm *corrosion.VMRecord, target string) {
	s.provisionVMNetworksOnRemote(ctx, vm.Name, target)
	s.ensureCloudInitOnTarget(ctx, target, vm)
}

// provisionVMNetworksOnRemote sets up on target the network of each of
// vmName's live NICs (MergedVMNICs): a NIC hot-attached on a hardware_v2
// cluster has a vm_nics row alone, and a detached one keeps its vm_interfaces
// row there. Best effort, as each provisionNetworkOnRemote is.
func (s *Server) provisionVMNetworksOnRemote(ctx context.Context, vmName, target string) {
	nics, err := corrosion.MergedVMNICs(ctx, s.db, vmName)
	if err != nil {
		slog.Warn("could not read the NICs of a VM to set up its networks on the target", "vm", vmName, "target", target, "error", err)
		return
	}
	done := map[string]bool{}
	for _, n := range nics {
		if n.NetworkName == "" || done[n.NetworkName] {
			continue
		}
		done[n.NetworkName] = true
		s.provisionNetworkOnRemote(ctx, target, n.NetworkName)
	}
}

// migrationTuning is what a VM's stored migration policy asks of a runtime
// migration.
type migrationTuning struct {
	// policy is the stored policy, nil when there is none. A pointer, read
	// with the nil-safe generated getters: copying the proto message by value
	// would drag its embedded mutex/MessageState along (go vet: "copies lock
	// value").
	policy        *pb.MigrationPolicy
	bandwidthMiB  int
	autoConverge  bool
	maxDowntimeMS int64
}

// migrationTuningFor reads vm's migration policy for a live (or cold runtime)
// migration. Shared by migrateOwnedVM and a drain's live move, so both hand
// libvirt the same parameters for the same VM.
func migrationTuningFor(vm *corrosion.VMRecord, live bool) migrationTuning {
	var t migrationTuning
	if vm.Spec != "" {
		var storedSpec pb.VMSpec
		if json.Unmarshal([]byte(vm.Spec), &storedSpec) == nil {
			t.policy = storedSpec.Migrate
		}
	}
	p := t.policy
	t.bandwidthMiB = int(p.GetBandwidthMibSec())
	t.autoConverge = p.GetAutoConverge()
	// Default auto-converge to true for live migrations when no policy is set,
	// preserving previous behaviour.
	if p == nil || p.GetBandwidthMibSec() == 0 && !p.GetAutoConverge() && p.GetStrategy() == 0 {
		t.autoConverge = live
	}
	if p.GetMaxDowntime() != "" {
		if d, err := time.ParseDuration(p.GetMaxDowntime()); err == nil {
			t.maxDowntimeMS = d.Milliseconds()
		}
	}
	return t
}

// ensureCloudInitRequest is the seed ensureCloudInitOnTarget sends for vm:
// its user-data and the network-config it was created with — the spec's, or
// the one derived from its NIC rows and networks as CreateVM derived it. nil
// sends none: a spec that cannot be parsed, or a network-config read that
// failed (the target would keep a seed written without it — the outcome of a
// target this host cannot reach).
func (s *Server) ensureCloudInitRequest(ctx context.Context, vm *corrosion.VMRecord) *pb.EnsureCloudInitRequest {
	var spec pb.VMSpec
	if vm.Spec == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(vm.Spec), &spec); err != nil {
		slog.Warn("ensureCloudInitOnTarget: parse spec", "vm", vm.Name, "error", err)
		return nil
	}
	req := &pb.EnsureCloudInitRequest{VmName: vm.Name}
	if spec.CloudInit != nil {
		req.Userdata = spec.CloudInit.Userdata
	}
	// The seed the VM runs on here: its NICs' guest names, and what is sent
	// when the network-config cannot be derived. Whose it is is the hotplug
	// rebuild's rule (cloudinit.OwnSeed).
	iso := lv.CloudInitISOPath(s.dataDir, vm.Name)
	own, ours, _ := cloudinit.OwnSeed(iso, s.seedClaim(vm, &spec))
	var prior *cloudinit.Prior
	if ours {
		prior = cloudinit.PriorFrom(own.NetworkConfig)
		prior.Stale = cloudinit.SeedMarkedStale(iso)
	}
	nc, err := cloudinit.SeedNetworkConfig(ctx, s.db, vm.Name, &spec, prior)
	switch {
	case errors.Is(err, cloudinit.ErrNICsAmbiguous):
		// Which NIC is which cannot be told: the target gets this host's seed's
		// network-config and vendor-data as they are, or — with no seed of the
		// VM's here — a seed that has cloud-init leave the guest's network as
		// it is; never a seed without network-config that update events the
		// guest recorded would re-render as cloud-init's fallback.
		var vd, detail string
		if ours {
			nc, vd = own.NetworkConfig, own.VendorData
			detail = fmt.Sprintf("the migration target's seed takes this host's network-config as it is: %v (the spec of a VM created before it recorded NIC MACs)", err)
		} else {
			nc, vd = cloudinit.NetworkConfigDisabled, cloudinit.NetworkUpdatesOffVendorData
			detail = fmt.Sprintf("the migration target's seed has cloud-init leave the guest's network as it is, as this host holds no seed of the VM's: %v (the spec of a VM created before it recorded NIC MACs); configure the VM's NICs in the guest", err)
		}
		s.recordVMEventSeverity(ctx, vm.Name, "seed.not_rebuilt", "ok", "warning", detail)
		req.Networkconfig, req.Vendordata = nc, &vd
		return req
	case err != nil:
		slog.Warn("ensureCloudInitOnTarget: network-config could not be derived; no seed sent", "vm", vm.Name, "error", err)
		return nil
	}
	vd := cloudinit.SeedVendorData(&spec, nc)
	req.Networkconfig, req.Vendordata = nc, &vd
	return req
}

// ensureCloudInitOnTarget calls the target host to generate the cloud-init ISO
// before migration starts, so libvirt can find the file when the domain arrives.
func (s *Server) ensureCloudInitOnTarget(ctx context.Context, targetHost string, vm *corrosion.VMRecord) {
	s.endMoveRecords(vm.Name)
	req := s.ensureCloudInitRequest(ctx, vm)
	if req == nil {
		return
	}

	// Check if the cloud-init ISO exists locally — if not, the VM was created
	// without one (e.g. non-cloud image) and we don't need it on the target.
	isoPath := lv.CloudInitISOPath(s.dataDir, vm.Name)
	if _, err := os.Stat(isoPath); err != nil {
		return // no ISO on source, skip
	}

	client, conn, err := s.peerClient(ctx, targetHost)
	if err != nil {
		slog.Warn("ensureCloudInitOnTarget: cannot reach host", "host", targetHost, "error", err)
		return
	}
	defer conn.Close()

	if _, err := client.EnsureCloudInit(ctx, req); err != nil {
		slog.Warn("ensureCloudInitOnTarget: failed", "host", targetHost, "vm", vm.Name, "error", err)
	}
}

// notifyDetachedContext builds the context for a migrate-notify call that
// outlives the originating RPC. It detaches from BOTH the inbound RPC's
// cancellation (context.WithoutCancel) AND its inbound gRPC metadata — a
// forwarded user's authorization bearer can expire mid-migration, and under
// ForwardedIdentityV1 the owning node never falls back to peer identity, so a
// stale bearer would otherwise fail this background nudge outright. Stripping
// makes the notify a plain peer/system call, which is correct for a
// background nudge. The span value is NOT metadata — it survives via ctx's
// ordinary value chain — so the notify still links into the same vm.migrate
// trace via dialPeer's injected traceparent. metadata.MD{} (present-but-empty)
// is used rather than an absent key so FromIncomingContext's ok/not-ok
// semantics stay unambiguous.
func notifyDetachedContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	base := metadata.NewIncomingContext(context.WithoutCancel(ctx), metadata.MD{})
	return context.WithTimeout(base, timeout)
}

// notifyTargetHostOfVM pings the target daemon so it picks up the migrated VM.
func (s *Server) notifyTargetHostOfVM(ctx context.Context, targetHostName, addr string, grpcPort int, vmName string) {
	conn, err := s.dialPeerAddr(peerTarget(addr, grpcPort))
	if err != nil {
		slog.Warn("migrate notify: dial target", "host", targetHostName, "error", err)
		return
	}
	defer conn.Close()

	client := pb.NewLiteVirtClient(conn)
	ctx, cancel := notifyDetachedContext(ctx, 10*time.Second)
	defer cancel()

	_, err = client.InspectVM(ctx, &pb.InspectVMRequest{Name: vmName})
	if err != nil {
		slog.Warn("migrate notify: InspectVM on target failed", "host", targetHostName, "vm", vmName, "error", err)
		return
	}
	slog.Info("migrate: target acknowledged VM", "host", targetHostName, "vm", vmName)
}

// migrationFinish is what the post-cutover work needs beyond the VM itself.
type migrationFinish struct {
	target      *corrosion.HostRecord
	detachedVFs []corrosion.PCIDeviceRecord
	pbVM        *pb.VM
	hspec       *pb.HooksSpec
	// createdStubs are the disk stubs this attempt created on the target
	// (EnsureDisks), the only disk files a failed attempt removes there.
	createdStubs []string
	// armed lets a guest handed over paused run once its NIC guards are in
	// force on the target (armedMigration.finish).
	armed *armedMigration
	// lease is the target's capacity reservation for the move, released when
	// an adopted migration ends, not when its request returns.
	lease *reservationLease
	// drainFrom is the drained host when a drain handed the move over: a
	// failed move then runs post_migrate (the drain's one-pre/one-post
	// pairing), and a completed one writes the drain record and leaves
	// drain_move_timed_out.
	drainFrom string
	// fwLive is a live firmware move: Release on the target lets its guest
	// run, in place of armed.finish (spec §6.1 step 10).
	fwLive *liveFirmwareRun
}

// drainForgetHookForTest runs just before a completed background drain move
// leaves drain_move_timed_out. Tests only.
var drainForgetHookForTest func()

// migratingDetailPrefix starts a migrating row's state detail, followed by
// the target host's name (migratingToward reads it back).
const migratingDetailPrefix = "→ "

// adoptedMigrationCeiling bounds how long an adopted migration may run before
// it is aborted. A var so tests can shorten it.
var adoptedMigrationCeiling = time.Hour

// abortOnMigrateTimeout aborts the libvirt job when the MIGRATE TIMEOUT is what
// ended the wait. timeout_sec is a policy on the operation — give up after N —
// and MigrateToTarget ignores contexts, so without the abort a migration that
// would not converge kept running, adopted, with the VM's lock held. A client
// that merely stopped listening (ctx itself done) is not a policy: that
// migration is adopted and allowed to finish.
func (s *Server) abortOnMigrateTimeout(ctx, migrateCtx context.Context, vmName string) bool {
	if ctx.Err() != nil || !errors.Is(migrateCtx.Err(), context.DeadlineExceeded) {
		return false
	}
	slog.Warn("migrate: timeout reached; aborting the libvirt migration job", "vm", vmName)
	if err := s.virt.AbortMigration(vmName); err != nil {
		slog.Error("migrate: could not abort the timed-out migration", "vm", vmName, "error", err)
	}
	return true
}

// finishMigrationOnTarget is everything after a committed cut-over that makes
// the rest of the cluster agree the guest has moved: the NetBox mirror, SR-IOV
// VFs, switch MAC tables, DNS, LB backends, VXLAN FDB, the post_migrate hook,
// the target's own view, and the source's leftovers. Shared by the watched
// path and an adopted migration, which used to commit ownership and stop.
//
// It returns an error only for a guest handed over paused that its target has
// not yet let run (armedMigration.finish): the move is done, and the guest is
// held paused there until its guards are in force (re-review R3-I2).
func (s *Server) finishMigrationOnTarget(ctx context.Context, vm *corrosion.VMRecord, f migrationFinish) error {
	// All of it runs DETACHED from the request: ownership has been committed,
	// nothing retries this finish, and the watched path passes the request
	// context, which a client that went away after the cutover has cancelled.
	// Not a timeout context cancelled on return: the target-notify goroutine
	// below outlives this call and uses it.
	ctx = context.WithoutCancel(ctx)
	target := f.target.Name
	s.enqueueMirrorSync(ctx, vm.Name, mirrorOpUpsert)
	// The VM may now run on its own replica target: replicate back to this host.
	s.reverseReplicationAfterMove(ctx, "vm", vm.Name, "", s.hostName, target)

	// Re-attach equivalent VFs on the target host for any VFs detached pre-migration.
	if len(f.detachedVFs) > 0 {
		failed := s.reattachVFsOnTarget(ctx, target, f.target.Address, f.target.GRPCPort, vm.Name, f.detachedVFs)
		if f.fwLive != nil && len(failed) > 0 {
			// Release still runs the guest: its NIC firewall is what the
			// move holds it for; the missing VF is named, not silent.
			s.noteFirmwareMoveVFsMissing(ctx, f.fwLive.marker, target, failed, len(f.detachedVFs))
		}
	}

	// The target announces each network's gateway to the guest from its own
	// bridge, so the guest's cached gateway entry moves with it. A guest that
	// arrived paused is announced to once it runs: a live firmware move's by
	// the target's Release (resumeReleased), a paused hand-over's below.
	pausedHandOver := f.armed != nil && f.armed.paused
	if f.fwLive == nil && !pausedHandOver {
		go s.announceOnTarget(ctx, f.target, vm.Name)
	}
	ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, vm.Name)

	// Update DNS records so VM names resolve correctly after migration.
	if s.dnsDomain != "" {
		for _, iface := range ifaces {
			if iface.IP != "" {
				dnsName := dns.VMRecordName(vm.Name, vm.StackName, s.dnsDomain)
				if err := dns.UpsertRecord(ctx, s.db, dnsName, iface.IP); err != nil {
					slog.Warn("post-migration DNS update failed", "vm", vm.Name, "name", dnsName, "error", err)
				}
				break // one A record per VM
			}
		}
	}

	// Refresh LB backends so traffic routes to the new host.
	go s.refreshLBForStack(context.Background(), vm.StackName)

	// Update FDB entries: VM MACs now live on target host's VTEP.
	for _, iface := range ifaces {
		s.updateFDBForMigration(ctx, iface, s.hostName, target)
	}

	// post_migrate hook (notify with new host)
	if f.pbVM != nil {
		f.pbVM.HostName = target
		f.pbVM.State = pb.VMState_VM_RUNNING
		hooks.Run(ctx, hooks.PostMigrate, f.pbVM, f.hspec)
	}

	// Dial target host to re-establish gRPC so it can load TLS creds.
	go s.notifyTargetHostOfVM(ctx, target, f.target.Address, f.target.GRPCPort, vm.Name)

	// Clean up orphaned files on the source host (cloud-init ISO, and disk
	// files for --with-storage migrations where copies now live on target).
	go s.cleanupPostMigration(vm.Name)
	// A plain UEFI VM's vars file, which libvirt's undefine leaves behind. A
	// live firmware move's source state is wiped by its own cleanup.
	if f.fwLive == nil {
		s.removeMigratedSourceVars(ctx, vm.Name, "")
	}

	// A live firmware move's guest runs only through Release, which puts its
	// NIC firewall in force first; then its NVRAM is confirmed and the source
	// cleaned up.
	if f.fwLive != nil {
		if err := s.releaseLiveFirmwareMove(ctx, f.fwLive); err != nil {
			s.recordVMEvent(ctx, vm.Name, "vm.held", "error", err.Error())
			return err
		}
		return nil
	}
	// Last, so a slow target holds up none of the above: a guest handed over
	// paused (a guarded NIC with no tap name of its own) runs once its guards
	// are in force under the taps it got there; the source retries until
	// handOverDeadline (re-review R3-I2).
	if err := f.armed.finish(ctx); err != nil {
		s.recordVMEvent(ctx, vm.Name, "vm.held", "error", err.Error())
		return err
	}
	if pausedHandOver {
		go s.announceOnTarget(ctx, f.target, vm.Name)
	}
	return nil
}

// migrationAbort is what MigrateVM has done, before libvirt took the guest, that
// an exit at that point must undo. See undoMigrationAttempt.
type migrationAbort struct {
	// armed is cleared once something else owns the outcome: libvirt's failure
	// branch and the adopter, or the firmware cold move.
	armed bool
	// stateWritten is set once the row has been written `migrating`.
	stateWritten bool
	// createdStubs are the disk stubs this attempt created on the target.
	createdStubs []string
	// detachedVFs are the SR-IOV VFs taken out of the guest for the move.
	detachedVFs []corrosion.PCIDeviceRecord
	// leaseWritten is set once THIS attempt wrote the migration VF lease. A
	// lease an earlier attempt left — the restart anchor of VFs still out of
	// the guest — is not this attempt's to end.
	leaseWritten bool
	// diskAddr is the target's address in migration.network, when the cold disk
	// copy is to use it ("" = the cluster address).
	diskAddr string
	// copyStarted is set once a cold move began copying a disk to the target.
	copyStarted bool
}

// undoMigrationAttempt is MigrateVM's exit path for an attempt that ended before
// libvirt was handed the guest — a client that went away, a late gate refusal, a
// target that cannot take the copy. The guest never left this host, so the row
// goes back to the state it is actually in and the target's pre-created
// artifacts are removed. Detached context: the request context going away is
// the commonest reason to be here.
func (s *Server) undoMigrationAttempt(ctx context.Context, vmName, target string, a *migrationAbort) {
	ctx = context.WithoutCancel(ctx)
	// The VFs first: the guest is staying, and every moment it runs without its
	// NIC, with the VF free for another VM to claim, is the damage being undone.
	s.reattachVFsOnSource(ctx, vmName, a.detachedVFs, a.leaseWritten)
	// A cold move rolls back from here after its disk copy began, too: the
	// record says which.
	when := "before the copy started"
	if a.copyStarted {
		when = "after its disk copy started"
	}
	if a.stateWritten {
		s.restoreSourceStateAfterFailedMigration(ctx, vmName,
			fmt.Sprintf("migration to %s abandoned %s", target, when),
			fmt.Sprintf("migration to %s abandoned %s, and the domain is not running", target, when))
	}
	s.cleanupFailedMigrationTarget(ctx, vmName, target, a.createdStubs)
	slog.Warn("migrate: attempt ended "+when+"; undone", "vm", vmName, "target", target)
}

// restoreSourceStateAfterFailedMigration takes a VM's row out of `migrating`
// after a migration that left the guest on this host: `running` when the domain
// still runs here, `error` otherwise. Reports whether it found it running.
//
// A LOCAL publish, unlike the post-cutover commit: the migration failed, so the
// guest and its domain are still here.
func (s *Server) restoreSourceStateAfterFailedMigration(ctx context.Context, vmName, runningDetail, errorDetail string) bool {
	// With no libvirt there is nothing to ask whether the domain runs, so it is
	// never claimed to.
	if st, sErr := s.sourceDomainState(vmName); sErr == nil && st == "running" {
		if werr := s.publishRunning(ctx, vmName, "running", func(ctx context.Context) error {
			return corrosion.UpdateVMState(ctx, s.db, vmName, "running", runningDetail)
		}); werr != nil {
			s.noteStateWriteFail(corrosion.OpVMState, werr)
		}
		return true
	}
	if werr := corrosion.UpdateVMState(ctx, s.db, vmName, "error", errorDetail); werr != nil {
		s.noteStateWriteFail(corrosion.OpVMState, werr)
	}
	return false
}

// reattachVFsOnSource puts the SR-IOV VFs MigrateVM hot-detached back into a
// guest that did not move: the migration stopped before libvirt was handed it,
// or libvirt failed. reattachVFsOnTarget is the cutover's counterpart. Without
// it the guest ran on without its passthrough NIC, and the VF — released for
// the move — was free for another VM to claim.
//
// Only into a running domain: a live attach to anything else fails, and a VM
// whose domain is gone is restarted through the paths that allocate devices.
// Best effort per VF, never failing the caller, whose own error is the one the
// operator needs; each VF that cannot go back is logged and recorded as a VM
// event.
func (s *Server) reattachVFsOnSource(ctx context.Context, vmName string, vfs []corrosion.PCIDeviceRecord, leaseWritten bool) {
	if len(vfs) == 0 {
		// Only a lease this attempt wrote, and no VF left the guest. One an
		// earlier attempt left still names VFs out of the guest.
		if leaseWritten {
			s.endMigrationVFLease(vmName)
		}
		return
	}
	// Keyed on the same disposition restart recovery uses: coarse DomainState
	// folds paused and pm-suspended into "stopped", and releasing the VFs of
	// a guest that will resume in place is the loss this exists to prevent.
	if s.virt == nil {
		slog.Warn("migrate: VFs detached for the move not reattached — libvirt not connected", "vm", vmName, "vfs", len(vfs))
		return
	}
	switch s.recoveryDomainDisposition(vmName) {
	case dispRunning:
	case dispShutoff:
		// Nothing to put them into, and the VM keeps owning them until here:
		// give them back to the pool, as a stopped guest's devices are
		// allocated again when it starts.
		slog.Warn("migrate: VFs detached for the move released — the domain is shut off",
			"vm", vmName, "vfs", len(vfs))
		if rerr := s.unbindAndReleaseOwnership(ctx, vmName, pciAddresses(vfs)); rerr != nil {
			slog.Error("migrate: releasing the VFs of a guest that stopped", "vm", vmName, "error", rerr)
			return
		}
		s.endMigrationVFLease(vmName)
		return
	default:
		// Paused, pm-suspended, or unreadable: the guest may resume here. The
		// VFs stay owned + bound and the lease stays for restart recovery.
		for _, vf := range vfs {
			slog.Error("migrate: VF detached for the move left out of a guest that is not running — kept for it",
				"vm", vmName, "address", vf.Address)
			s.recordVMEvent(ctx, vmName, "device.attached", "error",
				"VF "+vf.Address+" detached for a migration that did not happen is not back in the guest, which is not running; "+
					"it stays reserved for the VM and a daemon restart retries the reattach")
		}
		return
	}
	allBack := true
	for _, vf := range vfs {
		if err := s.reattachVFOnSource(ctx, vmName, vf.Address); err != nil {
			allBack = false
			slog.Error("migrate: could not reattach a VF to the guest that stayed on the source",
				"vm", vmName, "address", vf.Address, "error", err)
			s.recordVMEvent(ctx, vmName, "device.attached", "error",
				"VF "+vf.Address+" detached for a migration that did not happen could not be reattached: "+err.Error())
			continue
		}
		slog.Info("migrate: VF reattached on the source", "vm", vmName, "address", vf.Address)
	}
	if allBack {
		s.endMigrationVFLease(vmName)
	}
}

// reattachVFOnSource returns one VF to vmName on this host: ownership, then the
// vfio bind, then the guest — the order an attach takes, so a failure part way
// leaves the VF owned + bound (recoverable: a retried migration or detach
// converges it), never unowned + bound.
//
// Ownership is the VM's already: MigrateVM holds it until the cutover commits.
// A VF found unowned (released by an older daemon, or by hand) is claimed back
// with the same CAS any allocation uses, so a VF another VM took in the
// meantime is left to it.
func (s *Server) reattachVFOnSource(ctx context.Context, vmName, addr string) error {
	devs, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		return fmt.Errorf("read ownership: %w", err)
	}
	owner, known := "", false
	for _, d := range devs {
		if d.Address == addr {
			owner, known = d.VMName, true
			break
		}
	}
	claimed := false
	switch {
	case !known:
		return errors.New("no longer in this host's PCI inventory")
	case owner == vmName:
		// The release never happened; still ours.
	case owner == "":
		ok, cerr := corrosion.ClaimPCIDevice(ctx, s.db, s.hostName, addr, vmName)
		if cerr != nil {
			return fmt.Errorf("claim: %w", cerr)
		}
		if !ok {
			return errors.New("claimed by another VM while it was detached")
		}
		claimed = true
	default:
		return fmt.Errorf("claimed by VM %q while it was detached", owner)
	}
	if _, err := s.vfioHost().Bind(addr); err != nil {
		if claimed {
			// Give back what this call claimed; the strict primitive unbinds
			// first if the failed bind left it bound.
			if rerr := s.unbindAndReleaseOwnership(ctx, vmName, []string{addr}); rerr != nil {
				slog.Warn("migrate: releasing a VF whose rebind failed", "vm", vmName, "address", addr, "error", rerr)
			}
		}
		return fmt.Errorf("bind to vfio-pci: %w", err)
	}
	present, err := s.liveHostdevPresent(vmName, addr)
	if err != nil {
		return fmt.Errorf("read the guest's devices: %w", err)
	}
	if present {
		return nil
	}
	if err := s.virt.AttachHostdev(vmName, addr); err != nil {
		return fmt.Errorf("attach to the guest: %w", err)
	}
	return nil
}

// sourceDomainState is s.virt.DomainState, nil-safe: with no libvirt there is
// no answer.
func (s *Server) sourceDomainState(vmName string) (string, error) {
	if s.virt == nil {
		return "", errors.New("libvirt not connected")
	}
	return s.virt.DomainState(vmName)
}

// cleanupFailedMigrationTarget removes the disk stubs and cloud-init ISO a
// migration pre-created on the target. The VM never got defined there, so they
// are orphaned and would otherwise leak space and shadow a retry. Detached
// context: the request context may itself be the cause of the failure. Shared
// by the watched failure and an adopted one, which used to skip it.
//
// stubPaths is only what EnsureDisks reported CREATING for this attempt. A path
// it skipped already held a file — a disk partition settle kept there, say —
// and removing every disk path by name deleted it (drill D1). A target too old
// to report what it created reports nothing, and its stub is left in place.
func (s *Server) cleanupFailedMigrationTarget(ctx context.Context, vmName, target string, stubPaths []string) {
	// A live firmware move's target keeps its hold's state: CleanupMigrationArtifacts
	// leaves a held VM's firmware alone, and Abort disposes of it.
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	s.cleanupMigrationArtifactsOnTarget(cleanupCtx, target, vmName, stubPaths, "")
}
