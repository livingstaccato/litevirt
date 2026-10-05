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
	"github.com/litevirt/litevirt/internal/hooks"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/obs"
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

// withinDiskArtifactRoot reports whether p is inside a directory where VM disk
// artifacts legitimately live — the default disks dir or a file-backed storage
// pool's directory. The migration helpers bound their create/remove to these
// roots so they can never touch e.g. {dataDir}/state.db just because it's under
// the data dir.
func (s *Server) withinDiskArtifactRoot(p string) bool {
	if safename.Contains(filepath.Join(s.dataDir, "disks"), p) {
		return true
	}
	s.storagePoolsMu.RLock()
	pools := make([]StoragePoolRef, 0, len(s.storagePools))
	for _, pr := range s.storagePools {
		pools = append(pools, pr)
	}
	s.storagePoolsMu.RUnlock()
	for _, pr := range pools {
		if !isFileBasedDriver(pr.Driver) {
			continue
		}
		if dir, derr := fileBasedPoolDir(s.dataDir, pr); derr == nil && safename.Contains(dir, p) {
			return true
		}
	}
	return false
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
	unlock := releaseOnce(s.lockVM(req.VmName))
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
	// Secure Boot / vTPM firmware-state travel (G1). A firmware VM's NVRAM + swtpm
	// are host-local and bind BitLocker, so they need a CONSISTENT capture:
	//   - LIVE is refused: libvirt's native swtpm/NVRAM carry is not yet validated
	//     on this build, and we must not wipe the source copy on an unverified
	//     carry (a fresh-TPM target would brick BitLocker). Use cold migration.
	//   - COLD requires the VM STOPPED: its firmware can't be captured at a single
	//     instant while the guest keeps mutating TPM state, so we copy it quiescent.
	fwSpec := parseFirmwareSpec(vm.Spec)
	fwVM := fwSpec.SecureBoot || fwSpec.Tpm
	if fwVM {
		if req.Strategy != pb.MigrateStrategy_MIGRATE_COLD {
			return status.Errorf(codes.FailedPrecondition,
				"Secure Boot / vTPM VM %q must be migrated cold (--strategy=cold); live firmware carry is not yet a validated path", req.VmName)
		}
		if vm.State != "stopped" {
			return status.Errorf(codes.FailedPrecondition,
				"stop Secure Boot / vTPM VM %q before migrating it — its firmware state can't be captured consistently while running", req.VmName)
		}
	} else if vm.State != "running" {
		return status.Errorf(codes.FailedPrecondition, "VM %q must be running to migrate (state: %s)", req.VmName, vm.State)
	}
	// Resolve target host
	targetHost, err := corrosion.GetHost(ctx, s.db, req.TargetHost)
	if err != nil || targetHost == nil {
		return status.Errorf(codes.NotFound, "target host %q not found", req.TargetHost)
	}
	if targetHost.State != "active" {
		return status.Errorf(codes.FailedPrecondition, "target host %q is not active", req.TargetHost)
	}

	// CPU compatibility, SOURCE-side, before ANY target-side provisioning: a guest
	// whose CPU is derived from its host (host-model / host-passthrough) may be
	// executing instructions the destination does not have, and libvirt only says
	// so once the migration is already underway. Advisory and fail-open — it
	// refuses only on a positive "cannot run" from the target that the source,
	// running the guest, does not also give about itself (see
	// preflightTargetCPU), never on a peer that is old or cannot answer.
	if err := s.preflightTargetCPU(ctx, vm, req.TargetHost); err != nil {
		return err
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
			return status.Errorf(codes.FailedPrecondition,
				"VM %q holds PCI passthrough intent; cross-host migration of PCI devices is not supported in this release", vm.Name)
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
	if reason, refused := s.execGateRefused(ctx); refused {
		s.noteGateRefused(corrosion.ActionReschedule, reason)
		return status.Errorf(codes.FailedPrecondition, "migration refused: %s", reason)
	}

	// Gate the explicit target on the matching host capability (mirrors what
	// placement does for auto placement) — a firmware VM that lands on a
	// non-capable host can't define.
	if fwVM {
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
		// disk (G1 #3 / pre-existing for dir pools).
		if isHostLocalDiskDriver(d.StorageType) {
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

	// Local disks require --with-storage for live migration.
	withStorage := req.WithStorage
	if req.Strategy != pb.MigrateStrategy_MIGRATE_COLD && hasLocal && !withStorage {
		return status.Errorf(codes.FailedPrecondition,
			"VM %q has a local disk — use --with-storage for live migration or --strategy=cold", req.VmName)
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
		srcTLS = s.migrationTLSReady()
		if !srcTLS && !s.allowPlaintextStorageMigration {
			return plaintextStorageRefusal(req.VmName, s.hostName, req.TargetHost, s.hostName)
		}
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
				"VM %q has PCI passthrough device %s (%s) — live migration is not possible; use --strategy=cold",
				req.VmName, d.Address, d.Type)
		}
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
	defer migLease.release(ctx)

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
			s.undoMigrationAttempt(ctx, vm.Name, req.TargetHost, abort)
		}
	}()

	// Pre-provision networks on target host. This ensures bridges, DHCP, NAT,
	// VXLAN tunnels, and IRB gateways exist before the VM arrives — critical for
	// both live and cold migrations (#38).
	{
		preIfaces, _ := corrosion.GetVMInterfaces(ctx, s.db, req.VmName)
		for _, iface := range preIfaces {
			if iface.NetworkName == "" {
				continue
			}
			s.provisionNetworkOnRemote(ctx, req.TargetHost, iface.NetworkName)
		}
	}

	// Ensure cloud-init ISO exists on target before migration — libvirt will
	// reject the domain if the CDROM file path doesn't exist (#62).
	s.ensureCloudInitOnTarget(ctx, req.TargetHost, vm)

	// Ensure disk files exist on target before --with-storage migration.
	// libvirt validates all file paths in the domain XML before block copy starts.
	// createdStubs is what THIS attempt created there — all a failed attempt
	// may remove.
	var createdStubs []string
	useTLS := false
	if withStorage {
		var dstTLS bool
		if createdStubs, dstTLS, err = s.ensureDisksOnTarget(ctx, req.TargetHost, vm.Name, diskStubs, srcTLS); err != nil {
			// EnsureDisks removed whatever it had created; the cloud-init ISO
			// pre-created above is the only leftover, and the abort removes it.
			return err
		}
		abort.createdStubs = createdStubs
		useTLS = srcTLS && dstTLS
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
	}

	// Firmware-state travel (G1): a Secure-Boot/vTPM VM is migrated cold from a
	// STOPPED state WITHOUT libvirt runtime migration — that path can't carry the
	// host-local NVRAM/swtpm and would need a running (or OFFLINE-flagged) domain.
	// Instead push the quiescent firmware to the target, hand the VM over with its
	// state preserved (the target defines+starts it on demand with firmware
	// present), and clean up the source. Returns early — the runtime-migration
	// machinery below is for running VMs only.
	if fwVM {
		abort.armed = false // the cold move owns its outcome, and its cleanup
		return s.coldMigrateFirmwareVM(ctx, vm, targetHost, fwSpec, send)
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

	// Read migration policy from stored VM spec for tuning parameters.
	// Keep it as a pointer (nil = no policy) and use the nil-safe generated
	// getters — copying the proto message by value would drag its embedded
	// mutex/MessageState along (go vet: "copies lock value").
	var migratePolicy *pb.MigrationPolicy
	if vm.Spec != "" {
		var storedSpec pb.VMSpec
		if json.Unmarshal([]byte(vm.Spec), &storedSpec) == nil {
			migratePolicy = storedSpec.Migrate
		}
	}

	bandwidthMiB := int(migratePolicy.GetBandwidthMibSec())
	autoConverge := migratePolicy.GetAutoConverge()
	// Default auto-converge to true for live migrations when no policy is set,
	// preserving previous behaviour.
	if migratePolicy == nil || migratePolicy.GetBandwidthMibSec() == 0 && !migratePolicy.GetAutoConverge() && migratePolicy.GetStrategy() == 0 {
		autoConverge = live
	}
	var maxDowntimeMS int64
	if migratePolicy.GetMaxDowntime() != "" {
		if d, err := time.ParseDuration(migratePolicy.GetMaxDowntime()); err == nil {
			maxDowntimeMS = d.Milliseconds()
		}
	}

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

	// Split-brain gate, LATE re-check: the early gate (after target validation) is a
	// fail-fast, but preflight/provisioning ran since then. Re-check quorum on the
	// source IMMEDIATELY before the irreversible step (state → migrating, then
	// MigrateToTarget), so a quorum loss during setup still stops the move. Fail-open
	// until split_brain_gate_v1 is cluster-wide.
	if reason, refused := s.execGateRefused(ctx); refused {
		s.noteGateRefused(corrosion.ActionReschedule, reason)
		return status.Errorf(codes.FailedPrecondition, "migration refused: %s", reason)
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
	for _, vf := range detachedVFs {
		// Membership-aware (idempotent) guest detach so a retried migration converges: if a
		// prior attempt already live-detached the VF but its release failed, the VF is gone
		// from the guest and a bare DetachHostdev would error ("device not found") and abort
		// before re-attempting the release. detachHostdevIfPresent skips the already-gone
		// detach so control falls through to the idempotent release. A DumpXML error still
		// aborts the migration (fail closed — membership cannot be confirmed).
		if err := s.detachHostdevIfPresent(req.VmName, vf.Address); err != nil {
			return status.Errorf(codes.Internal, "detach VF %s before migration: %v", vf.Address, err)
		}
		abort.detachedVFs = append(abort.detachedVFs, vf)
		slog.Info("VF detached for migration", "vm", req.VmName, "address", vf.Address)
	}

	// Mark as migrating in state store. Recorded first, so a write that errored
	// after landing is still restored by the abort.
	abort.stateWritten = true
	if err := corrosion.UpdateVMState(ctx, s.db, vm.Name, "migrating", fmt.Sprintf("→ %s", req.TargetHost)); err != nil {
		s.noteStateWriteFail(corrosion.OpVMState, err)
	}
	migrationStart := time.Now()

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
	done := make(chan error, 1)
	go func() {
		done <- s.virt.MigrateToTarget(vm.Name, dconnuri, lv.MigrateParams{
			Live:          live,
			WithStorage:   withStorage,
			BandwidthMiB:  bandwidthMiB,
			AutoConverge:  autoConverge,
			MaxDowntimeMS: maxDowntimeMS,
			// Bracketed here, not in internal/libvirt: that package renders it
			// into a tcp:// migrate_uri authority but must not import corrosion.
			TargetAddress: corrosion.URIHost(targetHost.Address),
			DiskTargets:   diskTargets,
			// The target's migration certificate carries its address as an IP
			// SAN (`lv host init`/`add` issue it for the same address peers
			// dial), and the migrate_uri names that address.
			TLS:            useTLS,
			TLSDestination: targetHost.Address,
		})
	}()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

poll:
	for {
		select {
		case <-migrateCtx.Done():
			s.abortOnMigrateTimeout(ctx, migrateCtx, vm.Name)
			// libvirt is still migrating. MigrateToTarget takes no context, so
			// cancelling this request does not stop the guest moving — it only
			// stops us watching. Returning bare here left the VM at
			// host_name=source/state=migrating while it ran on the target, and
			// the reconciler skips `migrating`, so nothing ever healed it.
			adopted = true
			s.adoptAbandonedMigration(context.WithoutCancel(ctx), vm, req.TargetHost,
				withStorage, disks, done, unlock, migrationFinish{
					target: targetHost, detachedVFs: detachedVFs, pbVM: pbVM, hspec: hspec,
					createdStubs: createdStubs,
				})
			return status.Errorf(codes.DeadlineExceeded,
				"stopped waiting for the migration of %q to %s (%v); it is still running in "+
					"libvirt and will be completed in the background — watch `lv events %s`",
				vm.Name, req.TargetHost, migrateCtx.Err(), vm.Name)
		case migrateErr := <-done:
			if migrateErr != nil {
				// Migration failed — VM is still on the source host.
				// Check if the domain is still alive; if so, restore to "running"
				// instead of leaving it in "error" (#21).
				//
				// Bounded and detached from the request: a client that goes
				// away now must not drop the restore and strand the row
				// `migrating`, which nothing else heals.
				fctx, fcancel := detachedMigrateCleanupCtx(ctx)
				defer fcancel()
				// The VFs go back before the row says running: the guest stayed.
				s.reattachVFsOnSource(fctx, vm.Name, detachedVFs)
				if s.restoreSourceStateAfterFailedMigration(fctx, vm.Name,
					fmt.Sprintf("migration to %s failed: %v", req.TargetHost, migrateErr), migrateErr.Error()) {
					slog.Warn("migration failed but VM still running on source",
						"vm", vm.Name, "target", req.TargetHost, "error", migrateErr)
				}
				s.cleanupFailedMigrationTarget(fctx, vm.Name, req.TargetHost, createdStubs)
				send(pb.MigratePhase_MIGRATE_FAILED, 0, 0) //nolint:errcheck
				s.recordMigrationMetrics(strategyLabel, "failure", time.Since(migrationStart), 0, 0)
				return status.Errorf(codes.Internal, "migration failed: %v", migrateErr)
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

	// The libvirt cutover has happened and cannot be rolled back. Commit the
	// VM+disk ownership move to the target atomically BEFORE any destructive
	// source cleanup or success signal — a failed commit is loud divergence, never
	// silent success. `disks` is the pre-cutover snapshot captured above.
	if err := s.finalizeMigrationOwnership(ctx, vm, req.TargetHost, withStorage, disks); err != nil {
		s.recordMigrationMetrics(strategyLabel, "failure", time.Since(migrationStart), 0, 0)
		s.recordVMEvent(context.WithoutCancel(ctx), vm.Name, "vm.migrated", "error",
			"cut over to "+req.TargetHost+" but ownership commit failed: "+err.Error())
		s.audit(context.WithoutCancel(ctx), "vm.migrate", vm.Name, "from="+s.hostName+" to="+req.TargetHost, "error")
		return status.Errorf(codes.Internal,
			"VM %q cut over to %s but committing ownership failed: %v", vm.Name, req.TargetHost, err)
	}
	s.releaseSourceVFsAfterCutover(context.WithoutCancel(ctx), vm.Name, detachedVFs)

	downtimeMs := float64(time.Since(cutoverStart).Milliseconds())
	s.recordMigrationMetrics(strategyLabel, "success", time.Since(migrationStart), downtimeMs, 0)
	slog.Info("migration complete", "vm", vm.Name, "from", s.hostName, "to", req.TargetHost)
	s.recordVMEvent(context.WithoutCancel(ctx), vm.Name, "vm.migrated", "ok", "from="+s.hostName+" to="+req.TargetHost)
	s.audit(context.WithoutCancel(ctx), "vm.migrate", vm.Name, "from="+s.hostName+" to="+req.TargetHost, "ok")

	// (Firmware-state cleanup is handled in coldMigrateFirmwareVM, which firmware
	// VMs take instead of this runtime-migration path — see the early return above.)
	s.finishMigrationOnTarget(ctx, vm, migrationFinish{
		target: targetHost, detachedVFs: detachedVFs, pbVM: pbVM, hspec: hspec,
	})

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
		if err != nil {
			// The migration failed after we stopped watching; the guest is still
			// on the source. Anything but `migrating` — that is the state nothing
			// heals.
			// The guest stayed, so it gets back the VFs detached for the move,
			// as a watched failure does.
			s.reattachVFsOnSource(ctx, vm.Name, finish.detachedVFs)
			state, detail := "error", fmt.Sprintf("migration to %s failed after the request was abandoned: %v", targetHost, err)
			if st, sErr := s.virt.DomainState(vm.Name); sErr == nil && st == "running" {
				state, detail = "running", fmt.Sprintf("migration to %s failed after the request was abandoned; VM still running on %s: %v", targetHost, s.hostName, err)
			}
			// A LOCAL publish: the migration failed, so the guest and its domain
			// are still on THIS host. state is "error" or "running" depending on
			// what libvirt reports, so it can publish a running VM and has to be
			// routed — this function was added after the chokepoint landed and so
			// was never routed with the rest.
			if werr := s.publishRunning(ctx, vm.Name, state, func(ctx context.Context) error {
				return corrosion.UpdateVMState(ctx, s.db, vm.Name, state, detail)
			}); werr != nil {
				s.noteStateWriteFail(corrosion.OpVMState, werr)
			}
			s.cleanupFailedMigrationTarget(ctx, vm.Name, targetHost, finish.createdStubs)
			slog.Warn("migrate: adopted migration failed", "vm", vm.Name, "target", targetHost, "error", err)
			s.recordVMEvent(ctx, vm.Name, "vm.migrated", "error", "abandoned request; migration failed: "+err.Error())
			return
		}

		// libvirt cut over. The commit is the only thing that makes the cluster
		// agree with reality, and it cannot be skipped just because nobody is
		// listening any more.
		if ferr := s.finalizeMigrationOwnership(ctx, vm, targetHost, withStorage, disks); ferr != nil {
			slog.Error("migrate: adopted migration cut over but ownership commit FAILED — "+
				"the guest is on the target and the cluster does not know",
				"vm", vm.Name, "target", targetHost, "error", ferr)
			s.recordVMEvent(ctx, vm.Name, "vm.migrated", "error",
				"abandoned request; cut over to "+targetHost+" but ownership commit failed: "+ferr.Error())
			return
		}
		s.releaseSourceVFsAfterCutover(ctx, vm.Name, finish.detachedVFs)
		slog.Info("migrate: adopted migration completed", "vm", vm.Name, "target", targetHost)
		s.recordVMEvent(ctx, vm.Name, "vm.migrated", "ok",
			"abandoned request; completed to "+targetHost)
		// The same finish a watched migration gets. Committing ownership and
		// stopping here left the guest without its SR-IOV VFs, its FDB entries
		// on the old VTEP, its LB backends and DNS stale, and the source's files
		// orphaned.
		if finish.target != nil {
			s.finishMigrationOnTarget(ctx, vm, finish)
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
func (s *Server) cleanupPostMigration(vmName string) {
	// Always clean up cloud-init ISO — target regenerates from stored spec if needed.
	isoPath := filepath.Join(s.dataDir, "cloudinit", vmName+".iso")
	if err := os.Remove(isoPath); err == nil {
		slog.Info("post-migration: removed cloud-init ISO", "vm", vmName, "path", isoPath)
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
func (s *Server) reattachVFsOnTarget(ctx context.Context, targetHostName, addr string, grpcPort int, vmName string, vfs []corrosion.PCIDeviceRecord) {
	conn, err := s.dialPeerAddr(peerTarget(addr, grpcPort))
	if err != nil {
		slog.Warn("reattach VFs: dial target", "host", targetHostName, "error", err)
		return
	}
	defer conn.Close()
	s.sendReattachVFs(ctx, pb.NewLiteVirtClient(conn), targetHostName, vmName, vfs)
}

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
func (s *Server) sendReattachVFs(ctx context.Context, client pb.LiteVirtClient, targetHostName, vmName string, vfs []corrosion.PCIDeviceRecord) {
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
			slog.Warn("reattach VF on target failed", "vm", vmName, "type", vf.Type,
				"vendor", vf.VendorID, "target", targetHostName, "error", err)
		} else {
			slog.Info("VF reattached on target", "vm", vmName, "type", vf.Type, "target", targetHostName)
		}
	}
}

// EnsureCloudInit generates a cloud-init ISO on this host if it doesn't already exist.
// Called by the source host before migration so the target has the ISO ready.
func (s *Server) EnsureCloudInit(ctx context.Context, req *pb.EnsureCloudInitRequest) (*emptypb.Empty, error) {
	if _, err := s.authorizeMigrationHelper(ctx, req.VmName); err != nil {
		return nil, err
	}
	isoPath, err := lv.SafeCloudInitISOPath(s.dataDir, req.VmName)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if _, err := os.Stat(isoPath); err == nil {
		return &emptypb.Empty{}, nil // already exists
	}

	userData := req.Userdata
	if userData == "" {
		userData = "#cloud-config\n{}\n"
	}
	if err := cloudinit.GenerateISO(cloudinit.Config{
		InstanceID:    req.VmName,
		LocalHostname: req.VmName,
		UserData:      userData,
		NetworkConfig: req.Networkconfig,
	}, isoPath); err != nil {
		return nil, status.Errorf(codes.Internal, "generate cloud-init ISO: %v", err)
	}
	s.migrationISOs.add(req.VmName, isoPath)
	slog.Info("cloud-init ISO generated for migration", "vm", req.VmName, "path", isoPath)
	return &emptypb.Empty{}, nil
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
	if _, err := s.authorizeMigrationHelper(ctx, req.VmName); err != nil {
		return nil, err
	}
	for _, stub := range req.Disks {
		// Only ever create stubs in a real disk-artifact root (the disks dir or a
		// file-backed pool dir) — never an arbitrary path under the data dir such
		// as state.db.
		if !s.withinDiskArtifactRoot(stub.Path) {
			return nil, status.Errorf(codes.InvalidArgument, "disk stub path %q is not in a disk-artifact root", stub.Path)
		}
		if _, err := os.Lstat(stub.Path); err == nil {
			if !s.migrationStubs.owns(req.VmName, stub.Path) {
				return nil, status.Errorf(codes.FailedPrecondition,
					"disk %s of VM %q already exists on %s, and this migration did not create it. "+
						"It may be the VM's disk from an earlier stay on %s (a copy partition settle kept, say), "+
						"and copying the disk there would overwrite it. Check whether it is still needed, "+
						"move it aside or remove it on %s, then migrate again",
					stub.Path, req.VmName, s.hostName, s.hostName, s.hostName)
			}
		} else if !os.IsNotExist(err) {
			return nil, status.Errorf(codes.Internal, "stat disk stub %s: %v", stub.Path, err)
		}
	}
	resp := &pb.EnsureDisksResponse{}
	var made []string // created by this call: removed again if a later one fails
	undo := func() {
		for _, p := range made {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
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
		if _, err := os.Lstat(stub.Path); err == nil {
			// This host's own stub from an earlier attempt for this VM (checked
			// above). Reuse it at the size asked for now: the mirror needs the
			// sizes to agree, and a stub holds nothing worth keeping.
			if info, ierr := qcow2.Info(stub.Path); ierr == nil && info.VirtualSize == sizeBytes {
				resp.CreatedPaths = append(resp.CreatedPaths, stub.Path)
				slog.Info("disk stub reused for migration", "vm", req.VmName, "path", stub.Path)
				continue
			}
			if err := os.Remove(stub.Path); err != nil {
				undo()
				return nil, status.Errorf(codes.Internal, "replace stub %s: %v", stub.Path, err)
			}
			s.migrationStubs.forget(stub.Path)
		}
		dir := filepath.Dir(stub.Path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			undo()
			return nil, status.Errorf(codes.Internal, "create disk dir %s: %v", dir, err)
		}
		if err := qcow2.Create(stub.Path, sizeBytes, nil); err != nil {
			undo()
			return nil, status.Errorf(codes.Internal, "create stub %s: %v", stub.Path, err)
		}
		made = append(made, stub.Path)
		s.migrationStubs.add(req.VmName, stub.Path)
		resp.CreatedPaths = append(resp.CreatedPaths, stub.Path)
		slog.Info("disk stub created for migration", "vm", req.VmName, "path", stub.Path, "size_bytes", stub.SizeBytes)
	}
	if req.WantMigrationTls {
		// The source can encrypt the copy; tell it whether this host's QEMU can
		// take the other end.
		resp.MigrationTlsReady = s.migrationTLSReady()
	}
	return resp, nil
}

// EnsureFirmwareState materializes a Secure-Boot/vTPM VM's firmware-state bundle
// (NVRAM + swtpm) pushed by a cold-migration source, so libvirt can define the
// domain here with its BitLocker-binding state intact (G1). Mirrors EnsureDisks.
func (s *Server) EnsureFirmwareState(ctx context.Context, req *pb.EnsureFirmwareStateRequest) (*pb.EnsureFirmwareStateResponse, error) {
	if req.VmName == "" || len(req.Bundle) == 0 {
		return nil, status.Error(codes.InvalidArgument, "vm_name and a non-empty firmware bundle are required")
	}
	vm, err := s.authorizeMigrationHelper(ctx, req.VmName)
	if err != nil {
		return nil, err
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
	if s.virt != nil && s.virt.DomainExists(req.VmName) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"refusing to materialize firmware over already-defined domain %q", req.VmName)
	}
	if err := lv.ReadFirmwareBundle(bytes.NewReader(req.Bundle), s.dataDir, req.VmName, req.Uuid); err != nil {
		return nil, status.Errorf(codes.Internal, "materialize firmware state for %q: %v", req.VmName, err)
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
			lv.WipeFirmwareState(s.dataDir, req.VmName, req.Uuid)
			return nil, status.Errorf(codes.FailedPrecondition,
				"firmware path layout differs between source and target (dataDir/OVMF paths); cold firmware migration requires an identical layout on both hosts")
		}
		// Validate the XML identity matches the request — never define a mismatched
		// or unrelated domain via this RPC.
		if xn, xu := domainIdentity(req.DomainXml); xn != req.VmName || (req.Uuid != "" && xu != req.Uuid) {
			lv.WipeFirmwareState(s.dataDir, req.VmName, req.Uuid)
			return nil, status.Errorf(codes.InvalidArgument,
				"domain XML identity (name=%q uuid=%q) does not match request (name=%q uuid=%q)", xn, xu, req.VmName, req.Uuid)
		}
		if err := s.virt.DefineDomain(req.DomainXml); err != nil {
			// Roll back the firmware we just materialized so a retry is clean.
			lv.WipeFirmwareState(s.dataDir, req.VmName, req.Uuid)
			return nil, status.Errorf(codes.Internal, "define migrated domain %q: %v", req.VmName, err)
		}
		// This call materialized the firmware and defined the domain: record
		// them as the attempt's, the only thing its rollback may remove, and
		// say so to the source.
		s.firmwareTargets.add(req.VmName, req.AttemptId, req.Uuid)
		resp.DomainDefined = true
	}
	slog.Info("firmware state received for migration", "vm", req.VmName, "bytes", len(req.Bundle),
		"defined", resp.DomainDefined, "attempt", req.AttemptId)
	return resp, nil
}

// ensureFirmwareStateOnTarget captures this host's firmware-state bundle for a
// Secure-Boot/vTPM VM and pushes it to the cold-migration target before the
// libvirt migrate, so the target defines the domain with the BitLocker-binding
// state present. Unlike disks, this is NOT best-effort — a firmware VM that
// migrates without its state would boot a fresh TPM, so a failure aborts (G1).
//
// It reports what the call left on the target, for the rollback of a failure
// before the handoff commits (abandonFirmwareTarget). attempt names this
// migration attempt to the target, which records the domain it defines under it.
func (s *Server) ensureFirmwareStateOnTarget(ctx context.Context, targetHost, vmName string, fs firmwareSpec, domainXML, attempt string) (firmwareTargetOutcome, error) {
	// Per-component preflight: never push a PARTIAL bundle (WriteFirmwareBundle
	// alone would accept NVRAM-only or swtpm-only) — that restores a fresh TPM.
	if err := s.firmwarePresent(vmName, fs); err != nil {
		return fwTargetUntouched, err
	}
	var buf bytes.Buffer
	has, err := lv.WriteFirmwareBundle(s.dataDir, vmName, fs.UUID, &buf)
	if err != nil {
		return fwTargetUntouched, status.Errorf(codes.Internal, "capture firmware state for %q: %v", vmName, err)
	}
	if !has {
		return fwTargetUntouched, status.Errorf(codes.FailedPrecondition,
			"firmware state for %q is not present on this host; cannot migrate it consistently", vmName)
	}
	client, closeConn, err := s.dialPeer(ctx, targetHost)
	if err != nil {
		return fwTargetUntouched, status.Errorf(codes.Unavailable, "cannot reach target host %s to push firmware: %v", targetHost, err)
	}
	defer closeConn()
	resp, err := client.EnsureFirmwareState(ctx, &pb.EnsureFirmwareStateRequest{
		VmName: vmName, Uuid: fs.UUID, Bundle: buf.Bytes(), DomainXml: domainXML,
		SourceFirmwareFingerprint: s.firmwareLayoutFingerprint(),
		AttemptId:                 attempt,
	})
	if err != nil {
		// The target may have defined the domain before the call failed: a
		// cancelled request loses the answer, not the define.
		return fwTargetUnknown, status.Errorf(codes.Internal, "push firmware state to %s: %v", targetHost, err)
	}
	if !resp.GetDomainDefined() {
		return fwTargetUnreported, nil
	}
	return fwTargetDefined, nil
}

// coldMigrateFirmwareVM moves a STOPPED Secure-Boot/vTPM VM to targetHost WITHOUT
// libvirt runtime migration: it pushes the quiescent firmware bundle, hands the
// VM over with its stopped state preserved (the target defines+starts it on
// demand with firmware present), and cleans up the source. Requires shared
// storage — a stopped VM's host-local disk can't be block-copied here (G1).
func (s *Server) coldMigrateFirmwareVM(ctx context.Context, vm *corrosion.VMRecord, targetHost *corrosion.HostRecord, fwSpec firmwareSpec, send func(pb.MigratePhase, float32, float32) error) error {
	start := time.Now()
	if s.virt == nil {
		return status.Errorf(codes.Internal, "libvirt not connected on host %s", s.hostName)
	}
	// Must read disks successfully — proceeding on an error would skip the
	// host-local refusal AND the disk-ownership updates, diverging VM/disk records.
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		return status.Errorf(codes.Internal, "query disks for %q: %v", vm.Name, err)
	}
	for _, d := range disks {
		if isHostLocalDiskDriver(d.StorageType) {
			return status.Errorf(codes.FailedPrecondition,
				"Secure Boot / vTPM VM %q has a host-local disk (%s) and can't be migrated while stopped — move it to shared storage first (host-local firmware-VM migration is a follow-up)", vm.Name, d.StorageType)
		}
	}
	// PCI/hostdev passthrough isn't carried by this path — the source XML embeds
	// source host PCI addresses that won't be valid (or assigned) on the target.
	// Refuse for now rather than define a domain with stale hostdevs (G1).
	if assigned, _ := corrosion.ListPCIDevices(ctx, s.db, s.hostName, ""); len(assigned) > 0 {
		for _, d := range assigned {
			if d.VMName == vm.Name {
				return status.Errorf(codes.FailedPrecondition,
					"Secure Boot / vTPM VM %q has PCI passthrough device %s — migrating firmware VMs with hostdevs is not supported yet", vm.Name, d.Address)
			}
		}
	}
	// Dump the source's (shut-off) domain XML so the target can DEFINE the same
	// domain — a plain reassigned-stopped VM would otherwise be undefined on the
	// target and unstartable. Shared-storage disk paths + dataDir-relative NVRAM +
	// the UUID-keyed swtpm dir are identical across hosts, so the XML is portable.
	domXML, err := s.virt.DumpXML(vm.Name)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition,
			"cannot dump domain XML for %q (it must be defined to migrate its firmware): %v", vm.Name, err)
	}
	_ = send(pb.MigratePhase_MIGRATE_COPYING, 0, 0)

	// Push the quiescent firmware to the target AND define the domain there (the
	// handler materializes firmware then DefineDomain — shut off, not started).
	// Per-component preflight is inside. Source is untouched on failure.
	//
	// Any failure from here until the handoff commits — a cancelled request
	// included — rolls back what THIS attempt created on the target, and only
	// that: the target records the domain it defines under attempt, and
	// leaves a domain it found there (abandonFirmwareTarget).
	attempt := uuid.NewString()
	outcome, err := s.ensureFirmwareStateOnTarget(ctx, targetHost.Name, vm.Name, fwSpec, domXML, attempt)
	if err != nil {
		return s.abandonFirmwareTarget(ctx, targetHost.Name, vm.Name, fwSpec.UUID, attempt, outcome, err)
	}

	if err := s.handOffColdFirmwareVM(ctx, vm, targetHost); err != nil {
		return s.abandonFirmwareTarget(ctx, targetHost.Name, vm.Name, fwSpec.UUID, attempt, outcome, err)
	}
	// The handoff is committed: the target owns the VM. What follows is cleanup
	// and bookkeeping for a migration that has happened, so it must not die with
	// a client that went away.
	ctx = context.WithoutCancel(ctx)

	// Clean up the source ONLY after a fully successful handoff: undefine the
	// shut-off domain, then wipe the now-orphaned firmware. Do NOT wipe firmware
	// if the undefine fails — keep the source copy as a recoverable fallback and
	// surface the leftover (the VM is already correctly running on the target).
	if s.virt.DomainExists(vm.Name) {
		if err := s.virt.UndefineDomainPreservingState(vm.Name); err != nil {
			slog.Error("cold firmware migration: source domain undefine failed — leaving source firmware as a fallback; clean up manually",
				"vm", vm.Name, "host", s.hostName, "error", err)
			s.recordVMEvent(ctx, vm.Name, "vm.migrated", "warn", "migrated to "+targetHost.Name+" but source domain undefine failed (firmware retained on source)")
		} else {
			lv.WipeFirmwareState(s.dataDir, vm.Name, fwSpec.UUID)
		}
	} else {
		lv.WipeFirmwareState(s.dataDir, vm.Name, fwSpec.UUID)
	}

	_ = send(pb.MigratePhase_MIGRATE_CUTOVER, 100, 0)
	_ = send(pb.MigratePhase_MIGRATE_COMPLETING, 100, 0)
	// The same host-link catch-up as the runtime path above. This is the OTHER
	// migration — a firmware VM takes it instead — and the ownership move it
	// commits is just as invisible to NetBox.
	s.enqueueMirrorSync(ctx, vm.Name, mirrorOpUpsert)
	s.recordMigrationMetrics("cold", "success", time.Since(start), 0, 0)
	slog.Info("cold firmware migration complete", "vm", vm.Name, "from", s.hostName, "to", targetHost.Name, "state", vm.State)
	s.recordVMEvent(ctx, vm.Name, "vm.migrated", "ok", "from="+s.hostName+" to="+targetHost.Name+" (cold firmware, "+vm.State+")")
	s.audit(ctx, "vm.migrate", vm.Name, "from="+s.hostName+" to="+targetHost.Name+" (cold firmware)", "ok")
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
func (s *Server) CleanupMigrationArtifacts(ctx context.Context, req *pb.CleanupMigrationArtifactsRequest) (*emptypb.Empty, error) {
	if err := safename.ValidateVMName(req.VmName); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
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
	for p, at := range s.migrationStubs.recordedFor(req.VmName) {
		if named[p] {
			continue
		}
		if fi, err := os.Lstat(p); err != nil || fi.ModTime().After(at) {
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
		if !s.withinDiskArtifactRoot(p) {
			slog.Warn("cleanup migration artifacts: refusing to remove path outside a disk-artifact root", "vm", req.VmName, "path", p)
			continue
		}
		// Only a stub THIS host created for the VM (EnsureDisks). The source's
		// list is not trusted for it: a source built before EnsureDisks reported
		// what it created names every disk path, including a disk that was here
		// already, and removing that by name deleted it (drill D1).
		if vmLivesHere || !s.migrationStubs.owns(req.VmName, p) {
			slog.Warn("cleanup migration artifacts: leaving a disk file this host did not create as a migration stub",
				"vm", req.VmName, "path", p, "vm_lives_here", vmLivesHere)
			continue
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
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
		} else if vmLivesHere || !s.migrationISOs.owns(req.VmName, iso) {
			slog.Warn("cleanup migration artifacts: leaving a cloud-init ISO this host did not create for the migration",
				"vm", req.VmName, "path", iso, "vm_lives_here", vmLivesHere)
		} else if err := os.Remove(iso); err != nil && !os.IsNotExist(err) {
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
			lv.WipeFirmwareState(s.dataDir, req.VmName, req.FirmwareUuid)
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
	return d.Path != "" && (d.StorageType == "" || isHostLocalDiskDriver(d.StorageType))
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
					"migrate it cold (--strategy=cold) or repair its record", d.DiskName, vmName)
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
func (s *Server) ensureDisksOnTarget(ctx context.Context, targetHost, vmName string, stubs []*pb.DiskStub, wantTLS bool) ([]string, bool, error) {
	if len(stubs) == 0 && !wantTLS {
		return nil, false, nil
	}
	client, conn, err := s.peerClient(ctx, targetHost)
	if err != nil {
		return nil, false, status.Errorf(codes.Unavailable,
			"cannot reach %s to prepare the disks of VM %q for the copy: %v", targetHost, vmName, err)
	}
	defer conn.Close()

	resp, err := client.EnsureDisks(ctx, &pb.EnsureDisksRequest{VmName: vmName, Disks: stubs, WantMigrationTls: wantTLS})
	if err != nil {
		code := status.Code(err)
		if code == codes.Unknown {
			code = codes.Internal
		}
		return nil, false, status.Errorf(code, "could not prepare the disks of VM %q on %s for the copy: %s",
			vmName, targetHost, status.Convert(err).Message())
	}
	return resp.GetCreatedPaths(), wantTLS && resp.GetMigrationTlsReady(), nil
}

// ensureCloudInitOnTarget calls the target host to generate the cloud-init ISO
// before migration starts, so libvirt can find the file when the domain arrives.
func (s *Server) ensureCloudInitOnTarget(ctx context.Context, targetHost string, vm *corrosion.VMRecord) {
	// Parse spec to extract cloud-init data.
	var spec pb.VMSpec
	if vm.Spec == "" {
		return
	}
	if err := json.Unmarshal([]byte(vm.Spec), &spec); err != nil {
		slog.Warn("ensureCloudInitOnTarget: parse spec", "vm", vm.Name, "error", err)
		return
	}

	// Build the request — send cloud-init data if present, otherwise send
	// minimal data so the target generates a basic ISO.
	req := &pb.EnsureCloudInitRequest{VmName: vm.Name}
	if spec.CloudInit != nil {
		req.Userdata = spec.CloudInit.Userdata
		req.Networkconfig = spec.CloudInit.Networkconfig
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
}

// adoptedMigrationCeiling bounds how long an adopted migration may run before
// it is aborted. A var so tests can shorten it.
var adoptedMigrationCeiling = time.Hour

// abortOnMigrateTimeout aborts the libvirt job when the MIGRATE TIMEOUT is what
// ended the wait. timeout_sec is a policy on the operation — give up after N —
// and MigrateToTarget ignores contexts, so without the abort a migration that
// would not converge kept running, adopted, with the VM's lock held. A client
// that merely stopped listening (ctx itself done) is not a policy: that
// migration is adopted and allowed to finish.
func (s *Server) abortOnMigrateTimeout(ctx, migrateCtx context.Context, vmName string) {
	if ctx.Err() != nil || !errors.Is(migrateCtx.Err(), context.DeadlineExceeded) {
		return
	}
	slog.Warn("migrate: timeout reached; aborting the libvirt migration job", "vm", vmName)
	if err := s.virt.AbortMigration(vmName); err != nil {
		slog.Error("migrate: could not abort the timed-out migration", "vm", vmName, "error", err)
	}
}

// finishMigrationOnTarget is everything after a committed cut-over that makes
// the rest of the cluster agree the guest has moved: the NetBox mirror, SR-IOV
// VFs, switch MAC tables, DNS, LB backends, VXLAN FDB, the post_migrate hook,
// the target's own view, and the source's leftovers. Shared by the watched
// path and an adopted migration, which used to commit ownership and stop.
func (s *Server) finishMigrationOnTarget(ctx context.Context, vm *corrosion.VMRecord, f migrationFinish) {
	// All of it runs DETACHED from the request: ownership has been committed,
	// nothing retries this finish, and the watched path passes the request
	// context, which a client that went away after the cutover has cancelled.
	// Not a timeout context cancelled on return: the target-notify goroutine
	// below outlives this call and uses it.
	ctx = context.WithoutCancel(ctx)
	target := f.target.Name
	s.enqueueMirrorSync(ctx, vm.Name, mirrorOpUpsert)

	// Re-attach equivalent VFs on the target host for any VFs detached pre-migration.
	if len(f.detachedVFs) > 0 {
		s.reattachVFsOnTarget(ctx, target, f.target.Address, f.target.GRPCPort, vm.Name, f.detachedVFs)
	}

	// Send gratuitous ARP for each VM interface to update switch MAC tables.
	ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, vm.Name)
	for _, iface := range ifaces {
		if iface.IP != "" {
			go network.SendGARPBestEffort(iface.NetworkName, iface.IP)
		}
	}

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
	s.reattachVFsOnSource(ctx, vmName, a.detachedVFs)
	if a.stateWritten {
		s.restoreSourceStateAfterFailedMigration(ctx, vmName,
			fmt.Sprintf("migration to %s abandoned before the copy started", target),
			fmt.Sprintf("migration to %s abandoned before the copy started, and the domain is not running", target))
	}
	s.cleanupFailedMigrationTarget(ctx, vmName, target, a.createdStubs)
	slog.Warn("migrate: attempt ended before the copy started; undone", "vm", vmName, "target", target)
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
func (s *Server) reattachVFsOnSource(ctx context.Context, vmName string, vfs []corrosion.PCIDeviceRecord) {
	if len(vfs) == 0 {
		s.endMigrationVFLease(vmName) // written, but no VF left the guest
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
	if _, err := vfio.Bind(addr); err != nil {
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
	// (Firmware VMs never reach this runtime-migration path — they take the
	// stopped cold-move in coldMigrateFirmwareVM — so no firmware cleanup is
	// needed here.)
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	s.cleanupMigrationArtifactsOnTarget(cleanupCtx, target, vmName, stubPaths, "")
}
