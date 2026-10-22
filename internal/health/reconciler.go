package health

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/image"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/pitoverlay"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/storage"
)

const reconcileInterval = 15 * time.Second

// reconcileWalkBudget bounds the pending-VM walk inside ONE pass.
//
// The walk is serial and every per-VM step is bounded only on its own — the
// lease-term barrier, for instance, has a budget per call. Nothing bounded the
// SUM, so a large failover, or a partition where peers time out, could spend
// unbounded time in the walk. selfFence and assertRuntimeOwnership run after it
// on this same goroutine, and selfFence is how a doomed node stops driving
// decisions while it waits for the watchdog — it must not be pushed arbitrarily
// past the tick it is supposed to run on.
//
// Cutting the walk short costs a delayed VM start: it is idempotent and the next
// tick picks the row up again. Not cutting it short costs a delayed self-fence.
// That asymmetry is the whole reason for this value.
//
// Kept below reconcileInterval so a pass that spends its whole budget still
// leaves room for the two sweeps before the next tick. A var, not a const, so
// tests can shrink it.
var reconcileWalkBudget = 10 * time.Second

// imagePullBudget bounds one background backing-image transfer.
//
// The walk budget above must not be the transfer's deadline: a backing image
// that needs longer than the remaining budget was cancelled on every attempt,
// ImportImage discards its partial file on cancellation, and the next pass
// started from byte zero — so a VM whose image was merely LARGE never
// recovered. The transfer therefore runs detached from the walk (see
// pullBackingImage), and this is the bound it runs under instead.
//
// It is a last-resort bound on a stream that has hung, not a performance
// target, and it errs long on purpose: a hung transfer cut here delays that
// VM's recovery by this much and is then retried; a healthy transfer cut here
// restarts from zero and, if it is consistently this slow, never completes.
// The second failure is permanent and the first is not. A var so tests can
// shrink it.
var imagePullBudget = 4 * time.Hour

// errImagePullInProgress is pullBackingImage's answer when the walk's budget
// ran out before the transfer finished. The transfer continues; the VM is
// re-armed as pending and a later pass finds the image present.
var errImagePullInProgress = errors.New("backing image transfer still in progress")

// imagePullFlight is one in-progress background transfer of a backing image.
// err is written before done is closed and read only after it.
type imagePullFlight struct {
	done chan struct{}
	err  error
}

// Reconciler watches for VMs in "pending" state on the local host
// and starts them. It also detects split-brain conditions where a VM
// is running locally in libvirt but corrosion says it belongs to another host.
type Reconciler struct {
	// captures is the host's memory snapshot capture registry
	// (SetCaptureRegistry).
	captures *lv.CaptureRegistry
	// ioPausedWarn rate-limits the io-paused sweep's write-failure
	// warnings (io_paused.go).
	ioPausedWarn ioPausedWarnings
	// stopSyncHook, test-only, runs between the out-of-band stop sync's
	// decision and its write, where a concurrent `lv stop` can land.
	stopSyncHook func(ctx context.Context, vmName string)
	// rekeyDefineHook, test-only, runs once a re-keyed stopped VM's define
	// path holds the start lease, before it re-checks the row and domain.
	rekeyDefineHook func(ctx context.Context, vmName string)
	// rekeyDefined records, per VM, the row version (updated_at) for which
	// this process defined a stopped VM failover re-keyed here
	// (rekeyed_stopped.go).
	rekeyMu      sync.Mutex
	rekeyDefined map[string]string
	rekeyLogged  map[string]string
	// moveHoldLogged logs, once per VM and cause, a start held for its
	// unresolved move (unresolved_move_hold.go).
	moveHoldMu     sync.Mutex
	moveHoldLogged map[string]string
	// fwSkips logs, once per record, a VM this reconciler leaves alone
	// because a live firmware move's record names it here.
	fwSkips firmwareMoveSkips
	// startDomainHook runs immediately before StartDomain, with the context
	// the start is running under. Test-only seam: it makes a walk budget that
	// expires between the start and the commit reproducible instead of a
	// timing race, and lets a test see WHICH context the walk handed down.
	// Nil in production.
	startDomainHook func(context.Context)
	// startRowReadFault, when it returns an error, stands in for a failed
	// read of the row startRowGone re-reads before the boot. Test-only seam
	// for the transient read failure a stalled store produces. Nil in
	// production.
	startRowReadFault func(name string) error
	// proofClaimedHook runs right after a pending start has claimed its proof.
	// Test-only seam: it is the window in which a release of that proof can be
	// recorded, which the start checkpoint has to catch. Nil in production.
	proofClaimedHook func(context.Context)
	hostName         string
	dataDir          string
	db               *corrosion.Client
	virt             LibvirtBackend
	// operatorStopReplay records the forced stops made here under write
	// quarantine once it has lifted (operator_stop_marker.go); run first in
	// every pass, before the walk reads the rows. It reports whether a
	// marker of this host is still waiting for its replay.
	operatorStopReplay func(context.Context) bool
	// heldStartLive / recordVMEvent: a held start whose daemon restarted
	// before libvirt answered it (held_start_orphan.go).
	heldStartLive func(name string) bool
	recordVMEvent func(ctx context.Context, vm, typ, result, detail string)
	// virtWait bounds the walk's and the sweeps' reads of libvirt: a domain
	// libvirt has not answered for is skipped, never decided on
	// (domain_gate.go).
	virtWait virtWait
	// settleVerify / settleProofs are Layer 3 of partition pause (settle.go):
	// the certificate check and the proof source. nil verifier settles nothing.
	settleVerify SettleVerifier
	// pauseGuard runs the destroy of a copy this host's partition pause holds
	// paused under the pauser's mark lock (PartitionPauser.SettleDestroy).
	pauseGuard PauseSettleGuard
	pitReport  func(ctx context.Context, vm, disk, detail string)
	pitCleared func(ctx context.Context, vm, disk string)
	// pitFeature is this host's pit_overlay release-feature gate
	// (SetPITOverlayFeature); nil is closed: overlays are held, never settled.
	pitFeature pitoverlay.Gate
	// sharedWithheldReport / sharedWithheldClear report a VM started without
	// a shared disk whose row names an unproven host, and a start that
	// withheld none (SetSharedDiskWithheldReporter).
	sharedWithheldReport func(ctx context.Context, vm, detail string)
	sharedWithheldClear  func(ctx context.Context, vm string)
	// sharedWithheldReported: the VMs already reported when no reporter is
	// wired, so a bare reconciler records the event once per VM.
	sharedWithheldReported sync.Map
	// pitHeldReported: the holds already reported when no reporter is wired
	// (reportPITHeld).
	pitHeldReported sync.Map
	// settleProofs replaces corrosion.TransferProofs (tests).
	settleProofs func(ctx context.Context, c *corrosion.Client, kind, name string) ([]corrosion.ProofRecord, error)
	// settleFault fails a settle record write (tests; settle_pending.go).
	settleFault    func(step string) error
	settleRecOnce  sync.Once
	settleRecorder *settleRecorder
	// settleDeclines rate-limits the decline report (settle_declined.go).
	settleDeclines   settleDeclineTracker
	onVMStarted      func(ctx context.Context, stackName string)       // optional: called after VM starts (LB refresh)
	vmStartObserver  VMStartObserver                                   // optional: told of every guest start (start grace)
	autoPullImage    func(ctx context.Context, imageName string) error // optional: auto-pull image from peer
	backupInProgress func(vmName string) bool                          // optional: is a backup actively running locally?
	firmware         lv.FirmwarePaths                                  // resolved OVMF paths (G1); set via SetFirmwarePaths
	fwStore          *lv.FirmwareStore                                 // this host's NVRAM and swtpm state; set via SetFirmwareStore

	// recreateOverlay rebuilds a missing disk as an overlay of its image
	// (SetRecreateOverlay); nil builds it in a store of its own, unheld.
	recreateOverlay func(vmName, diskName, imageName, size string) (string, error)

	// sparePCIeRootPortsCfg is `pci.spare_pcie_root_ports` (see
	// daemon.PCIConfig.SparePCIeRootPorts), set via SetSparePCIeRootPorts.
	sparePCIeRootPortsCfg int
	// provision sets up a network on this host for a VM start. nil means
	// network.SafeProvision. Set via SetNetworkProvision.
	provision network.ProvisionFunc

	// Now is the reconciler's clock for vm_lock lease timestamps. Defaults to
	// time.Now; the fleet harness overrides it so lock-expiry scenarios advance
	// deterministically without sleeping.
	Now func() time.Time

	// checkPeerRuntime asks a peer for its LOCAL libvirt view of a VM
	// (absent/defined_stopped/running/unknown) — injected by the daemon (it wires
	// the gRPC runtime-inventory client). nil disables runtime owner-assert (e.g. in
	// tests that don't exercise it). See SetPeerRuntimeChecker.
	checkPeerRuntime func(ctx context.Context, host, name string) (string, error)
	// onOwnerAssert observes each owner-assert decision (result ∈ asserted /
	// split_brain / inconclusive / error) — nil-safe; tests assert on it and
	// Phase 5 can wire a metric. See SetOwnerAssertObserver.
	onOwnerAssert func(vm, result string)

	// pullMu guards pulls: the background backing-image transfers in flight,
	// keyed by image name, so every pass that needs the same image joins the
	// one transfer rather than opening another stream. See pullBackingImage.
	pullMu sync.Mutex
	pulls  map[string]*imagePullFlight

	// transferDisks: disks a pending transfer rebuilt here (superseded_disk.go).
	transferDisks transferDisks
	// onDiskStranded: notified for each disk this host sets aside
	// (stranded_disk.go); nil = no notification.
	onDiskStranded func(vm, host, detail string)
	// heldSavedNoted: held VMs whose saved state was reported, once each
	// (stranded_disk.go, noteHeldSavedState).
	heldSavedMu    sync.Mutex
	heldSavedNoted map[string]bool
	// deferredTransfers: proof-less transfers parked in "starting" while their
	// backing image transfers (missing_disk.go).
	deferredTransfers deferredTransfers
	// startDeferral / startDeferred: starts deferred for want of time or an
	// answer from storage, walked first on the next pass (start_deferral.go).
	startDeferral func(ctx context.Context, vm *corrosion.VMRecord) error
	startDeferred startDeferredSet
	// diskStat / diskLstat are how the reconcile pass looks at a disk file
	// (disk_stat.go); nil is os.Stat / os.Lstat. Tests stand in a storage
	// that does not answer.
	diskStat  func(string) (os.FileInfo, error)
	diskLstat func(string) (os.FileInfo, error)

	// ownerMu guards ownershipFirstSeen, the debounce map recording when each VM
	// was first observed running-locally-but-owned-elsewhere, so a transient
	// in-flight ownership move isn't reclaimed before its marker lands.
	ownerMu            sync.Mutex
	ownershipFirstSeen map[string]time.Time

	// ownerEpochBackfill enables the Phase 4 per-sweep backfill
	// (enforcement.owner_epoch).
	ownerEpochBackfill bool

	// replicaCaughtUp reports whether this node's replica has been reconciled
	// against a peer since it last had reason to believe it is stale (process
	// start, or losing every gossip peer). The daemon wires the corrosion
	// client's ReplicaCaughtUp. nil = unwired (tests that do not exercise it):
	// the replica is treated as trusted. See SetReplicaFreshness.
	replicaCaughtUp func() (bool, string)
	// staleDeferMu guards staleDeferLogged: VM name → the cause its out-of-band
	// stop sync is currently deferred on, already logged, so a deferral that
	// lasts several ticks logs once, not every 15s. See stopSyncAllowed.
	staleDeferMu     sync.Mutex
	staleDeferLogged map[string]string

	// gate is the split-brain safety gate (Phase 1). When a pending VM carries a
	// proof marker (vms.pending_action_id), the reconciler enforces ExecutionGate
	// and validates/claims the linked runtime_action_proofs row before starting.
	// nil disables gating (tests that don't exercise it). See SetGate.
	gate runtimeGate

	// leaseTermGate judges a pending proof's lease term. See SetLeaseTermGate.
	leaseTermGate LeaseTermGate
	// recoveryClaimGate verifies a pending proof's recovery-claim certificate.
	// See SetRecoveryClaimGate.
	recoveryClaimGate RecoveryClaimGate
	// sharedStorageFenceEnforce is the config kill-switch for the shared-disk
	// ownership-transfer fence gate (enforcement.shared_storage_fence). With it AND
	// SharedStorageFenceV1 latched, an ownership-transfer start of a VM with a
	// writable shared disk requires a proof-grade fence of the old owner (carried in
	// the proof's fence_epoch). See SetSharedStorageFenceEnforce.
	sharedStorageFenceEnforce bool
	// onGateRefused observes each gate/proof refusal (action, reason from the
	// closed vocab) — nil-safe; the daemon wires it to the refusal metric.
	onGateRefused func(action, reason string)
	// onStateWriteFail observes an authoritative state write that failed (nil-safe);
	// the daemon wires it to the litevirt_state_write_failures_total counter.
	onStateWriteFail func(op, class string)

	// onbootMu guards onbootPending: onboot VMs whose boot-time autostart the
	// split-brain gate refused (warmup / transient quorum loss). reconcile() retries
	// them each tick (dropping any now running) so a latched gate can't PERMANENTLY
	// strand onboot autostart after a reboot — the refusal is a safe gap that closes
	// when quorum returns. Only VMs that are onboot AND not-running-at-boot ever
	// enter this set. A VM its operator stopped enters it only on a host boot
	// (onbootOverride); otherwise the retry never autostarts an operator stop.
	onbootMu      sync.Mutex
	onbootPending map[string]corrosion.VMRecord
	// onbootOverride (under onbootMu): the VMs a HOST boot starts although
	// their operator stopped them, each with the stop it found
	// (onboot_boot.go); persisted with onbootBootID, this boot's ID, on every
	// change.
	onbootOverride map[string]onbootStop
	onbootBootID   string
	// bootID reads this boot's ID; nil is the kernel's (onboot_boot.go).
	bootID func() (string, error)
	// cancelledStart reports whether this host holds a cancelled start of a
	// VM (SetCancelledStartProbe); nil: none.
	cancelledStart func(name, state, detail string) bool
	// writeRecord writes the onboot record; nil is writeOnbootRecord. Tests
	// make it fail.
	writeRecord func(dataDir string, rec onbootRecord) error
	// listVMs lists this host's VMs for onboot; nil is corrosion.ListVMs.
	// Tests make it fail.
	listVMs func(ctx context.Context) ([]corrosion.VMRecord, error)

	// prepareHardwareForStart, when wired (the daemon passes the gRPC Server's
	// PrepareHardwareForStart), runs the hardware_v2 adoption gate + PCI start-preflight
	// before a failover/reschedule StartDomain: it refuses a "blocked" VM (returns an
	// error) and, for a VM with reserved passthrough intents, acquires + realizes +
	// reconciles its devices into the domain definition so it comes back with them bound.
	// It is a strict NO-OP unless hardware_v2 is latched, so a pre-latch fleet reconciles
	// exactly as before. nil in tests / when unwired → treated as a no-op. The returned
	// release func is invoked ONLY if the subsequent StartDomain fails.
	prepareHardwareForStart func(ctx context.Context, vm *corrosion.VMRecord) (func(), error)

	// passthroughForRebuild claims the PCI passthrough a rebuilt domain
	// carries (passthrough_rebuild.go). nil: none.
	passthroughForRebuild func(ctx context.Context, vm *corrosion.VMRecord) (PassthroughRebuild, error)

	// seedRefreshRaced, set only by tests, runs in refreshOwnSeed between the
	// derivation of the network-config and the rewrite.
	seedRefreshRaced func()

	// orphans / onOrphans: the orphan-runtime report (orphan_runtime.go) — the
	// sighting counts between passes, and the metric observer (nil-safe).
	orphans   orphanReporter
	onOrphans func(kind string, orphans []OrphanRuntime)
}

// SetOperatorStopReplay wires the replay of operator-stop markers
// (grpcapi.Server.ReplayOperatorStopMarkers), run at the start of every pass.
func (r *Reconciler) SetOperatorStopReplay(fn func(context.Context) bool) { r.operatorStopReplay = fn }

// SetHardwareStartPreparer wires the hardware_v2 pre-start hook (adoption gate + PCI
// start-preflight). nil-safe; unwired means every start behaves exactly as before.
func (r *Reconciler) SetHardwareStartPreparer(fn func(ctx context.Context, vm *corrosion.VMRecord) (func(), error)) {
	r.prepareHardwareForStart = fn
}

// hwPrepareStart runs the wired hardware pre-start hook (a strict no-op when unwired or
// pre-latch), returning a release func for the caller to invoke ONLY if its StartDomain
// then fails.
func (r *Reconciler) hwPrepareStart(ctx context.Context, vm *corrosion.VMRecord) (func(), error) {
	if r.prepareHardwareForStart == nil {
		return func() {}, nil
	}
	return r.prepareHardwareForStart(ctx, vm)
}

// stopSyncEpochRead is the read of the row an out-of-band stop sync takes its
// owner epoch from; a test makes it fail.
var stopSyncEpochRead = corrosion.GetVM

// runtimeGate is the subset of *Checker the reconciler needs (injectable for tests).
// LeaseTermGate judges a proof read off the replicated row and returns the
// fence its claim must carry (nil = unfenced), or a countable refusal reason
// and an error. Implemented by grpcapi.
type LeaseTermGate func(ctx context.Context, pr corrosion.ProofRecord) (*corrosion.TermFence, string, error)

// RecoveryClaimGate verifies the recovery-claim certificate on a proof read off
// the replicated row (docs/design/recovery-claims.md §3.10) and returns a
// countable refusal reason with an error, or "" and nil to proceed.
// Implemented by grpcapi (RecoveryClaimGateForPendingProof), which answers
// "proceed" whenever recovery claims are not enforced.
type RecoveryClaimGate func(ctx context.Context, pr corrosion.ProofRecord) (string, error)

type runtimeGate interface {
	ExecutionGate(ctx context.Context) GateResult
	CapabilityActive(ctx context.Context, token string) (bool, string)
	// Enforced is the LATCHED enforcement decision (partition → fail closed).
	Enforced(ctx context.Context, token string) bool
	// SelfFenced reports whether THIS node has self-fenced (tripped the watchdog).
	SelfFenced() bool
}

// selfFenceHardGate reports whether a self-fenced node must refuse a runtime-ownership
// action HERE — unconditionally, before any marker/enforcement branch. A self-fenced node
// (doomed, waiting for the watchdog to reboot it) takes NO decide/execute at all. This is
// checked separately from ExecutionGate because the health loops only consult ExecutionGate
// on the marker-or-enforced path, while `vip_demote_v1` (whose demote-failure path can
// self-fence when a verified watchdog is armed) latches INDEPENDENTLY of
// `split_brain_gate_v1` — so a node can self-fence while the Phase-1 gate is unenforced
// and would otherwise take the legacy (ungated) markerless path.
func selfFenceHardGate(g runtimeGate) bool { return g != nil && g.SelfFenced() }

// SetGate injects the split-brain safety gate (the health.Checker).
func (r *Reconciler) SetGate(g runtimeGate) { r.gate = g }

// SetCaptureRegistry wires the host's memory snapshot capture registry: a
// settle that drops a VM's pause record drops the pauser's hold with it.
// Set before the reconciler runs.
func (r *Reconciler) SetCaptureRegistry(c *lv.CaptureRegistry) { r.captures = c }

// SetCancelledStartProbe wires the probe that says whether this host holds a
// start of the VM `lv stop --force` cancelled while libvirt had not answered
// it (grpcapi.Server.HasCancelledStart). A domain running under such a VM's
// error row is the cancel's to destroy, so the pass does not record it
// running.
func (r *Reconciler) SetCancelledStartProbe(fn func(name, state, detail string) bool) {
	r.cancelledStart = fn
}

// SetLeaseTermGate injects the executor-side lease-term judgment for a pending
// proof (grpcapi's LeaseTermGateForPendingProof).
//
// Injected rather than implemented here because internal/grpcapi imports this
// package: the barrier, the closed key set and the two-arm check all live
// there, and a second copy of a quorum comparison would diverge as a wrong
// verdict rather than a compile error. nil leaves the path exactly as it was
// before Phase 2.
func (r *Reconciler) SetLeaseTermGate(fn LeaseTermGate) { r.leaseTermGate = fn }

// SetRecoveryClaimGate injects the executor-side certificate check for a
// pending proof (grpcapi's RecoveryClaimGateForPendingProof), for the
// SetLeaseTermGate reason: it lives with the verifier and the voter set in
// internal/grpcapi, which imports this package. nil leaves the path as it was
// before recovery claims.
func (r *Reconciler) SetRecoveryClaimGate(fn RecoveryClaimGate) { r.recoveryClaimGate = fn }

// SetOwnerEpochBackfill enables the Phase 4 backfill pass in each sweep
// (enforcement.owner_epoch; the daemon wires it).
func (r *Reconciler) SetOwnerEpochBackfill(on bool) { r.ownerEpochBackfill = on }

// SetReplicaFreshness wires the replica-freshness signal the out-of-band stop
// sync is gated on (the daemon passes corrosion.Client.ReplicaCaughtUp).
func (r *Reconciler) SetReplicaFreshness(fn func() (bool, string)) { r.replicaCaughtUp = fn }

// SetSharedStorageFenceEnforce sets the config kill-switch for the shared-disk
// ownership-transfer fence gate (enforcement.shared_storage_fence).
func (r *Reconciler) SetSharedStorageFenceEnforce(v bool) { r.sharedStorageFenceEnforce = v }

// SetGateRefusedObserver wires the refusal metric hook (nil-safe).
func (r *Reconciler) SetGateRefusedObserver(fn func(action, reason string)) { r.onGateRefused = fn }

// SetStateWriteFailObserver wires the state-write-failure metric hook (nil-safe).
func (r *Reconciler) SetStateWriteFailObserver(fn func(op, class string)) { r.onStateWriteFail = fn }

func (r *Reconciler) noteStateWriteFail(op string, err error) {
	if r.onStateWriteFail != nil {
		r.onStateWriteFail(op, corrosion.ClassifyWriteErr(err))
	}
}

func (r *Reconciler) noteGateRefused(action, reason string) {
	if r.onGateRefused != nil {
		r.onGateRefused(action, reason)
	}
}

// SetFirmwarePaths injects the host's resolved OVMF firmware paths (G1) so the
// reconciler renders the same firmware as CreateVM when it rebuilds a domain.
func (r *Reconciler) SetFirmwarePaths(fp lv.FirmwarePaths) { r.firmware = fp }

// SetFirmwareStore injects this host's firmware store, the one the daemon
// shares with its gRPC server. NewReconciler starts from the production
// layout under dataDir.
//
// nil is ignored, as the server does. A store whose DataDir is not the
// reconciler's panics: the domain XML names the NVRAM under the reconciler's
// data dir, so the store must be the one that holds it.
func (r *Reconciler) SetFirmwareStore(fw *lv.FirmwareStore) {
	if fw == nil {
		return
	}
	if filepath.Clean(fw.DataDir) != filepath.Clean(r.dataDir) {
		panic(fmt.Sprintf("health: firmware store data dir %q is not the reconciler's %q", fw.DataDir, r.dataDir))
	}
	r.fwStore = fw
}

// FirmwareStore is this host's firmware store.
func (r *Reconciler) FirmwareStore() *lv.FirmwareStore { return r.fwStore }

// SetSparePCIeRootPorts sets `pci.spare_pcie_root_ports` — see
// daemon.PCIConfig.SparePCIeRootPorts.
func (r *Reconciler) SetSparePCIeRootPorts(n int) { r.sparePCIeRootPortsCfg = n }

// ensureSparePCIeRootPorts gives a domain this reconciler just defined from
// GenerateDomainXML its pci.spare_pcie_root_ports free root ports, once
// libvirt has placed every device (lv.EnsureSparePCIeRootPorts). Best
// effort: a failure leaves a valid domain that a later hot-plug may find
// full, which is no reason to keep the VM from starting.
func (r *Reconciler) ensureSparePCIeRootPorts(name string) {
	if _, err := lv.EnsureSparePCIeRootPorts(r.virt, name, r.sparePCIeRootPortsCfg); err != nil {
		slog.Warn("reconciler: spare PCIe root ports not added; a hot-plug may find no free slot",
			"vm", name, "want", r.sparePCIeRootPortsCfg, "error", err)
	}
}

// SetNetworkProvision replaces how a VM start provisions the VM's networks on
// this host (nil restores network.SafeProvision). The daemon passes the same
// provisioner the gRPC server uses, so a failover restart and a VM create set
// a network up the same way; the fleet harness passes its per-node fake.
func (r *Reconciler) SetNetworkProvision(fn network.ProvisionFunc) { r.provision = fn }

// publishRunning routes a NON-MINTING transition through the marker chokepoint.
// See PublishVMRunning for the ordering and why it is the right one here.
func (r *Reconciler) publishRunning(ctx context.Context, name, state string, commit func(context.Context) error) error {
	return PublishRunningVia(ctx, r.virt, r.db, r.dataDir, r.hostName, name, state, commit)
}

// publishRunningMinted routes a MINTING transition through the chokepoint in the
// other order. See PublishVMRunningMinted.
func (r *Reconciler) publishRunningMinted(ctx context.Context, name string, commit func(context.Context) error) error {
	return PublishVMRunningMinted(ctx, r.virt, r.db, r.dataDir, r.hostName, name, commit)
}

// NewReconciler creates a VM reconciler for the local host. virt is a
// LibvirtBackend — production passes the real *libvirt.Client; tests/the fleet
// harness pass a fake. A nil virt is tolerated (the reconcile loop guards every
// use), so existing call sites that pass nil keep working.
func NewReconciler(hostName, dataDir string, db *corrosion.Client, virt LibvirtBackend) *Reconciler {
	return &Reconciler{
		hostName: hostName,
		dataDir:  dataDir,
		fwStore:  lv.NewFirmwareStore(dataDir),
		db:       db,
		virt:     virt,
	}
}

// now returns the reconciler's clock (overridable via Now for tests).
func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetOnVMStarted registers a callback invoked after a pending VM is started.
// Used to trigger LB refresh after failover.
func (r *Reconciler) SetOnVMStarted(fn func(ctx context.Context, stackName string)) {
	r.onVMStarted = fn
}

// VMStartObserver is told when this host has just booted a VM's guest — the
// VM healthcheck (VMChecker.NoteVMStarted) opens its start grace from it.
type VMStartObserver interface {
	NoteVMStarted(name string)
}

// SetVMStartObserver wires the observer told of every guest start the
// reconciler makes: a pending start (failover, reschedule, recovery) and a
// boot-time onboot start. Without it, the healthcheck's first sweep after a
// daemon start sees such a VM for the first time, and a first sighting then
// opens no grace — a still-booting guest's failing probe would act on it.
// nil-safe; the daemon passes the VMChecker.
func (r *Reconciler) SetVMStartObserver(o VMStartObserver) { r.vmStartObserver = o }

// SetAutoPullImage registers a callback to pull images from peers when missing locally.
func (r *Reconciler) SetAutoPullImage(fn func(ctx context.Context, imageName string) error) {
	r.autoPullImage = fn
}

// SetRecreateOverlay registers how a missing disk is rebuilt as an overlay of
// its backing image: the daemon's Server.RecreateOverlayDisk, which builds it
// in the daemon's image store under an image hold, so an image prune cannot
// remove the file between its resolve and the overlay (m-6). Unset (tests),
// the overlay is built in a store of the reconciler's own, with no hold.
func (r *Reconciler) SetRecreateOverlay(fn func(vmName, diskName, imageName, size string) (string, error)) {
	r.recreateOverlay = fn
}

// SetBackupInProgress registers a predicate reporting whether a backup is
// actively running locally for a VM. The reconciler uses it to avoid clearing
// the "backing-up" state of a genuinely in-flight backup. When nil, the
// reconciler treats any "backing-up" row as stuck (no live backup tracked).
func (r *Reconciler) SetBackupInProgress(fn func(vmName string) bool) {
	r.backupInProgress = fn
}

// ReconcileOnce runs a single reconcile + self-fence pass — the body of the
// periodic loop, exported for the fleet harness (and one-shot ops) to drive a
// deterministic pass without waiting on the ticker.
func (r *Reconciler) ReconcileOnce(ctx context.Context) {
	r.reconcilePass(ctx)
}

// reconcilePass is one tick's work: the bounded pending-VM walk, then the two
// safety sweeps. The sweeps deliberately take the UNBOUNDED ctx — they are what
// the walk's budget exists to protect, not things to cut short.
func (r *Reconciler) reconcilePass(ctx context.Context) {
	// The walk carries one probe turn (start_deferral.go): its first storage
	// probe runs on whatever time is left.
	wctx, cancel := context.WithTimeout(WithWalkProbeTurn(ctx), reconcileWalkBudget)
	r.reconcile(wctx)
	cancel()

	r.selfFence(ctx)
	r.finishOrphanedStages()
	r.assertRuntimeOwnership(ctx)
	// Both sweeps above skip a domain with no live row. Stamp every domain that
	// has one here, so it stays recognisable once its row is gone; then report
	// the ones litevirt created that have none. Neither touches the runtime.
	r.adoptManagedDomains(ctx)
	r.reportOrphanRuntimes(ctx)
	r.reportIOPausedVMs(ctx)
	r.resolveGoneSubjects(ctx)
}

// Start begins the reconcile loop. Blocks until ctx is cancelled.
func (r *Reconciler) Start(ctx context.Context) {
	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.reconcilePass(ctx)
		}
	}
}

// StartOnbootVMs starts every local VM marked onboot that is NOT currently
// running in libvirt, in ascending startup_order, pausing start_delay_sec
// between each (#10). Run ONCE at daemon startup, not on the periodic tick.
//
// KillMode=process keeps qemu alive across a daemon restart (domains still
// running → skipped), whereas a host reboot leaves the domains shut off (→
// started here). A VM its operator stopped is not running either way, so the
// host boot is told from a daemon restart by the kernel's boot ID
// (onboot_boot.go): such a VM is started only when the host has booted since
// onboot last ran, and a plain daemon restart leaves it stopped.
func (r *Reconciler) StartOnbootVMs(ctx context.Context) {
	// Defensive: this runs in a startup goroutine — a panic here must never take
	// the daemon down (which would strand the host).
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("onboot: recovered from panic", "panic", rec)
		}
	}()
	if r.virt == nil {
		return
	}
	listVMs := r.listVMs
	if listVMs == nil {
		listVMs = func(ctx context.Context) ([]corrosion.VMRecord, error) {
			return corrosion.ListVMs(ctx, r.db, "", r.hostName)
		}
	}
	vms, err := listOnbootVMs(ctx, listVMs)
	boot := r.onbootBootState()
	if err != nil {
		// Fail closed: record this boot owing nothing, so a daemon restart
		// later in this boot reads "same boot, nothing owed" and honours
		// every operator stop — never the previous boot's record, which
		// reads as a host boot and would override a stop made since. The
		// cost: an operator-stopped onboot VM stays stopped on this boot
		// (`lv start` starts it).
		slog.Error("onboot: cannot list this host's VMs; no onboot VM is started, and this boot is recorded owing none, so a VM its operator stopped stays stopped",
			"error", err, "host_boot", boot.hostBoot)
		r.onbootMu.Lock()
		r.onbootBootID = boot.id
		r.onbootOverride = map[string]onbootStop{}
		r.persistOnbootLocked()
		r.onbootMu.Unlock()
		return
	}
	type onbootVM struct {
		vm    corrosion.VMRecord
		order int
		delay int
	}
	overrides := map[string]onbootStop{}
	var list []onbootVM
	for _, vm := range vms {
		if vm.Spec == "" {
			continue
		}
		spec := &pb.VMSpec{}
		if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil || !spec.Onboot {
			continue
		}
		// Already running (e.g. survived a daemon restart) → leave it. A
		// domain libvirt has not answered for is not known to run: it is
		// owed its start, which startPendingVM leaves until libvirt answers
		// (the onboot retry asks again each pass).
		if r.domainAnswers(vm.Name) && r.virt.DomainExists(vm.Name) {
			if st, sErr := r.virt.DomainState(vm.Name); sErr == nil && st == "running" {
				continue
			}
		}
		// An operator's stop is overridden by a host boot only — onboot is
		// "start at host boot" — or, on a daemon restart later in that boot,
		// when the boot still owes it (onboot_boot.go). A drain's stop or a
		// re-key's is not an operator's choice that a reboot answers, and
		// stays.
		if IsOperatorStop(vm.StateDetail) {
			if !onbootOverrides(boot, vm) {
				slog.Info("onboot: left stopped — not a host boot, a stop made since the boot, or not an operator's stop",
					"vm", vm.Name, "state_detail", vm.StateDetail, "host_boot", boot.hostBoot)
				continue
			}
			overrides[vm.Name] = onbootStop{VM: vm.Name, State: vm.State, StateDetail: vm.StateDetail}
		}
		list = append(list, onbootVM{vm: vm, order: int(spec.StartupOrder), delay: int(spec.StartDelaySec)})
	}
	// Every override is registered and recorded before any start is tried
	// and before any start-delay wait: the reconcile loop runs beside this,
	// and a restart at any point after reads exactly what is still owed
	// (review I-1, I-2).
	r.onbootMu.Lock()
	r.onbootBootID = boot.id
	r.onbootOverride = overrides
	r.persistOnbootLocked()
	r.onbootMu.Unlock()
	if len(list) == 0 {
		return
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].order < list[j].order })
	slog.Info("onboot: starting VMs in order", "count", len(list))
	for i, e := range list {
		slog.Info("onboot: starting VM", "vm", e.vm.Name, "order", e.order)
		// Record the boot-time autostart decision BEFORE attempting: if the split-brain
		// gate refuses now (warmup / transient quorum loss), reconcile() retries from
		// this set until quorum returns, so onboot autostart isn't permanently stranded.
		r.rememberOnboot(e.vm)
		r.startPendingVM(ctx, e.vm)
		if e.delay > 0 && i < len(list)-1 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(e.delay) * time.Second):
			}
		}
	}
}

// rememberOnboot records a VM whose onboot autostart is owed, so reconcile() keeps
// retrying it through the gate until it runs (a gate refusal is a safe gap, not a
// permanent stop). Only ever called for onboot=true, not-running-at-boot VMs.
func (r *Reconciler) rememberOnboot(vm corrosion.VMRecord) {
	r.onbootMu.Lock()
	if r.onbootPending == nil {
		r.onbootPending = make(map[string]corrosion.VMRecord)
	}
	r.onbootPending[vm.Name] = vm
	r.onbootMu.Unlock()
}

// clearOnbootPending ends name's onboot duty, and its override with it.
func (r *Reconciler) clearOnbootPending(name string) {
	r.onbootMu.Lock()
	delete(r.onbootPending, name)
	r.endOnbootOverrideLocked(name)
	r.onbootMu.Unlock()
}

// endOnbootOverride ends the host boot's override of name's operator stop.
// The VM stays owed its onboot start, as any onboot VM is; only a stop it
// carries from now on is honoured, now and after a daemon restart.
func (r *Reconciler) endOnbootOverride(name string) {
	r.onbootMu.Lock()
	r.endOnbootOverrideLocked(name)
	r.onbootMu.Unlock()
}

// endOnbootOverrideLocked ends name's override and records what is left owed.
func (r *Reconciler) endOnbootOverrideLocked(name string) {
	if _, ok := r.onbootOverride[name]; !ok {
		return
	}
	delete(r.onbootOverride, name)
	r.persistOnbootLocked()
}

// settleOnbootOverride ends the override of name's operator stop once its
// row no longer carries that stop (a write this process did not make: the
// start's own "starting" write ends it at once, startPendingVM).
func (r *Reconciler) settleOnbootOverride(name string, fresh *corrosion.VMRecord) {
	if IsOperatorStop(fresh.StateDetail) {
		return
	}
	r.endOnbootOverride(name)
}

// onbootStopOverridden reports whether fresh's operator stop is the one a
// host boot found and starts name over: the same state and detail. A stop
// recorded since is a new choice, and stands.
func (r *Reconciler) onbootStopOverridden(name string, fresh *corrosion.VMRecord) bool {
	r.onbootMu.Lock()
	defer r.onbootMu.Unlock()
	s, ok := r.onbootOverride[name]
	return ok && fresh.State == s.State && fresh.StateDetail == s.StateDetail
}

// specOnboot reports whether a VM's stored spec still marks it onboot. An empty or
// unparseable spec → false (fail safe: never autostart a VM we can't confirm is
// onboot). Used by the retry path so a since-disabled onboot is not resurrected.
func specOnboot(specJSON string) bool {
	if specJSON == "" {
		return false
	}
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(specJSON), spec); err != nil {
		return false
	}
	return spec.Onboot
}

// retryOnbootPending re-attempts onboot autostarts the gate previously refused.
// It re-reads the CURRENT row each time (the remembered snapshot is stale) and
// drops the retry — never autostarting — if the VM is already running, its row is
// gone or reassigned, the operator has since stopped it (operator-stop), or onboot
// was disabled. So a returning quorum can't resurrect a VM the operator stood down
// while it was absent. An operator stop a host boot found and overrides is not
// "since" (onboot_boot.go): the boot's start of it is still owed (lab 2 F-4).
// Idempotent: startPendingVM no-ops on an already-running domain.
//
// The only argument picks which of them this call retries: the ones whose
// start was deferred for time last pass go before the walk, the rest after
// it — those whose storage did not answer first (start_deferral.go), in
// deferral rank order.
func (r *Reconciler) retryOnbootPending(ctx context.Context, only func(name string) bool, deferred map[string]int) {
	r.onbootMu.Lock()
	names := make([]string, 0, len(r.onbootPending))
	for name := range r.onbootPending {
		if only(name) {
			names = append(names, name)
		}
	}
	r.onbootMu.Unlock()
	sort.Strings(names)
	rank := func(name string) int {
		if rk, ok := deferred[name]; ok {
			return rk
		}
		return rankNotDeferred
	}
	sort.SliceStable(names, func(i, j int) bool { return rank(names[i]) < rank(names[j]) })
	for _, name := range names {
		if r.virt != nil && !r.domainAnswers(name) {
			continue // the duty is kept; asked again next pass
		}
		if r.virt != nil && r.virt.DomainExists(name) {
			if st, err := r.virt.DomainState(name); err == nil && st == "running" {
				r.clearOnbootPending(name) // already up — duty discharged
				continue
			}
		}
		fresh, err := corrosion.GetVM(ctx, r.db, name)
		if err != nil {
			// A read that failed (the walk's budget spent, a transient DB
			// error) says nothing about the VM: the duty is kept for the
			// next pass, never dropped as "gone" (lab 2 F-5).
			slog.Warn("reconciler: onboot retry could not read the VM's row; tried again next pass",
				"vm", name, "error", err)
			continue
		}
		if fresh == nil || fresh.HostName != r.hostName {
			slog.Info("reconciler: dropping onboot retry — the VM is gone or on another host", "vm", name)
			r.clearOnbootPending(name) // gone / reassigned — no longer our onboot duty
			continue
		}
		r.settleOnbootOverride(name, fresh)
		// Operator intent may have changed while quorum was absent: honor it.
		if (IsOperatorStop(fresh.StateDetail) && !r.onbootStopOverridden(name, fresh)) || !specOnboot(fresh.Spec) {
			slog.Info("reconciler: dropping onboot retry — operator intent changed",
				"vm", name, "state_detail", fresh.StateDetail, "onboot", specOnboot(fresh.Spec))
			r.clearOnbootPending(name)
			continue
		}
		if fresh.State == "pending" || fresh.State == "starting" {
			// The walk drives every pending or starting row of this host on
			// each pass (a deferred start among them), so the retry leaves
			// it to the walk: driven once per pass, not twice (lab 2 O-8).
			// The duty stays until the start is made or dropped.
			continue
		}
		r.startPendingVM(ctx, *fresh) // gated + current row; succeeds once quorum returns
	}
}

func (r *Reconciler) reconcile(ctx context.Context) {
	// A marker at owner epoch 0 still waiting for its replay: the backfill
	// below would move that pre-epoch row's generation from under it (0 to
	// 1), and the marker would stop holding the VM. The backfill waits for
	// the replay; it is retried every pass, and the wait is logged.
	markersPending := false
	if r.operatorStopReplay != nil {
		markersPending = r.operatorStopReplay(ctx)
	}
	if r.ownerEpochBackfill && markersPending && operatorStopBackfillWaitDue(r.now()) {
		slog.Warn("reconciler: owner-epoch backfill waits — an operator-stop marker at owner epoch 0 has not been replayed yet; " +
			"`lv stop` of its VM records the stop and ends the wait (repeated at most every 10m)")
	}
	if r.ownerEpochBackfill && !markersPending {
		// Phase 4 backfill: graduate every workload this host owns out of the
		// pre-epoch 0. Idempotent by predicate; the convergence pass below then
		// writes the runtime markers for whatever just graduated. Readiness
		// (advertising owner_epoch_v1) keys off no owned row remaining at 0.
		if err := corrosion.BackfillOwnerEpochs(ctx, r.db, r.hostName); err != nil {
			slog.Warn("reconciler: owner-epoch backfill pass failed (will retry)", "error", err)
		}
	}
	vms, err := corrosion.ListVMs(ctx, r.db, "", r.hostName)
	if err != nil {
		slog.Error("reconciler: list VMs", "error", err)
		return
	}

	live := make(map[string]bool, len(vms))
	for _, vm := range vms {
		live[vm.Name] = true
	}
	r.virtWait.prune(live)

	r.resolveDiskMissing(ctx)
	r.tendStrandedDisks(ctx)
	r.cleanupRekeyLeftovers(ctx)

	// Starts deferred last pass go first — the onboot retries deferred for
	// time among them too — so the same VMs are not the ones the walk's
	// budget runs out on every pass; a start whose storage did not answer
	// goes after those deferred for time (start_deferral.go).
	deferred := r.startDeferred.take()
	vms = walkOrder(vms, deferred)
	r.retryOnbootPending(ctx, func(name string) bool { rk, ok := deferred[name]; return ok && rk == rankTime }, deferred)

	for _, vm := range vms {
		// A domain libvirt has not answered for is skipped this pass:
		// every case below asks libvirt about it, and decides from the
		// answer (domain_gate.go).
		if r.virt != nil && !r.domainAnswers(vm.Name) {
			continue
		}
		switch vm.State {
		case "pending":
			r.startPendingVM(ctx, vm)

		case "creating":
			r.finishNewbornVM(ctx, vm.Name)

		case "starting":
			// "starting" is an INTERMEDIATE state written only by startPendingVM (just
			// before the libvirt define+start). A VM left here means a start didn't
			// finish its final state write — a daemon crash mid-start, or a failed
			// post-libvirt DB write (revert-to-pending / CompleteVMStartProof). Without
			// this path such a VM would strand (reconcile otherwise only retries
			// "pending"), and a proof-gated one would strand its proof in_progress too.
			// Re-drive startPendingVM: it is idempotent (an already-running domain
			// completes the proof + heals to running; a not-yet-running one re-attempts),
			// serialized by the per-VM vm_lock so an in-flight start isn't double-driven.
			r.startPendingVM(ctx, vm)

		case "running":
			if r.virt == nil {
				break
			}
			// After daemon restart or libvirt reconnect, verify VMs that
			// corrosion says are "running" are actually alive in libvirt (#43/#53).
			if !r.virt.DomainExists(vm.Name) {
				// Phase 4 enforcement (the dual-run killer): this self-heal
				// restart is decided purely from THIS NODE'S replica, and a
				// just-rejoined node's replica is exactly the untrustworthy
				// input — on 2026-08-01 a rejoined host restarted a VM that had
				// already been rescheduled away, running a second live copy.
				// The runtime marker is the host's own attestation of which
				// generation its runtime belongs to; when the DB knows a NEWER
				// one, this host's runtime is superseded and must not be
				// resurrected from local state. Absent marker = pre-epoch, and
				// the gate below still applies.
				if r.ownerEpochEnforced(ctx) && r.runtimeSuperseded(ctx, vm.Name) {
					slog.Warn("reconciler: refusing self-heal restart — this host's runtime belongs to a superseded ownership generation",
						"vm", vm.Name)
					r.noteGateRefused(corrosion.ActionReschedule, ReasonStaleEpoch)
					break
				}
				// Automated recovery must never act on a workload whose OWNERSHIP
				// is in dispute: restarting one side of a dual-run is exactly how
				// a transient condition becomes a corrupted disk. The condition is
				// durable state, so this refusal holds across restarts and leader
				// changes; recovery resumes when the evaluator proves resolution.
				if disputed, code, cerr := corrosion.WorkloadHasActiveOwnershipCondition(ctx, r.db, "vm", vm.Name); cerr != nil {
					slog.Warn("reconciler: cannot read health conditions; deferring self-heal restart", "vm", vm.Name, "error", cerr)
					break
				} else if disputed {
					slog.Warn("reconciler: refusing self-heal restart — active ownership condition",
						"vm", vm.Name, "condition", code)
					break
				}
				slog.Warn("reconciler: VM marked running but not in libvirt — attempting restart",
					"vm", vm.Name)
				r.startPendingVM(ctx, vm)
				break
			}
			// One-shot machine-type backfill: pin the concrete machine type for VMs created
			// before pinning existed. No-op once pinned (cheap stored-spec check).
			r.maybePinMachineType(ctx, vm)
			// One-shot uuid backfill, same shape and same reason: a VM created
			// before litevirt recorded a domain uuid cannot be named in NetBox,
			// and its unreadable record blocks every mirror delete cluster-wide.
			r.maybeBackfillUUID(ctx, vm)
			// The domain is defined but may have been stopped out-of-band (a
			// crash, an external `virsh destroy`, or a fence that powered it
			// off). Reconcile the cluster state to libvirt reality so it doesn't
			// linger as "running" everywhere (the list/host UI reads cluster
			// state, the detail view reads live state — they must not disagree),
			// AND record WHY in state_detail so the restart engine can later tell
			// a crash from a clean guest shutdown. Never reclassify an operator
			// stop. classifyStop decides whether the VM is genuinely down.
			st, err := r.virt.DomainStateReason(vm.Name)
			if err != nil || st.State == "running" {
				if err == nil && st.State == "running" {
					// Phase 4 convergence: with the domain CONFIRMED running
					// here, repair a missing/stale owner-epoch marker toward
					// the DB row — the crash window between a completion mint
					// and its write-through, and pre-marker domains. ListVMs
					// omits the epoch, so read the full row; pre-epoch rows
					// (epoch 0) are the backfill's to graduate, never stamped.
					r.convergeOwnerEpochMarker(ctx, vm.Name)
				}
				break
			}
			if IsOperatorStop(vm.StateDetail) {
				break
			}
			// An operator's forced stop made here under write quarantine is
			// recorded by its marker's replay as the operator's stop, not
			// synced as an out-of-band one (operator_stop_marker.go).
			if why, _ := OperatorStopHold(r.dataDir, r.hostName, &vm); why != "" {
				break
			}
			// A cutover whose RUNTIME HANDOFF has not finished has, by definition,
			// no domain installed under this name yet. Syncing it to "stopped"
			// would erase the running intent the journaled retry reads, and the
			// retry would then finish the operation with the VM down — the exact
			// shape of a VM that silently never comes back from a cutover.
			if pending, pErr := corrosion.VMReplaceHandoffPending(ctx, r.db, r.hostName, vm.Name); pErr != nil {
				slog.Warn("reconciler: cannot tell whether a cutover handoff is owed — leaving the VM alone",
					"vm", vm.Name, "error", pErr)
				break
			} else if pending {
				slog.Info("reconciler: VM is shut off with a cutover handoff still owed — not syncing",
					"vm", vm.Name)
				break
			}
			// A restart-same VM failover held for this host is owed a start,
			// not a stop sync: a power-off fence leaves its domain defined
			// and shut off here (stranded_disk.go, startHeldVM).
			if r.startHeldVM(ctx, vm, st) {
				break
			}
			newState, detail, sync := classifyStop(st.State, st.Reason)
			if !sync {
				break // paused / migrated / not genuinely down — leave alone
			}
			// This write PUBLISHES a belief read from this node's replica, and
			// a replica that has not caught up since the node came back is
			// exactly the one that can be wrong: on 2026-09-24 a fenced host
			// that booted back still read "ha1 is mine, running" for ~75s and
			// wrote stopped over the VM's real owner four times. The owner-
			// epoch write below only guards that with enforcement on, so this
			// gate is unconditional; it fails closed and retries next tick.
			if !r.stopSyncAllowed(ctx, vm.Name) {
				break
			}
			slog.Warn("reconciler: VM stopped out-of-band — syncing cluster state",
				"vm", vm.Name, "reason", st.Reason, "to", newState)
			// Phase 4: carry the generation this decision was made against, so
			// the statement cannot stomp a peer whose row has moved on. A
			// rejoined host's stale sync was doing exactly that on every rejoin
			// (observed live 2026-08-01) — it now lands locally and stops there.
			// Pre-epoch rows (0) and un-latched clusters keep the plain write.
			//
			// The write is also conditional on the row still saying "running"
			// in its own transaction: the decision above was made from the walk's
			// snapshot, and an `lv stop` that finished since has recorded
			// "operator-stop", which a clean shutdown's "guest-shutdown" must
			// not replace — failover recovers a stop nobody asked for
			// (corrosion.SyncVMStopIfRunning).
			// With enforcement on, a row whose epoch cannot be read is not
			// synced this pass: the plain statement would publish the stop
			// unfenced. The next pass reads it again.
			var epoch int64
			if r.ownerEpochEnforced(ctx) {
				fresh, gerr := stopSyncEpochRead(ctx, r.db, vm.Name)
				if gerr != nil {
					slog.Warn("reconciler: VM's owner epoch cannot be read; not syncing its out-of-band stop this pass",
						"vm", vm.Name, "error", gerr)
					break
				}
				if fresh != nil && fresh.OwnerEpoch > 0 {
					epoch = fresh.OwnerEpoch
				}
			}
			if r.stopSyncHook != nil {
				r.stopSyncHook(ctx, vm.Name)
			}
			//runningcheck:allow provably not running — newState comes from classifyStop,
			// which returns ("", "", false) for the "running" reason, so this out-of-band
			// STOP sync never publishes a running VM. The guard cannot see through the
			// helper's return.
			syncErr := corrosion.SyncVMStopIfRunning(ctx, r.db, vm.Name, newState, detail, epoch)
			if errors.Is(syncErr, corrosion.ErrNoRowsAffected) {
				slog.Info("reconciler: VM's row changed before the out-of-band stop sync; leaving it", "vm", vm.Name)
				break
			}
			if err := syncErr; err != nil {
				slog.Error("reconciler: out-of-band stop sync write failed", "vm", vm.Name, "error", err)
				r.noteStateWriteFail(corrosion.OpVMState, err)
			}

		case "stopped":
			// A stopped VM failover moved here off a failed host has no domain
			// here yet: define it, shut off (rekeyed_stopped.go).
			if corrosion.IsStoppedRekeyDetail(vm.StateDetail) {
				r.defineRekeyedStoppedVM(ctx, vm)
			}
			// One-shot machine-type backfill for a STOPPED but still-defined VM (a legacy VM,
			// or one updated with --machine q35 while stopped): pin the concrete
			// machine type from its persistent domain. No-op once pinned, and a
			// no-op if the domain isn't defined (DumpXMLInactive errors → "").
			r.maybePinMachineType(ctx, vm)
			// A stopped VM is still defined, so its domain uuid is readable and
			// worth recording — a legacy VM is no less invisible to the mirror
			// for being powered off.
			r.maybeBackfillUUID(ctx, vm)

		case "error":
			// An errored VM is still a DEFINED domain, so its uuid is readable —
			// and it is no less invisible to the inventory mirror for being in
			// error. Leaving it out stranded exactly the VMs most likely to be
			// legacy, and one unreadable record withholds every mirror delete
			// cluster-wide, so the gap was not confined to the VM itself.
			// Unconditional like the other two sites: the backfill's own checks
			// make an undefined domain a no-op (DumpXMLInactive errors → "").
			r.maybeBackfillUUID(ctx, vm)
			// Check if an errored VM is actually running in libvirt (e.g. after
			// daemon crash mid-operation). If so, update state to running.
			if r.cancelledStart != nil && r.cancelledStart(vm.Name, vm.State, vm.StateDetail) {
				// A start of it was cancelled here while libvirt had not
				// answered it: a domain libvirt started late is destroyed
				// by the cancelled-starts sweep, the row kept error.
				slog.Info("reconciler: VM in error has a cancelled start here; its domain is not recorded running", "vm", vm.Name)
			} else if r.virt != nil && r.virt.DomainExists(vm.Name) {
				if state, err := r.virt.DomainState(vm.Name); err == nil && state == "running" {
					slog.Info("reconciler: VM in error state but running in libvirt — updating state",
						"vm", vm.Name)
					if err := r.publishRunning(ctx, vm.Name, "running", func(ctx context.Context) error {
						return corrosion.UpdateVMState(ctx, r.db, vm.Name, "running", "reconciler: domain is alive")
					}); err != nil {
						r.noteStateWriteFail(corrosion.OpVMState, err)
					}
				}
			}

		case "backing-up":
			// Self-heal a stuck "backing-up" flag. A crashed/restarted daemon or
			// an interrupted backup stream can strand a VM in "backing-up"
			// forever, which blocks console/VNC, delete, and drain even though
			// the VM is running fine. If no backup is actually running here,
			// reconcile the state from libvirt reality.
			if r.backupInProgress != nil && r.backupInProgress(vm.Name) {
				continue // genuine backup in flight — leave it alone
			}
			if r.virt == nil {
				continue
			}
			live := "stopped"
			if r.virt.DomainExists(vm.Name) {
				st, err := r.virt.DomainState(vm.Name)
				if err != nil {
					continue // can't determine — retry next tick
				}
				live = st
			}
			slog.Info("reconciler: clearing stuck backing-up state", "vm", vm.Name, "live", live)
			if err := r.publishRunning(ctx, vm.Name, live, func(ctx context.Context) error {
				return corrosion.UpdateVMState(ctx, r.db, vm.Name, live, "reconciler: stale backing-up cleared")
			}); err != nil {
				r.noteStateWriteFail(corrosion.OpVMState, err)
			}
		}
	}

	// Retry any onboot autostart the split-brain gate refused during warmup/quorum
	// loss, so a latched gate can't permanently strand it after a reboot.
	r.retryOnbootPending(ctx, func(name string) bool { rk, ok := deferred[name]; return !ok || rk != rankTime }, deferred)
}

// selfFence detects split-brain: VMs running locally in libvirt that corrosion
// says belong to another host. This happens when a network partition heals and
// the VM was rescheduled during the partition (#5).
// maybePinMachineType is the one-shot machine-type backfill for VMs created before
// machine-type pinning. If the stored spec still carries an unversioned alias
// ("q35"/"pc"/"") but libvirt has the domain bound to a concrete versioned type
// (e.g. "pc-q35-9.0"), it rewrites spec.machine to that concrete value so a
// later failover/reschedule regenerates the domain XML with the same guest ABI
// instead of re-resolving the alias on the destination host's qemu version.
// Fires at most once per VM — the cheap stored-spec pre-check makes every
// subsequent tick a no-op — and preserves every other spec field via a raw edit.
func (r *Reconciler) maybePinMachineType(ctx context.Context, vm corrosion.VMRecord) {
	if r.virt == nil || vm.Spec == "" {
		return
	}
	var cur struct {
		Machine string `json:"machine"`
	}
	if err := json.Unmarshal([]byte(vm.Spec), &cur); err != nil {
		return
	}
	if lv.IsPinnedMachineType(cur.Machine) {
		return // already pinned — the steady-state case
	}
	xmlDesc, err := r.virt.DumpXMLInactive(vm.Name)
	if err != nil {
		return
	}
	resolved := lv.MachineTypeFromXML(xmlDesc)
	if !lv.IsPinnedMachineType(resolved) {
		return // libvirt gave no concrete type; leave the alias untouched
	}
	// Surgical edit through the sanctioned barrier-respecting writer: MutateDesiredSpec
	// re-reads the FRESH spec and replaces only "machine" (no other field dropped or
	// reordered), so a concurrent user UpdateVM isn't clobbered — if the spec moved
	// underneath us the CAS misses and we retry next tick. It also defers (applied=
	// false) while an operation holds the VM's mutation barrier — a pin must not race
	// an in-flight resource update.
	applied, _, err := corrosion.MutateDesiredSpec(ctx, r.db, vm.Name, func(old string) (string, error) {
		var freshM struct {
			Machine string `json:"machine"`
		}
		if err := json.Unmarshal([]byte(old), &freshM); err == nil && lv.IsPinnedMachineType(freshM.Machine) {
			return old, nil // already pinned in the fresh spec → no-op (no generation bump)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(old), &raw); err != nil {
			return "", err
		}
		mj, err := json.Marshal(resolved)
		if err != nil {
			return "", err
		}
		raw["machine"] = mj
		b, err := json.Marshal(raw)
		if err != nil {
			return "", err
		}
		return string(b), nil
	})
	if err != nil {
		slog.Warn("reconciler: pin machine type failed", "vm", vm.Name, "machine", resolved, "error", err)
		return
	}
	if !applied {
		return // spec changed underneath us / operation active; retry next tick off the fresh value
	}
	slog.Info("reconciler: pinned machine type (one-shot backfill)", "vm", vm.Name, "from", cur.Machine, "to", resolved)
}

// maybeBackfillUUID is the one-shot uuid backfill for VMs created before
// litevirt recorded a domain uuid in the stored spec.
//
// WHY IT MATTERS beyond tidiness: the uuid is what makes an identity
// incarnation-unique, so a VM without one cannot be named in NetBox at all. The
// inventory mirror skips it AND counts it as an unreadable record — and an
// unreadable record is indistinguishable from a destroyed VM, so the mirror
// withholds EVERY delete for as long as one exists (see netboxsync's
// deleteBlocker). One legacy VM therefore stops the whole mirror converging.
//
// libvirt minted a uuid for the domain whatever litevirt stored, so the
// persistent XML on the OWNING host is the authority — which is why this runs in
// the reconciler's per-VM sweep rather than in a cluster-wide command: no other
// node can read that XML.
//
// It NEVER rewrites a uuid the spec already carries, even if libvirt reports a
// different one (a restore or import can redefine a domain under a fresh uuid).
// The stored value is the identity other systems already hold; replacing it
// would orphan every object stamped with it and mint a duplicate under the new
// one. Absence is the only state this fills in.
//
// Fires at most once per VM — the stored-spec pre-check makes every subsequent
// tick a no-op — and preserves every other spec field via the same raw edit
// maybePinMachineType uses.
func (r *Reconciler) maybeBackfillUUID(ctx context.Context, vm corrosion.VMRecord) {
	if r.virt == nil || vm.Spec == "" {
		return
	}
	var cur struct {
		UUID string `json:"uuid"`
	}
	if err := json.Unmarshal([]byte(vm.Spec), &cur); err != nil {
		return
	}
	if cur.UUID != "" {
		return // already recorded — the steady-state case
	}
	xmlDesc, err := r.virt.DumpXMLInactive(vm.Name)
	if err != nil {
		return
	}
	resolved := lv.UUIDFromXML(xmlDesc)
	if resolved == "" {
		return // no usable uuid; a bogus one is worse than none
	}
	// Same sanctioned writer as the machine-type pin: MutateDesiredSpec re-reads
	// the FRESH spec and replaces only "uuid", so a concurrent UpdateVM is not
	// clobbered, and it defers while an operation holds the VM's mutation
	// barrier.
	applied, _, err := corrosion.MutateDesiredSpec(ctx, r.db, vm.Name, func(old string) (string, error) {
		var freshU struct {
			UUID string `json:"uuid"`
		}
		if err := json.Unmarshal([]byte(old), &freshU); err == nil && freshU.UUID != "" {
			return old, nil // filled in underneath us → no-op (no generation bump)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(old), &raw); err != nil {
			return "", err
		}
		uj, err := json.Marshal(resolved)
		if err != nil {
			return "", err
		}
		raw["uuid"] = uj
		b, err := json.Marshal(raw)
		if err != nil {
			return "", err
		}
		return string(b), nil
	})
	if err != nil {
		slog.Warn("reconciler: uuid backfill failed", "vm", vm.Name, "uuid", resolved, "error", err)
		return
	}
	if !applied {
		return // spec moved underneath us / operation active; retry next tick
	}
	slog.Info("reconciler: recorded the domain uuid (one-shot backfill)", "vm", vm.Name, "uuid", resolved)
}

func (r *Reconciler) selfFence(ctx context.Context) {
	if r.virt == nil {
		return
	}

	localDomains, err := r.listDomainsBounded("reconciler: self-fence")
	if err != nil {
		if !errors.Is(err, errLibvirtNoAnswer) {
			slog.Error("reconciler: list local domains", "error", err)
		}
		return
	}

	// Owners whose runtime probe failed this pass: probed once, not once per
	// leftover, so a fence-and-return with many leftovers and an unreachable
	// owner costs one probe timeout rather than one per VM.
	unreachable := map[string]string{}
	// Live copies Layer 3 declined to settle this pass, reported once the pass
	// is over (settle_declined.go). keep: copies this pass could not examine
	// (row unreadable, migrating, runtime state unreadable). Their absence from
	// declines says nothing, so an open decline for one is kept, not resolved
	// and re-raised a pass later.
	var declines []settleDecline
	keep := map[string]bool{}
	defer func() { r.reportSettleDeclines(ctx, declines, keep) }()
	r.retryPendingSettles(ctx, localDomains)
	r.resolveSettled(ctx, localDomains)
	for _, domName := range localDomains {
		vm, err := corrosion.GetVM(ctx, r.db, domName)
		if err != nil {
			keep[domName] = true // unread: its decline status is unknown, not over
		}
		if err != nil || vm == nil {
			// Domain exists locally but not in corrosion — might be external/manual.
			// A litevirt-stamped one is reported by reportOrphanRuntimes, never here.
			continue
		}

		// If the VM is mid-migration, a transient domain will appear on the
		// target host before corrosion is updated — don't destroy it.
		if vm.State == "migrating" {
			keep[domName] = true // not examined this pass
			continue
		}

		// If corrosion says this VM belongs to a different host, we no longer own it.
		if vm.HostName != r.hostName {
			// A live firmware move's record names it here: a moved VM's
			// source leftover (reason migrated, or unknown after a reboot)
			// or a held target guest. Its definition and both copies of
			// its state stay until the move resolves it (spec §6.9, R-I5).
			if r.firmwareMoveSkip(domName, specUUIDOf(vm.Spec), "leftover cleanup") {
				keep[domName] = true
				continue
			}
			// Non-destruction guard (LWW-repair Phase 1): NEVER destroy a domain
			// that holds live or resumable state locally, whatever the DB host_name
			// says. A converged-wrong host_name — the equal-`updated_at` LWW tie this
			// repair targets — must not be able to drive selfFence into destroying a
			// live VM. Destroying is permitted ONLY on positive proof the domain is a
			// clearly-dead leftover (see cleanableDomainReason); everything else —
			// running, PAUSED, PM-SUSPENDED, SAVED (managed-save memory image),
			// shutting-down, crashed, migrated, from-snapshot, and any unknown or
			// unreadable state — is skipped and deferred to the Phase-3 runtime/
			// fencing ownership reconciliation. We use DomainStateReason, not the
			// coarse DomainState, because the latter collapses paused/pm-suspended/
			// saved/shutoff all into "stopped" and would destroy resumable workloads.
			//
			// Reason "unknown" is the one exception, and it needs MORE proof, not
			// less: see provenOwnerLeftover.
			st, serr := r.virt.DomainStateReason(domName)
			if serr != nil {
				keep[domName] = true // state unreadable: settle not examined this pass
			}
			cleanable := serr == nil && cleanableLeftover(st)
			why := ""
			if serr == nil && !cleanable && unknownShutoff(st) {
				cleanable, why = r.provenOwnerLeftover(ctx, domName, vm.HostName, unreachable)
			}
			// Layer 3 of partition pause (settle.go): a LIVE copy — running, or
			// paused by this host's partition pause — whose row a VERIFIED
			// recovery-claim certificate gave to another host is stopped on that
			// positive proof, never on host_name. The leftover cleanup above
			// takes the shut-off domain on a later pass.
			if serr == nil && !cleanable && (st.State == RuntimeRunning || st.Reason == "paused") {
				settled, swhy, local := r.settleCertifiedMove(ctx, domName, vm)
				if settled {
					continue
				}
				why = swhy
				declines = append(declines, settleDecline{Name: domName, RowHost: vm.HostName,
					Reason: swhy, Local: local, RuntimeState: st.State, RuntimeReason: st.Reason})
			}
			if !cleanable {
				slog.Warn("reconciler: NOT destroying a local domain whose DB row points elsewhere — not a clearly-dead leftover; deferring to runtime ownership repair",
					"vm", domName, "local_host", r.hostName, "corrosion_host", vm.HostName, "state", st.State, "reason", st.Reason, "state_err", serr, "unproven", why)
				continue
			}
			slog.Warn("reconciler: removing clearly-dead local leftover whose DB row moved to another host",
				"vm", domName, "local_host", r.hostName, "corrosion_host", vm.HostName, "reason", st.Reason)
			// No DestroyDomain: every path here proved the domain shut off
			// (cleanableLeftover and unknownShutoff both require it), so a
			// destroy only fails with "domain is not running". And were the
			// domain to start between that check and now, undefining leaves
			// the running copy alone, where a destroy would kill it.
			//
			// A leftover that holds firmware state here (NVRAM, swtpm tree)
			// is never wiped: an owed DISCARD of a live firmware move may name
			// it before its record reaches this host. Its state is quarantined
			// and the domain undefined keeping state.
			if r.quarantineLeftoverFirmware(domName, vm) {
				continue
			}
			// wipe by design: a stopped/defined leftover whose VM now lives on
			// another host (the authoritative firmware state travels with it).
			if err := r.virt.UndefineDomain(domName, false); err != nil {
				slog.Warn("reconciler: undefine stale domain failed", "vm", domName, "error", err)
			}
		}
	}
}

// quarantineLeftoverFirmware takes a clearly-dead leftover that holds
// firmware state here: the NVRAM and the swtpm tree of its domain's uuid go
// into <data_dir>/fwmig-quarantine/<vm>-reconciled-<unix>/ with a reason.txt,
// as a firmware move's quarantine, and the domain is undefined keeping state.
// The state is gathered in <vm>-reconciling-<uuid> first and renamed into
// place whole, reason.txt included (FirmwareStore.QuarantineLeftoverFirmwareState),
// so a pass that stops part way is finished by the next one rather than split
// across two directories. A definition with no canonical uuid has its NVRAM
// quarantined alone. These directories are kept while the VM exists and
// removed by the hourly sweep after superseded_disk_retention_days once it is
// gone (reconciled_quarantine.go); `lv host superseded-disks` lists them.
// true when the domain was taken here (done, or left for a later pass on an
// error); false when it holds no firmware state, so the ordinary cleanup runs.
func (r *Reconciler) quarantineLeftoverFirmware(domName string, vm *corrosion.VMRecord) bool {
	if r.fwStore == nil {
		return false
	}
	xml, err := r.virt.DumpXMLInactive(domName)
	if err != nil {
		slog.Warn("reconciler: leftover kept: its definition cannot be read to find its firmware state", "vm", domName, "error", err)
		return true
	}
	uuid := lv.UUIDFromXML(xml)
	if !lv.ValidFirmwareUUID(uuid) {
		uuid = ""
	}
	has := func(p string) bool { _, err := os.Lstat(p); return err == nil }
	qdir := filepath.Join(r.fwStore.DataDir, fwmig.QuarantineDir)
	stage := filepath.Join(qdir, reconcilingName(domName, uuid))
	if !has(r.fwStore.NvramPath(domName)) && (uuid == "" || !has(r.fwStore.SwtpmDir(uuid))) && !has(stage) {
		return false
	}
	now := time.Now()
	final := filepath.Join(qdir, fmt.Sprintf("%s%s%d", domName, reconciledInfix, now.Unix()))
	uuidLine := uuid
	if uuid == "" {
		uuidLine = fmt.Sprintf("(none: the definition gives no canonical uuid; only the NVRAM is here, and a swtpm tree, if any, stays under %s)", r.fwStore.SwtpmBase)
	}
	reason := fmt.Sprintf("vm: %s\nuuid: %s\nhost: %s\nrow_host: %s\nquarantined_at: %s\n"+
		"reason: the reconciler cleaned a shut-off leftover whose row names another host; its firmware state is kept here\n"+
		"retention: kept while VM %s exists; once it is gone, removed after superseded_disk_retention_days (lv host superseded-disks lists it)\n",
		domName, uuidLine, r.hostName, vm.HostName, now.UTC().Format(time.RFC3339), domName)
	// Stage, undefine, then finish (D2-18 verify, m-A): while the stage
	// exists the guard refuses the VM's start, so a failed or interrupted
	// undefine leaves a defined domain whose start is refused, never one that
	// boots on blank firmware state. The next pass retries the undefine; a
	// crash after it leaves an orphaned stage, which finishOrphanedStages
	// finishes.
	if err := r.fwStore.StageLeftoverFirmwareState(domName, uuid, stage, []byte(reason)); err != nil {
		slog.Warn("reconciler: leftover kept: its firmware state cannot be quarantined", "vm", domName, "dir", stage, "error", err)
		return true
	}
	if err := r.virt.UndefineDomainPreservingState(domName); err != nil {
		slog.Warn("reconciler: undefine the quarantined leftover keeping its state; its state stays staged", "vm", domName, "stage", stage, "error", err)
		return true
	}
	if err := r.fwStore.FinishStage(stage, final); err != nil {
		slog.Warn("reconciler: finish the leftover's quarantine; a later pass finishes it as an orphaned stage", "vm", domName, "stage", stage, "error", err)
		return true
	}
	slog.Warn("reconciler: a leftover's firmware state was quarantined, not wiped", "vm", domName, "row_host", vm.HostName, "dir", final)
	// The leftover's seed, stamped for its uuid, goes with it: the VM lives
	// on vm.HostName (lab-2 D2: seeds left on a lost target).
	if uuid != "" {
		if iso, err := lv.SafeCloudInitISOPath(r.fwStore.DataDir, domName); err == nil && cloudinit.SeedIsFor(iso, uuid) {
			if err := cloudinit.RemoveSeed(iso); err != nil {
				slog.Warn("reconciler: the quarantined leftover's seed was not removed", "vm", domName, "seed", iso, "error", err)
			}
		}
	}
	return true
}

// finishOrphanedStages finishes every reconciler stage
// (<vm>-reconciling-<uuid>) whose leftover domain is gone: no domain of the
// name is defined here, or the one defined has another uuid. It writes the
// stage's reason.txt ("orphaned stage") and renames it to
// <vm>-reconciled-<unix>, so it takes the retention rule and --remove like
// any other (D2-18 re-review 4, m-2). A stage whose domain is still defined
// with its uuid is left: as a leftover the cleanup finishes it, and as the
// VM's own domain the guard refuses its start until --restore puts the state
// back. An interrupted restore (<vm>-restoring-<uuid>) is never touched.
func (r *Reconciler) finishOrphanedStages() {
	if r.fwStore == nil {
		return
	}
	qdir := filepath.Join(r.fwStore.DataDir, fwmig.QuarantineDir)
	ents, err := os.ReadDir(qdir)
	if err != nil {
		return
	}
	var defined map[string]bool
	for _, e := range ents {
		vm, kind, uuid, ok := fwmig.ParseStageName(e.Name())
		if !e.IsDir() || !ok || kind != fwmig.StageReconciling {
			continue
		}
		stage := filepath.Join(qdir, e.Name())
		if defined == nil {
			// A listing error is never read as "no domain": the stage stays.
			names, err := r.virt.ListDomains()
			if err != nil {
				return
			}
			defined = map[string]bool{}
			for _, n := range names {
				defined[n] = true
			}
		}
		why := ""
		if !defined[vm] {
			why = "no domain of the VM is defined on this host any more"
		} else if uuid != "" {
			xml, err := r.virt.DumpXMLInactive(vm)
			if err != nil {
				continue // unreadable: not known to be another domain
			}
			if du := lv.UUIDFromXML(xml); du != "" && !strings.EqualFold(du, uuid) {
				why = fmt.Sprintf("the domain of the VM defined on this host has uuid %s, not this stage's", du)
			}
		}
		if why == "" {
			continue
		}
		now := time.Now()
		final := filepath.Join(qdir, fmt.Sprintf("%s%s%d", vm, reconciledInfix, now.Unix()))
		reason := fmt.Sprintf("vm: %s\nuuid: %s\nhost: %s\nquarantined_at: %s\n"+
			"reason: orphaned stage: the reconciler had gathered this leftover's firmware state when %s; it is finished here as is\n"+
			"retention: kept while VM %s exists; once it is gone, removed after superseded_disk_retention_days (lv host superseded-disks lists it)\n",
			vm, uuidOrNone(uuid), r.hostName, now.UTC().Format(time.RFC3339), why, vm)
		staged := time.Time{}
		if fi, err := os.Lstat(stage); err == nil {
			staged = fi.ModTime()
		}
		if err := r.fwStore.FinishOrphanedStage(stage, final, []byte(reason)); err != nil {
			slog.Warn("reconciler: an orphaned firmware quarantine stage cannot be finished", "stage", stage, "error", err)
			continue
		}
		slog.Warn("reconciler: finished an orphaned firmware quarantine stage", "vm", vm, "dir", final, "why", why)
		if !defined[vm] {
			r.removeOrphanedStageSeed(vm, uuid, staged)
		}
	}
}

// removeOrphanedStageSeed removes the seed of the leftover whose orphaned
// stage was just finished, as quarantineLeftoverFirmware does after its own
// finish (re-review 3, m-3): only a seed stamped for the stage's uuid and
// written no later than the stage was (a seed written since is another copy
// of the VM arriving), never while a hold or a domain of the VM is here, and
// never while the VM's row names this host or cannot be read.
func (r *Reconciler) removeOrphanedStageSeed(vm, uuid string, staged time.Time) {
	if uuid == "" || staged.IsZero() || r.db == nil {
		return
	}
	row, err := corrosion.GetVM(context.Background(), r.db, vm)
	if err != nil || (row != nil && row.HostName == r.hostName) {
		return
	}
	iso, err := lv.SafeCloudInitISOPath(r.fwStore.DataDir, vm)
	if err != nil || !cloudinit.SeedIsFor(iso, uuid) {
		return
	}
	if fi, err := os.Stat(iso); err != nil || fi.ModTime().After(staged) {
		return
	}
	// An incoming copy of the VM may reuse the seed without rewriting it:
	// kept while a hold or a domain of the VM is here now (round-4 re-review
	// m-1). Anything unreadable keeps it.
	if _, held, err := fwmig.New(r.fwStore.DataDir).GetHold(vm); err != nil || held {
		return
	}
	names, err := r.virt.ListDomains()
	if err != nil || slices.Contains(names, vm) {
		return
	}
	if err := cloudinit.RemoveSeed(iso); err != nil {
		slog.Warn("reconciler: the orphaned stage's seed was not removed", "vm", vm, "seed", iso, "error", err)
		return
	}
	slog.Info("reconciler: removed the seed of an orphaned stage's leftover", "vm", vm, "seed", iso)
}

// stagedOwnFirmware reports whether a stage of vm's firmware state is on
// this host (by name or by the spec's uuid), logging it. A quarantine
// directory that cannot be read counts as one.
func (r *Reconciler) stagedOwnFirmware(vm corrosion.VMRecord) bool {
	if r.fwStore == nil {
		return false
	}
	staged, err := fwmig.New(r.fwStore.DataDir).Staged(vm.Name, specUUIDOf(vm.Spec))
	if err != nil {
		slog.Warn("reconciler: not starting the VM: its firmware quarantine directory cannot be read", "vm", vm.Name, "error", err)
		return true
	}
	if len(staged) == 0 {
		return false
	}
	slog.Warn("reconciler: not starting the VM: its firmware state is in a stage, not in place; `lv host superseded-disks <host> --restore <dir>` puts it back",
		"vm", vm.Name, "dir", staged[0].Path)
	return true
}

func uuidOrNone(u string) string {
	if u == "" {
		return "(none)"
	}
	return u
}

// cleanableLeftover reports whether a local domain is a CLEARLY-DEAD leftover —
// no live or resumable state — so it is safe to destroy+undefine when its DB row
// has moved to another host. Both conditions must hold (positive proof, fail
// closed):
//
//   - coarse State == "stopped" — defensive belt-and-suspenders. Today the
//     cleanable reasons below all originate from DomainShutoff (which coarse-maps
//     to "stopped"), so this is redundant against the current mapping; it guards
//     against a future reason/state decoupling silently re-admitting a non-stopped
//     (possibly live) domain to destruction.
//   - Reason in the allowlist below. An allowlist (default: do NOT clean) so any
//     state holding recoverable memory (paused, pmsuspended, saved), in transition
//     (shutting-down, migrated, from-snapshot), needing investigation (crashed), or
//     unknown/unreadable is skipped and deferred to Phase-3 runtime ownership repair.
func cleanableLeftover(st lv.DomainStatus) bool {
	if st.State != "stopped" {
		return false
	}
	switch st.Reason {
	case "guest-shutdown", // guest cleanly powered itself off
		"destroyed", // forcibly destroyed — no state retained
		"daemon",    // shut off by the daemon
		"failed":    // failed to start — never held live state
		return true
	default:
		return false
	}
}

// unknownShutoff reports a stopped domain whose shutoff reason libvirt could not
// supply. Under the real mapping (normalizeDomainReason) a paused or pm-suspended
// domain always carries its own reason, so a coarse "stopped" with reason
// "unknown" can only be DomainShutoff with an unrecognised or lost reason — the
// shape every leftover takes after the host reboots or loses power, because
// libvirt does not persist the shutoff reason across that.
func unknownShutoff(st lv.DomainStatus) bool {
	return st.State == "stopped" && st.Reason == "unknown"
}

// provenOwnerLeftover decides whether a shut-off domain with reason "unknown" is
// a leftover safe to destroy+undefine. "unknown" alone proves nothing — it is
// the absence of a reason, and cleanableLeftover's allowlist rightly refuses it —
// so it is admitted only on two further pieces of POSITIVE proof, each failing
// closed when unreadable:
//
//   - no managed-save image. A managed-save is saved RAM; libvirt reports it as
//     shutoff/"saved" while it knows, but after a reboot the reason can come
//     back "unknown" with the image still on disk, and UndefineDomain would
//     discard it.
//   - the DB owner itself reports the VM RUNNING in its own libvirt (the peer
//     runtime inventory, answered from the owner's libvirt, not from replicated
//     rows). This is what defuses the converged-wrong host_name the non-
//     destruction guard exists for: the claim "this copy is not the live one"
//     rests on a live copy being observed elsewhere, not on a DB field. Absent,
//     defined-but-stopped, unknown, an incomplete inventory, an unreachable
//     owner, or no checker wired are all "not proven".
//
// It returns why the proof failed, for the refusal log line. unreachable
// carries owners whose probe already failed in this pass; they are not probed
// again, and a new failure is recorded there.
func (r *Reconciler) provenOwnerLeftover(ctx context.Context, name, owner string, unreachable map[string]string) (bool, string) {
	if owner == "" || owner == r.hostName {
		return false, "no other owner recorded"
	}
	ms, err := r.virt.HasManagedSaveImage(name)
	if err != nil {
		return false, "managed-save image unreadable: " + err.Error()
	}
	if ms {
		return false, "managed-save image present (saved RAM)"
	}
	if r.checkPeerRuntime == nil {
		return false, "no peer runtime checker to confirm the owner runs it"
	}
	if why, ok := unreachable[owner]; ok {
		return false, why
	}
	// Same bound as owner-assert: an unreachable owner must not stall the tick.
	pctx, cancel := context.WithTimeout(ctx, peerRuntimeProbeTimeout)
	state, err := r.checkPeerRuntime(pctx, owner, name)
	cancel()
	if err != nil {
		why := "owner " + owner + " unreachable: " + err.Error()
		unreachable[owner] = why
		return false, why
	}
	if state != RuntimeRunning {
		return false, "owner " + owner + " reports the VM " + state + ", not running"
	}
	return true, ""
}

// startedDetail is the state_detail a reconciler start records on success: why
// the VM was started. A start an operator re-armed (`lv start` after `lv stop
// --force`) is told by its open vm_start_cancelled record, which the
// reconciler does not rewrite (the row's own detail is overwritten by a
// deferral or a retry); a row that reads running with no domain is a
// self-heal restart; an onboot-owed VM is an onboot start; anything else is
// the failover/reschedule start this detail was written for.
func (r *Reconciler) startedDetail(ctx context.Context, vm corrosion.VMRecord) string {
	if strings.HasPrefix(vm.StateDetail, "operator start") {
		return "started by reconciler: operator start re-armed"
	}
	// Only a row in starting: a re-armed start is entered in that state, while an
	// onboot start (stopped) or a self-heal (running) can find a record still open.
	if vm.State == "starting" {
		if ev, err := StartCancelledOf(ctx, r.db, vm.Name, r.hostName); err == nil && ev != nil {
			return "started by reconciler: operator start re-armed"
		}
	}
	if vm.State == "running" {
		return "restarted by reconciler: the domain was not running"
	}
	r.onbootMu.Lock()
	_, onboot := r.onbootPending[vm.Name]
	r.onbootMu.Unlock()
	if onboot {
		return "started by reconciler: onboot"
	}
	return "started by reconciler after failover"
}

func (r *Reconciler) startPendingVM(ctx context.Context, vm corrosion.VMRecord) {
	// A VM a live firmware move's record names here is not started (and its
	// domain not redefined) by the reconciler (spec §6.9).
	if r.firmwareMoveSkip(vm.Name, specUUIDOf(vm.Spec), "start") {
		return
	}
	// The VM's own firmware state sits in a stage (an unfinished quarantine,
	// an interrupted restore): its domain is neither started, destroyed nor
	// undefined here, so the stage is never finished away as orphaned and the
	// VM never boots on blank state (D2-18 verify, m-B). --restore ends it.
	if r.stagedOwnFirmware(vm) {
		return
	}
	// A start that would be deferred for want of time is left as it is
	// before anything is done for it — no lease, no proof claimed, no
	// define — and goes first on the next pass (start_deferral.go).
	if r.deferredBeforeWork(ctx, vm) {
		return
	}
	// A domain libvirt has not answered for is not started, nor anything
	// else decided about it (domain_gate.go): the walk skips it already;
	// this holds for the onboot start too.
	if r.virt != nil && !r.domainAnswers(vm.Name) {
		return
	}
	// An operator's forced stop made here under write quarantine and not
	// yet recorded (operator_stop_marker.go) holds every start of the VM
	// here: self-heal, onboot, a re-driven start. Asked again of the fresh
	// row under the lease below.
	if operatorStopHeld("reconciler", r.dataDir, r.hostName, &vm) {
		return
	}
	// A paused domain a live move left here while that move is unresolved
	// is never replaced: it may be the guest's only copy
	// (unresolved_move_hold.go). Nothing is claimed or written for it.
	if r.holdForUnresolvedMove(ctx, vm.Name) {
		return
	}
	// Take a per-VM startup lease before doing anything destructive.
	// Without this, two reconcilers on different hosts that both briefly
	// see vm.HostName=self in CRDT-stale state would both call libvirt.Start
	// on the same VM UUID — the same physical disk gets two QEMU writers
	// → guaranteed corruption.
	if !r.acquireVMLock(ctx, vm.Name) && !r.takeOverOrphanedHeldStart(ctx, vm) {
		slog.Info("reconciler: VM lock held by another host, skipping",
			"vm", vm.Name)
		return
	}
	// Re-read the VM row after acquiring the lock — if CRDT replication
	// between the lock-acquire and now has reassigned the VM elsewhere,
	// abort so the legitimate host can pick it up.
	fresh, err := corrosion.GetVM(ctx, r.db, vm.Name)
	if err != nil || fresh == nil || fresh.HostName != vm.HostName {
		slog.Info("reconciler: VM no longer assigned to this host after lock, releasing",
			"vm", vm.Name)
		r.releaseVMLock(ctx, vm.Name)
		return
	}
	// A start decided from a running row (the self-heal, a held VM's start)
	// is for a VM the walk read as running here. A stop recorded since —
	// `lv stop`, or any other — wins: operator intent is never overridden
	// by a start decided from an older read.
	if vm.State == "running" && (fresh.State != "running" || IsOperatorStop(fresh.StateDetail)) {
		slog.Info("reconciler: VM was stopped after the walk read it running; not starting it",
			"vm", vm.Name, "state", fresh.State, "detail", fresh.StateDetail)
		r.releaseVMLock(ctx, vm.Name)
		return
	}
	// A start decided from a pending or starting row that an operator has
	// since cancelled (`lv stop --force`, start_cancelled.go) is not made.
	if (vm.State == "pending" || vm.State == "starting") && fresh.State == "stopped" && IsOperatorStop(fresh.StateDetail) {
		slog.Info("reconciler: VM's start was cancelled after the walk read it; not starting it",
			"vm", vm.Name, "state", fresh.State, "detail", fresh.StateDetail)
		r.releaseVMLock(ctx, vm.Name)
		return
	}
	if operatorStopHeld("reconciler", r.dataDir, r.hostName, fresh) {
		r.releaseVMLock(ctx, vm.Name)
		return
	}
	// Releasing the lease is CLEANUP, and cleanup must not inherit the caller's
	// deadline. reconcilePass bounds this walk with reconcileWalkBudget; on the
	// very case that budget exists for, it expires mid-start and the DELETE
	// fails (Debug-logged), stranding the lease for the full vmLockTTL so no
	// other host can reconcile this VM.
	defer r.releaseVMLock(context.WithoutCancel(ctx), vm.Name)

	// A pending transition that carries a proof marker (pending_action_id) was minted
	// by a coordinator that held the lease + quorum, so we MUST validate + claim it
	// single-use — AND run the local ExecutionGate — regardless of local activation.
	proofID := fresh.PendingActionID
	// An ownership transfer onto this host (the coordinator's pending row, or
	// its proof after a crash or re-arm), as opposed to a local start: it never
	// finds the VM's current host-local disk here (superseded_disk.go).
	// A proof-less transfer whose image pull outlived the walk is parked in
	// "starting" (deferPendingStart) and is still that transfer.
	transfer := fresh.State == "pending" || proofID != "" ||
		(fresh.State == "starting" && (r.deferredTransfers.has(vm.Name) || r.cancelledTransfer(ctx, vm.Name)))

	// A proof MARKER present with NO gate wired fails CLOSED: we can't verify quorum,
	// and a marker implies enforcement was active when it was stamped. (Production
	// wires the gate before the reconcile loops; this is defense-in-depth.)
	if proofID != "" && r.gate == nil {
		slog.Warn("reconciler: pending proof marker present but no gate wired — refusing start (fail closed)", "vm", vm.Name)
		r.noteGateRefused(corrosion.ActionReschedule, ReasonNoQuorum)
		return
	}

	// Self-fence is an UNCONDITIONAL hard gate (independent of marker/enforcement): a
	// doomed node must not start ANY VM — pending transfer, onboot autostart, or local
	// domain-died recovery — during its fence-timeout window.
	if selfFenceHardGate(r.gate) {
		slog.Warn("reconciler: self-fenced — refusing VM start (no runtime action while doomed)", "vm", vm.Name)
		r.noteGateRefused(corrosion.ActionReschedule, ReasonSelfFenced)
		return
	}

	// Split-brain gate (Phase 1), EXECUTE side: run the local ExecutionGate when a
	// proof MARKER is present OR enforcement is latched. The marker forcing the gate
	// is the key case: in an asymmetric partition a target can receive a valid marker
	// while itself lacking quorum, and must NOT execute. Any automated start (pending
	// reschedule, onboot autostart, "DB running / libvirt missing" recovery) is thus
	// gated. Legacy (ungated) is allowed ONLY when there's no marker AND enforcement
	// never activated.
	if r.gate != nil && (proofID != "" || r.gate.Enforced(ctx, capabilities.SplitBrainGateV1)) {
		if g := r.gate.ExecutionGate(ctx); !g.OK {
			slog.Warn("reconciler: execution gate refused start (no quorum)", "vm", vm.Name, "reason", g.Reason)
			r.noteGateRefused(corrosion.ActionReschedule, g.Reason)
			return // lock released by defer; retry next tick if quorum returns
		}
	}

	// Ownership-dispute gate, EXECUTE side. The coordinator refuses to plan
	// recovery for a disputed workload, but this reconciler is the node that
	// actually starts things — and it also serves pending rows minted before
	// the condition was raised, and local starts (onboot autostart, domain-died
	// recovery) that never passed through the coordinator at all. Starting any
	// of them while ownership is contested adds a holder. Fail closed on a read
	// error; the row stays pending and the next tick retries.
	if disputed, code, cerr := corrosion.WorkloadHasActiveOwnershipCondition(ctx, r.db, "vm", vm.Name); cerr != nil {
		slog.Warn("reconciler: cannot read health conditions; deferring start (fail closed)",
			"vm", vm.Name, "error", cerr)
		return
	} else if disputed {
		slog.Warn("reconciler: refusing automated start — active ownership condition",
			"vm", vm.Name, "condition", code)
		r.noteGateRefused(corrosion.ActionReschedule, ReasonOwnershipDispute)
		return
	}

	// Post-activation, a coordinator OWNERSHIP TRANSFER writes state=pending AND a
	// proof marker (pending_action_id) atomically. A PENDING row with NO marker under
	// enforcement is therefore stale / pre-activation / hand-mutated — refuse it
	// (proof_missing) rather than complete an ownership transfer with no proof. This
	// enforces the "post-activation proof + pending_action_id mandatory" rule for the
	// transfer path even though the coordinator should never mint such a row.
	//
	// Scope is deliberately state=="pending" (the transfer signal the coordinator
	// writes): onboot autostart and domain-died recovery ENTER with state stopped/
	// running (not pending), so they stay legitimate markerless LOCAL starts gated by
	// the ExecutionGate above — no ownership transfer, no proof required. A markerless
	// "starting" row is likewise not a transfer: a transfer can only reach "starting"
	// via "pending", which is refused here first, so a markerless "starting" is a local
	// start (or a pre-flip transfer off an already-fenced source) — both safe under the
	// ExecutionGate — and refusing it would strand a crashed local start.
	if proofID == "" && fresh.State == "pending" &&
		r.gate != nil && r.gate.Enforced(ctx, capabilities.SplitBrainGateV1) {
		slog.Warn("reconciler: enforced pending start carries no proof marker — refusing (proof_missing): stale/pre-activation/hand-mutated pending row",
			"vm", vm.Name)
		r.noteGateRefused(corrosion.ActionReschedule, ReasonProofMissing)
		return
	}

	var proofFenceEpoch string // the validated proof's fence_epoch (shared-disk gate below)
	if proofID != "" {
		// The proof must actually authorize THIS start: a reschedule proof whose
		// target/dest is this VM on this host. A mismatched id (stale pointer,
		// collision) must never authorize a start.
		pr, ok, gerr := corrosion.GetActionProof(ctx, r.db, proofID)
		if gerr != nil || !ok {
			// Can't read/find the proof row → we can't verify it authorizes THIS start, and
			// ClaimActionProof matches only by id+status, so it would start the VM UNVALIDATED
			// (a fail-open double-run vector). Refuse (fail closed).
			slog.Warn("reconciler: pending proof unreadable/missing — refusing start (fail closed)",
				"vm", vm.Name, "proof", proofID, "found", ok, "error", gerr)
			r.noteGateRefused(corrosion.ActionReschedule, ReasonProofConflict)
			return
		}
		// Exact match required: a reschedule proof for THIS vm, destined for THIS host. An
		// empty/other dest is not accepted — a malformed/stale proof for the right VM must not
		// become usable on any host.
		if pr.Action != corrosion.ActionReschedule || pr.TargetKind != "vm" ||
			pr.TargetName != vm.Name || pr.DestHost != r.hostName {
			slog.Warn("reconciler: pending proof does not match this VM/host, refusing start",
				"vm", vm.Name, "proof", proofID, "proof_target", pr.TargetName, "proof_dest", pr.DestHost)
			r.noteGateRefused(corrosion.ActionReschedule, ReasonProofConflict)
			return
		}
		// Bind the proof to the exact ownership generation the coordinator
		// observed. A proof left prepared across owner A→B→A must not authorize a
		// start after the row's owner epoch advances (ABA). Empty is the pre-epoch
		// form and remains inert until owner_epoch_v1 enforcement is activated.
		if pr.OwnerEpoch != "" && pr.OwnerEpoch != strconv.FormatInt(fresh.OwnerEpoch, 10) {
			slog.Warn("reconciler: pending proof owner epoch is stale, refusing start",
				"vm", vm.Name, "proof", proofID, "proof_epoch", pr.OwnerEpoch,
				"current_epoch", fresh.OwnerEpoch)
			r.noteGateRefused(corrosion.ActionReschedule, ReasonStaleEpoch)
			return
		}
		proofFenceEpoch = pr.FenceEpoch

		// Lease-term enforcement (Phase 2), EXECUTE side. This is the SECOND
		// executor trust boundary and it is easy to miss: a reschedule proof
		// never travels over an RPC, so grpcapi's claimCarriedProof — where the
		// rest of this regime lives — is never reached on the failover path.
		// The coordinator writes the row with the pending marker and this
		// reconciler claims it straight off replication. Without the check
		// here, a superseded coordinator's reschedules execute exactly as they
		// did before the feature existed, while every other proof path is
		// gated.
		//
		// The judgment is INJECTED (see SetLeaseTermGate) rather than
		// reimplemented: it lives in internal/grpcapi, which imports this
		// package, so this package cannot import it back. A second copy of a
		// quorum comparison is the class of bug this phase has already paid for
		// twice.
		//
		// Unwired = inert, which is deliberate. A nil gate here is the
		// pre-Phase-2 daemon, not a refusal: the enforcement decision is inside
		// the injected function, which answers "no fence, no refusal" whenever
		// the token is unlatched or the flag is off.
		var termFence *corrosion.TermFence
		if r.leaseTermGate != nil {
			fence, reason, terr := r.leaseTermGate(ctx, pr)
			if terr != nil {
				slog.Warn("reconciler: pending proof refused by the lease-term gate",
					"vm", vm.Name, "proof", proofID, "reason", reason, "error", terr)
				r.noteGateRefused(corrosion.ActionReschedule, reason)
				return
			}
			termFence = fence
		}

		// Recovery claims, EXECUTE side (docs/design/recovery-claims.md §3.10):
		// after the exact-match and owner-epoch checks above and BEFORE the
		// claim. This is the check that makes two coordinators' reschedules
		// safe: each can write a well-formed proof into its own replica, and
		// only the one a majority of voters certified verifies here. A refusal
		// leaves the row pending, like every other gate refusal, so a
		// certificate whose voter generation or CRL has not replicated yet
		// verifies on a later tick.
		if r.recoveryClaimGate != nil {
			if reason, cerr := r.recoveryClaimGate(ctx, pr); cerr != nil {
				slog.Warn("reconciler: pending proof refused — no recovery-claim certificate verifies",
					"vm", vm.Name, "proof", proofID, "reason", reason, "error", cerr)
				r.noteGateRefused(corrosion.ActionReschedule, reason)
				return
			}
		}

		if err := corrosion.ClaimActionProofFenced(ctx, r.db, proofID, r.hostName, termFence); err != nil {
			if errors.Is(err, corrosion.ErrTermClaimantConflict) {
				// This host already acted at this (key, term) for a different
				// coordinator. Distinct from a spent proof: the proof is fine,
				// the CLAIMANT is the problem.
				slog.Warn("reconciler: this host has already acted at this lease term for another "+
					"coordinator — refusing start",
					"vm", vm.Name, "proof", proofID, "term", pr.LeaseTerm,
					"lease", pr.LeaseKey, "coordinator", pr.Coordinator)
				r.noteGateRefused(corrosion.ActionReschedule, ReasonStaleLeaseTerm)
				return
			}
			if errors.Is(err, corrosion.ErrProofSpent) {
				slog.Warn("reconciler: pending proof terminal/missing, refusing start",
					"vm", vm.Name, "proof", proofID)
				r.noteGateRefused(corrosion.ActionReschedule, ReasonProofTerminal)
				return
			}
			if errors.Is(err, corrosion.ErrProofAbandoned) {
				if r.awaitingStaleTermRepoint(ctx, vm.Name, proofID) {
					return
				}
				// Terminal, not transient: this host has promised never to run
				// the proof, and no later tick can change that. Fail the proof
				// so the row leaves pending instead of retrying every tick.
				slog.Warn("reconciler: this host abandoned the pending proof and will never execute it — not starting",
					"vm", vm.Name, "proof", proofID)
				r.noteGateRefused(corrosion.ActionReschedule, ReasonClaimLost)
				r.failPendingStart(ctx, vm.Name, proofID, false, "proof abandoned by this host")
				return
			}
			// Transient (proof row not yet visible / DB error): retry next tick.
			// The vm_lock is released by defer, so we don't tie it up while waiting.
			slog.Warn("reconciler: claim pending proof failed (transient), retrying",
				"vm", vm.Name, "proof", proofID, "error", err)
			return
		}
		if r.proofClaimedHook != nil {
			r.proofClaimedHook(ctx)
		}
	}

	slog.Info("reconciler: starting pending VM", "vm", vm.Name)

	// A volume move this host left unresolved points the disk row at the file
	// the persistent config names — read before the domain is undefined and
	// rebuilt from the rows below — or the start is refused
	// (move_unresolved.go). A domain already running is left to the branch
	// below.
	if r.virt == nil || !r.virt.DomainExists(vm.Name) || !domainRunningNow(r.virt, vm.Name) {
		dom := MoveDomain{InactiveXML: func() (string, error) { return "", errors.New("no libvirt backend") }}
		if r.virt != nil {
			dom = MoveDomain{
				InactiveXML: func() (string, error) { return r.virt.DumpXMLInactive(vm.Name) },
				State:       func() (string, error) { return r.virt.DomainState(vm.Name) },
			}
		}
		if merr := ResolveUnresolvedMoves(ctx, r.db, r.dataDir, r.hostName, vm.Name, dom); merr != nil {
			slog.Warn("reconciler: start refused — an unresolved volume move", "vm", vm.Name, "error", merr)
			if MoveUnresolvedRetryable(merr) {
				// Transient (a move in flight, a read that failed): the row is
				// left as it is and a later pass starts it again.
				if proofID != "" {
					r.failPendingStart(ctx, vm.Name, proofID, true, merr.Error())
				}
				return
			}
			r.failPendingStart(ctx, vm.Name, proofID, false, merr.Error())
			return
		}
	}
	// Check if a domain already exists locally from a partial migration (#14).
	if r.virt != nil && r.virt.DomainExists(vm.Name) {
		state, err := r.virt.DomainState(vm.Name)
		if err == nil && state == "running" {
			slog.Warn("reconciler: domain already running locally, updating state", "vm", vm.Name)
			// Not a start, but the guest ran here: the evidence an operator
			// judges a forked move history by (MoveStartsText).
			if eerr := NoteAdoptedRunning(ctx, r.db, r.hostName, vm.Name); eerr != nil {
				slog.Warn("reconciler: recording the running domain's adoption failed", "vm", vm.Name, "error", eerr)
			}
			// Idempotent retry: the domain is already up. Complete the proof
			// (single-use) + clear pending_action_id in one guarded mutation. Do NOT
			// downgrade to a plain running update on guard failure — that would bypass
			// the pointer/status preconditions and could strand pending_action_id. If
			// completion doesn't apply (proof already terminal / VM re-pointed), leave
			// the row: the domain is running, so the state reconciler converges it.
			if proofID != "" {
				// Routed: the completion MINTS (its second statement is
				// vm_owner_epoch = vm_owner_epoch + 1 under the same guard), and
				// before this it wrote no marker at all — a running VM at a fresh
				// generation that could not prove it until the next sweep.
				if cerr := r.publishRunningMinted(ctx, vm.Name, func(ctx context.Context) error {
					return corrosion.CompleteVMStartProof(ctx, r.db, proofID, vm.Name, r.hostName)
				}); cerr != nil {
					slog.Error("reconciler: complete start proof (already-running) did not apply — leaving state for reconcile",
						"vm", vm.Name, "proof", proofID, "error", cerr)
				}
			} else if err := r.publishRunning(ctx, vm.Name, "running", func(ctx context.Context) error {
				return corrosion.UpdateVMState(ctx, r.db, vm.Name, "running", "domain already present")
			}); err != nil {
				LogPublishRefusal("reconciler: already-present running-state write failed", vm.Name, err)
				r.noteStateWriteFail(corrosion.OpVMState, err)
			} else if fresh.State == "starting" {
				// A held start whose daemon restarted before libvirt
				// answered it: its outcome, recorded once, with this move
				// from starting (held_start_orphan.go).
				r.recordHeldStartRan(ctx, vm.Name, fresh.StateDetail)
			}
			r.clearOnbootPending(vm.Name) // onboot duty discharged
			return
		}
		// Domain exists but not running — destroy and redefine the SAME VM cleanly.
		// KEEP firmware state: the redefine below reuses the NVRAM/swtpm; wiping
		// here would break an SB/vTPM guest on the next start (G1).
		r.virt.DestroyDomain(vm.Name)
		r.virt.UndefineDomainPreservingState(vm.Name)
	}
	// A start this pass makes (a domain found running is not one).
	noteStartingHere(ctx, r.db, r.dataDir, vm.Name)

	// wroteStarting: this pass's own "starting" write landed, so a stop the
	// row says from here on was made while the start was under way (the
	// re-reads before the define and the boot, cancelledSinceStart). A failed
	// write leaves the row as it was, which for an onboot override is the
	// operator stop the boot starts over.
	wroteStarting := true
	if err := corrosion.UpdateVMState(ctx, r.db, vm.Name, "starting", "reconciler"); err != nil {
		wroteStarting = false
		slog.Error("reconciler: failover start-marker write failed", "vm", vm.Name, "error", err)
		r.noteStateWriteFail(corrosion.OpVMState, err)
	} else {
		// The start is past every gate and its row no longer carries the
		// stop: a host boot's override of an operator stop has done its
		// job, and a stop recorded from here on — even one identical to the
		// stop it overrode — is honoured (review M-1). Not when the write
		// failed: the row still reads as that stop, and the next retry
		// would drop the VM (review round 1, m-2).
		r.endOnbootOverride(vm.Name)
	}

	// Parse the stored spec to rebuild the domain XML.
	spec := &pb.VMSpec{}
	if vm.Spec != "" {
		if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
			slog.Error("reconciler: parse VM spec", "vm", vm.Name, "error", err)
			r.failPendingStart(ctx, vm.Name, proofID, false, "invalid spec JSON")
			return
		}
	}

	// Retrieve stored disk records to build disk config.
	diskRecords, err := corrosion.ListDisks(ctx, r.db, vm.Name)
	if err != nil {
		slog.Error("reconciler: list disks", "vm", vm.Name, "error", err)
		r.failPendingStart(ctx, vm.Name, proofID, true, fmt.Sprintf("list disks: %v", err)) // transient DB
		return
	}

	// Shared-disk split-brain gate: an ownership TRANSFER (a pending row carrying a
	// coordinator proof) of a VM with a writable SHARED disk (corrosion.
	// DiskOnSharedStorage: storage type nfs/ceph/rbd/iscsi, or a pool whose driver
	// is shared on the disk's host or this one — colonelpanik/litevirt#258) may
	// start only once the old owner is PROVEN powered off — carried in the proof's
	// fence_epoch and re-verified against the append-only fencing_log. A local-disk
	// transfer keeps the proof/quorum gate above (its disk is host-local; no
	// shared-write hazard). Fail closed once enforced; the kill-switch restores legacy.
	// host_name was re-pointed to this target, so we trust the proof-protected
	// fence_epoch.Host as the old owner (oldOwner "").
	//
	// "Shared" consults the pool rows of this host and of the old owner the
	// proof's fence names: the transfer re-pointed every disk row here, so
	// the disk's own row names this host.
	poolHosts := []string{r.hostName}
	if ref, ok := corrosion.ParseFenceEpoch(proofFenceEpoch); ok {
		poolHosts = append(poolHosts, ref.Host)
	}
	if proofID != "" && r.sharedStorageFenceEnforce && r.gate != nil &&
		r.gate.Enforced(ctx, capabilities.SharedStorageFenceV1) &&
		corrosion.VMHasSharedDisk(ctx, r.db, diskRecords, poolHosts...) {
		switch verdict, detail := corrosion.CheckProofGradeFence(ctx, r.db, proofFenceEpoch, "", corrosion.SharedDiskFenceWindow); verdict {
		case corrosion.FenceOK:
			// proof-grade fence verified — proceed.
		case corrosion.FenceRetry:
			// The fencing_log row rides the same replication as the proof; the proof was
			// already single-use-claimed, so re-mint on the next failover cycle if needed.
			slog.Warn("reconciler: shared-disk transfer fence not yet verifiable, retrying",
				"vm", vm.Name, "detail", detail)
			return
		default: // FenceReject
			slog.Error("reconciler: shared-disk transfer refused — no proof-grade fence of old owner (storage_unverified)",
				"vm", vm.Name, "detail", detail)
			r.noteGateRefused(corrosion.ActionReschedule, ReasonStorageUnverified)
			r.failPendingStart(ctx, vm.Name, proofID, false, "shared-disk transfer refused: "+detail)
			return
		}
	}

	// A shared disk whose row names another host — a partial promotion leaves
	// one naming the VM's old owner, which was not proven off — is attached
	// only once that host is proven powered off (review R4-I2): this start
	// builds the domain from every live row, and attaching it while that host
	// may still run its qemu is two writers on one disk. Such a disk is left
	// out and reported, never the whole start refused: main started the VM.
	_, withheld := corrosion.JudgeSharedDiskRows(ctx, r.db, diskRecords, r.hostName, func(d corrosion.DiskRecord) bool {
		return corrosion.DiskOnSharedStorage(ctx, r.db, d, r.hostName)
	})
	withheldDisk := map[string]bool{}
	for _, w := range withheld {
		withheldDisk[w.Disk.DiskName] = true
	}
	// A withheld boot disk (review m1): the VM would boot nothing, so the
	// start waits for the proof instead (a pending transfer retries; a local
	// start is left in error with the remedy, and `lv start` after the proof
	// builds it again).
	if boot, ok := corrosion.WithheldBootDisk(withheld); ok {
		detail := corrosion.WithheldSharedDiskDetail(vm.Name, r.hostName, withheld)
		r.reportSharedWithheld(ctx, vm.Name, detail)
		r.failPendingStart(ctx, vm.Name, proofID, true, fmt.Sprintf("not started: its boot disk %s is withheld; %s",
			boot.Disk.DiskName, detail))
		return
	}

	var attach []corrosion.DiskRecord
	for _, d := range diskRecords {
		if transfer {
			if _, err := r.setAsideSupersededDisk(ctx, vm.Name, proofID, d); err != nil {
				if storage.IsFSNoAnswer(err) {
					// Whether an old copy is at the path cannot be told:
					// nothing is renamed, and the start waits.
					r.deferStart(ctx, vm.Name, proofID, transfer, diskNoAnswer(d, err))
					return
				}
				r.failPendingStart(ctx, vm.Name, proofID, true,
					fmt.Sprintf("set aside the old copy of disk %s found at %s: %v", d.DiskName, d.Path, err))
				return
			}
		}
		// Verify disk file exists on this host. An rbd disk is no file: it is
		// in the cluster, not on a host, and is never rebuilt here — an
		// overlay "recreated" in its place would boot the VM on a blank copy
		// of its image.
		//
		// Bounded (disk_stat.go): a disk whose storage does not answer is
		// not missing — never refused as gone, never rebuilt — and does not
		// hold the pass: the start is deferred (lab 2 F-3).
		var statErr error
		if !isNetworkDiskPath(d.Path) {
			_, statErr = r.statDisk(d.Path)
		}
		if storage.IsFSNoAnswer(statErr) {
			slog.Warn("reconciler: a disk's storage does not answer; the start waits",
				"vm", vm.Name, "disk", d.DiskName, "path", d.Path, "error", statErr)
			r.deferStart(ctx, vm.Name, proofID, transfer, diskNoAnswer(d, statErr))
			return
		}
		if statErr != nil {
			if !transfer {
				// A local start of a VM whose disk is gone: never rebuilt
				// blank (missing_disk.go).
				r.refuseLocalStartWithoutDisk(ctx, vm.Name, d)
				return
			}
			// If disk has a backing image, try auto-pulling it and recreating the overlay.
			if d.BackingImage != "" && r.autoPullImage != nil {
				slog.Info("reconciler: disk missing, attempting auto-pull of backing image",
					"vm", vm.Name, "disk", d.DiskName, "image", d.BackingImage)
				if pullErr := r.pullBackingImage(ctx, d.BackingImage); pullErr != nil {
					if errors.Is(pullErr, errImagePullInProgress) {
						// The walk's budget ran out first. The transfer is still
						// running in the background; hand the VM back to pending
						// so a later pass — one that finds the image present —
						// finishes the start. Not a failure, so not
						// failPendingStart: a legacy (proof-less) VM would be
						// parked in error for a transfer that is going fine.
						slog.Info("reconciler: backing image still transferring; the start resumes on a later pass",
							"vm", vm.Name, "disk", d.DiskName, "image", d.BackingImage)
						if proofID == "" {
							r.deferredTransfers.add(vm.Name)
						}
						r.deferPendingStart(ctx, vm.Name, proofID,
							fmt.Sprintf("waiting for backing image %s to finish transferring", d.BackingImage))
						return
					}
					slog.Error("reconciler: auto-pull failed", "vm", vm.Name, "image", d.BackingImage, "error", pullErr)
					// Transient — a peer may return — unless the image itself
					// was refused as corrupt: every copy of it is the same
					// bytes, so a retry can only be refused again.
					r.failPendingStart(ctx, vm.Name, proofID, !qcow2.IsMisaligned(pullErr),
						fmt.Sprintf("disk %s not found and image auto-pull failed: %v", d.DiskName, pullErr))
					return
				}
				// Recreate overlay disk from pulled image, at the disk's
				// recorded size: left empty, the overlay inherits the backing
				// image's virtual size (a 20 GiB root came back at 112 MiB).
				// A row with no recorded size still inherits it.
				size := ""
				if d.SizeBytes > 0 {
					size = strconv.FormatInt(d.SizeBytes, 10)
				}
				recreate := r.recreateOverlay
				if recreate == nil {
					recreate = image.NewStore(r.dataDir).CreateOverlayDisk
				}
				newPath, createErr := recreate(vm.Name, d.DiskName, d.BackingImage, size)
				if createErr != nil {
					slog.Error("reconciler: recreate overlay failed", "vm", vm.Name, "error", createErr)
					// Transient — retry the overlay build — unless the base
					// image is one qemu refuses as corrupt: no retry mends it.
					r.failPendingStart(ctx, vm.Name, proofID, !qcow2.IsMisaligned(createErr),
						fmt.Sprintf("recreate disk %s: %v", d.DiskName, createErr))
					return
				}
				d.Path = newPath
				r.transferDisks.note(newPath, proofID)
				slog.Info("reconciler: recreated overlay disk", "vm", vm.Name, "disk", d.DiskName, "path", newPath)
			} else {
				slog.Error("reconciler: disk not found", "vm", vm.Name, "disk", d.DiskName, "path", d.Path)
				r.failPendingStart(ctx, vm.Name, proofID, false, // non-retryable: no source to rebuild from
					fmt.Sprintf("disk %s not found at %s (no backing image for auto-pull)", d.DiskName, d.Path))
				return
			}
		}
		if withheldDisk[d.DiskName] {
			// Checked for presence like every disk (a missing one refuses
			// the start, as on main), but not attached.
			continue
		}
		attach = append(attach, d)
	}
	diskConfigs := failoverDiskConfigs(spec, attach)
	// Every disk is in place: a parked transfer has done its rebuilding.
	r.deferredTransfers.drop(vm.Name)

	// The PCI passthrough the domain is built with, claimed on this host
	// (passthrough_rebuild.go). A VM this host has no devices for is not
	// started, rather than started without them; what was claimed is given
	// back by every return below that does not start it.
	pt, ptErr := r.rebuildPassthrough(ctx, fresh)
	if ptErr != nil {
		slog.Warn("reconciler: PCI passthrough not available here — not starting VM", "vm", vm.Name, "error", ptErr)
		r.noteGateRefused(corrosion.ActionReschedule, ReasonHardwareBlocked)
		r.failPendingStart(ctx, vm.Name, proofID, hwPrepareRetryable(ptErr), fmt.Sprintf("PCI passthrough: %v", ptErr))
		return
	}
	ptStarted := false
	defer func() { pt.done(ptStarted) }()
	if pt.Dropped != "" {
		ctx = WithPassthroughDropped(ctx)
	}

	domXML, retryable, failure := r.domainXMLWith(ctx, vm, spec, diskConfigs, pt.Addresses)
	if failure != "" {
		r.failPendingStart(ctx, vm.Name, proofID, retryable, failure)
		return
	}

	// The start checkpoint, before anything is defined or started: appended only
	// if this host has not abandoned the proof, decided in one transaction
	// (docs/design/recovery-claims.md §3.12, §10 item 37). The start lease is not
	// what keeps an operator release (`lv cluster claim-release`) from racing
	// this start — it can expire under a start that runs past vmLockTTL — the
	// database is: a release before this point makes it refuse, and one after it
	// refuses the proof for the recorded step. A re-driven start appends nothing.
	if proofID != "" {
		if err := corrosion.AppendProofStepUnlessAbandoned(ctx, r.db, proofID, "start_attempted"); err != nil {
			if errors.Is(err, corrosion.ErrProofAbandoned) {
				slog.Warn("reconciler: this host abandoned the pending proof and will never execute it — not starting",
					"vm", vm.Name, "proof", proofID)
				r.noteGateRefused(corrosion.ActionReschedule, ReasonClaimLost)
				r.failPendingStart(ctx, vm.Name, proofID, false, "proof abandoned by this host")
				return
			}
			slog.Warn("reconciler: record the start checkpoint failed (transient), retrying",
				"vm", vm.Name, "proof", proofID, "error", err)
			r.failPendingStart(ctx, vm.Name, proofID, true, fmt.Sprintf("start checkpoint: %v", err))
			return
		}
	}

	// After the start checkpoint (a host that abandoned the proof has
	// returned above): settle any point-in-time overlay into the disk before
	// the domain is defined on it.
	failure, deferred := r.settlePITOverlays(ctx, vm, spec, diskConfigs)
	if deferred != nil {
		// Not a failure: the disk's storage did not answer. Re-driven next
		// pass — never parked in error, as the hardware pre-start's
		// deferral below.
		r.deferStart(ctx, vm.Name, proofID, transfer, deferred)
		return
	}
	if failure != "" {
		r.failPendingStart(ctx, vm.Name, proofID, true, failure)
		return
	}

	// Whether this VM's UEFI vars were here before this pass defined its
	// domain: vars a boot creates for a since-deleted record are this pass's
	// own to remove (start_row_gone.go).
	nvramBefore := nvramExists(r.fwStore, vm.Name)

	// A start the operator cancelled meanwhile (`lv stop --force`) is not
	// made: the start lease can run out under a slow start (vmLockTTL),
	// so the cancel may have run inside this one.
	if r.cancelledSinceStart(ctx, vm, wroteStarting) {
		slog.Warn("reconciler: not defining the VM — its start was cancelled while it was being made", "vm", vm.Name)
		return
	}

	// Define and start the domain.
	if err := r.virt.DefineDomain(domXML); err != nil {
		slog.Error("reconciler: define domain", "vm", vm.Name, "error", err)
		r.failPendingStart(ctx, vm.Name, proofID, true, fmt.Sprintf("define: %v", err)) // transient libvirt
		return
	}

	// hardware_v2 pre-start (adoption gate + PCI start-preflight), between DefineDomain
	// and StartDomain — the disk/nic rows this failover acts on already exist (replicated),
	// so the preflight's reconcile-from-authoritative-tables step patches the just-defined
	// domain with the aliased <hostdev>s and binds the passthrough BEFORE it boots. A strict
	// no-op unless hardware_v2 is latched (so a pre-latch failover is byte-for-behavior
	// unchanged). A refusal is NON-FATAL: a blocked VM / unacquirable device (FailedPrecondition)
	// is a non-retryable operator-repair condition → terminalize the proof + set the VM error;
	// a transient read/DB failure (Internal/Unavailable) re-arms for the next reconcile tick.
	// domainXMLFor above has tried the VM's own seed for this start: the
	// hook does not try it again (one failure, one warning).
	releaseHW, hwErr := r.hwPrepareStart(cloudinit.WithSeedTriedForStart(ctx), fresh)
	if hwErr != nil && errors.Is(hwErr, ErrStartDeferred) {
		// Not a failure: storage did not answer, or there was no time left
		// to ask it. Re-driven next pass — never parked in error.
		r.deferStart(ctx, vm.Name, proofID, transfer, hwErr)
		return
	}
	if hwErr != nil {
		slog.Warn("reconciler: hardware pre-start refused/failed — not starting VM", "vm", vm.Name, "error", hwErr)
		r.noteGateRefused(corrosion.ActionReschedule, hwRefusalReason(hwErr))
		r.failPendingStart(ctx, vm.Name, proofID, hwPrepareRetryable(hwErr), fmt.Sprintf("hardware pre-start: %v", hwErr))
		return
	}
	// Spare root ports last: the pre-start above may have patched hostdevs
	// in, and libvirt places those on any free port, spares included.
	r.ensureSparePCIeRootPorts(vm.Name)

	if r.startDomainHook != nil {
		r.startDomainHook(ctx)
	}
	// The row this start was decided from must still be this host's at the
	// moment the domain boots: a delete can tombstone it in the window above
	// by replication, without this host's start lease (start_row_gone.go).
	// What this pass defined is its own, so it is taken back, firmware state
	// kept. A row merely unreadable is transient and is retried next pass,
	// never parked in error: a proof-gated start is re-armed to pending
	// (failPendingStart, retryable), and a proof-less one — self-heal,
	// onboot, whose failPendingStart would write "error", a state no pass
	// re-drives — writes nothing, since its row already reads "starting" and
	// the walk's starting case re-drives it. The read is local and is not
	// cut short by the walk budget: a pass whose budget ran out here still
	// starts the VM, as it did before this check.
	if why, unreadable := r.startRowGone(context.WithoutCancel(ctx), vm.Name, fresh.CreatedAt); why != "" {
		releaseHW()
		slog.Warn("reconciler: not starting the VM — "+why, "vm", vm.Name)
		if err := r.virt.UndefineDomainPreservingState(vm.Name); err != nil {
			slog.Warn("reconciler: could not take back the definition of a VM not started", "vm", vm.Name, "error", err)
		}
		if unreadable && proofID != "" {
			r.failPendingStart(ctx, vm.Name, proofID, true, "not started: "+why)
		}
		return
	}
	// Again just before the boot: what this pass defined is taken back,
	// firmware state kept, so the VM is as the cancel found it.
	if r.cancelledSinceStart(ctx, vm, wroteStarting) {
		releaseHW()
		slog.Warn("reconciler: not starting the VM — its start was cancelled while it was being made", "vm", vm.Name)
		if err := r.virt.UndefineDomainPreservingState(vm.Name); err != nil {
			slog.Warn("reconciler: could not take back the definition of a VM not started", "vm", vm.Name, "error", err)
		}
		return
	}
	// A shared disk this host released to another (review c2b) is never
	// started here again unjudged.
	releaseGuard, gerr := GuardSharedDiskStart(ctx, r.db, r.dataDir, r.hostName, vm.Name, domXML)
	if gerr != nil {
		releaseHW()
		slog.Warn("reconciler: start refused — a shared disk this host released", "vm", vm.Name, "error", gerr)
		r.failPendingStart(ctx, vm.Name, proofID, false, gerr.Error())
		return
	}
	startErr := r.virt.StartDomain(vm.Name)
	releaseGuard()
	if err := startErr; err != nil {
		releaseHW() // release any passthrough the preflight bound for this failed start
		slog.Error("reconciler: start domain", "vm", vm.Name, "error", err)
		r.failPendingStart(ctx, vm.Name, proofID, true, fmt.Sprintf("start: %v", err)) // transient libvirt
		return
	}
	ptStarted = true
	// The guest is booting: the healthcheck's start grace runs from now (every
	// reconciler start — failover, reschedule, onboot — comes through here).
	if r.vmStartObserver != nil {
		r.vmStartObserver.NoteVMStarted(vm.Name)
	}

	// Success. When a proof authorized this start, mark it completed AND move the
	// VM to running + clear pending_action_id in ONE guarded mutation (crash can't
	// desync state and pointer; the terminal proof makes a duplicate start a no-op).
	// Do NOT downgrade to a plain running update if the guard doesn't apply — that
	// would bypass the pointer/status preconditions. If CompleteVMStartProof fails
	// (DB error / guard didn't apply), the VM is left in "starting" with the proof
	// still in_progress — NOT stranded: the reconcile "starting" case re-drives
	// startPendingVM, whose already-running-domain branch retries CompleteVMStartProof
	// until it lands (the marker safely blocks any re-start meanwhile).
	// StartDomain is not context-bound, so past this line the GUEST IS RUNNING
	// whatever the walk budget says. Recording that is no longer optional work
	// the caller may cancel: a running guest whose row still reads "starting"
	// is a VM the cluster cannot account for, and the reconcile retry only
	// converges it a tick later — after the budget has already cost the lease.
	commitCtx := context.WithoutCancel(ctx)
	// The boot and a replicated tombstone cannot be ordered: look before
	// anything is published — a running write must not land on a row of
	// the name created since — and once more after (start_row_gone.go).
	if r.startedForGoneRow(commitCtx, *fresh, len(diskConfigs), releaseHW, nvramBefore) {
		return
	}
	if proofID != "" {
		// Routed through the minting chokepoint, which IS the hand-rolled
		// write-through this block used to carry — same ordering, one
		// implementation, and it gains the typed-nil guard and the
		// ownership-moved check the hand-rolled version did not have.
		if err := r.publishRunningMinted(commitCtx, vm.Name, func(ctx context.Context) error {
			return corrosion.CompleteVMStartProof(ctx, r.db, proofID, vm.Name, r.hostName)
		}); err != nil {
			slog.Error("reconciler: complete start proof did not apply after start — leaving 'starting' for the reconcile starting-case to retry",
				"vm", vm.Name, "proof", proofID, "error", err)
		}
	} else if err := r.publishRunning(commitCtx, vm.Name, "running", func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, r.db, vm.Name, "running", r.startedDetail(ctx, vm))
	}); err != nil {
		LogPublishRefusal("reconciler: post-failover running-state write failed", vm.Name, err)
		r.noteStateWriteFail(corrosion.OpVMState, err)
	}
	r.clearOnbootPending(vm.Name) // onboot duty discharged
	if r.startedForGoneRow(commitCtx, *fresh, len(diskConfigs), releaseHW, nvramBefore) {
		return
	}
	r.reportSharedWithheld(commitCtx, vm.Name, corrosion.WithheldSharedDiskDetail(vm.Name, r.hostName, withheld))
	if pt.Dropped != "" {
		r.reportPassthroughDropped(commitCtx, vm.Name, pt.Dropped)
	}
	slog.Info("reconciler: VM started successfully", "vm", vm.Name)

	// Notify LB to refresh backends now that this VM is running.
	if r.onVMStarted != nil && vm.StackName != "" {
		go r.onVMStarted(context.Background(), vm.StackName)
	}
}

// SetSharedDiskWithheldReporter wires the report of a VM whose domain was
// built without a shared disk whose row names a host not proven off, and of
// one built withholding none (grpcapi.Server.ReportSharedDiskWithheld and
// ClearSharedDiskWithheld: a durable per-VM health condition shown by
// `lv inspect`, notified when it is raised or changes).
func (r *Reconciler) SetSharedDiskWithheldReporter(held func(ctx context.Context, vm, detail string), cleared func(ctx context.Context, vm string)) {
	r.sharedWithheldReport, r.sharedWithheldClear = held, cleared
}

// reportSharedWithheld reports detail (corrosion.WithheldSharedDiskDetail)
// for vm through the wired reporter, or clears it when detail is "". Without
// a reporter (a bare reconciler) it logs and records the event once per VM.
func (r *Reconciler) reportSharedWithheld(ctx context.Context, vm, detail string) {
	if detail == "" {
		r.sharedWithheldReported.Delete(vm)
		if r.sharedWithheldClear != nil {
			r.sharedWithheldClear(ctx, vm)
		}
		return
	}
	if r.sharedWithheldReport != nil {
		r.sharedWithheldReport(ctx, vm, detail)
		return
	}
	if _, done := r.sharedWithheldReported.LoadOrStore(vm, true); done {
		return
	}
	slog.Error("reconciler: "+detail, "vm", vm)
	_ = corrosion.InsertVMEvent(ctx, r.db, corrosion.VMEventRecord{
		ID: randid.New(), VMName: vm, HostName: r.hostName, Type: "vm.shared_disk_withheld",
		Result: "error", Severity: "error", Detail: detail, Username: "reconciler",
	})
}

// SetPITOverlayReporter wires the report of a VM the define path holds on an
// overlay it cannot verify, and of a disk whose hold has cleared
// (grpcapi.Server.ReportPITOverlayHeld and ClearPITOverlayHold: a durable,
// per-disk health condition, notified once and then at most daily).
func (r *Reconciler) SetPITOverlayReporter(held func(ctx context.Context, vm, disk, detail string), cleared func(ctx context.Context, vm, disk string)) {
	r.pitReport, r.pitCleared = held, cleared
}

// SetPITOverlayFeature wires this host's pit_overlay release-feature gate
// (grpcapi.Server.PITOverlayFeature). Below it the define path settles no
// overlay: a VM with one is held. Unwired, it is closed.
func (r *Reconciler) SetPITOverlayFeature(g pitoverlay.Gate) { r.pitFeature = g }

// settlePITOverlays settles each disk's point-in-time copy overlay
// (pitoverlay) before the domain is defined on the disk: a copy whose commit
// failed, or whose host died mid-window, left the guest's newest writes in it
// — on a shared pool it travels here with the disk — and the definition names
// only the disk. An overlay bound to this VM's disk as the file is now is
// committed offline (no -U: a qemu still holding it fails this closed); one
// already merged is removed. Any other cannot be verified, so the VM is
// HELD: not defined or started on the bare disk, which would drop the
// overlay's writes; the hold says what an admin should do for its verdict
// (lv resolve-pit-overlay). Nothing replicated records an overlay; its fixed
// name beside the disk is what finds it. A failure is the start's failure,
// retried; a disk settled or without an overlay clears its hold.
//
// A disk whose storage does not answer whether an overlay is there (lab 2
// N-4) is not a failure: deferred is then set (it errors.Is
// ErrStartDeferred), with failure saying why, and the caller defers the
// start (deferStart) — a proof-less start (onboot, self-heal) waits in
// "starting", which the next pass re-drives, instead of being parked in
// error. The pass is not held by it.
func (r *Reconciler) settlePITOverlays(ctx context.Context, vm corrosion.VMRecord, spec *pb.VMSpec, diskConfigs []lv.DiskConfig) (failure string, deferred error) {
	for _, dc := range diskConfigs {
		owner := pitoverlay.Owner{VM: vm.Name, VMUUID: spec.GetUuid(), Disk: dc.Name}
		// Looked for under a bound first: on storage that does not answer
		// whether an overlay is there is unknown, never "none".
		presence, perr := pitoverlay.PresenceOfBounded(dc.Path)
		if storage.IsFSNoAnswer(perr) {
			slog.Warn("reconciler: a disk's storage does not answer; whether it has a point-in-time overlay cannot be told, so the start waits",
				"vm", vm.Name, "disk", dc.Name, "error", perr)
			why := fmt.Sprintf("disk %s: whether a point-in-time overlay %s holds writes the disk lacks cannot be told: its storage does not answer: %v",
				dc.Name, pitoverlay.Path(dc.Path), perr)
			return why, fmt.Errorf("%w: %s", ErrStartProbeFailed, why)
		}
		// Established absent (overlay and binding ENOENT): nothing to settle,
		// and no second, unbounded look (Settle's own lstat).
		if presence != pitoverlay.OverlayAbsent {
			out, err := pitoverlay.Settle(ctx, r.pitFeature, dc.Path, owner)
			switch {
			case out == pitoverlay.Held:
				detail := pitoverlay.HoldDetail(vm.Name, dc.Name, dc.Path, pitoverlay.AssessAt(r.pitFeature, dc.Path, owner, false))
				r.reportPITHeld(ctx, vm.Name, dc.Name, detail)
				return detail, nil
			case err != nil:
				slog.Error("reconciler: a point-in-time overlay holds writes the disk lacks and could not be committed; not defining the VM",
					"vm", vm.Name, "disk", dc.Name, "overlay", pitoverlay.Path(dc.Path), "error", err)
				return fmt.Sprintf("disk %s: commit its point-in-time overlay %s: %v", dc.Name, pitoverlay.Path(dc.Path), err), nil
			case out == pitoverlay.Committed:
				slog.Warn("reconciler: committed a point-in-time overlay into the disk before defining the VM",
					"vm", vm.Name, "disk", dc.Name, "overlay", pitoverlay.Path(dc.Path))
			}
		}
		// A disk this host cannot see (a shared pool not mounted here) reads
		// as "no overlay" too: only a disk that is here clears a hold.
		_, serr := storage.Bounded("stat", dc.Path, func() (os.FileInfo, error) { return os.Stat(dc.Path) })
		if serr == nil && r.pitCleared != nil {
			r.pitCleared(ctx, vm.Name, dc.Name)
		}
	}
	return "", nil
}

// reportPITHeld reports a hold through the wired reporter, which keeps it as
// a durable condition and decides when to notify. Without one (a bare
// reconciler) it records the event once per (VM, disk) for as long as this
// process runs: the start is retried every pass.
func (r *Reconciler) reportPITHeld(ctx context.Context, vm, disk, detail string) {
	if r.pitReport != nil {
		r.pitReport(ctx, vm, disk, detail)
		return
	}
	key := vm + "\x00" + disk
	if _, done := r.pitHeldReported.LoadOrStore(key, true); done {
		return
	}
	slog.Error("reconciler: "+detail, "vm", vm)
	_ = corrosion.InsertVMEvent(ctx, r.db, corrosion.VMEventRecord{
		ID: randid.New(), VMName: vm, HostName: r.hostName, Type: "disk.pit_overlay_held",
		Result: "error", Severity: "error", Detail: detail, Username: "reconciler",
	})
}

// seedClaim is what this host knows of vm for cloudinit.OwnSeed: its spec
// and the domain definition of its name here, if any, read-only. A definition
// that cannot be read attaches nothing.
func (r *Reconciler) seedClaim(vm corrosion.VMRecord, spec *pb.VMSpec) cloudinit.SeedClaim {
	return cloudinit.SeedClaim{VMName: vm.Name, UUID: cloudinit.SpecUUID(vm.Spec),
		CloudInit: cloudinit.SpecHasCloudInit(spec), UserData: cloudinit.SpecUserData(spec), DomainXML: func() string {
			if !r.virt.DomainExists(vm.Name) {
				return ""
			}
			x, err := r.virt.DumpXMLInactive(vm.Name)
			if err != nil {
				return ""
			}
			return x
		}}
}

// refreshOwnSeed brings the VM's own seed at iso up to date before a start
// here. It may be a copy this host kept while the VM ran elsewhere (a
// failover leaves it, and nothing removes it when the host rejoins), which
// NICs attached or detached since are not in, and a guest applies a seed's
// network-config on every boot: its network-config and vendor-data are
// derived again from the VM's NICs, each NIC keeping its name, and its
// meta-data (the instance-id) and user-data are kept byte for byte. Where the
// VM's NICs cannot be told from its spec the seed is kept as it is. The VM
// starts on the seed whatever happens here: a seed that cannot be read, or
// whose network-config cannot be derived or rewritten, is used as it is, with
// a seed.rebuild_failed warning naming it and the seed marked stale
// (cloudinit.MarkSeedStale) until a rebuild succeeds.
func (r *Reconciler) refreshOwnSeed(ctx context.Context, vm corrosion.VMRecord, spec *pb.VMSpec, iso string) {
	warn := func(cause error) {
		if merr := cloudinit.MarkSeedStale(iso); merr != nil {
			slog.Warn("reconciler: could not mark the VM's cloud-init seed stale", "vm", vm.Name, "seed", iso, "error", merr)
		}
		detail := fmt.Sprintf("the VM's seed at %s on %s could not be brought up to date with its NICs: %v; the VM starts on it as it is, so a NIC attached or detached since the seed was written may lose its configuration in the guest at this boot; the next start or NIC attach or detach of the VM on %s tries again", iso, r.hostName, cause, r.hostName)
		slog.Warn("reconciler: "+detail, "vm", vm.Name)
		_ = corrosion.InsertVMEvent(ctx, r.db, corrosion.VMEventRecord{
			ID: randid.New(), VMName: vm.Name, HostName: r.hostName, Type: "seed.rebuild_failed",
			Result: "error", Severity: "warning", Detail: detail, Username: "reconciler",
		})
	}
	cur, err := cloudinit.ReadSeed(iso)
	if err == nil && cur.InstanceID() == "" {
		err = errors.New("the seed names no instance-id")
	}
	if err != nil {
		warn(fmt.Errorf("read it: %w", err))
		return
	}
	prior := cloudinit.PriorFrom(cur.NetworkConfig)
	prior.Stale = !r.seedIsCurrent(ctx, vm.Name, iso)
	nc, err := cloudinit.SeedNetworkConfig(ctx, r.db, vm.Name, spec, prior)
	if errors.Is(err, cloudinit.ErrNICsAmbiguous) {
		detail := fmt.Sprintf("the seed on %s keeps its network-config as it is: %v (the spec of a VM created before it recorded NIC MACs); configure changed NICs in the guest", r.hostName, err)
		slog.Warn("reconciler: "+detail, "vm", vm.Name)
		_ = corrosion.InsertVMEvent(ctx, r.db, corrosion.VMEventRecord{
			ID: randid.New(), VMName: vm.Name, HostName: r.hostName, Type: "seed.not_rebuilt",
			Result: "ok", Severity: "warning", Detail: detail, Username: "reconciler",
		})
		return
	}
	changed := false
	if err == nil {
		if r.seedRefreshRaced != nil {
			r.seedRefreshRaced()
		}
		changed, err = cloudinit.RebuildISO(iso, nc, cloudinit.SeedVendorData(spec, nc))
	}
	if err != nil {
		warn(err)
		return
	}
	// The start holds its lease, not the VM lock an attach or detach holds:
	// one can commit while this refresh runs, and this rewrite can land after
	// its own. Derived again, a NIC set that moved keeps the seed marked
	// stale, so the next start or attach or detach rewrites it.
	if again, aerr := cloudinit.SeedNetworkConfig(ctx, r.db, vm.Name, spec, prior); aerr != nil || again != nc {
		if merr := cloudinit.MarkSeedStale(iso); merr != nil {
			slog.Warn("reconciler: could not mark the VM's cloud-init seed stale", "vm", vm.Name, "seed", iso, "error", merr)
		}
	}
	if changed {
		slog.Info("reconciler: the VM's cloud-init seed here takes its current NICs", "vm", vm.Name, "seed", iso)
	}
}

// seedIsCurrent reports whether the VM's seed at iso on this host is the one
// it runs on here, not a copy kept from an earlier stay: the VM's domain
// definition here attaches it and has exactly the VM's live NICs (an attach
// or detach on this host changes both, and rebuilds the seed with them), and
// no rebuild of it has failed since the last that succeeded (a failed one
// leaves the domain with NICs the seed does not list: MarkSeedStale). A
// current seed's names are complete: a NIC it does not list was never named,
// such as one an earlier release attached.
func (r *Reconciler) seedIsCurrent(ctx context.Context, vmName, iso string) bool {
	if r.virt == nil || cloudinit.SeedMarkedStale(iso) || !r.virt.DomainExists(vmName) {
		return false
	}
	x, err := r.virt.DumpXMLInactive(vmName)
	if err != nil || !lv.DomainAttachesCDROM(x, iso) {
		return false
	}
	rows, err := corrosion.MergedVMNICs(ctx, r.db, vmName)
	if err != nil {
		return false
	}
	var d struct {
		Interfaces []struct {
			MAC struct {
				Address string `xml:"address,attr"`
			} `xml:"mac"`
		} `xml:"devices>interface"`
	}
	if xml.Unmarshal([]byte(x), &d) != nil || len(d.Interfaces) != len(rows) {
		return false
	}
	have := map[string]bool{}
	for _, i := range d.Interfaces {
		have[strings.ToLower(strings.TrimSpace(i.MAC.Address))] = true
	}
	for _, row := range rows {
		if !have[strings.ToLower(row.MAC)] {
			return false
		}
	}
	return true
}

// domainXMLFor builds vm's domain XML on this host from its stored spec and
// the disk configs the caller resolved: the cloud-init ISO, the networks
// (provisioned here), firmware and resources. On failure it returns "" with
// whether a later attempt may succeed and what failed.
func (r *Reconciler) domainXMLFor(ctx context.Context, vm corrosion.VMRecord, spec *pb.VMSpec, diskConfigs []lv.DiskConfig) (domXML string, retryable bool, failure string) {
	return r.domainXMLWith(ctx, vm, spec, diskConfigs, nil)
}

// domainXMLWith is domainXMLFor with the PCI devices, at pciAddrs on this
// host, that the domain passes through (passthrough_rebuild.go).
func (r *Reconciler) domainXMLWith(ctx context.Context, vm corrosion.VMRecord, spec *pb.VMSpec, diskConfigs []lv.DiskConfig, pciAddrs []string) (domXML string, retryable bool, failure string) {
	// Check for cloud-init ISO. The reconciler acts on a stored (possibly
	// peer-replicated) row, so build the ISO path through the validated builder
	// — a malformed vm.Name must not escape the cloudinit dir.
	cloudInitISO := ""
	isoPath, isoErr := lv.SafeCloudInitISOPath(r.dataDir, vm.Name)
	if isoErr != nil {
		slog.Error("reconciler: invalid vm name for cloud-init path", "vm", vm.Name, "error", isoErr)
		return "", false, fmt.Sprintf("invalid name: %v", isoErr) // non-retryable
	}
	// A seed here is reused only when it is this VM's: one left by a deleted
	// VM of the name would boot its user-data (cloudinit/seed_owner.go). A VM
	// whose spec has no cloud-init gets no seed at all, stamped or not: no
	// create or clone writes one for it, so any file at its path is another
	// VM's, or a copy a migration made of one.
	seedOwner := cloudinit.SpecUUID(vm.Spec)
	hasCloudInit := cloudinit.SpecHasCloudInit(spec)
	if hasCloudInit && cloudinit.SeedIsFor(isoPath, seedOwner) {
		r.refreshOwnSeed(ctx, vm, spec, isoPath)
		cloudInitISO = isoPath
	} else if hasCloudInit {
		// Regenerate the seed the VM was created with: its user-data, and
		// the network-config derived from the spec, its NIC rows and its
		// networks exactly as CreateVM derived it (a cloud image with no
		// cloud-init in its spec got the empty user-data). A read that fails
		// writes no seed — one written without its network-config would be
		// kept by every later pass — and the start is retried.
		userData := ""
		if spec.CloudInit != nil {
			userData = spec.CloudInit.Userdata
		}
		if userData == "" {
			userData = "#cloud-config\n{}\n"
		}
		// The NICs' guest names: those the VM's own seed here gives, which a
		// copy kept while the VM ran elsewhere may predate (Stale); with no
		// seed of the VM's, those its NIC records give (cloudinit.Prior).
		var prior *cloudinit.Prior
		if own, ok, _ := cloudinit.OwnSeed(isoPath, r.seedClaim(vm, spec)); ok {
			prior = cloudinit.PriorFrom(own.NetworkConfig)
			prior.Stale = !r.seedIsCurrent(ctx, vm.Name, isoPath)
		}
		netCfg, ncErr := cloudinit.SeedNetworkConfig(ctx, r.db, vm.Name, spec, prior)
		vendorData := cloudinit.SeedVendorData(spec, netCfg)
		if errors.Is(ncErr, cloudinit.ErrNICsAmbiguous) {
			// No network-config litevirt can derive. The VM's own seed here
			// keeps its network-config and vendor-data; with none, the seed
			// disables network rendering and turns the per-boot re-render off,
			// so a guest that recorded the update events earlier keeps the
			// network it has rather than rendering cloud-init's fallback.
			var detail string
			if own, ok, _ := cloudinit.OwnSeed(isoPath, r.seedClaim(vm, spec)); ok {
				netCfg, vendorData = own.NetworkConfig, own.VendorData
				detail = fmt.Sprintf("the seed written on %s keeps the network-config of the VM's seed there: %v (the spec of a VM created before it recorded NIC MACs); configure changed NICs in the guest", r.hostName, ncErr)
			} else {
				netCfg, vendorData = cloudinit.NetworkConfigDisabled, cloudinit.NetworkUpdatesOffVendorData
				detail = fmt.Sprintf("the seed written on %s has cloud-init leave the guest's network as it is: %v (the spec of a VM created before it recorded NIC MACs); configure the VM's NICs in the guest", r.hostName, ncErr)
			}
			slog.Warn("reconciler: "+detail, "vm", vm.Name)
			_ = corrosion.InsertVMEvent(ctx, r.db, corrosion.VMEventRecord{
				ID: randid.New(), VMName: vm.Name, HostName: r.hostName, Type: "seed.not_rebuilt",
				Result: "ok", Severity: "warning", Detail: detail, Username: "reconciler",
			})
			ncErr = nil
		}
		if ncErr != nil {
			slog.Warn("reconciler: cloud-init network-config could not be derived", "vm", vm.Name, "error", ncErr)
			return "", true, fmt.Sprintf("derive cloud-init network-config: %v", ncErr) // transient DB
		}
		if genErr := cloudinit.GenerateISO(cloudinit.Config{
			InstanceID:    vm.Name,
			LocalHostname: vm.Name,
			UserData:      userData,
			NetworkConfig: netCfg,
			VendorData:    vendorData,
		}, isoPath); genErr != nil {
			slog.Warn("reconciler: cloud-init ISO generation failed", "vm", vm.Name, "error", genErr)
		} else {
			cloudInitISO = isoPath
		}
	}
	if cloudInitISO != "" {
		if err := cloudinit.StampSeed(cloudInitISO, seedOwner); err != nil {
			slog.Warn("reconciler: could not stamp the cloud-init seed with its VM", "vm", vm.Name, "error", err)
		}
	}

	// Provision networks and build network configs from the VM's live NICs:
	// the vm_nics/vm_interfaces overlay, which carries a hot-attached NIC and
	// drops a detached one on every cluster (a hardware_v2 cluster writes both
	// to vm_nics alone).
	// A query failure must NOT be swallowed: starting the VM with zero NICs
	// brings it up headless (no network) after a failover. Fail it instead,
	// matching the ListDisks error handling above.
	ifaces, err := corrosion.MergedVMNICs(ctx, r.db, vm.Name)
	if err != nil {
		slog.Error("reconciler: get VM interfaces", "vm", vm.Name, "error", err)
		return "", true, fmt.Sprintf("get interfaces: %v", err) // transient DB
	}
	rowModels, reattached, err := corrosion.NICModelSources(ctx, r.db, vm.Name, ifaces, compose.SpecNICModelsByMAC(spec))
	if err != nil {
		slog.Error("reconciler: get VM NIC models", "vm", vm.Name, "error", err)
		return "", true, fmt.Sprintf("get NIC models: %v", err) // transient DB
	}
	nicModels := compose.NewNICModels(spec, rowModels, reattached)
	var netConfigs []lv.NetworkConfig
	for _, iface := range ifaces {
		bridge := network.FlatBridgeName(iface.NetworkName)
		rate := compose.NICRate(spec, iface.MAC, iface.Ordinal, iface.NetworkName)
		model := nicModels.Model(iface.MAC, iface.NetworkName, iface.Ordinal, iface.Model)
		// Provision network infrastructure (VXLAN tunnels, DHCP, NAT, bridges).
		// This is critical after failover — the new host may not have the network set up.
		provision := r.provision
		if provision == nil {
			provision = network.SafeProvision
		}
		if provBridge, err := network.ProvisionForVMWith(ctx, r.db, iface.NetworkName, r.hostName, provision); err != nil {
			slog.Warn("reconciler: network provision failed, using raw name",
				"vm", vm.Name, "network", iface.NetworkName, "error", err)
		} else if provBridge != "" {
			bridge = provBridge
		}
		if strings.HasPrefix(bridge, "direct:") {
			netConfigs = append(netConfigs, lv.NetworkConfig{
				Direct:      strings.TrimPrefix(bridge, "direct:"),
				Model:       model,
				MAC:         iface.MAC,
				SpecOrdinal: iface.Ordinal + 1,
				RateMBps:    rate,
			})
		} else {
			netConfigs = append(netConfigs, lv.NetworkConfig{
				Bridge:      bridge,
				Model:       model,
				MAC:         iface.MAC,
				SpecOrdinal: iface.Ordinal + 1,
				RateMBps:    rate,
			})
		}
	}

	// Build the libvirt domain config with the builder CreateVM and a redefine
	// use, so the VM boots on this host with the hardware it was created with:
	// its CPU mode and model, vCPU ceiling, balloon, consoles, disk and NIC
	// tuning, resources. The vCPU and memory are the VM's current ones. A spec
	// with no cpu_mode (stored before the create-time default) renders as it
	// does on every other path, with no <cpu>: a boot here must not change the
	// CPU the guest sees (lv doctor cpu-mode, lv update --cpu-mode).
	vmCfg := compose.DomainConfig(spec, diskConfigs, netConfigs, nil)
	vmCfg.Name = vm.Name
	vmCfg.CPU = vm.CPUActual
	vmCfg.CloudInitISO = cloudInitISO
	if vmCfg.Machine == "" {
		vmCfg.Machine = "q35"
	}
	if vmCfg.Firmware == "" {
		vmCfg.Firmware = "uefi"
	}
	// Memory hot-add: the same NUMA cell and virtio-mem region the VM was
	// created with, plugged to its desired memory, so a set-memory after the
	// recovery plugs instead of finding no region. (USB devices are added by
	// the start hook every start path runs, PrepareHardwareForStart.)
	if spec.MemoryHotplugMaxMib == 0 {
		vmCfg.MemoryMiB = vm.MemActual
	}
	// Secure Boot + vTPM (G1): stable UUID makes the swtpm state path
	// (/var/lib/libvirt/swtpm/<uuid>/) deterministic; render the same firmware
	// CreateVM did. A vTPM VM whose state isn't present on this host can't be
	// rebuilt faithfully — fail clearly (state=error) rather than booting with a
	// fresh TPM and silently breaking BitLocker.
	r.firmware.ApplyTo(&vmCfg, r.dataDir, vm.Name, spec.SecureBoot, spec.Tpm)
	if spec.Tpm && !r.fwStore.HasTPMState(spec.Uuid) {
		slog.Error("reconciler: vTPM VM has no local TPM state; refusing to start with a fresh TPM", "vm", vm.Name)
		return "", false, "vTPM state missing on this host (would break BitLocker)" // non-retryable
	}
	// Same rule for NVRAM (Secure Boot keys / boot entries): a UEFI firmware VM
	// whose vars aren't present here can't be rebuilt faithfully — refuse rather
	// than redefine with fresh vars from the template (would lose enrolled keys).
	uefiFW := spec.Firmware == "uefi" || spec.Firmware == ""
	if (spec.SecureBoot || spec.Tpm) && uefiFW && !r.fwStore.HasNvram(vm.Name) {
		slog.Error("reconciler: firmware VM has no local UEFI NVRAM; refusing to start with fresh vars", "vm", vm.Name)
		return "", false, "UEFI NVRAM missing on this host (would lose Secure Boot keys)" // non-retryable
	}
	// NIC MTUs resolve against this host's bridges, provisioned above.
	if br, ok := r.virt.(lv.BridgeMTUReader); ok {
		vmCfg.BridgeMTU = br.BridgeMTU
	}
	vmCfg.HostName = r.hostName
	for _, addr := range pciAddrs {
		vmCfg.Hostdevs = append(vmCfg.Hostdevs, lv.HostdevConfig{Address: addr})
	}
	domXML, err = lv.GenerateDomainXML(vmCfg)
	if err != nil {
		slog.Error("reconciler: generate domain XML", "vm", vm.Name, "error", err)
		// Non-retryable (bad config), except a bridge whose MTU could not be
		// read: a bridge being recreated is a transient failure, retried on a
		// later pass like any other.
		return "", lv.IsBridgeMTUReadError(err), fmt.Sprintf("XML gen: %v", err)
	}
	return domXML, false, ""
}

// pullBackingImage fetches a missing backing image through autoPullImage
// without letting the walk's budget become the transfer's deadline.
//
// The transfer runs in a background flight keyed by image name, under
// imagePullBudget rather than under ctx: reconcilePass bounds the walk with
// reconcileWalkBudget so the safety sweeps behind it run on their tick, and a
// transfer of a whole image is the one per-VM step that legitimately needs
// longer than that. Handing it the walk's context cancelled every transfer
// that outlived the budget, and since ImportImage discards its partial file on
// cancellation, each pass restarted from zero — a VM with a large backing image
// never recovered.
//
// The caller waits as long as ITS context allows. With no deadline (onboot,
// the fleet harness) that is the whole transfer, exactly as before. Under the
// walk budget it is the remainder of the budget, after which the caller gets
// errImagePullInProgress, re-arms the VM as pending and moves on; the flight
// keeps running, and a later pass joins it or finds the image already present
// (autoPullImage short-circuits on a complete local copy).
//
// One flight per image: forty VMs on one lost host that share a base image
// open one stream, not forty.
func (r *Reconciler) pullBackingImage(ctx context.Context, imageName string) error {
	fl := r.imagePullFlight(ctx, imageName)
	select {
	case <-fl.done:
		return fl.err
	case <-ctx.Done():
		return fmt.Errorf("%w: %v", errImagePullInProgress, ctx.Err())
	}
}

// imagePullFlight returns the in-flight transfer of imageName, starting one if
// none is running. The transfer's context keeps ctx's values (identity) but
// not its cancellation: it is bounded by imagePullBudget alone.
func (r *Reconciler) imagePullFlight(ctx context.Context, imageName string) *imagePullFlight {
	r.pullMu.Lock()
	defer r.pullMu.Unlock()
	if fl, ok := r.pulls[imageName]; ok {
		return fl
	}
	if r.pulls == nil {
		r.pulls = make(map[string]*imagePullFlight)
	}
	fl := &imagePullFlight{done: make(chan struct{})}
	r.pulls[imageName] = fl
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), imagePullBudget)
	go func() {
		defer cancel()
		err := r.autoPullImage(pctx, imageName)
		r.pullMu.Lock()
		delete(r.pulls, imageName)
		r.pullMu.Unlock()
		fl.err = err
		close(fl.done)
	}()
	return fl
}

// deferPendingStart records that a VM's start is waiting on something still in
// progress, with the reason, in a state the next pass re-drives. Distinct from
// failPendingStart: nothing failed, so the proof (if any) is left in_progress
// for the same executor to re-claim, and a proof-less VM is NOT parked in
// error.
//
// WHICH state depends on whether the start is an ownership transfer:
//
//   - With a proof it goes back to "pending". The marker (pending_action_id)
//     stays on the row, so the re-drive re-validates and re-claims the same
//     proof — the shape failPendingStart's retryable arm already produces.
//   - Without a proof it stays in "starting". A proof-less start is a LOCAL
//     recovery — onboot autostart, a domain that died under a running row —
//     and under the split-brain gate a markerless PENDING row is refused as
//     proof_missing, by design: the coordinator writes pending and its marker
//     atomically, so pending without one is stale or hand-mutated. Deferring a
//     local start into pending therefore refused it on every later pass, even
//     after the image had finished — a VM permanently unstarted for having a
//     large image. A markerless "starting" row is the documented shape of an
//     interrupted local start, and the "starting" arm of reconcile re-drives it.
//
// Written on a context that survives the walk budget, which is usually already
// spent by the time this runs.
//
// Two literal writes rather than one with a variable state: the runningcheck
// guard proves statically that no write here can publish "running".
func (r *Reconciler) deferPendingStart(ctx context.Context, vmName, proofID, detail string) {
	cctx := context.WithoutCancel(ctx)
	var err error
	if proofID != "" {
		err = corrosion.UpdateVMState(cctx, r.db, vmName, "pending", detail)
	} else {
		err = corrosion.UpdateVMState(cctx, r.db, vmName, "starting", detail)
	}
	if err != nil {
		slog.Error("reconciler: re-arm pending write failed", "vm", vmName, "error", err)
		r.noteStateWriteFail(corrosion.OpVMState, err)
	}
}

// staleTermRepointGrace is how long a destination leaves a row pending on a
// proof it abandoned at the lease holder's request because the proof's lease
// stamp was superseded (corrosion.AbandonReasonLeaseOutran). The holder
// re-points the row at the proof decided in its place right after the
// abandonment: one claim (failover's claimTimeout, 5 s) and replication. Twice
// one claim and one reconcile tick (reconcileInterval) bounds that; past it the row fails
// as for any abandoned proof, so a holder that never re-points still ends
// visibly.
const staleTermRepointGrace = 2 * (5*time.Second + reconcileInterval)

// awaitingStaleTermRepoint reports whether the pending start of vmName on
// proofID, which this host abandoned, is left for the lease holder to
// re-point instead of failed now: the abandonment was the holder's lease-term
// one, it is younger than staleTermRepointGrace, and the row still names the
// proof. Any other abandonment (an operator's claim-release) fails at once.
func (r *Reconciler) awaitingStaleTermRepoint(ctx context.Context, vmName, proofID string) bool {
	reason, at, ok, err := r.db.ProofAbandonment(ctx, proofID)
	if err != nil || !ok || !strings.HasPrefix(reason, corrosion.AbandonReasonLeaseOutran) {
		return false
	}
	if age := time.Since(at); age < 0 || age >= staleTermRepointGrace {
		return false
	}
	fresh, err := corrosion.GetVM(ctx, r.db, vmName)
	if err != nil || fresh == nil || fresh.PendingActionID != proofID {
		return false
	}
	slog.Info("reconciler: this host abandoned the pending proof for the lease holder, which re-points the row; "+
		"waiting for it", "vm", vmName, "proof", proofID, "abandoned_at", at, "grace", staleTermRepointGrace)
	return true
}

// failPendingStart records a local start failure inside startPendingVM, honoring the
// proof lifecycle (plan: transient → retryable, only a KNOWN non-retryable point →
// terminal) so a proof-gated start is never stranded in_progress:
//   - no proof (legacy): set the VM to error (unchanged behavior).
//   - retryable (a transient libvirt / DB / image-pull hiccup): revert the VM to
//     pending and LEAVE the proof in_progress, so reconcile retries and the same
//     executor re-claims it — never stranding HA on a blip. (The pending_action_id
//     stays set, so the retry re-validates + re-claims the same proof.)
//   - non-retryable (bad spec/disk/firmware/XML — retrying HERE can't help): mark the
//     proof FAILED (terminal) which atomically sets the VM to error + clears the
//     pointer, so no in_progress proof dangles and no marker-less pending row is left.
func (r *Reconciler) failPendingStart(ctx context.Context, vmName, proofID string, retryable bool, detail string) {
	if proofID == "" {
		if err := corrosion.UpdateVMState(ctx, r.db, vmName, "error", detail); err != nil {
			r.noteStateWriteFail(corrosion.OpVMState, err)
		}
		return
	}
	if retryable {
		if err := corrosion.UpdateVMState(ctx, r.db, vmName, "pending", "retrying after transient start failure: "+detail); err != nil {
			slog.Error("reconciler: retry re-arm write failed", "vm", vmName, "error", err)
			r.noteStateWriteFail(corrosion.OpVMState, err)
		}
		return
	}
	if err := corrosion.FailActionProof(ctx, r.db, proofID, vmName, "start_failed", detail); err != nil {
		slog.Error("reconciler: terminalize failed-start proof did not apply — setting VM error",
			"vm", vmName, "proof", proofID, "error", err)
		if werr := corrosion.UpdateVMState(ctx, r.db, vmName, "error", detail); werr != nil {
			r.noteStateWriteFail(corrosion.OpVMState, werr)
		}
	}
}

// hwRefusalReason is the refusal-metric reason of a pre-start refusal: a
// disk's storage not mounted (ErrStartStorageNotMounted) is not a hardware
// one.
func hwRefusalReason(err error) string {
	if errors.Is(err, ErrStartStorageNotMounted) {
		return ReasonStorageNotMounted
	}
	return ReasonHardwareBlocked
}

// hwPrepareRetryable classifies a hardware pre-start error for the proof lifecycle: a
// blocked adoption / unacquirable passthrough (FailedPrecondition) or a malformed record
// (InvalidArgument) is an operator-repair condition that retrying on this host can't fix
// → non-retryable (terminalize + set error); anything else (a transient read/DB failure,
// Internal/Unavailable) → retryable, re-armed for the next reconcile tick.
func hwPrepareRetryable(err error) bool {
	switch status.Code(err) {
	case codes.FailedPrecondition, codes.InvalidArgument:
		return false
	default:
		return true
	}
}

// vmLockTTL is the lease duration for vm_locks entries. It must comfortably
// exceed the worst-case startPendingVM duration (image pull + disk recreate
// + libvirt start). Longer is safer; in pathological cases a stuck reconciler
// will hold the lock until expiry.
const vmLockTTL = 10 * time.Minute

// VMStartLeaseTTL is how long a TryVMStartLease lease stands without being
// taken again by its holder. A holder that keeps a lease longer than this — a
// cold migration copying disks — re-takes it well within it.
const VMStartLeaseTTL = vmLockTTL

// acquireVMLock takes the per-VM startup lease. Returns true if this host
// holds the lock. CRDT-tolerant via the same INSERT-OR-UPDATE-WHERE-expired
// pattern as failover leader election.
//
// NOT linearizable across partitions — but combined with the "re-read VM
// row after lock" check in startPendingVM, the failure mode is "we held a
// lock then discovered the VM moved, and we release without acting", not
// "two hosts both started the VM."
func (r *Reconciler) acquireVMLock(ctx context.Context, vmName string) bool {
	return acquireVMLockFor(ctx, r.db, reconcilerLockHolder(r.hostName), vmName, r.now())
}

// The per-VM lease is held by a COMPONENT on a host, not by the host. Both
// the reconciler's start path and the restart-policy path run in the same
// daemon, and the upsert guard admits `holder = excluded.holder` so that a
// component can re-take its own lease across passes. With a bare host name as
// the holder that clause matched the OTHER component too: the restart path
// took a lease the reconciler was holding for a start in progress, and its
// deferred release — a DELETE by holder — then freed it, after which a peer
// reading host_name=self could start the same VM against the same disk.
//
// The reconciler keeps the bare host name so a lease written by an older
// binary mid-upgrade is still recognised as its own.
func reconcilerLockHolder(hostName string) string { return hostName }

// vmcheckLockHolder is the restart-policy path's distinct identity.
func vmcheckLockHolder(hostName string) string { return hostName + "/vmcheck" }

// OperatorStartLockHolder is the per-VM lease identity of an operator's
// `lv start` of a VM failover re-keyed here still stopped
// (corrosion.StoppedRekeyDetail): the start takes the lease the reconciler's
// define of that VM holds, so the two never interleave (rekeyed_stopped.go).
func OperatorStartLockHolder(hostName string) string { return hostName + "/start" }

// acquireVMLockFor is acquireVMLock without a Reconciler. The restart-policy
// path in VMChecker needs the same lease and is not a Reconciler, and a second
// copy of this CRDT-tolerant upsert would be a second thing to get wrong.
func acquireVMLockFor(ctx context.Context, db *corrosion.Client, hostName, vmName string, nowT time.Time) bool {
	heldBy, err := TryVMStartLease(ctx, db, hostName, vmName, nowT)
	return err == nil && heldBy == hostName
}

// RepairLockHolder is the per-VM lease identity of an operator-asked compose
// repair (UpdateVM on a VM in error or mid-transition), which starts the VM
// and so must exclude every other start path for its duration. Distinct from
// the reconciler's bare host name for the reason reconcilerLockHolder gives:
// sharing it would let one component re-take and then free the other's lease.
func RepairLockHolder(hostName string) string { return hostName + "/repair" }

// TryVMStartLease attempts the per-VM start lease for holder and returns the
// holder the lease names afterwards: holder itself when it was taken (or
// already held by holder), another holder's name when that one's unexpired
// lease stands. A non-nil error means the lease state is unknown, which a
// caller about to start a VM treats as not holding it.
//
// It is THE lease write — the reconciler, the restart-policy path and the
// grpcapi repair all take the lease through it, so every start path is
// mutually exclusive through one replicated statement. Release with
// ReleaseVMStartLease under the same holder.
func TryVMStartLease(ctx context.Context, db *corrosion.Client, holder, vmName string, nowT time.Time) (string, error) {
	hostName := holder
	// Read the clock ONCE so `now` and `expires` derive from the same instant
	// (a per-call test clock could otherwise advance between two reads).
	base := nowT.UTC()
	now := base.Format(time.RFC3339)
	expires := base.Add(vmLockTTL).Format(time.RFC3339)
	// expired-check compares RFC3339-vs-RFC3339 (bound now), not datetime('now'):
	// expires_at is RFC3339, so a string compare to datetime('now')'s space text
	// breaks on a date match ('T' > ' ') and a same-day lock NEVER looks expired —
	// a crashed holder's vm_lock would then block another host from reconciling
	// that VM until the UTC date rolls.
	if err := db.Execute(ctx,
		`INSERT INTO vm_locks (vm_name, holder, expires_at, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(vm_name) DO UPDATE
		   SET holder = excluded.holder,
		       expires_at = excluded.expires_at,
		       updated_at = excluded.updated_at
		   WHERE vm_locks.expires_at < ?
		      OR vm_locks.holder = excluded.holder`,
		vmName, hostName, expires, now, now); err != nil {
		slog.Warn("vm_lock write failed", "vm", vmName, "holder", hostName, "error", err)
		return "", err
	}
	rows, err := db.Query(ctx,
		`SELECT holder FROM vm_locks WHERE vm_name = ?`, vmName)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", fmt.Errorf("vm_lock for %s absent after its write", vmName)
	}
	return rows[0].String("holder"), nil
}

// ReadVMStartLease returns the per-VM start lease's holder and the time it
// was last taken (its updated_at, on the holder's clock); ok is
// false when no lease row exists.
func ReadVMStartLease(ctx context.Context, db *corrosion.Client, vmName string) (holder string, takenAt time.Time, ok bool, err error) {
	rows, err := db.Query(ctx, `SELECT holder, updated_at FROM vm_locks WHERE vm_name = ?`, vmName)
	if err != nil || len(rows) == 0 {
		return "", time.Time{}, false, err
	}
	takenAt, _ = corrosion.ParseUpdatedAt(rows[0].String("updated_at"))
	return rows[0].String("holder"), takenAt, true, nil
}

// releaseVMLock clears the per-VM lock. Best-effort; leaving a stale lock
// is recoverable (next acquire after vmLockTTL succeeds).
func (r *Reconciler) releaseVMLock(ctx context.Context, vmName string) {
	releaseVMLockFor(ctx, r.db, reconcilerLockHolder(r.hostName), vmName)
}

// releaseVMLockFor is releaseVMLock without a Reconciler. See acquireVMLockFor.
func releaseVMLockFor(ctx context.Context, db *corrosion.Client, hostName, vmName string) {
	ReleaseVMStartLease(ctx, db, hostName, vmName)
}

// ReleaseVMStartLease frees the per-VM start lease holder took with
// TryVMStartLease; a lease another holder has taken since is left alone.
// Best-effort: a lease left behind expires after its TTL.
func ReleaseVMStartLease(ctx context.Context, db *corrosion.Client, holder, vmName string) {
	hostName := holder
	if err := db.Execute(ctx,
		`DELETE FROM vm_locks WHERE vm_name = ? AND holder = ?`,
		vmName, hostName); err != nil {
		slog.Debug("vm_lock release failed", "vm", vmName, "holder", hostName, "error", err)
	}
}

// finishNewbornVM completes a create that stopped short of publishing its VM
// running: the row is "creating", the guest already runs here, and the create
// path's graduate → mark → publish did not finish (a store fault on the
// graduation, no marker landing, a failed flip). It runs the same
// PublishNewbornVMRunning the create path does, so a retry can only take the
// row through the same ordering, never to running at epoch 0.
//
// "creating" is not only a stranded newborn, so the finish is keyed narrowly:
//
//   - the domain runs on THIS host — a create still defining or starting its
//     domain (an import starts it after the insert) is not stranded, and a row
//     with no runtime here has nothing to publish;
//   - no active_operation_id — the journaled create protocol holds its
//     provisional row "creating" under that barrier and commits it itself;
//   - no pending_action_id — a proof-gated action owns the transition;
//   - no live vm_locks lease — an operation holds the VM.
//
// The create path can reach the same row at the same moment; that race is
// benign, because every step is idempotent — the graduation is guarded on
// epoch 0, the markers name the one epoch the row holds, and the flip is
// guarded on that epoch.
func (r *Reconciler) finishNewbornVM(ctx context.Context, name string) {
	if r.virt == nil {
		return
	}
	if st, err := r.virt.DomainState(name); err != nil || st != "running" {
		return
	}
	row, err := corrosion.GetVM(ctx, r.db, name)
	if err != nil || row == nil || row.State != "creating" || row.HostName != r.hostName {
		return
	}
	if row.ActiveOperationID != "" || row.PendingActionID != "" {
		return
	}
	if r.activeVMLock(ctx, name) {
		return
	}
	slog.Info("reconciler: finishing a created VM that was never published running",
		"vm", name, "epoch", row.OwnerEpoch)
	if err := PublishNewbornVMRunning(ctx, r.virt, r.db, r.dataDir, r.hostName, name); err != nil {
		slog.Warn("reconciler: could not finish a created VM — it stays \"creating\" and is retried next sweep",
			"vm", name, "error", err)
		r.noteStateWriteFail(corrosion.OpVMState, err)
	}
}

// convergeOwnerEpochMarker repairs the domain's owner-epoch metadata toward
// the DB row for a VM confirmed running on this host. Absent or stale →
// stamped with the row's generation; corrupt (Get errors) → overwritten the
// same way, because a marker that can't be read protects nothing. A row still
// at epoch 0 is pre-epoch: the sweep never stamps it — deciding when a
// workload graduates into the marker regime is the backfill's job, and a
// sweep-stamped zero would be indistinguishable from a real generation.
//
// The row must still name THIS host. Its caller confirms only that the local
// domain is running, which is also true of a domain this host has not yet torn
// down after losing ownership — so without this check convergence stamped the
// old runtime with the NEW owner's generation. runtimeSuperseded decides by
// `row.OwnerEpoch > marker`, so a marker equal to the row reads as current, and
// the superseded runtime it exists to catch was made to look live. That is the
// same unsafe direction the publish chokepoint refuses, reached by the repair
// path rather than by a publish — and refusing to converge is the fail-safe
// answer: a marker LAGGING the row is exactly what the check should see when
// ownership has genuinely moved.
func (r *Reconciler) convergeOwnerEpochMarker(ctx context.Context, name string) {
	row, err := corrosion.GetVM(ctx, r.db, name)
	if err != nil || row == nil || row.OwnerEpoch == 0 {
		return
	}
	if row.HostName != r.hostName {
		slog.Warn("reconciler: not converging the owner-epoch marker for a VM the row says "+
			"belongs elsewhere — stamping it would make this superseded runtime look current",
			"vm", name, "epoch", row.OwnerEpoch, "owner", row.HostName, "self", r.hostName)
		return
	}
	// Each marker converges INDEPENDENTLY. A single early-return keyed on the
	// metadata copy meant that once metadata matched, the durable file was never
	// created — so the check that reads the file stayed blind (lab, 2026-08-02).
	if cur, ok, gerr := r.virt.GetDomainOwnerEpoch(name); gerr != nil || !ok || cur != row.OwnerEpoch {
		if serr := r.virt.SetDomainOwnerEpoch(name, row.OwnerEpoch, true); serr != nil {
			slog.Warn("reconciler: owner-epoch marker convergence failed (will retry next sweep)",
				"vm", name, "epoch", row.OwnerEpoch, "error", serr)
		}
	}
	if cur, ok, ferr := ReadVMOwnerEpochMarker(r.dataDir, name); ferr != nil || !ok || cur != row.OwnerEpoch {
		if werr := WriteVMOwnerEpochMarker(r.dataDir, name, row.OwnerEpoch); werr != nil {
			slog.Warn("reconciler: owner-epoch file marker convergence failed (will retry next sweep)",
				"vm", name, "epoch", row.OwnerEpoch, "error", werr)
		}
	}
}

// ownerEpochEnforced reports whether owner_epoch_v1 enforcement is live here
// (latched fleet-wide; partition fails closed via the gate's own semantics).
func (r *Reconciler) ownerEpochEnforced(ctx context.Context) bool {
	return r.gate != nil && r.gate.Enforced(ctx, capabilities.OwnerEpochV1)
}

// runtimeSuperseded reports whether this host's runtime marker for a workload
// names an ownership generation the DB has already moved past. An absent or
// unreadable marker is NOT superseded: pre-epoch workloads and hosts whose
// marker is missing must keep their existing self-heal behavior (the backfill
// and convergence passes are what graduate them), and failing closed on an
// unreadable marker would strand a legitimately-owned VM.
func (r *Reconciler) runtimeSuperseded(ctx context.Context, name string) bool {
	// The HOST-LOCAL FILE MARKER IS THE ONLY INPUT, deliberately and by
	// necessity. The sole caller sits inside `!DomainExists`, so by the time this
	// runs libvirt has no domain for the VM — and undefining a domain destroys
	// its metadata with it, which is the whole reason the durable file marker
	// exists (lab-proven 2026-08-02).
	//
	// There used to be a domain-metadata fallback here "for a VM whose file
	// marker has not been written yet". It could not fire: DomainExists IS a
	// DomainLookupByName, the same lookup GetDomainOwnerEpoch performs first, so
	// at this point that call can only ever return a lookup error. It read as a
	// second line of defence that did not exist.
	//
	// So: a host with no readable file marker is never treated as superseded.
	// That is fail-open, which is the intended direction for an unreadable
	// marker, but it is the actual coverage — do not add a metadata read back
	// without moving the call site to somewhere a domain still exists.
	marker, ok, err := ReadVMOwnerEpochMarker(r.dataDir, name)
	if errors.Is(err, ErrPreEpochMarker) {
		// A marker asserting generation 0 is not an unreadable marker, and must not
		// be treated as one. It is this host's own statement that its runtime
		// belongs to NO generation — so any row at a real generation has superseded
		// it, and the comparison below reaches that conclusion with marker = 0.
		// Collapsing it into the unreadable case instead would license exactly the
		// resurrection this check exists to refuse, for precisely the population
		// most likely to carry such a marker: a node returning from an older build.
		marker, ok, err = 0, true, nil
	}
	if err != nil || !ok {
		return false
	}
	row, gerr := corrosion.GetVM(ctx, r.db, name)
	if gerr != nil || row == nil {
		return false
	}
	return row.OwnerEpoch > marker
}

// ── Live firmware moves (spec §6.9) ──
//
// While a live firmware move's record — a source marker or a target hold —
// names a VM on this host, the health paths that would undefine, define,
// start, stop or restart it leave it alone: the move, its recovery or an
// operator's D-5 action resolves it. The firmware move guard refuses the
// libvirt calls beneath them too; skipping first keeps a refused call from
// being followed by another (a refused destroy by a start) or by a row
// write, and keeps the leftover's state and definition as they are.

// firmwareMoveSkips logs each skip once per VM and record.
type firmwareMoveSkips struct {
	mu     sync.Mutex
	logged map[string]map[string]string // VM → what was skipped → why
}

// specUUIDOf is the uuid a stored VM spec carries, or "".
func specUUIDOf(spec string) string {
	var sp struct {
		UUID string `json:"uuid"`
	}
	_ = json.Unmarshal([]byte(spec), &sp)
	return sp.UUID
}

// skip reports whether a live firmware move's record names the VM on this
// host (by name, or by uuid when known), logging it once. A record that
// cannot be read counts as one: the guard refuses on it too. dataDir "" is a
// host with no records.
func (k *firmwareMoveSkips) skip(dataDir, name, uuid, what string) bool {
	if dataDir == "" {
		return false
	}
	recs, err := fwmig.New(dataDir).Lookup(name, uuid)
	var why string
	switch {
	case err != nil:
		why = "a firmware move record cannot be read: " + err.Error()
	case len(recs) == 0:
		k.mu.Lock()
		delete(k.logged, name)
		k.mu.Unlock()
		return false
	default:
		r := recs[0]
		dir := "to"
		if r.Kind == lv.FirmwareHold {
			dir = "from"
		}
		why = fmt.Sprintf("live firmware migration %s %s %s in %s %s", r.Attempt, dir, r.Peer, r.Kind, r.State)
	}
	k.mu.Lock()
	if k.logged == nil {
		k.logged = map[string]map[string]string{}
	}
	if k.logged[name] == nil {
		k.logged[name] = map[string]string{}
	}
	first := k.logged[name][what] != why
	k.logged[name][what] = why
	k.mu.Unlock()
	if first {
		slog.Info("health: leaving a VM in a live firmware move alone", "vm", name, "skipped", what, "reason", why)
	}
	return true
}

// firmwareMoveSkip is skip over this reconciler's firmware store.
func (r *Reconciler) firmwareMoveSkip(name, uuid, what string) bool {
	if r.fwStore == nil {
		return false
	}
	return r.fwSkips.skip(r.fwStore.DataDir, name, uuid, what)
}
