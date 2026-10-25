package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/healthdefaults"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// vmCheckSweepInterval is the sweep period: every healthcheck interval's
// default and floor.
const vmCheckSweepInterval = healthdefaults.Interval
const healthCheckGracePeriod = 5 * time.Minute

// VMChecker runs per-VM health checks defined in each VM's HealthCheckSpec.
type VMChecker struct {
	hostName string
	// dataDir is the host data root the owner-epoch file marker lives under.
	// Taken positionally like NewReconciler's rather than through a setter: a
	// setter would leave every existing construction at "", and an empty dataDir
	// SKIPS the file marker — so the path would be untested by construction.
	dataDir string
	db      *corrosion.Client
	// followNetworks moves a stopped VM's NICs onto their networks' devices
	// before a start (SetNetworkFollower).
	followNetworks func(ctx context.Context, name string)
	// virt is nil when there is no libvirt connection (most tests). An
	// interface, not *lv.Client, so a test can drive a restart through
	// libvirtfake; NewVMChecker keeps a nil *lv.Client a nil interface.
	virt vmCheckBackend
	// virtWait bounds the restart pass's reads of libvirt: a domain libvirt
	// has not answered for is skipped, never decided on (domain_gate.go).
	virtWait virtWait
	bus      *events.Bus
	// cancelledStart reports whether this host holds a cancelled start of a
	// VM (SetCancelledStartProbe); nil: none.
	cancelledStart func(name, state, detail string) bool
	// now is the clock (nil → time.Now). A test seam: the start grace and the
	// action backoff are minutes long.
	now func() time.Time

	mu          sync.Mutex
	failures    map[string]int       // vmName → consecutive failures
	lastAction  map[string]time.Time // vmName → last action timestamp (for backoff)
	actionCount map[string]int       // vmName → consecutive actions without recovery

	// activeActions tracks how many VMs per stack are currently being acted on
	// to enforce max-unavailable limits.
	activeActions map[string]int // stackName → count of VMs mid-action

	// tracks is the probe state behind the published verdict (vmprobe.go),
	// one per owned VM, reset whenever the VM's incarnation changes. Guarded
	// by mu; created lazily so a literal VMChecker{} in a test stays usable.
	tracks map[string]*probeTrack
	// sightings is what the sweep last saw of each owned VM, and when it last
	// saw one start (vmcheck_grace.go). Guarded by mu; created lazily.
	sightings map[string]*vmSighting
	// swept is set once a sweep has listed this host's VMs: a VM first seen
	// after that has arrived here, one seen on the first sweep may have been
	// running for weeks.
	swept bool
	// probeFn replaces the probe transport (SetProbeFunc). nil → the real
	// tcp/http/ping/exec probe.
	probeFn ProbeFunc
	// nicIPDiscovery replaces the owner-host ARP / dnsmasq-lease lookup behind
	// vmAddress (SetNICIPDiscovery). nil → the real lookup.
	nicIPDiscovery func(mac, bridge string) string
	// probes counts in-flight checkVM goroutines so SweepOnce can wait for
	// them. Production's Start loop never waits.
	probes sync.WaitGroup

	// migrateVM is an optional callback to migrate a VM via the full MigrateVM
	// RPC path (with post-migration steps: GARP, LB, FDB, DNS, network provisioning).
	migrateVMFunc func(ctx context.Context, vmName, targetHost string) error

	// fwSkips logs, once per record, a VM the checker leaves alone because a
	// live firmware move's record names it here.
	fwSkips firmwareMoveSkips

	// gate is the split-brain safety gate (Phase 1). When set + enforced, a
	// restart-policy start requires local quorum. nil disables (tests). onGateRefused
	// feeds the refusal metric (nil-safe).
	gate          runtimeGate
	onGateRefused func(action, reason string)
	// onStateWriteFail observes an authoritative state write that failed (nil-safe);
	// wired to the litevirt_state_write_failures_total counter by the daemon.
	onStateWriteFail func(op, class string)

	// prepareHardwareForStart, when wired (the daemon passes the gRPC Server's
	// PrepareHardwareForStart), runs the hardware_v2 adoption gate + PCI start-preflight
	// before a health-driven auto-restart's StartDomain: it refuses a "blocked" VM and,
	// for a passthrough VM, re-acquires + realizes + reconciles its devices so a restarted
	// PCI VM comes back with them bound. A strict NO-OP unless hardware_v2 is latched, so a
	// pre-latch fleet's health-restart is byte-for-behavior unchanged. nil → no-op.
	prepareHardwareForStart func(ctx context.Context, vm *corrosion.VMRecord) (func(), error)

	// vmLock, when wired (the daemon passes the gRPC Server's
	// TryLockVMForHealth), takes the VM's API lock without waiting: the lock
	// a move, a start or a stop of the VM holds, so a health restart runs as
	// one step none of them interleaves with (healthRestart). nil → the
	// restart runs without it (tests). A lock another operation holds skips
	// the restart this pass.
	vmLock func(name string) (release func(), ok bool)
}

// vmCheckBackend is the subset of *lv.Client the VMChecker calls.
// libvirtfake satisfies it too.
type vmCheckBackend interface {
	DomainState(name string) (string, error)
	DomainStateReason(name string) (lv.DomainStatus, error)
	HasManagedSaveImage(name string) (bool, error)
	StartDomain(name string) error
	DestroyDomain(name string) error
	MigrateToTarget(name, dconnuri string, p lv.MigrateParams) error
	ExecInGuest(name, command string, args []string) (string, error)
	SetDomainOwnerEpoch(name string, epoch int64, running bool) error
	GetDomainOwnerEpoch(name string) (int64, bool, error)
}

// clock is the checker's time source.
func (v *VMChecker) clock() time.Time {
	if v.now != nil {
		return v.now()
	}
	return time.Now()
}

// SetHardwareStartPreparer wires the hardware_v2 pre-start hook (adoption gate + PCI
// start-preflight). nil-safe; unwired means every restart behaves exactly as before.
func (v *VMChecker) SetHardwareStartPreparer(fn func(ctx context.Context, vm *corrosion.VMRecord) (func(), error)) {
	v.prepareHardwareForStart = fn
}

// hwPrepareStart runs the wired hardware pre-start hook (a strict no-op when unwired or
// pre-latch), returning a release func for the caller to invoke ONLY if its StartDomain
// then fails.
func (v *VMChecker) hwPrepareStart(ctx context.Context, vm *corrosion.VMRecord) (func(), error) {
	if v.prepareHardwareForStart == nil {
		return func() {}, nil
	}
	return v.prepareHardwareForStart(ctx, vm)
}

// SetNetworkFollower wires the hook that moves a stopped VM's NICs onto the
// devices their networks are on now before the checker starts it
// (grpcapi.Server.FollowNetworkDevices), as every start through the Server
// does. nil-safe; unwired, the domain starts as defined.
func (v *VMChecker) SetNetworkFollower(fn func(ctx context.Context, name string)) {
	v.followNetworks = fn
}

// SetGate injects the split-brain safety gate (the health.Checker).
func (v *VMChecker) SetGate(g runtimeGate) { v.gate = g }

// SetGateRefusedObserver wires the refusal metric hook (nil-safe).
func (v *VMChecker) SetGateRefusedObserver(fn func(action, reason string)) { v.onGateRefused = fn }

func (v *VMChecker) noteGateRefused(action, reason string) {
	if v.onGateRefused != nil {
		v.onGateRefused(action, reason)
	}
}

// SetStateWriteFailObserver wires the state-write-failure metric hook (nil-safe).
func (v *VMChecker) SetStateWriteFailObserver(fn func(op, class string)) { v.onStateWriteFail = fn }

func (v *VMChecker) noteStateWriteFail(op string, err error) {
	if v.onStateWriteFail != nil {
		v.onStateWriteFail(op, corrosion.ClassifyWriteErr(err))
	}
}

// ProbeFunc runs one healthcheck probe against vm and reports whether it
// passed and, when it did not, why. ctx carries the probe timeout. hspec's
// Target is already RESOLVED against the VM's address (vmprobe_target.go): a
// transport never sees a bare port or localhost, and is never called at all
// for a VM whose address is not known.
type ProbeFunc func(ctx context.Context, vm corrosion.VMRecord, hspec *pb.HealthCheckSpec) (ok bool, reason string)

// SetProbeFunc replaces the probe transport. It exists for tests that must
// script probe results (a fleet VM has no guest to answer a real probe); the
// daemon never calls it. nil restores the real probe.
func (v *VMChecker) SetProbeFunc(fn ProbeFunc) {
	v.mu.Lock()
	v.probeFn = fn
	v.mu.Unlock()
}

// SweepOnce runs one sweep and waits for the probes it started, verdict
// publication included. For tests that drive the checker instead of running
// its ticker; the daemon uses Start.
func (v *VMChecker) SweepOnce(ctx context.Context) {
	v.sweep(ctx)
	v.probes.Wait()
}

// SetCancelledStartProbe wires the probe that says whether this host holds a
// start of the VM `lv stop --force` cancelled while libvirt had not answered
// it (grpcapi.Server.HasCancelledStart). Such a VM's row says what the cancel
// wrote (stopped by its operator, or error), and a domain libvirt starts for
// it late is the cancelled-starts sweep's to destroy: the restart-policy pass
// neither records it running nor starts the VM.
func (v *VMChecker) SetCancelledStartProbe(fn func(name, state, detail string) bool) {
	v.cancelledStart = fn
}

// VMCheckBackend is the libvirt surface the checker calls (*lv.Client, or
// libvirtfake in a test of another package).
type VMCheckBackend = vmCheckBackend

// SetBackend replaces the checker's libvirt backend. For tests that drive
// the checker from another package (SweepOnce).
func (v *VMChecker) SetBackend(b VMCheckBackend) { v.virt = b }

// SetVMLocker wires the VM lock a health restart runs under (vmLock).
func (v *VMChecker) SetVMLocker(fn func(name string) (release func(), ok bool)) { v.vmLock = fn }

// healthRestart is the destroy → pre-start → start of a health restart of
// vm (a failed health check's, or the restart policy's) as ONE step: under
// the VM's API lock when one is wired, with the row read again under it. A
// row that is no longer this host's, or no longer in the state the checker
// decided from — a move recorded migrating since, a cold move that handed
// the VM over, an operator stop — is left alone: nothing is destroyed and
// nothing written. The row is written only while it still is that row
// (UpdateVMStateFrom), so a writer that changed it meanwhile keeps its
// change: a refused restart recorded `error` over a move's `migrating` would
// make the row startable again under the start guard. what names the
// restart in the row's detail. onAct, when given, runs once the restart is
// going ahead — under the lock, the row re-read, before the destroy — and
// not for a pass that is skipped: the restart policy counts its attempt
// there, so a pass skipped for a held lock uses none, and a restart is never
// counted twice. from is the row acted on (nil when nothing was touched);
// started says the guest is booting again; lockHeld says the pass was
// skipped for the lock.
func (v *VMChecker) healthRestart(ctx context.Context, vm corrosion.VMRecord, what string, onAct func()) (from *corrosion.VMRecord, started, lockHeld bool) {
	if v.vmLock != nil {
		release, ok := v.vmLock(vm.Name)
		if !ok {
			slog.Info("vmcheck: not restarting the VM — another operation holds its lock; next pass", "vm", vm.Name, "restart", what)
			return nil, false, true
		}
		defer release()
	}
	fresh, err := corrosion.GetVM(ctx, v.db, vm.Name)
	if err != nil || fresh == nil {
		slog.Warn("vmcheck: not restarting the VM — its row cannot be read", "vm", vm.Name, "restart", what, "error", err)
		return nil, false, false
	}
	if fresh.HostName != v.hostName || fresh.State != vm.State ||
		(fresh.State == "stopped" && IsOperatorStop(fresh.StateDetail) && !IsOperatorStop(vm.StateDetail)) {
		slog.Info("vmcheck: not restarting the VM — its row changed since the check read it",
			"vm", vm.Name, "restart", what, "host", fresh.HostName, "state", fresh.State, "detail", fresh.StateDetail)
		return nil, false, false
	}
	// An operator's forced stop made here under write quarantine and not
	// yet recorded (operator_stop_marker.go) is never undone by a restart.
	if operatorStopHeld("vmcheck", v.dataDir, v.hostName, fresh) {
		return nil, false, false
	}
	if onAct != nil {
		onAct()
	}
	_ = v.virt.DestroyDomain(vm.Name)
	// hardware_v2 pre-start (adoption gate + PCI preflight), after the
	// destroy and before the start, as RestartVM's destroy → startVMLocked.
	// No-op unless hardware_v2 is latched. A refusal is non-fatal: no
	// restart, and the row flagged error — if it still is the row acted on.
	releaseHW, hwErr := v.hwPrepareStart(ctx, fresh)
	if hwErr != nil {
		slog.Warn("vmcheck: hardware pre-start refused/failed the restart", "vm", vm.Name, "restart", what, "error", hwErr)
		v.noteGateRefused(corrosion.ActionReschedule, hwRefusalReason(hwErr))
		v.recordRestartFailure(ctx, fresh, fmt.Sprintf("hardware pre-start: %v", hwErr))
		return fresh, false, false
	}
	if err := v.startGuarded(ctx, vm.Name); err != nil {
		releaseHW() // release any passthrough the preflight bound for this failed start
		slog.Error("vmcheck: "+what+" failed", "vm", vm.Name, "error", err)
		v.recordRestartFailure(ctx, fresh, fmt.Sprintf("%s failed: %v", what, err))
		return fresh, false, false
	}
	// The guest is booting again from here, whether or not the running
	// publication lands: its start grace begins now.
	v.noteStarted(vm.Name, v.clock())
	return fresh, true, false
}

// recordRestartFailure records a health restart that did not bring the
// guest up as `error`, over the row the restart acted on and no other.
func (v *VMChecker) recordRestartFailure(ctx context.Context, from *corrosion.VMRecord, detail string) {
	applied, werr := corrosion.UpdateVMStateFrom(ctx, v.db, from.Name, from.HostName, from.State, "error", detail)
	if werr != nil {
		v.noteStateWriteFail(corrosion.OpVMState, werr)
		return
	}
	if !applied {
		slog.Warn("vmcheck: the VM's row changed under its restart; its state is left as it is",
			"vm", from.Name, "acted_on", from.State, "detail", detail)
	}
}

// restartedRecordedMeanwhile answers for a health restart's running write
// that did not apply (UpdateVMStateFrom: the row acted on changed under the
// restart): a row that already says running here was recorded by another
// writer and is taken as recorded; any other change refuses the publication
// (ErrNoRowsAffected), as a vanished row does.
func (v *VMChecker) restartedRecordedMeanwhile(ctx context.Context, name string) error {
	cur, err := corrosion.GetVM(ctx, v.db, name)
	if err != nil {
		return err
	}
	if cur != nil && cur.HostName == v.hostName && cur.State == "running" {
		return nil
	}
	return corrosion.ErrNoRowsAffected
}

// SetEventBus sets the event bus for publishing health check events.
func (v *VMChecker) SetEventBus(bus *events.Bus) { v.bus = bus }

// SetMigrateFunc registers a callback to migrate VMs via the full MigrateVM RPC
// path, ensuring all post-migration steps (GARP, LB, FDB, DNS) are executed.
func (v *VMChecker) SetMigrateFunc(fn func(ctx context.Context, vmName, targetHost string) error) {
	v.migrateVMFunc = fn
}

// publish sends an event to the bus if one is configured.
func (v *VMChecker) publish(action, target, detail string) {
	if v.bus == nil {
		return
	}
	v.bus.Publish(events.Event{
		Action: action,
		Target: target,
		Detail: detail,
	})
}

// NewVMChecker creates a VM-level health checker for the local host.
func NewVMChecker(hostName, dataDir string, db *corrosion.Client, virt *lv.Client) *VMChecker {
	v := &VMChecker{
		hostName:      hostName,
		dataDir:       dataDir,
		db:            db,
		failures:      make(map[string]int),
		lastAction:    make(map[string]time.Time),
		actionCount:   make(map[string]int),
		activeActions: make(map[string]int),
	}
	if virt != nil {
		v.virt = virt // a nil *lv.Client boxed here would pass every `v.virt != nil`
	}
	return v
}

// publishRunning routes a NON-MINTING transition through the marker chokepoint.
// v.virt is nil in most tests, and a nil vmCheckBackend must reach
// PublishRunningVia as a nil DomainEpochSetter, not as a boxed nil.
func (v *VMChecker) publishRunning(ctx context.Context, name, state string, commit func(context.Context) error) error {
	var setter DomainEpochSetter
	if v.virt != nil {
		setter = v.virt
	}
	return PublishRunningVia(ctx, setter, v.db, v.dataDir, v.hostName, name, state, commit)
}

// Start begins the sweep loop. Blocks until ctx is cancelled.
func (v *VMChecker) Start(ctx context.Context) {
	ticker := time.NewTicker(vmCheckSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			v.sweep(ctx)
		}
	}
}

// correlatedFailureThreshold: if this many VMs fail health checks simultaneously,
// suppress auto-restart to avoid thundering herd during shared-storage outages (#47).
const correlatedFailureThreshold = 3

func (v *VMChecker) sweep(ctx context.Context) {
	vms, err := corrosion.ListVMs(ctx, v.db, "", v.hostName)
	if err != nil {
		slog.Error("vmcheck: list VMs", "error", err)
		return
	}

	// Prune per-VM tracking for VMs no longer on this host, so a deleted VM neither
	// leaks these maps nor keeps poisoning isCorrelatedFailure below with a stale
	// failures[…] ≥ 2 (which would wrongly suppress auto-restart of healthy VMs).
	// Behind the ListVMs-success guard above so a transient DB error can't wipe live
	// counters mid-episode. Benign race: an in-flight async checkVM for a just-deleted
	// VM can repopulate its key AFTER this prune; the next sweep re-prunes it — do NOT
	// "fix" that by holding v.mu across the whole sweep.
	now := v.clock()
	current := make(map[string]bool, len(vms))
	for i := range vms {
		current[vms[i].Name] = true
	}
	v.pruneVMState(current)
	v.observeStarts(vms, now)

	// Pre-sweep: count how many VMs are in a failing state. If many are
	// failing simultaneously, it's likely correlated (NFS outage, etc.) (#47).
	if v.isCorrelatedFailure() {
		slog.Warn("vmcheck: multiple VMs failing simultaneously — possible storage/network event, suppressing auto-restart",
			"host", v.hostName)
	}

	durable := v.loadVerdicts(ctx)
	for _, vm := range vms {
		hspec := vmCheckSpec(&vm)
		if vm.State != "running" || hspec == nil || hspec.Type == "" {
			// Nothing to probe. A verdict this host published for the VM
			// no longer describes it: bring the row to "unknown".
			v.settleIdleVerdict(ctx, vm, hspec, durable[vm.Name])
			continue
		}
		if !v.probeDue(vm, hspec, now) {
			continue
		}
		// Start grace: a VM created or started less than 5 minutes ago is
		// still finishing cloud-init, getting IPs, starting services, so a
		// failed probe does not count toward the healthcheck's ACTION yet.
		// The probe still runs and its verdict is still published: a
		// depends-on or rolling-update wait on a just-started VM needs its
		// first pass, and "not passing yet" is the truth about a VM that is
		// still booting.
		inGrace := v.inStartGrace(vm, now)
		v.probes.Add(1)
		go func(vm corrosion.VMRecord) {
			defer v.probes.Done()
			v.checkVMAt(ctx, vm, hspec, inGrace)
		}(vm)
	}
	v.settleOrphanVerdicts(ctx, durable, current)

	// Second pass: restart policy for stopped/error VMs.
	for _, vm := range vms {
		if vm.State != "stopped" && vm.State != "error" {
			continue
		}
		if v.cancelledStart != nil && v.cancelledStart(vm.Name, vm.State, vm.StateDetail) {
			// A start of it was cancelled here while libvirt had not
			// answered it: its row stays what the cancel wrote, and a
			// domain libvirt started late is destroyed by the
			// cancelled-starts sweep, not recorded running or restarted.
			continue
		}
		// A domain libvirt has not answered for is neither healed nor
		// restarted this pass: both decide from libvirt's answer
		// (domain_gate.go).
		if v.virt != nil && !v.virtWait.domainAnswers(v.virt, "vmcheck", vm.Name) {
			continue
		}
		// Reconcile a state desync first: if libvirt actually has the domain
		// running, the cluster record is stale (an out-of-band start, or an
		// RPC that mutated libvirt but failed before writing state). Heal it to
		// "running" instead of letting the restart policy fight reality. This
		// is the only safe direction — we promote to running solely when
		// libvirt confirms it. Operator-stopped VMs are left alone: the
		// operator's intent wins even if a stop didn't fully take effect.
		if !IsOperatorStop(vm.StateDetail) && v.virt != nil {
			if st, err := v.virt.DomainState(vm.Name); err == nil && st == "running" {
				if werr := v.publishRunning(ctx, vm.Name, "running", func(ctx context.Context) error {
					return corrosion.UpdateVMStateStrict(ctx, v.db, vm.Name, "running",
						"reconciled from libvirt: domain running")
				}); werr != nil {
					if errors.Is(werr, corrosion.ErrNoRowsAffected) {
						// Row vanished between the list and here (concurrent delete)
						// — nothing to reconcile, not a write fault.
						slog.Debug("vmcheck: reconcile target row gone; skipping", "vm", vm.Name)
						continue
					}
					LogPublishRefusal("vmcheck: reconcile write failed — NOT publishing reconciled event",
						vm.Name, werr)
					v.noteStateWriteFail(corrosion.OpVMState, werr)
					continue
				}
				v.publish("vm.state.reconciled", vm.Name,
					fmt.Sprintf("cluster state was %q, libvirt reports running", vm.State))
				slog.Warn("vmcheck: reconciled stale VM state", "vm", vm.Name, "was", vm.State)
				continue
			}
		}
		// Never restart VMs explicitly stopped by the operator (#29).
		if IsOperatorStop(vm.StateDetail) {
			continue
		}
		v.maybeRestartVM(ctx, vm, now)
	}
}

// pruneVMState drops per-VM tracking (failures/lastAction/actionCount) for VMs not in the
// current host-scoped set. Called from sweep after a successful ListVMs so a deleted (or
// moved-away) VM stops leaking and stops counting toward isCorrelatedFailure. Also drops a
// zero-valued activeActions entry for a stack that has no VMs mid-action (minor leak only).
func (v *VMChecker) pruneVMState(current map[string]bool) {
	v.virtWait.prune(current)
	v.mu.Lock()
	defer v.mu.Unlock()
	for name := range v.failures {
		if !current[name] {
			delete(v.failures, name)
			delete(v.lastAction, name)
			delete(v.actionCount, name)
		}
	}
	// lastAction/actionCount may hold keys not in failures (e.g. failures reset to 0 then
	// deleted) — sweep those independently.
	for name := range v.lastAction {
		if !current[name] {
			delete(v.lastAction, name)
		}
	}
	for name := range v.actionCount {
		if !current[name] {
			delete(v.actionCount, name)
		}
	}
	for stack, n := range v.activeActions {
		if n == 0 {
			delete(v.activeActions, stack)
		}
	}
	for name := range v.tracks {
		if !current[name] {
			delete(v.tracks, name)
		}
	}
	for name := range v.sightings {
		if !current[name] {
			delete(v.sightings, name)
		}
	}
}

// isCorrelatedFailure returns true if many VMs are failing simultaneously,
// indicating a shared infrastructure issue rather than individual VM problems (#47).
func (v *VMChecker) isCorrelatedFailure() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.correlatedFailureLocked(v.clock())
}

// correlatedFailureLocked is isCorrelatedFailure for a caller holding mu.
//
// A VM whose action its backoff is holding back does not count: it has
// already been acted on, and its failure run survives the hold (so the first
// failure after it acts). Counting it, a few VMs sitting in backoff would
// keep the guard on — suppressing every other VM's action — for as long as
// their backoff lasted, and longer, since a suppressed action is retried.
func (v *VMChecker) correlatedFailureLocked(now time.Time) bool {
	count := 0
	for name, f := range v.failures {
		if f >= 2 && !v.inActionBackoffLocked(name, now) {
			count++
		}
	}
	return count >= correlatedFailureThreshold
}

// inActionBackoffLocked reports whether the backoff after name's last action
// still holds its next one back. Caller holds mu.
func (v *VMChecker) inActionBackoffLocked(name string, now time.Time) bool {
	acts := v.actionCount[name]
	if acts <= 0 {
		return false
	}
	last, ok := v.lastAction[name]
	return ok && now.Sub(last) < actionBackoff(acts)
}

func (v *VMChecker) checkVM(ctx context.Context, vm corrosion.VMRecord, hspec *pb.HealthCheckSpec) {
	v.checkVMAt(ctx, vm, hspec, false)
}

// checkVMAt probes vm once, publishes the verdict that result leads to, and —
// outside the start grace period — counts it toward the healthcheck's action.
// Interval enforcement is the sweep's (probeDue), not this function's.
func (v *VMChecker) checkVMAt(ctx context.Context, vm corrosion.VMRecord, hspec *pb.HealthCheckSpec, inGrace bool) {
	timeout := probeTimeout(hspec)
	retries := probeRetries(hspec)

	out := v.runProbe(ctx, vm, hspec, timeout)
	if !v.recordVerdict(ctx, vm, hspec, out) {
		// The VM's incarnation changed while this probe ran (a restart, a
		// move, a redefine): the result describes a VM that no longer exists,
		// and the new incarnation is probed by a sweep of its own. Counting it
		// would feed two probes into one failure run.
		return
	}
	// The grace is judged again now the result has landed: a start this host
	// saw WHILE the probe ran — `lv restart` keeps the row running, so the
	// incarnation above is unchanged — cleared the failure run, and this
	// result, from before that start, must not begin a new one against the
	// freshly booted guest.
	if inGrace || v.inStartGrace(vm, v.clock()) {
		return
	}

	v.mu.Lock()
	if out.unknown {
		// The probe could not be run (no address known for the VM yet, or a
		// target that cannot be interpreted). That says nothing about the
		// VM, so it is neither a pass nor a failure: it breaks any run of
		// consecutive failures and never counts toward the action. The
		// verdict published above says why.
		v.failures[vm.Name] = 0
		v.mu.Unlock()
		slog.Debug("vmcheck: probe not run", "vm", vm.Name, "type", hspec.Type, "reason", out.reason)
		return
	}
	healthy := out.ok
	if healthy {
		v.failures[vm.Name] = 0
		v.actionCount[vm.Name] = 0
		v.mu.Unlock()
		return
	}
	v.failures[vm.Name]++
	count := v.failures[vm.Name]
	v.mu.Unlock()

	slog.Warn("vmcheck: probe failed", "vm", vm.Name, "type", hspec.Type, "consecutive", count)

	if count < retries {
		return
	}

	// Threshold crossed — take action (with backoff and max-unavailable).
	// The failure run is reset only once the action is actually taken: a run
	// the backoff or the max-unavailable limit holds back keeps counting, so
	// the first failed probe after the hold acts, rather than `retries` more.
	v.mu.Lock()

	// Exponential backoff: if we've already acted on this VM without recovery,
	// wait progressively longer before acting again.
	now := v.clock()
	if acts := v.actionCount[vm.Name]; v.inActionBackoffLocked(vm.Name, now) {
		next := v.lastAction[vm.Name].Add(actionBackoff(acts))
		v.mu.Unlock()
		slog.Warn("vmcheck: action backoff active", "vm", vm.Name, "consecutive_actions", acts,
			"next_eligible", next.Format(time.RFC3339))
		return
	}

	// Correlated failures (#47): many VMs failing at once is likely a shared
	// storage or network event, and acting on each would be a thundering herd.
	// Decided HERE, before anything is counted: a suppressed action was not
	// taken, so it neither grows the backoff nor ends the failure run — the
	// first failed probe once the event is over acts.
	if v.correlatedFailureLocked(now) {
		v.mu.Unlock()
		v.publish("vm.health.suppressed", vm.Name, "correlated failures detected — possible storage/network event")
		slog.Warn("vmcheck: suppressing action due to correlated failures — likely storage/network event",
			"vm", vm.Name, "action", probeAction(hspec))
		return
	}

	// Max-unavailable: limit concurrent actions per stack to 1 (or configurable).
	stack := vm.StackName
	if stack != "" {
		maxUnavailable := 1 // default: only 1 VM per stack can be acted on at a time
		if v.activeActions[stack] >= maxUnavailable {
			v.mu.Unlock()
			slog.Warn("vmcheck: max-unavailable reached for stack", "stack", stack,
				"active_actions", v.activeActions[stack], "max", maxUnavailable)
			return
		}
		v.activeActions[stack]++
	}

	v.failures[vm.Name] = 0
	v.actionCount[vm.Name]++
	v.lastAction[vm.Name] = now
	v.mu.Unlock()

	// Release the stack action slot when done.
	defer func() {
		if stack != "" {
			v.mu.Lock()
			v.activeActions[stack]--
			v.mu.Unlock()
		}
	}()

	v.takeAction(ctx, vm, hspec)
}

// maxActionBackoff caps actionBackoff.
const maxActionBackoff = 32 * time.Minute

// actionBackoff is how long after its last action a VM that has had acts
// consecutive actions without recovering must wait before the next one:
// 1 min after the first, doubling per action, capped at maxActionBackoff.
// A passing probe resets acts to 0.
func actionBackoff(acts int) time.Duration {
	if acts <= 0 {
		return 0
	}
	return time.Duration(1<<min(acts, 6)) * 30 * time.Second
}

// probeRetries is the healthcheck's retries: consecutive failures before the
// VM is unhealthy (and before its action runs). Default healthdefaults.Retries.
func probeRetries(hspec *pb.HealthCheckSpec) int {
	if hspec.Retries > 0 {
		return int(hspec.Retries)
	}
	return healthdefaults.Retries
}

// probeTimeout bounds one probe: the healthcheck's timeout, default
// healthdefaults.Timeout.
func probeTimeout(hspec *pb.HealthCheckSpec) time.Duration {
	return parseDuration(hspec.Timeout, healthdefaults.Timeout)
}

// probeAction is what is done to an unhealthy VM: the healthcheck's action,
// default healthdefaults.Action.
func probeAction(hspec *pb.HealthCheckSpec) string {
	if hspec.Action != "" {
		return hspec.Action
	}
	return healthdefaults.Action
}

// probeOutcome is one probe's result. unknown means the probe could not be
// run at all — see resolveProbeSpec — and is neither a pass nor a failure.
type probeOutcome struct {
	ok      bool
	unknown bool
	reason  string
}

// runProbe resolves the healthcheck's target against the VM, then runs one
// probe through the wired transport (SetProbeFunc) or the real one, bounded by
// timeout.
func (v *VMChecker) runProbe(ctx context.Context, vm corrosion.VMRecord, hspec *pb.HealthCheckSpec, timeout time.Duration) probeOutcome {
	resolved, why := v.resolveProbeSpec(ctx, vm, hspec)
	if resolved == nil {
		return probeOutcome{unknown: true, reason: why}
	}
	v.mu.Lock()
	fn := v.probeFn
	v.mu.Unlock()
	if fn == nil {
		ok, reason := v.probeDetail(ctx, vm.Name, resolved, timeout)
		return probeOutcome{ok: ok, reason: reason}
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ok, reason := fn(tctx, vm, resolved)
	return probeOutcome{ok: ok, reason: reason}
}

func (v *VMChecker) probe(ctx context.Context, vmName string, hspec *pb.HealthCheckSpec, timeout time.Duration) bool {
	ok, _ := v.probeDetail(ctx, vmName, hspec, timeout)
	return ok
}

// probeDetail is the real probe transport. hspec.Target is used literally —
// runProbe has already resolved it against the VM (vmprobe_target.go). On
// failure it also says why, which is what the published verdict carries to a
// waiter that times out.
func (v *VMChecker) probeDetail(ctx context.Context, vmName string, hspec *pb.HealthCheckSpec, timeout time.Duration) (bool, string) {
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch hspec.Type {
	case "tcp":
		conn, err := (&net.Dialer{}).DialContext(tctx, "tcp", hspec.Target)
		if err != nil {
			return false, fmt.Sprintf("tcp %s: %v", hspec.Target, err)
		}
		conn.Close()
		return true, ""

	case "http", "https":
		req, err := http.NewRequestWithContext(tctx, http.MethodGet, hspec.Target, nil)
		if err != nil {
			return false, fmt.Sprintf("%s %s: %v", hspec.Type, hspec.Target, err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false, fmt.Sprintf("%s %s: %v", hspec.Type, hspec.Target, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			return false, fmt.Sprintf("%s %s: status %d", hspec.Type, hspec.Target, resp.StatusCode)
		}
		return true, ""

	case "ping":
		cmd := exec.CommandContext(tctx, "ping", "-c", "1", "-W", "2", hspec.Target)
		if err := cmd.Run(); err != nil {
			return false, fmt.Sprintf("ping %s: %v", hspec.Target, err)
		}
		return true, ""

	case "exec":
		// Run command inside the VM via guest agent.
		if v.virt == nil {
			return false, "exec probe: no libvirt connection on this host"
		}
		// Guard: exec probes require a guest agent. If the VM spec says
		// guest_agent is disabled, skip the probe and treat as healthy (#9).
		spec := vmSpecFromDB(ctx, v.db, vmName)
		if spec != nil && !spec.GuestAgent {
			slog.Warn("vmcheck: exec probe skipped — guest agent disabled", "vm", vmName)
			return true, ""
		}
		// ExecInGuest takes no context (the guest-agent call can block ~30-60s),
		// so honor the probe timeout ourselves — otherwise a hung agent makes the
		// probe run far past `timeout`, piling up overlapping sweeps (bug-sweep
		// #10). A timed-out probe counts as a failure.
		done := make(chan error, 1)
		go func() { _, e := v.virt.ExecInGuest(vmName, "/bin/sh", []string{"-c", hspec.Target}); done <- e }()
		select {
		case err := <-done:
			if err != nil {
				return false, fmt.Sprintf("exec %q: %v", hspec.Target, err)
			}
			return true, ""
		case <-tctx.Done():
			slog.Warn("vmcheck: exec probe timed out", "vm", vmName, "timeout", timeout)
			return false, fmt.Sprintf("exec %q: timed out after %s", hspec.Target, timeout)
		}

	default:
		slog.Warn("vmcheck: unknown probe type", "type", hspec.Type)
		return true, ""
	}
}

func (v *VMChecker) takeAction(ctx context.Context, vm corrosion.VMRecord, hspec *pb.HealthCheckSpec) {
	action := probeAction(hspec)

	// Suppress action if correlated failures detected (#47).
	if v.isCorrelatedFailure() {
		v.publish("vm.health.suppressed", vm.Name, "correlated failures detected — possible storage/network event")
		slog.Warn("vmcheck: suppressing action due to correlated failures — likely storage/network event",
			"vm", vm.Name, "action", action)
		return
	}

	// Re-read VM state before acting. If the operator stopped the VM
	// between the probe and now, do not restart it (#29).
	fresh, err := corrosion.GetVM(ctx, v.db, vm.Name)
	if err != nil || fresh == nil {
		return
	}
	// Ownership may have moved off this host since the health probe was QUEUED (the
	// sweep spawns checks async on a snapshot). Act ONLY if we still own it — else a
	// destroy/start would hit a stale local domain, or a migrate would use a stale
	// source host, fighting the new owner. Everything below acts on the FRESH record.
	if fresh.HostName != v.hostName {
		slog.Info("vmcheck: skipping action — VM no longer owned by this host",
			"vm", vm.Name, "owner", fresh.HostName)
		return
	}
	if fresh.State == "stopped" && IsOperatorStop(fresh.StateDetail) {
		slog.Info("vmcheck: skipping action — VM was stopped by operator", "vm", vm.Name)
		return
	}
	if fresh.State != "running" {
		slog.Info("vmcheck: skipping action — VM state changed", "vm", vm.Name, "state", fresh.State)
		return
	}
	// A VM a live firmware move's record names here: no action, no row
	// write (spec §6.9). A destroy the guard refused would be followed by a
	// refused start and an `error` row.
	if v.fwSkips.skip(v.dataDir, vm.Name, specUUIDOf(fresh.Spec), "health-check action") {
		return
	}

	// Split-brain gate (Phase 1): "restart" (destroy+start) and "migrate" are
	// automated RUNTIME actions — once enforcement is latched they require local
	// quorum (ExecutionGate), so an isolated host with a failing health probe can't
	// restart-in-place or migrate a VM without quorum. "alert" is a notification, not
	// a runtime action, and still fires. Fail-open until split_brain_gate_v1 is
	// cluster-wide. (This is separate from the restart-POLICY gate in maybeRestartVM.)
	if action == "restart" || action == "migrate" {
		// Self-fence is an UNCONDITIONAL hard gate (independent of enforcement): a doomed
		// node must not restart-in-place or migrate a VM during its fence-timeout window.
		if selfFenceHardGate(v.gate) {
			slog.Warn("vmcheck: self-fenced — refusing health-check action", "vm", vm.Name, "action", action)
			v.noteGateRefused(corrosion.ActionReschedule, ReasonSelfFenced)
			return
		}
		if v.gate != nil && v.gate.Enforced(ctx, capabilities.SplitBrainGateV1) {
			if g := v.gate.ExecutionGate(ctx); !g.OK {
				slog.Warn("vmcheck: execution gate refused health-check action (no quorum)",
					"vm", vm.Name, "action", action, "reason", g.Reason)
				v.noteGateRefused(corrosion.ActionReschedule, g.Reason)
				return
			}
		}
	}

	// While cluster HA is disarmed, an automatic restart or migrate is held
	// like every other automatic recovery: it becomes an alert. A policy this
	// node cannot read holds it too. The restart POLICY (maybeRestartVM)
	// starting a VM on its own host after a crash is kept.
	if action == "restart" || action == "migrate" {
		if why := haHoldsHealthAction(ctx, v.db); why != "" {
			slog.Warn("vmcheck: cluster HA is disarmed — health-check action downgraded to an alert",
				"vm", vm.Name, "action", action, "reason", why)
			v.publish("vm.health.downgraded", vm.Name, fmt.Sprintf("action=%s downgraded to alert: %s", action, why))
			action = "alert"
		}
	}

	slog.Warn("vmcheck: taking action", "vm", vm.Name, "action", action)
	v.publish("vm.health.failed", vm.Name, fmt.Sprintf("action=%s type=%s", action, hspec.Type))

	switch action {
	case "restart":
		if v.virt == nil {
			return
		}
		// One step under the VM's lock, the row read again under it: a move
		// recorded migrating since the re-read above is left alone.
		from, started, _ := v.healthRestart(ctx, *fresh, "health check restart", nil)
		if !started {
			return
		}
		if err := v.publishRunning(ctx, vm.Name, "running", func(ctx context.Context) error {
			// Over the row the restart acted on, and no other.
			applied, err := corrosion.UpdateVMStateFrom(ctx, v.db, from.Name, from.HostName, from.State, "running", "restarted by health checker")
			if err != nil || applied {
				return err
			}
			return v.restartedRecordedMeanwhile(ctx, from.Name)
		}); err != nil {
			LogPublishRefusal("vmcheck: restart state write failed — NOT publishing restarted event", vm.Name, err)
			v.noteStateWriteFail(corrosion.OpVMState, err)
			return
		}
		v.publish("vm.health.restarted", vm.Name, "restarted by health checker")
		slog.Info("vmcheck: VM restarted", "vm", vm.Name)

	case "migrate":
		v.migrateVM(ctx, *fresh) // act on the fresh record (current owner), not the queued snapshot

	case "alert":
		v.publish("vm.health.alert", vm.Name, fmt.Sprintf("type=%s target=%s", hspec.Type, hspec.Target))
		slog.Error("vmcheck: ALERT — VM health check failed", "vm", vm.Name, "type", hspec.Type, "target", hspec.Target)

	default:
		slog.Warn("vmcheck: unknown action", "action", action, "vm", vm.Name)
	}
}

// migrateVM picks a healthy target host and live-migrates the VM there.
// Prefers the full MigrateVM RPC path (via callback) which handles all
// post-migration steps (GARP, LB, FDB, DNS, network provisioning).
func (v *VMChecker) migrateVM(ctx context.Context, vm corrosion.VMRecord) {
	// Find a healthy target host.
	target, err := v.pickMigrationTarget(ctx, vm.HostName, vm.MemActual)
	if err != nil {
		slog.Error("vmcheck: no migration target available", "vm", vm.Name, "error", err)
		if werr := corrosion.UpdateVMState(ctx, v.db, vm.Name, "error", "health check failed, no migration target available"); werr != nil {
			v.noteStateWriteFail(corrosion.OpVMState, werr)
		}
		return
	}

	slog.Info("vmcheck: migrating VM", "vm", vm.Name, "from", v.hostName, "to", target.Name)

	// Use the full MigrateVM RPC path if available — it handles GARP, LB refresh,
	// FDB updates, DNS, and network provisioning on the target.
	if v.migrateVMFunc != nil {
		if err := v.migrateVMFunc(ctx, vm.Name, target.Name); err != nil {
			slog.Error("vmcheck: migration via RPC failed", "vm", vm.Name, "target", target.Name, "error", err)
			return
		}
		v.publish("vm.health.migrated", vm.Name, fmt.Sprintf("from=%s to=%s", v.hostName, target.Name))
		slog.Info("vmcheck: VM migrated successfully via RPC", "vm", vm.Name, "to", target.Name)
		return
	}

	// Fallback: direct libvirt migration (no post-migration steps).
	if v.virt == nil {
		slog.Error("vmcheck: migrate action requires libvirt or migrate callback", "vm", vm.Name)
		return
	}
	// It carries no firmware state: a Secure Boot / vTPM VM is moved by
	// `lv migrate` only (spec §12). Refused before the row is touched.
	if spec := (&pb.VMSpec{}); json.Unmarshal([]byte(vm.Spec), spec) == nil && (spec.SecureBoot || spec.Tpm) {
		slog.Error("vmcheck: the health-check migrate fallback does not move a Secure Boot / vTPM VM; it stays here",
			"vm", vm.Name, "target", target.Name)
		return
	}
	// Nor a VM with a trunk NIC: its VLANs live on its taps, and this
	// fallback neither hands the guest over paused nor asks the target to
	// put them on, so an access NIC would run on the target's VLAN 1. A
	// spec that cannot be read is refused the same way.
	if spec := (&pb.VMSpec{}); json.Unmarshal([]byte(vm.Spec), spec) != nil || specHasTrunkNIC(spec) {
		slog.Error("vmcheck: the health-check migrate fallback does not move a VM with a trunk: NIC (or an unreadable spec); it stays here",
			"vm", vm.Name, "target", target.Name)
		return
	}

	if err := corrosion.UpdateVMState(ctx, v.db, vm.Name, "migrating", fmt.Sprintf("health check → %s", target.Name)); err != nil {
		v.noteStateWriteFail(corrosion.OpVMState, err)
	}

	dconnuri := fmt.Sprintf("qemu+tls://%s/system", corrosion.URIHost(target.Address))
	if err := v.virt.MigrateToTarget(vm.Name, dconnuri, lv.MigrateParams{Live: true, SharesWeight: v.sharesWeightOf(vm)}); err != nil {
		slog.Error("vmcheck: migration failed", "vm", vm.Name, "target", target.Name, "error", err)
		// A LOCAL publish, unlike the successful handoff below, which repoints the
		// row to another host while running on this one.
		//
		// No DomainState guard here, unlike migrate.go's twin: a migration that
		// failed after libvirt destroyed the source domain makes the domain-marker
		// write fail, and writeBothMarkers publishes on the strength of the file
		// marker instead of refusing. The state-detail write is what matters on
		// this path and it is no longer gated on a domain that may be gone.
		if werr := v.publishRunning(ctx, vm.Name, "running", func(ctx context.Context) error {
			return corrosion.UpdateVMState(ctx, v.db, vm.Name, "running", fmt.Sprintf("migration to %s failed: %v", target.Name, err))
		}); werr != nil {
			v.noteStateWriteFail(corrosion.OpVMState, werr)
		}
		return
	}

	// The domain has already moved to the target; the ownership write MUST land or
	// the source row strands a VM it no longer runs (dual/stale ownership). Retry
	// briefly to absorb a transient error before giving up to the reconciler.
	var werr error
	for attempt := 0; attempt < 4; attempt++ {
		// Phase 4: the post-migration re-home is an ownership transition —
		// fresh-read CAS + epoch increment. Re-reading inside the retry loop
		// keeps a transient CAS loss (a concurrent transition) retryable.
		//runningcheck:allow ownership handoff — names target.Name while running on this
		// host, whose domain the migration has undefined. The destination marks its own.
		if werr = corrosion.TransferVMOwnerFresh(ctx, v.db, vm.Name, target.Name, "running"); werr == nil {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
	}
	if werr != nil {
		slog.Error("vmcheck: post-migration ownership write failed after retries — VM stranded on source row; reconciler must resolve",
			"vm", vm.Name, "to", target.Name, "error", werr)
		v.noteStateWriteFail(corrosion.OpVMHost, werr)
		return
	}
	// The VM may now run on its own replica target: replicate back to this host.
	// (The RPC path above switches it in MigrateVM's own finish.)
	corrosion.ReverseReplicationAudited(ctx, v.db, "vm", vm.Name, "", v.hostName, target.Name, func(detail, result string) {
		auditSystem(ctx, v.db, v.hostName, "replication.reverse", vm.Name, detail, result)
	})
	v.publish("vm.health.migrated", vm.Name, fmt.Sprintf("from=%s to=%s", v.hostName, target.Name))
	slog.Info("vmcheck: VM migrated successfully", "vm", vm.Name, "to", target.Name)
}

// pickMigrationTarget finds an active host other than the current one,
// preferring the host with the most free memory. Validates the target
// has enough free memory for the VM (#2).
func (v *VMChecker) pickMigrationTarget(ctx context.Context, excludeHost string, vmMemMiB int) (*corrosion.HostRecord, error) {
	hosts, err := corrosion.ListHosts(ctx, v.db)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}

	// Compute per-host memory usage by summing running VM allocations.
	vms, _ := corrosion.ListVMs(ctx, v.db, "", "")
	memUsed := map[string]int{}
	for _, vm := range vms {
		if vm.State == "running" || vm.State == "creating" || vm.State == "starting" {
			memUsed[vm.HostName] += vm.MemActual
		}
	}

	var best *corrosion.HostRecord
	var bestFree int
	for i := range hosts {
		h := &hosts[i]
		if h.Name == excludeHost || h.State != "active" {
			continue
		}
		free := h.MemTotal - memUsed[h.Name]
		// Only consider hosts with enough free memory for the VM.
		if vmMemMiB > 0 && free < vmMemMiB {
			continue
		}
		if best == nil || free > bestFree {
			best = h
			bestFree = free
		}
	}

	if best == nil {
		return nil, fmt.Errorf("no active hosts available with sufficient memory")
	}
	return best, nil
}

// maybeRestartVM checks if a stopped/error VM has a restart policy and attempts restart.
func (v *VMChecker) maybeRestartVM(ctx context.Context, vm corrosion.VMRecord, now time.Time) {
	spec := vmSpecFromDB(ctx, v.db, vm.Name)
	if spec == nil || spec.Restart == nil {
		return
	}
	rp := spec.Restart

	// Decide whether to restart based on WHY the VM stopped — not merely that it
	// is "stopped" (a crash also lands there). Prefer the live libvirt shutoff
	// reason (authoritative); fall back to the persisted state_detail when
	// libvirt is unreachable. A suspended VM (managed-save) is never cold-booted.
	// restartDecision holds the full matrix; "guest-stick" means a clean guest
	// shutdown / operator stop never restarts under any condition.
	cause := ""
	hasManagedSave := false
	if v.virt != nil {
		if st, err := v.virt.DomainStateReason(vm.Name); err == nil {
			cause = st.Reason
		}
		if ms, err := v.virt.HasManagedSaveImage(vm.Name); err == nil {
			hasManagedSave = ms
		}
	}
	ok, decision := restartDecision(cause, vm.StateDetail, hasManagedSave, rp.Condition)
	if !ok {
		slog.Debug("vmcheck: not restarting per policy", "vm", vm.Name, "decision", decision)
		return
	}

	// Check restart state from DB.
	rs, err := corrosion.GetRestartState(ctx, v.db, vm.Name)
	if err != nil {
		slog.Error("vmcheck: get restart state", "vm", vm.Name, "error", err)
		return
	}

	window := parseDuration(rp.Window, time.Hour)
	delay := parseDuration(rp.Delay, 5*time.Second)

	// If window has elapsed, reset the counter.
	if rs != nil && !rs.WindowStart.IsZero() && now.Sub(rs.WindowStart) > window {
		_ = corrosion.ResetRestartState(ctx, v.db, vm.Name)
		rs = nil
	}

	// Check max_attempts within the window.
	if rp.MaxAttempts > 0 && rs != nil && rs.AttemptCount >= int(rp.MaxAttempts) {
		slog.Warn("vmcheck: restart max attempts reached", "vm", vm.Name,
			"attempts", rs.AttemptCount, "max", rp.MaxAttempts)
		return
	}

	// Check delay since last restart.
	if rs != nil && !rs.LastRestart.IsZero() && now.Sub(rs.LastRestart) < delay {
		return
	}

	// Self-fence is an UNCONDITIONAL hard gate (independent of enforcement): a doomed
	// node must not restart a VM per restart-policy during its fence-timeout window.
	if selfFenceHardGate(v.gate) {
		slog.Info("vmcheck: self-fenced — refusing restart-policy start", "vm", vm.Name)
		v.noteGateRefused(corrosion.ActionReschedule, ReasonSelfFenced)
		return
	}
	// Split-brain gate (Phase 1): a restart-policy start is a runtime action; once
	// enforced it needs local quorum, so an isolated host with stale local ownership
	// can't restart-into a double-run. Fail-open until latched.
	if v.gate != nil && v.gate.Enforced(ctx, capabilities.SplitBrainGateV1) {
		if g := v.gate.ExecutionGate(ctx); !g.OK {
			slog.Info("vmcheck: execution gate refused restart (no quorum)", "vm", vm.Name, "reason", g.Reason)
			v.noteGateRefused(corrosion.ActionReschedule, g.Reason)
			return
		}
	}

	// Ownership, three ways — this path had none of them, while every sibling
	// start path has at least one.
	//
	// ExecutionGate above proves QUORUM, not ownership, and a rejoined node
	// holding a stale replica is exactly the case that has quorum. Ownership
	// used to be consulted only afterwards by publishRunning, which declines to
	// publish once the guest is already booted — by which point a second QEMU is
	// writing to the same disk.
	//
	// 1. Re-read the row. The snapshot this call was handed may be minutes old.
	fresh, ferr := corrosion.GetVM(ctx, v.db, vm.Name)
	if ferr != nil {
		slog.Warn("vmcheck: restart-policy ownership re-read failed — not restarting",
			"vm", vm.Name, "error", ferr)
		return
	}
	if fresh == nil {
		slog.Info("vmcheck: restart-policy skipped — VM record is gone", "vm", vm.Name)
		return
	}
	if fresh.HostName != v.hostName {
		slog.Info("vmcheck: restart-policy skipped — VM no longer owned by this host",
			"vm", vm.Name, "owner", fresh.HostName)
		return
	}
	// An operator's forced stop made here under write quarantine and not
	// yet recorded (operator_stop_marker.go): no lease taken, no attempt
	// counted. healthRestart asks again under the VM's lock.
	if operatorStopHeld("vmcheck", v.dataDir, v.hostName, fresh) {
		return
	}

	// 2. Take the per-VM lease, so this host's own reconciler cannot start the
	// same VM concurrently. Its comment is the reason: "the same physical disk
	// gets two QEMU writers -> guaranteed corruption".
	//
	// Under vmcheckLockHolder, NOT the bare host name. The upsert admits
	// `holder = excluded.holder` so a component can re-take its own lease
	// across passes; sharing the host name with the reconciler made that
	// clause match ITS lease too, so this path acquired a lease held for a
	// start already in flight and then freed it on the way out.
	holder := vmcheckLockHolder(v.hostName)
	if !acquireVMLockFor(ctx, v.db, holder, vm.Name, time.Now()) {
		slog.Info("vmcheck: restart-policy skipped — vm_lock held elsewhere", "vm", vm.Name)
		return
	}
	defer releaseVMLockFor(ctx, v.db, holder, vm.Name)

	// 3. Refuse a runtime this cluster has superseded. The row can still name us
	// while the owner epoch has moved on, which is what the self-heal path
	// checks. Readable here because the domain still exists — we are about to
	// destroy and restart it — unlike the post-undefine case that forces the
	// reconciler to prefer its on-disk marker.
	if v.virt != nil {
		if marker, ok, merr := v.virt.GetDomainOwnerEpoch(vm.Name); merr == nil && ok &&
			fresh.OwnerEpoch > marker {
			slog.Info("vmcheck: restart-policy skipped — local runtime superseded",
				"vm", vm.Name, "domain_epoch", marker, "row_epoch", fresh.OwnerEpoch)
			return
		}
	}

	// Everything below acts on the FRESH record.
	vm = *fresh
	if v.fwSkips.skip(v.dataDir, vm.Name, specUUIDOf(vm.Spec), "restart policy") {
		return
	}

	// Perform restart.
	slog.Info("vmcheck: restarting VM per restart policy", "vm", vm.Name,
		"condition", rp.Condition, "state", vm.State)

	// The attempt is counted once the restart is going ahead: under the VM's
	// lock, the row re-read, before the destroy (healthRestart's onAct). A
	// pass skipped for a lock another operation holds (a backup, a snapshot,
	// a replication) uses no attempt and sets no delay: it is a deferral,
	// and the VM restarts on the first pass after the lock frees, instead of
	// the held passes exhausting the policy's attempts.
	countAttempt := func() {
		if err := corrosion.IncrementRestart(ctx, v.db, vm.Name); err != nil {
			slog.Error("vmcheck: increment restart counter", "vm", vm.Name, "error", err)
		}
	}
	if v.virt == nil {
		countAttempt() // no libvirt: the counter is the record of going ahead
		return
	}
	// One step under the VM's lock, the row read again under it: a VM a cold
	// move handed over, or an operator stopped, since the re-read above is
	// left alone.
	from, started, lockHeld := v.healthRestart(ctx, vm, "restart policy start", countAttempt)
	if lockHeld {
		v.publish("vm.restart.deferred", vm.Name,
			"another operation holds the VM's lock; the restart policy retries next pass, no attempt used")
		return
	}
	if !started {
		return
	}
	if err := v.publishRunning(ctx, vm.Name, "running", func(ctx context.Context) error {
		// Over the row the restart acted on, and no other.
		applied, err := corrosion.UpdateVMStateFrom(ctx, v.db, from.Name, from.HostName, from.State, "running", "restart policy: "+decision)
		if err != nil || applied {
			return err
		}
		return v.restartedRecordedMeanwhile(ctx, from.Name)
	}); err != nil {
		LogPublishRefusal("vmcheck: restart-policy state write failed — NOT publishing restart event", vm.Name, err)
		v.noteStateWriteFail(corrosion.OpVMState, err)
		return
	}
	v.publish("vm.restart.policy", vm.Name,
		fmt.Sprintf("condition=%s attempt=%d (%s)", rp.Condition, safeAttemptCount(rs)+1, decision))
}

func safeAttemptCount(rs *corrosion.RestartState) int {
	if rs == nil {
		return 0
	}
	return rs.AttemptCount
}

// vmCheckSpec extracts the HealthCheckSpec from a VMRecord's stored JSON spec.
func vmCheckSpec(vm *corrosion.VMRecord) *pb.HealthCheckSpec {
	if vm.Spec == "" {
		return nil
	}
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
		return nil
	}
	return spec.Healthcheck
}

// vmSpecFromDB loads the full VMSpec from a VM's stored JSON.
func vmSpecFromDB(ctx context.Context, db *corrosion.Client, vmName string) *pb.VMSpec {
	vm, err := corrosion.GetVM(ctx, db, vmName)
	if err != nil || vm == nil || vm.Spec == "" {
		return nil
	}
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
		return nil
	}
	return spec
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}

// sharesWeightOf is the VM's cpu-shares weight in the user's scale, carried to
// a direct libvirt migration, by the same rule as the RPC path's
// Server.vmSharesWeight: the stored weight, else the default when the domain
// carries a <shares> (a cleared weight), else 0. This fallback has no peer to
// ask for the target's cgroup version, so it retargets nothing on its own; the
// RPC path (migrateVMFunc), which production wires, does.
func (v *VMChecker) sharesWeightOf(vm corrosion.VMRecord) int {
	spec := &pb.VMSpec{}
	if vm.Spec != "" && json.Unmarshal([]byte(vm.Spec), spec) == nil && spec.GetCpuShares() > 0 {
		return int(spec.GetCpuShares())
	}
	if d, ok := v.virt.(interface{ DumpXML(string) (string, error) }); ok {
		if x, err := d.DumpXML(vm.Name); err == nil && strings.Contains(x, "<shares>") {
			return lv.DefaultCPUWeight()
		}
	}
	return 0
}

// startGuarded starts name's domain under the shared-disk release check
// (GuardSharedDiskStart, review c2b).
func (v *VMChecker) startGuarded(ctx context.Context, name string) error {
	if v.followNetworks != nil {
		v.followNetworks(ctx, name)
	}
	xml, xerr := "", errors.New("no persistent config reader")
	if d, ok := v.virt.(interface {
		DumpXMLInactive(string) (string, error)
	}); ok {
		xml, xerr = d.DumpXMLInactive(name)
	}
	// A volume move this host left unresolved (move_unresolved.go).
	if err := ResolveUnresolvedMoves(ctx, v.db, v.dataDir, v.hostName, name, MoveDomain{
		InactiveXML: func() (string, error) { return xml, xerr },
		State:       func() (string, error) { return v.virt.DomainState(name) },
	}); err != nil {
		return err
	}
	noteStartingHere(ctx, v.db, v.dataDir, name)
	release, err := GuardSharedDiskStart(ctx, v.db, v.dataDir, v.hostName, name, xml)
	if err != nil {
		return err
	}
	defer release()
	return v.virt.StartDomain(name)
}

// haHoldsHealthAction says why an automatic health-check restart or migrate
// is held ("" when it is not): cluster HA is disarmed, or the policy cannot be
// read.
func haHoldsHealthAction(ctx context.Context, db *corrosion.Client) string {
	p, err := corrosion.GetHAPolicy(ctx, db)
	switch {
	case err != nil && !errors.Is(err, corrosion.ErrUnreadableHAPolicy):
		return "the cluster HA policy could not be read: " + err.Error()
	case p.Unreadable:
		return "the cluster HA policy cannot be read"
	case p.Disarmed():
		return "cluster HA is disarmed (lv cluster ha)"
	}
	return ""
}

// specHasTrunkNIC reports whether spec has a NIC on the `trunk:` feature.
func specHasTrunkNIC(spec *pb.VMSpec) bool {
	for _, n := range spec.GetNetwork() {
		if len(n.GetTrunk()) > 0 {
			return true
		}
	}
	return false
}
