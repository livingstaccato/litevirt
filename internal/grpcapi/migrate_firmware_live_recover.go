package grpcapi

// Restart recovery of a live firmware move on its source (spec §8.1,
// RecoverFirmwareMoves). At daemon start every marker is taken under its VM's
// lock, before the gRPC server serves, and its move is resumed, parked or
// aborted by the phase it records and what the source observes now. Every
// minute after, each marker whose VM no move holds is taken the same way: a
// parked move re-raises its condition and retries its blocked call, a move
// parked unreachable is resolved by fence when the spec allows it (§7), and
// each owed DISCARD is sent again.
//
// Nothing here decides anything the in-process move would not: the same steps
// run (Abort before cutover, M1 and M1p, cutover and Verify, the commit,
// Release, the cleanup), and every outcome other than the happy flow keeps
// both copies. A record that cannot be read is skipped with its own
// condition (firmware_migration_record_unreadable), and its guard keeps
// refusing.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
)

// Timing of the recovery; vars so tests can shorten them.
var (
	// firmwareRecoveryInterval is how often a parked move's blocked call is
	// retried, and any marker no move holds is taken again (§8.1).
	firmwareRecoveryInterval = time.Minute
	// firmwareRecoveryCatchUpWait bounds how long the start-up recovery of a
	// marker waits for this host's replica to catch up before it reads the
	// VM's row; a marker still waiting is left to the next pass.
	firmwareRecoveryCatchUpWait = 2 * time.Minute
	// firmwareRecoveryJobPoll is how often a migration job libvirt still runs
	// after a restart is looked at.
	firmwareRecoveryJobPoll = 2 * time.Second
	// firmwareRecoveryParallel bounds how many moves the recovery takes at
	// once.
	firmwareRecoveryParallel = 8
)

// errFirmwareMoveRecovered is the "migration error" of a move found after a
// restart with its source domain active and no migration job: the migration
// failed or never reached libvirt (§7 M1, M1p).
var errFirmwareMoveRecovered = errors.New("found after a daemon restart with the source domain active and no migration job")

// RecoverFirmwareMoves is §8.1 at daemon start, right after the operation
// journal's recovery and before the runtime loops start (review D2-13 m-2).
// It sweeps the temp files crashed record writes left, takes each marker's
// VM lock, so nothing else acts on the move first, and recovers each locked
// move in its own goroutine, which releases the lock once the move is
// resolved or parked. It reads the VM's row only from a replica that has
// caught up, and leaves a move whose replica does not catch up within
// firmwareRecoveryCatchUpWait to a later pass of RunFirmwareMoveRecovery.
// The work starts at once: a startup step that waits on one of these locks
// must not wait on a later step of the start.
func (s *Server) RecoverFirmwareMoves(ctx context.Context) {
	if err := s.fwRecords().SweepTemps(); err != nil {
		slog.Warn("live firmware move recovery: the temp files of crashed record writes cannot be swept", "error", err)
	}
	var locked []pendingFirmwareRecovery
	for _, vm := range s.firmwareMarkerVMs() {
		locked = append(locked, pendingFirmwareRecovery{vm: vm, unlock: s.lockVM(vm)})
	}
	s.startLockedFirmwareRecoveries(ctx, locked)
}

// RunFirmwareMoveRecovery starts a recovery pass every
// firmwareRecoveryInterval until ctx is done.
func (s *Server) RunFirmwareMoveRecovery(ctx context.Context) {
	s.dbWorkerEvent(ctx, "firmware_recovery", "entry")
	defer s.dbWorkerEvent(ctx, "firmware_recovery", "exit")
	t := time.NewTicker(firmwareRecoveryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.startFirmwareMoveRecoveryPass(ctx)
	}
}

// startLockedFirmwareRecoveries starts the recovery of each move
// RecoverFirmwareMoves locked, and one send of the owed DISCARDs.
func (s *Server) startLockedFirmwareRecoveries(ctx context.Context, locked []pendingFirmwareRecovery) {
	for _, p := range locked {
		s.fwLive.recovering.Add(1)
		go func(p pendingFirmwareRecovery) {
			defer s.fwLive.recovering.Done()
			defer p.unlock()
			// Locked from the journal barrier, recovered only once every
			// setter has run (review D2-13 N-1): the finish reads what they
			// set.
			if !s.waitStartupWired(ctx) {
				return
			}
			if !s.takeRecoverySlot(ctx, true) {
				return
			}
			defer s.releaseRecoverySlot()
			if !s.waitReplicaCaughtUp(ctx, firmwareRecoveryCatchUpWait) {
				slog.Warn("live firmware move recovery: the replica has not caught up; the move is taken on a later pass", "vm", p.vm)
				return
			}
			s.recoverFirmwareMoveLocked(ctx, p.vm, true)
		}(p)
	}
	// The owed DISCARDs wait for the replica too: an empty or reseeded one
	// would read the target host as gone and drop the record (review m-6).
	s.fwLive.recovering.Add(1)
	go func() {
		defer s.fwLive.recovering.Done()
		if s.waitStartupWired(ctx) && s.waitReplicaCaughtUp(ctx, firmwareRecoveryCatchUpWait) {
			s.dbWorkerEvent(ctx, "firmware_startup_discard", "entry")
			defer s.dbWorkerEvent(ctx, "firmware_startup_discard", "exit")
			s.sendOwedFirmwareDiscards(ctx)
		}
	}()
}

// MarkStartupWired is called by the daemon once every late setter has run:
// the start-up recovery, locked earlier, then goes on.
func (s *Server) MarkStartupWired() {
	ch := s.startupWiredCh()
	s.fwLive.recoveryMu.Lock()
	defer s.fwLive.recoveryMu.Unlock()
	select {
	case <-ch:
	default:
		close(ch)
	}
}

func (s *Server) startupWiredCh() chan struct{} {
	s.fwLive.recoveryMu.Lock()
	defer s.fwLive.recoveryMu.Unlock()
	if s.fwLive.wired == nil {
		s.fwLive.wired = make(chan struct{})
	}
	return s.fwLive.wired
}

// waitStartupWired waits for MarkStartupWired, or ctx.
func (s *Server) waitStartupWired(ctx context.Context) bool {
	select {
	case <-s.startupWiredCh():
		return true
	case <-ctx.Done():
		return false
	}
}

// WaitFirmwareMoveRecovery joins only already-admitted recovery and owed-
// DISCARD children. Callers must first stop and join every recovery producer,
// including the startup caller. Unlike FirmwareMoveRecoveryOnce, this starts
// no pass. Dependencies must stay open until it returns.
func (s *Server) WaitFirmwareMoveRecovery() {
	s.fwLive.recovering.Wait()
}

// FirmwareMoveRecoveryOnce is one recovery pass, waited for, then the
// sweep of the vm.migration_unresolved conditions the pass may have settled.
func (s *Server) FirmwareMoveRecoveryOnce(ctx context.Context) {
	s.startFirmwareMoveRecoveryPass(ctx)
	s.fwLive.recovering.Wait()
	s.ResolveSettledMigrationsOnce(ctx)
}

// startFirmwareMoveRecoveryPass takes each marker whose VM's lock is free (a
// move in progress holds it, and is left alone) as at start, except a
// cleaning one, which the cleanup retry takes, each in its own goroutine and
// at most firmwareRecoveryParallel at once, so one move that waits does not
// hold up the others; then sends each owed DISCARD. Nothing is decided from a
// replica that has not caught up. Each pass first resolves the
// vm.migration_unresolved conditions settled since the last
// (ResolveSettledMigrationsOnce).
func (s *Server) startFirmwareMoveRecoveryPass(ctx context.Context) {
	s.dbWorkerEvent(ctx, "firmware_recovery", "pass")
	if s.db != nil {
		if ok, why := s.db.ReplicaCaughtUp(); !ok {
			slog.Debug("live firmware move recovery: waiting for the replica to catch up", "why", why)
			return
		}
	}
	s.ResolveSettledMigrationsOnce(ctx)
	for _, vm := range s.firmwareMarkerVMs() {
		unlock, ok := s.tryLockVM(vm)
		if !ok {
			continue
		}
		if !s.takeRecoverySlot(ctx, false) {
			unlock() // every slot busy: the next pass takes it
			continue
		}
		s.fwLive.recovering.Add(1)
		go func(vm string) {
			defer s.fwLive.recovering.Done()
			defer unlock()
			defer s.releaseRecoverySlot()
			s.recoverFirmwareMoveLocked(ctx, vm, false)
		}(vm)
	}
	s.fwLive.recovering.Add(1)
	go func() {
		defer s.fwLive.recovering.Done()
		s.dbWorkerEvent(ctx, "firmware_periodic_discard", "entry")
		defer s.dbWorkerEvent(ctx, "firmware_periodic_discard", "exit")
		s.sendOwedFirmwareDiscards(ctx)
	}()
	s.ResolveFirmwareVFMissingOnce(ctx)
}

// ResolveFirmwareVFMissingOnce judges each open firmware_migration_vf_missing
// condition (review D2-13 N-3), on the host the VM's row names, as the guest
// is now: resolved when the VM is deleted, has moved off the host the
// condition named, is not running, or runs with at least as many VFs it owns
// here in the guest as were missing. Anything unreadable leaves it.
func (s *Server) ResolveFirmwareVFMissingOnce(ctx context.Context) {
	if s.db == nil {
		return
	}
	conds, err := corrosion.ListOpenHealthConditionsByCode(ctx, s.db, firmwareMigrationEvaluator, condFwmigVFMissing)
	if err != nil {
		slog.Debug("live firmware move: the VF-missing conditions cannot be listed", "error", err)
		return
	}
	for _, c := range conds {
		if c.SubjectKind != "vm" {
			continue
		}
		// A condition raised by a build before vfs_wanted was recorded has
		// none, and resolves on the next look (unreleased: no backfill).
		var ev struct {
			RunsOn    string   `json:"runs_on"`
			VFs       []string `json:"vfs"`
			VFsWanted int      `json:"vfs_wanted"`
		}
		vm := c.SubjectID
		if err := json.Unmarshal([]byte(c.Evidence), &ev); err != nil {
			slog.Debug("live firmware move: VF-missing left open: its evidence cannot be read", "vm", vm, "error", err)
			continue
		}
		// A move in progress (or its recovery) decides its VM's condition
		// itself: one it just raised is not resolved under it.
		unlock, ok := s.tryLockVM(vm)
		if !ok {
			slog.Debug("live firmware move: VF-missing left open: the VM is locked", "vm", vm)
			continue
		}
		s.judgeFirmwareVFMissing(ctx, vm, ev.RunsOn, ev.VFs, ev.VFsWanted)
		unlock()
	}
}

// judgeFirmwareVFMissing is ResolveFirmwareVFMissingOnce for one VM, under its
// lock.
func (s *Server) judgeFirmwareVFMissing(ctx context.Context, vm, runsOn string, vfs []string, wanted int) {
	row, err := corrosion.GetVM(ctx, s.db, vm)
	if err != nil {
		slog.Debug("live firmware move: VF-missing left open: the VM's row cannot be read", "vm", vm, "error", err)
		return
	}
	why := ""
	switch {
	case row == nil:
		why = "the VM was deleted"
	case runsOn != "" && row.HostName != runsOn:
		why = "the VM moved to " + row.HostName
	case row.HostName != s.hostName:
		slog.Debug("live firmware move: VF-missing left to the host the VM's row names", "vm", vm, "host", row.HostName)
		return
	default:
		want := wanted
		if want < len(vfs) {
			want = len(vfs)
		}
		why = s.firmwareVFsBack(ctx, vm, want)
	}
	if why == "" {
		return
	}
	if err := s.resolveFirmwareMigrationCondition(ctx, condFwmigVFMissing, vm); err == nil {
		slog.Info("live firmware move: the VF-missing condition is resolved", "vm", vm, "why", why)
	}
}

// firmwareVFsBack says why vm, whose row names this host, no longer misses
// VFs: its domain is shut off, or it runs with at least want of the VFs it
// owns here in the guest. "" is still missing (paused or pm-suspended
// included), or unknown.
func (s *Server) firmwareVFsBack(ctx context.Context, vm string, want int) string {
	if s.virt == nil {
		return ""
	}
	// Only an inactive (shut off) domain no longer misses its VFs: a paused
	// or pm-suspended guest resumes with what it has (re-review 2 I-B).
	active, err := s.virt.DomainIsActive(vm)
	switch {
	case err != nil:
		slog.Debug("live firmware move: VF-missing left open: whether the domain is active cannot be read", "vm", vm, "error", err)
		return ""
	case !active:
		return "the VM is shut off"
	}
	if st, err := s.sourceDomainState(vm); err != nil || st != "running" {
		slog.Debug("live firmware move: VF-missing left open: the guest is active but not running", "vm", vm, "state", st, "error", err)
		return ""
	}
	devs, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		slog.Debug("live firmware move: VF-missing left open: the PCI devices cannot be listed", "vm", vm, "error", err)
		return ""
	}
	in := 0
	for _, d := range devs {
		if d.VMName != vm {
			continue
		}
		if ok, err := s.liveHostdevPresent(vm, d.Address); err == nil && ok {
			in++
		}
	}
	if in < want {
		slog.Debug("live firmware move: VF-missing left open: VFs still missing", "vm", vm, "in_guest", in, "want", want)
		return ""
	}
	return fmt.Sprintf("the guest runs with %d VF(s) it owns here", in)
}

// sendOwedFirmwareDiscards is RetryOwedFirmwareDiscardsOnce, one at a time.
func (s *Server) sendOwedFirmwareDiscards(ctx context.Context) {
	s.fwLive.recoveryMu.Lock()
	if s.fwLive.owedRunning {
		s.fwLive.recoveryMu.Unlock()
		return
	}
	s.fwLive.owedRunning = true
	s.fwLive.recoveryMu.Unlock()
	defer func() {
		s.fwLive.recoveryMu.Lock()
		s.fwLive.owedRunning = false
		s.fwLive.recoveryMu.Unlock()
	}()
	s.RetryOwedFirmwareDiscardsOnce(ctx)
}

// takeRecoverySlot takes one of firmwareRecoveryParallel slots: waiting for
// one when wait is set (until ctx is done), else only if one is free.
func (s *Server) takeRecoverySlot(ctx context.Context, wait bool) bool {
	s.fwLive.recoverySlotsOnce.Do(func() {
		s.fwLive.recoverySlots = make(chan struct{}, firmwareRecoveryParallel)
	})
	if !wait {
		select {
		case s.fwLive.recoverySlots <- struct{}{}:
			return true
		default:
			return false
		}
	}
	select {
	case s.fwLive.recoverySlots <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *Server) releaseRecoverySlot() { <-s.fwLive.recoverySlots }

// firmwareMarkerVMs names the VM of each marker file on this host, read from
// the directory so that one marker that cannot be read holds up no other.
func (s *Server) firmwareMarkerVMs() []string {
	dir := filepath.Join(s.fw().DataDir, fwmig.InflightDir)
	ents, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("live firmware move recovery: the markers cannot be listed", "dir", dir, "error", err)
		}
		return nil
	}
	var vms []string
	for _, e := range ents {
		if vm, ok := strings.CutSuffix(e.Name(), ".json"); ok && e.Type().IsRegular() {
			vms = append(vms, vm)
		}
	}
	return vms
}

// waitReplicaCaughtUp waits up to d for this host's replica to catch up.
func (s *Server) waitReplicaCaughtUp(ctx context.Context, d time.Duration) bool {
	if s.db == nil {
		return true
	}
	deadline := time.Now().Add(d)
	for {
		if ok, _ := s.db.ReplicaCaughtUp(); ok {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Second):
		}
	}
}

// recoverFirmwareMoveLocked recovers vm's move; the caller holds lockVM(vm).
// The marker is read here, under that lock. startup is the pass at daemon
// start, which also redoes the source's part of a committed move's finish.
func (s *Server) recoverFirmwareMoveLocked(ctx context.Context, vm string, startup bool) {
	waitCtx := ctx
	if waitCtx.Err() != nil {
		return
	}
	ctx = context.WithoutCancel(ctx)
	worker := "firmware_periodic_child"
	if startup {
		worker = "firmware_startup_child"
	}
	s.dbWorkerEvent(ctx, worker, "entry")
	defer s.dbWorkerEvent(ctx, worker, "exit")
	m, ok, err := s.fwRecords().GetMarker(vm)
	if err != nil {
		// firmware_migration_record_unreadable names the file; the guard
		// keeps refusing while it cannot be read.
		slog.Warn("live firmware move recovery: the marker cannot be read; it is left", "vm", vm, "error", err)
		return
	}
	if !ok {
		return
	}
	if m.CapacityLease != "" {
		// The process that took the move's admission lease died holding it,
		// or could not release it: a move clears it from the marker once it
		// released it (review m4).
		// This pass holds it in that process's place, and releases it when
		// it ends, as the move releases it when it returns (lab2-D2-proof
		// F8). One that cannot be released is tried again by the next pass.
		defer s.releaseDeadMoveLease(ctx, m)
	}
	if m.Phase == fwmig.PhaseCleaning && !startup {
		return // RetryLiveFirmwareCleanupsOnce takes it
	}
	r := s.recoveredFirmwareRun(ctx, m)
	r.waitCtx = waitCtx
	if noRetryPark(m.Phase) {
		s.reraiseParkedCondition(ctx, m)
		return
	}
	vfs, verr := s.recoveredMoveVFs(ctx, vm)
	if verr != nil && movePhaseBeforeRelease(m) {
		// The guest is never run (resumed here or released there) without
		// the VFs detached for the move: the move waits until they can be
		// read.
		if m.Phase.Parked() {
			r.parked = m
			r.marker.Phase, r.marker.ParkedFrom, r.marker.Detail = m.ParkedFrom, "", ""
		}
		if s.opJournal == nil {
			r.parkAction = "both copies of the firmware state are kept, and the guest is not run: this host's operation journal did not open (see the daemon log), " +
				"so the VFs the move detached cannot be known; repair <data_dir>/opjournal and restart the daemon, and the move is retried each minute"
		}
		_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourceStateMissing,
			fmt.Sprintf("the SR-IOV VFs detached for the move cannot be read on %s: %v", s.hostName, verr))
		if m.Phase.Parked() {
			s.settleRetriedPark(ctx, m)
		}
		return
	}
	if verr != nil {
		slog.Warn("live firmware move recovery: the VFs detached for the move cannot be read; the released move goes on without them", "vm", vm, "error", verr)
	}
	r.vfs = vfs
	if m.Phase.Parked() {
		s.retryParkedFirmwareMove(ctx, r)
		return
	}
	slog.Info("live firmware move recovery: resuming", "vm", vm, "attempt", m.Attempt, "target", m.Target, "phase", m.Phase, "vfs", len(vfs))
	// An unparked marker with its lock free was left by a process that died:
	// a committed one redoes the whole finish, the target's VF attach with it
	// (review D2-13 N-4).
	s.recoverFirmwareMoveFrom(ctx, r, m.Phase, true)
}

// releaseDeadMoveLease releases m's admission lease on its holder, which the
// process that took it can no longer release, and drops it from the marker
// when the marker of m's attempt is still there. A lease already gone is
// released. One that cannot be released stays in the marker for the next
// pass, and the stale-lease sweep collects it in any case.
func (s *Server) releaseDeadMoveLease(ctx context.Context, m fwmig.Marker) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
	defer cancel()
	var err error
	if m.CapacityLeaseHolder == "" || m.CapacityLeaseHolder == s.hostName {
		err = corrosion.AppendOperationStep(rctx, s.db, corrosion.OperationStepRecord{
			OperationID: m.CapacityLease, StepName: corrosion.OpStepCompleted})
	} else {
		err = s.releaseRemoteHostLease(rctx, m.CapacityLeaseHolder, m.CapacityLease)
	}
	if err != nil && status.Code(err) != codes.NotFound {
		slog.Warn("live firmware move recovery: the admission lease still named in the marker (its move's process died, or its release failed) was not released; the next pass tries again, and the stale-lease sweep collects it",
			"vm", m.VM, "attempt", m.Attempt, "lease", m.CapacityLease, "holder", m.CapacityLeaseHolder, "error", err)
		return
	}
	slog.Info("live firmware move recovery: released the admission lease still named in the marker (its move's process died, or its release failed)",
		"vm", m.VM, "attempt", m.Attempt, "lease", m.CapacityLease, "holder", m.CapacityLeaseHolder)
	s.clearMarkerLease(m.VM, m.Attempt)
}

// clearMarkerLease drops the admission lease from vm's marker of attempt,
// once it was released.
func (s *Server) clearMarkerLease(vm, attempt string) {
	cur, ok, gerr := s.fwRecords().GetMarker(vm)
	if gerr != nil || !ok || cur.Attempt != attempt || cur.CapacityLease == "" {
		return
	}
	cur.CapacityLease, cur.CapacityLeaseHolder = "", ""
	if perr := s.fwRecords().PutMarker(cur); perr != nil {
		slog.Warn("live firmware move: the released lease stays named in the marker", "vm", vm, "error", perr)
	}
}

// noRetryPark reports a park that takes no further step (§8.1 amendment
// 2026-10-17): only its condition is re-raised.
func noRetryPark(p fwmig.Phase) bool {
	return p == fwmig.PhaseTargetRan || p == fwmig.PhaseSourcePaused || p == fwmig.PhaseSourceStateSuspect
}

// movePhaseBeforeRelease reports whether m's move, parked or not, is before
// released: the guest has yet to run again here or there.
func movePhaseBeforeRelease(m fwmig.Marker) bool {
	p := m.Phase
	if p.Parked() {
		p = m.ParkedFrom
	}
	return p != fwmig.PhaseReleased && p != fwmig.PhaseCleaning
}

// recoveredFirmwareRun is the run of a move this process did not start (or
// one a pass retries): its target as the hosts table has it, each call one
// attempt.
func (s *Server) recoveredFirmwareRun(ctx context.Context, m fwmig.Marker) *liveFirmwareRun {
	r := &liveFirmwareRun{target: corrosion.HostRecord{Name: m.Target}, marker: m, prepared: m.Since, oneAttempt: true}
	if s.db != nil {
		if h, err := corrosion.GetHost(ctx, s.db, m.Target); err == nil && h != nil {
			r.target = *h
		}
	}
	return r
}

// recoveredMoveVFs are the SR-IOV VFs the move detached from the guest, as
// its migration_detached device lease names them (review D2-13 I-1); the
// firmware recovery owns that lease while the VM has a marker
// (RecoverDeviceLeases leaves it). No lease is no VF. With no operation
// journal no lease was written, so a VM that owns any PCI device here is not
// known to have its VFs: an error, as is anything unreadable.
func (s *Server) recoveredMoveVFs(ctx context.Context, vm string) ([]corrosion.PCIDeviceRecord, error) {
	if s.db == nil {
		return nil, nil
	}
	devs, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		return nil, fmt.Errorf("list this host's PCI devices: %w", err)
	}
	if s.opJournal == nil {
		for _, d := range devs {
			if d.VMName == vm {
				return nil, fmt.Errorf("the VM owns PCI device %s here, and with no operation journal there is no lease to say whether the move detached it", d.Address)
			}
		}
		return nil, nil
	}
	e, found, err := s.opJournal.Read(deviceLeaseOpID(vm))
	if err != nil {
		return nil, fmt.Errorf("read the VM's device lease: %w", err)
	}
	if !found || e.Stage != deviceLeaseStageMigrationDetached {
		return nil, nil
	}
	byAddr := map[string]corrosion.PCIDeviceRecord{}
	for _, d := range devs {
		byAddr[d.Address] = d
	}
	var vfs []corrosion.PCIDeviceRecord
	for _, a := range splitCSVNonEmpty(e.Artifacts["addresses"]) {
		d, ok := byAddr[a]
		if !ok {
			return nil, fmt.Errorf("VF %s, named by the VM's migration lease, has no device row on %s", a, s.hostName)
		}
		vfs = append(vfs, d)
	}
	return vfs, nil
}

// noteSourceVFs raises firmware_migration_vf_missing when the source guest runs
// without a VF the move detached from it, and resolves it once none is
// missing.
func (s *Server) noteSourceVFs(ctx context.Context, r *liveFirmwareRun) {
	if len(r.vfs) == 0 || s.virt == nil {
		return
	}
	if st, err := s.sourceDomainState(r.marker.VM); err != nil || st != "running" {
		return
	}
	var missing []string
	for _, vf := range r.vfs {
		if in, err := s.liveHostdevPresent(r.marker.VM, vf.Address); err != nil || !in {
			missing = append(missing, vf.Address)
		}
	}
	s.noteFirmwareMoveVFsMissing(ctx, r.marker, s.hostName, missing, len(r.vfs))
}

// noteFirmwareMoveVFsMissing raises (missing set) or resolves the condition
// that m's guest runs on host without VFs it owns.
func (s *Server) noteFirmwareMoveVFsMissing(ctx context.Context, m fwmig.Marker, host string, missing []string, wanted int) {
	if len(missing) == 0 {
		_ = s.resolveFirmwareMigrationCondition(ctx, condFwmigVFMissing, m.VM)
		return
	}
	if err := s.raiseFirmwareMigrationCondition(ctx, fwmigCondition{
		Code: condFwmigVFMissing, VM: m.VM, Attempt: m.Attempt, Source: s.hostName, Target: m.Target,
		RunsOn: host, VFs: missing, VFsWanted: wanted,
		Detail: fmt.Sprintf("the guest runs on %s without the SR-IOV VFs %s it had before live firmware migration %s", host, strings.Join(missing, ", "), m.Attempt),
		Action: fmt.Sprintf("attach %d SR-IOV VF(s) to the guest on %s again, or restart it there so its devices are allocated again; "+
			"the condition clears on its own once the guest runs there with all %d of its VFs, or is stopped, deleted or moved", len(missing), host, wanted),
	}); err != nil {
		slog.Warn("live firmware move: raise the condition", "vm", m.VM, "code", condFwmigVFMissing, "error", err)
	}
}

// recoverFirmwareMoveFrom takes r's move on from phase, by §8.1's table.
// finish is whether a committed move redoes the source's part of the finish
// (the cluster's records of where the guest runs) before Release; a retry
// of a parked Release does not.
func (s *Server) recoverFirmwareMoveFrom(ctx context.Context, r *liveFirmwareRun, phase fwmig.Phase, finish bool) {
	switch phase {
	case fwmig.PhasePreparing, fwmig.PhasePrepared:
		s.recoverFirmwareMoveBeforeMigration(ctx, r)
	case fwmig.PhaseMigrating:
		s.recoverFirmwareMoveMigrating(ctx, r)
	case fwmig.PhaseCutover:
		s.recoverFirmwareMoveCutover(ctx, r)
	case fwmig.PhaseVerified:
		s.recoverFirmwareMoveVerified(ctx, r)
	case fwmig.PhaseCommitted:
		s.recoverFirmwareMoveCommitted(ctx, r, finish)
	case fwmig.PhaseReleased:
		s.recoverFirmwareMoveReleased(ctx, r)
	case fwmig.PhaseCleaning:
		// §6.7 resumed at its first undone step; a stop raises its own
		// condition and is retried.
		_ = s.fwmigCleanupSource(ctx, r.marker)
	}
}

// retryParkedFirmwareMove is §8.1 "other parked": the condition re-raised and
// the blocked call retried, from the phase the move was parked from.
//   - target_ran (the guard failed, V5), source_paused (both guests paused,
//     M1p) and source_state_suspect (the source copy may be stale or ran
//     again after the cutover, I6) take no further step: an operator
//     resolves them (D-5). A retry could only find the same answer, or carry
//     on from a comparison the park exists to distrust. Only the condition
//     is re-raised.
//   - target_unreachable and discard_pending are resolved by fence when §7
//     allows it.
//   - Every other park retries its blocked call. A retry that ends
//     unanswered keeps the park (D2-10 m-7), one that ends in the same park
//     with the same detail writes nothing, and one that leaves the park
//     resolves its condition.
func (s *Server) retryParkedFirmwareMove(ctx context.Context, r *liveFirmwareRun) {
	m := r.marker
	if noRetryPark(m.Phase) {
		s.reraiseParkedCondition(ctx, m)
		return
	}
	switch m.Phase {
	case fwmig.PhaseTargetUnreachable, fwmig.PhaseDiscardPending:
		resolved, err := s.resolveLiveFirmwareMoveByFenceLocked(ctx, m)
		if err != nil {
			slog.Warn("live firmware move recovery: fence resolution", "vm", m.VM, "attempt", m.Attempt, "error", err)
		}
		if resolved {
			return
		}
	}
	r.parked = m
	r.marker.Phase, r.marker.ParkedFrom, r.marker.Detail = m.ParkedFrom, "", ""
	s.recoverFirmwareMoveFrom(ctx, r, m.ParkedFrom, false)
	s.settleRetriedPark(ctx, m)
}

// reraiseParkedCondition raises a parked marker's condition again when it is
// not open with the marker's detail (§8.1).
func (s *Server) reraiseParkedCondition(ctx context.Context, m fwmig.Marker) {
	code, ok := fwmigConditionFor[m.Phase]
	if !ok || s.fwmigConditionOpenWith(ctx, code, m.VM, m.Detail) {
		return
	}
	s.raiseParkCondition(ctx, m, m.Phase, m.Detail, "")
}

// settleRetriedPark resolves the condition of the park orig once a retry
// moved the move out of it (on, resolved, or into a park of another code).
func (s *Server) settleRetriedPark(ctx context.Context, orig fwmig.Marker) {
	code, ok := fwmigConditionFor[orig.Phase]
	if !ok {
		return
	}
	cur, found, err := s.fwRecords().GetMarker(orig.VM)
	if err != nil {
		return
	}
	if found && cur.Attempt == orig.Attempt && cur.Phase.Parked() && fwmigConditionFor[cur.Phase] == code {
		return
	}
	if err := s.resolveFirmwareMigrationCondition(ctx, code, orig.VM); err != nil {
		slog.Warn("live firmware move recovery: resolve the condition of a park the move left", "vm", orig.VM, "code", code, "error", err)
	}
}

// ── preparing, prepared ──

// recoverFirmwareMoveBeforeMigration is §8.1's preparing/prepared row: libvirt
// never had the guest (the marker is migrating before the migration call), so
// the move is undone. Abort PRE_CUTOVER, with source_domain_active as
// observed; a target that does not answer, or refuses, parks it
// target_unreachable (retried each interval, and resolved by fence). The row
// is then set from the source domain, and the marker removed once the target
// answered.
func (s *Server) recoverFirmwareMoveBeforeMigration(ctx context.Context, r *liveFirmwareRun) {
	phase, why := s.abortLiveFirmwareBeforeCutover(ctx, r, false)
	s.restoreRecoveredFirmwareRow(ctx, r, "the live firmware migration was undone after a daemon restart")
	if phase != "" {
		_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable, why)
		return
	}
	s.unmarkLiveFirmwareMove(r, "undone before the migration after a daemon restart")
}

// restoreRecoveredFirmwareRow sets the row of a move that did not cut over
// from its source domain (running, else error), as a failed migration does,
// but only when the row is still this move's: it names this host for the
// marker's incarnation, and is migrating (a row never set migrating is left).
func (s *Server) restoreRecoveredFirmwareRow(ctx context.Context, r *liveFirmwareRun, why string) {
	if s.db == nil {
		return
	}
	m := r.marker
	row, err := corrosion.GetVM(ctx, s.db, m.VM)
	if err != nil || row == nil || row.HostName != s.hostName || row.State != "migrating" ||
		!m.Binding.SameIncarnation(fwmig.Binding{UUID: parseFirmwareSpec(row.Spec).UUID, CreatedAt: row.CreatedAt}) {
		return
	}
	s.restoreSourceStateAfterFailedMigration(ctx, m.VM, fmt.Sprintf("%s; the VM runs on %s", why, s.hostName), why)
}

// ── migrating ──

// recoverFirmwareMoveMigrating is §8.1's migrating rows, by what the source
// observes:
//   - active with a migration job: wait for it to end, then look again;
//   - active, no job: M1 (running) or M1p (paused), as a failed migration;
//   - inactive, or unreadable: the cutover — the stop reason and the final
//     state read (an unreadable domain or state parks source_state_missing),
//     then Verify, which decides by the recorded reason (V1, V1b, V3, V4);
//     on MATCH the move goes on as verified.
func (s *Server) recoverFirmwareMoveMigrating(ctx context.Context, r *liveFirmwareRun) {
	vm := r.marker.VM
	if s.virt == nil {
		return
	}
	for {
		active, err := s.virt.DomainIsActive(vm)
		if err != nil || !active {
			break
		}
		job, err := s.virt.DomainJobActive(vm)
		if err == nil && !job {
			s.recoverFirmwareMigrationFailed(ctx, r)
			return
		}
		if !s.waitFirmwareMigrationJob(r.recoveryWaitCtx(ctx), vm) {
			return
		}
	}
	err := s.liveFirmwareCutover(ctx, r)
	switch {
	case errors.Is(err, errLiveFirmwareSourceActive):
		s.recoverFirmwareMigrationFailed(ctx, r)
		return
	case err != nil:
		return
	}
	s.recoverFirmwareMoveVerified(ctx, r)
}

// waitFirmwareMigrationJob waits for vm's migration job to end. Past
// adoptedMigrationCeiling it aborts the job, as the adopter does, and waits a
// little longer; it reports false when the job did not end (or its state
// stayed unreadable), and the move is taken again on a later pass.
func (s *Server) waitFirmwareMigrationJob(ctx context.Context, vm string) bool {
	slog.Info("live firmware move recovery: libvirt still runs the migration; waiting for it to end", "vm", vm)
	deadline := time.Now().Add(adoptedMigrationCeiling)
	aborted := false
	for {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(firmwareRecoveryJobPoll):
		}
		job, err := s.virt.DomainJobActive(vm)
		if err == nil && !job {
			return true
		}
		if time.Now().Before(deadline) {
			continue
		}
		if aborted {
			slog.Warn("live firmware move recovery: the migration job did not end after its abort; the move is taken on a later pass", "vm", vm, "error", err)
			return false
		}
		slog.Warn("live firmware move recovery: the migration job exceeded its ceiling; aborting it", "vm", vm, "ceiling", adoptedMigrationCeiling)
		if aerr := s.virt.AbortMigration(vm); aerr != nil {
			slog.Warn("live firmware move recovery: abort the migration job", "vm", vm, "error", aerr)
		}
		aborted, deadline = true, time.Now().Add(30*firmwareRecoveryJobPoll)
	}
}

// recoveryWaitCtx is the context the recovery's waits honour.
func (r *liveFirmwareRun) recoveryWaitCtx(ctx context.Context) context.Context {
	if r.waitCtx != nil {
		return r.waitCtx
	}
	return ctx
}

// recoverFirmwareMigrationFailed is §7 M1/M1p for a move found with its
// source domain active and no migration job, as the watched path's failure
// branch handles it: Abort PRE_CUTOVER (the automatic DISCARD of a held copy
// the source can account for, M1), or the paused source resumed first (M1p);
// the row restored unless the source guest is left paused; the marker
// removed once nothing of the move is left; the target's artifacts cleaned.
func (s *Server) recoverFirmwareMigrationFailed(ctx context.Context, r *liveFirmwareRun) {
	unmark, keepRow := s.liveFirmwareMigrateFailed(ctx, r, errFirmwareMoveRecovered)
	// The VFs go back into a guest that runs (M1, or M1p after its resume),
	// as the watched failure branch puts them back.
	s.reattachVFsOnSource(ctx, r.marker.VM, r.vfs, len(r.vfs) > 0)
	s.noteSourceVFs(ctx, r)
	if !keepRow {
		s.restoreRecoveredFirmwareRow(ctx, r, fmt.Sprintf("migration to %s failed: %v", r.target.Name, errFirmwareMoveRecovered))
	}
	if unmark != nil {
		unmark()
		s.cleanupFailedMigrationTarget(ctx, r.marker.VM, r.target.Name, r.marker.CreatedStubs)
	}
}

// ── cutover ──

// recoverFirmwareMoveCutover is §8.1's cutover row. The source domain must
// still be inactive, and its state what the cutover recorded: re-hashed, a
// change parks source_state_suspect (its copy may no longer be the final
// one, I6), a file that cannot be read parks source_state_missing. Then
// Verify, judged by the recorded stop reason (V1, V1b).
func (s *Server) recoverFirmwareMoveCutover(ctx context.Context, r *liveFirmwareRun) {
	if !s.recoveredSourceStillOff(ctx, r) {
		return
	}
	m := r.marker
	fw := s.fw()
	type check struct {
		on   bool
		what string
		want string
		read func() (string, error)
	}
	for _, c := range []check{
		{m.TPM, "TPM state", m.SrcPermallSHA256, func() (string, error) { return fw.PermallSHA256(m.UUID) }},
		{m.UEFI, "NVRAM", m.SrcNvramSHA256, func() (string, error) { return fw.NvramSHA256(m.VM) }},
	} {
		if !c.on {
			continue
		}
		got, err := c.read()
		if err != nil {
			_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourceStateMissing,
				fmt.Sprintf("after a daemon restart, the source's final %s cannot be read: %v", c.what, err))
			return
		}
		if got != c.want {
			_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourceStateSuspect,
				fmt.Sprintf("after a daemon restart, the source's %s is %s, not the %s recorded at cutover", c.what, got, c.want))
			return
		}
	}
	if err := s.verifyLiveFirmwareMove(ctx, r); err != nil {
		return
	}
	s.recoverFirmwareMoveVerified(ctx, r)
}

// recoveredSourceStillOff reports whether the source domain is still
// inactive, as a move past its cutover needs before it commits or releases
// (one copy of the VM at every moment). Active parks the move
// source_state_suspect: the source copy ran again after the cutover, which
// only a path outside the guard can do. Unreadable parks
// source_state_missing, retried each interval.
func (s *Server) recoveredSourceStillOff(ctx context.Context, r *liveFirmwareRun) bool {
	if s.virt == nil {
		return false
	}
	active, err := s.virt.DomainIsActive(r.marker.VM)
	switch {
	case err != nil:
		_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourceStateMissing,
			fmt.Sprintf("after a daemon restart, whether the source domain is still shut off cannot be read: %v", err))
		return false
	case active:
		_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourceStateSuspect,
			"after a daemon restart, the source domain is active again although the move cut over: its state may have changed since, so nothing is committed or released")
		return false
	}
	return true
}

// ── verified, committed ──

// recoverFirmwareMoveVerified is §8.1's verified row. The row, re-read now,
// decides: naming this host for the marker's incarnation, the move commits
// (C1: a commit that fails leaves the marker verified for the next pass);
// naming the target for it, the commit landed already. Either way the move is
// then committed and released. A row naming anything else parks the move
// target_unreachable for an operator.
func (s *Server) recoverFirmwareMoveVerified(ctx context.Context, r *liveFirmwareRun) {
	m := r.marker
	row, err := corrosion.GetVM(ctx, s.db, m.VM)
	if err != nil {
		slog.Warn("live firmware move recovery: the VM's row cannot be read; the commit waits for the next pass", "vm", m.VM, "error", err)
		return
	}
	ours := row != nil && m.Binding.SameIncarnation(fwmig.Binding{UUID: parseFirmwareSpec(row.Spec).UUID, CreatedAt: row.CreatedAt})
	switch {
	case ours && row.HostName == m.Target:
		if err := s.liveFirmwareCommitted(r); err != nil {
			slog.Warn("live firmware move recovery: record the commit", "vm", m.VM, "error", err)
			return
		}
	case ours && row.HostName == s.hostName:
		if !s.recoveredSourceStillOff(ctx, r) {
			return
		}
		disks, err := corrosion.GetVMDisks(ctx, s.db, m.VM)
		if err != nil {
			slog.Warn("live firmware move recovery: the VM's disks cannot be read; the commit waits for the next pass", "vm", m.VM, "error", err)
			return
		}
		if err := s.finalizeMigrationOwnership(ctx, row, m.Target, m.Route == fwmig.RouteStorageCopy, disks); err != nil {
			// C1: the target keeps its verified guest paused under its hold.
			slog.Error("live firmware move recovery: the commit failed; it is retried", "vm", m.VM, "attempt", m.Attempt, "target", m.Target, "error", err)
			s.recordVMEvent(ctx, m.VM, "vm.migrated", "error", "after a daemon restart, the verified move to "+m.Target+" did not commit: "+err.Error())
			return
		}
		if err := s.liveFirmwareCommitted(r); err != nil {
			slog.Warn("live firmware move recovery: record the commit", "vm", m.VM, "error", err)
			return
		}
		s.recordVMEvent(ctx, m.VM, "vm.migrated", "ok", "from="+s.hostName+" to="+m.Target+" (committed after a daemon restart)")
	default:
		where := "no row"
		if row != nil {
			where = fmt.Sprintf("a row on %s (uuid %s, created %s)", row.HostName, parseFirmwareSpec(row.Spec).UUID, row.CreatedAt)
		}
		_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable, fmt.Sprintf(
			"after a daemon restart, the verified move has %s, which names neither this host nor %s for the move's incarnation; nothing is committed or released", where, m.Target))
		return
	}
	s.recoverFirmwareMoveCommitted(ctx, r, true)
}

// recoverFirmwareMoveCommitted is §8.1's committed row: Release (idempotent),
// the NVRAM confirmation and the cleanup, as releaseLiveFirmwareMove runs
// them, with the source domain checked still off first. finish redoes the
// source's part of the finish before it (the records of where the guest now
// runs, which a restart after the commit may have left undone).
func (s *Server) recoverFirmwareMoveCommitted(ctx context.Context, r *liveFirmwareRun, finish bool) {
	if !s.recoveredSourceStillOff(ctx, r) {
		return
	}
	// The commit landed: the source's VFs go back to the pool, as after a
	// watched commit; the target allocates its own. Parked (re-review 2
	// m-1): a finish redone after a crash may attach a VF the first one
	// already attached, since AttachDevice allocates per call.
	s.releaseSourceVFsAfterCutover(ctx, r.marker.VM, r.vfs)
	if finish {
		if row, err := corrosion.GetVM(ctx, s.db, r.marker.VM); err == nil && row != nil {
			_ = s.finishMigrationOnTarget(ctx, row, migrationFinish{target: &r.target, fwLive: r, detachedVFs: r.vfs,
				pbVM: &pb.VM{Name: row.Name, HostName: row.HostName, State: pb.VMState_VM_RUNNING}, hspec: vmHooks(row)})
			return
		}
	}
	_ = s.releaseLiveFirmwareMove(ctx, r)
}

// ── released ──

// recoverFirmwareMoveReleased is §8.1's released row (review D2-12c I-2):
// the target released the guest and confirmed its NVRAM, and the source
// cleanup did not finish. It checks the target first, and cleans up only on
// a positive answer: the row names the target for the marker's incarnation,
// the target is not proved off, and Release, sent again, answers that the
// guest runs there (or, with no hold left, that its domain is defined there).
// Anything else parks the move target_unreachable with the source state
// kept, for the next pass or an operator (§17 D-5, released with the target
// fenced). The NVRAM was confirmed when the marker became released, so a
// guest that has written variables since does not hold the cleanup up.
func (s *Server) recoverFirmwareMoveReleased(ctx context.Context, r *liveFirmwareRun) {
	m := r.marker
	row, err := corrosion.GetVM(ctx, s.db, m.VM)
	if err != nil {
		slog.Warn("live firmware move recovery: the VM's row cannot be read; the cleanup waits for the next pass", "vm", m.VM, "error", err)
		return
	}
	if row == nil || row.HostName != m.Target ||
		!m.Binding.SameIncarnation(fwmig.Binding{UUID: parseFirmwareSpec(row.Spec).UUID, CreatedAt: row.CreatedAt}) {
		_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable, fmt.Sprintf(
			"the move was released, but the VM's row (on %s) does not name %s for the move's incarnation; the source state is kept", rowHost(row), m.Target))
		return
	}
	_, off, err := s.fwTargetProvedOff(ctx, m.Target)
	if err != nil {
		slog.Warn("live firmware move recovery: whether the target is proved off cannot be read; the cleanup waits for the next pass", "vm", m.VM, "error", err)
		return
	}
	if off {
		_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable, fmt.Sprintf(
			"the move was released, but %s is proved off (fenced); the source state is kept for an operator", m.Target))
		return
	}
	var resp *pb.ReleaseLiveFirmwareTargetResponse
	err = s.retryLiveFirmwareCall(ctx, r, "release", func(cctx context.Context, c pb.LiteVirtClient) (err error) {
		resp, err = c.ReleaseLiveFirmwareTarget(cctx, &pb.ReleaseLiveFirmwareTargetRequest{
			VmName: m.VM, Uuid: m.UUID, AttemptId: m.Attempt, CreatedAt: m.CreatedAt, SrcNvramSha256: m.SrcNvramSHA256})
		return err
	})
	if err != nil {
		_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable, fmt.Sprintf("Release was not answered by %s: %v", m.Target, err))
		return
	}
	td := resp.GetTargetDomain()
	switch v := resp.GetVerdict(); {
	case v == pb.FirmwareVerdict_FIRMWARE_VERDICT_UNSPECIFIED:
	case v == pb.FirmwareVerdict_FIRMWARE_VERDICT_NOT_HELD && td.GetPresent():
	default:
		_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable, fmt.Sprintf(
			"the move was released, but Release now answers %s (domain %s): %s; the source state is kept", v, domainWord(td), resp.GetDetail()))
		return
	}
	slog.Info("live firmware move recovery: the target holds the released guest; cleaning up the source", "vm", m.VM, "attempt", m.Attempt, "target", m.Target)
	s.releaseSourceVFsAfterCutover(ctx, m.VM, r.vfs)
	s.fwLiveStep("cleanup")
	_ = s.fwmigCleanupSource(ctx, r.marker)
}
