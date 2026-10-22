package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/health"
)

// condMigrationUnresolved names a VM whose row a drain left migrating: its
// live move ended without libvirt's answer and the guest was not running on
// the source, so it may run on the target. Raised by that drain (and by
// failover's hold of such a row); resolved by `lv doctor repair-owner` and
// `lv stop`, which settle the row, and by any other ending that settles it
// (ResolveSettledMigrationsOnce).
const condMigrationUnresolved = "vm.migration_unresolved"

// migrationUnresolvedEvidence is vm.migration_unresolved's evidence.
type migrationUnresolvedEvidence struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Detail string `json:"detail"`
	// LeaseID is the target's capacity reservation the move kept, released
	// when the condition is resolved.
	LeaseID string `json:"lease_id,omitempty"`
}

// raiseMigrationUnresolved raises vm.migration_unresolved for vm, left
// migrating on this host by a move to target, which keeps leaseID.
func (s *Server) raiseMigrationUnresolved(ctx context.Context, vm, target, leaseID, detail string) {
	s.raiseMigrationUnresolvedOf(ctx, vm, s.hostName, target, leaseID, detail)
}

// raiseMigrationUnresolvedFrom raises vm.migration_unresolved for vm, left
// migrating on source by a move to target, from a host that is not source
// (failover's hold). A target capacity reservation an earlier raise recorded
// is kept, so resolving the condition still releases it.
func (s *Server) raiseMigrationUnresolvedFrom(ctx context.Context, vm, source, target, detail string) {
	var leaseID string
	if row, ok, err := corrosion.GetHealthCondition(ctx, s.db, drainEvaluator, condMigrationUnresolved, "vm", vm); err == nil && ok &&
		row.Lifecycle != corrosion.ConditionResolved {
		var ev migrationUnresolvedEvidence
		if json.Unmarshal([]byte(row.Evidence), &ev) == nil && ev.Target == target {
			leaseID = ev.LeaseID
		}
	}
	s.raiseMigrationUnresolvedOf(ctx, vm, source, target, leaseID, detail)
}

// raiseMigrationUnresolvedOf raises vm.migration_unresolved for vm, left
// migrating on source by a move to target, which keeps leaseID.
func (s *Server) raiseMigrationUnresolvedOf(ctx context.Context, vm, source, target, leaseID, detail string) {
	ev, _ := json.Marshal(migrationUnresolvedEvidence{Source: source, Target: target, Detail: detail, LeaseID: leaseID})
	hosts := []string{source}
	if target != "" {
		hosts = append(hosts, target)
	}
	s.setConditionOf(ctx, drainEvaluator, condMigrationUnresolved, "vm", vm,
		hosts, true, corrosion.SeverityCritical, string(ev))
}

// resolveMigrationUnresolved resolves vm's vm.migration_unresolved, once its
// row is settled (or the VM deleted), and releases the target's capacity
// reservation the move kept. A release that fails is left to the stale-lease
// sweep.
func (s *Server) resolveMigrationUnresolved(ctx context.Context, vm string) {
	if s.db == nil {
		return
	}
	row, ok, err := corrosion.GetHealthCondition(ctx, s.db, drainEvaluator, condMigrationUnresolved, "vm", vm)
	if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
		return
	}
	var ev migrationUnresolvedEvidence
	if json.Unmarshal([]byte(row.Evidence), &ev) == nil && ev.LeaseID != "" && ev.Target != "" {
		lease := &reservationLease{s: s, id: ev.LeaseID, hostHolder: ev.Target}
		if !lease.released(ctx) {
			slog.Warn("vm.migration_unresolved: the target's capacity reservation was not released; the stale-lease sweep collects it",
				"vm", vm, "target", ev.Target, "lease", ev.LeaseID)
		}
	}
	s.setConditionOf(ctx, drainEvaluator, condMigrationUnresolved, "vm", vm, nil, false, corrosion.SeverityCritical, "")
}

// migrationSettled reports whether row, the VM's row now, settles a
// vm.migration_unresolved whose evidence names source: the row no longer
// records the VM migrating on source (and, on the host it names, no live
// firmware move of it is still marked: resolveMigrationUnresolvedIfSettled). Each ending that leaves one copy of the
// guest writes such a row: a re-point or repair-owner records it where it
// runs, a firmware move's doctor or fence resolution records it on the host
// whose copy it took (stopped or running), a stop records it stopped.
func migrationSettled(row *corrosion.VMRecord, source string) bool {
	return row != nil && !(row.State == "migrating" && row.HostName == source)
}

// resolveMigrationUnresolvedIfSettled resolves vm's vm.migration_unresolved
// when its row, read now, is settled (migrationSettled). Reports whether it
// resolved it.
func (s *Server) resolveMigrationUnresolvedIfSettled(ctx context.Context, vm string) bool {
	if s.db == nil {
		return false
	}
	c, ok, err := corrosion.GetHealthCondition(ctx, s.db, drainEvaluator, condMigrationUnresolved, "vm", vm)
	if err != nil || !ok || c.Lifecycle == corrosion.ConditionResolved {
		return false
	}
	var ev migrationUnresolvedEvidence
	if json.Unmarshal([]byte(c.Evidence), &ev) != nil {
		return false
	}
	row, err := corrosion.GetVM(ctx, s.db, vm)
	if err != nil || !migrationSettled(row, ev.Source) {
		return false
	}
	if row.HostName == s.hostName {
		// A live firmware move still marked here is not settled, whatever
		// its row says: its recovery may have restored the row while the
		// move stays parked, the guest's start refused until it resolves.
		if _, marked, merr := s.fwRecords().GetMarker(vm); marked || merr != nil {
			return false
		}
	}
	s.resolveMigrationUnresolved(ctx, vm)
	slog.Info("vm.migration_unresolved: resolved, the VM's row no longer records the move",
		"vm", vm, "source", ev.Source, "host", row.HostName, "state", row.State)
	return true
}

// ResolveSettledMigrationsOnce resolves each open vm.migration_unresolved
// whose VM's row names this host and is settled (migrationSettled), whatever
// settled it: an operator's doctor action, a firmware move's own recovery or
// fence resolution, a re-point, a host-side step the next poll recorded. Only
// the host the row names judges it, from a replica that has caught up, so a
// replica holding the condition but an older row cannot resolve it; a VM a
// move or another action holds is left to the next pass. A deleted VM's
// condition is `lv rm`'s.
func (s *Server) ResolveSettledMigrationsOnce(ctx context.Context) {
	if s.db == nil {
		return
	}
	if ok, _ := s.db.ReplicaCaughtUp(); !ok {
		return
	}
	conds, err := corrosion.ListOpenHealthConditionsByCode(ctx, s.db, drainEvaluator, condMigrationUnresolved)
	if err != nil {
		slog.Debug("vm.migration_unresolved: the open conditions cannot be listed", "error", err)
		return
	}
	for _, c := range conds {
		if c.SubjectKind != "vm" {
			continue
		}
		vm := c.SubjectID
		row, err := corrosion.GetVM(ctx, s.db, vm)
		if err != nil || row == nil || row.HostName != s.hostName {
			continue
		}
		unlock, ok := s.tryLockVM(vm)
		if !ok {
			continue
		}
		s.resolveMigrationUnresolvedIfSettled(ctx, vm)
		unlock()
	}
}

// migrationUnresolved reports whether vm's vm.migration_unresolved is open.
func (s *Server) migrationUnresolved(ctx context.Context, vm string) bool {
	if s.db == nil {
		return false
	}
	row, ok, err := corrosion.GetHealthCondition(ctx, s.db, drainEvaluator, condMigrationUnresolved, "vm", vm)
	return err == nil && ok && row.Lifecycle != corrosion.ConditionResolved
}

// settleMigratingAdvice is what to do about a VM whose row says migrating
// and whose move is not running: find where the guest runs, and record it.
func settleMigratingAdvice(vm string) string {
	return fmt.Sprintf("if the guest runs on a host, `lv doctor repair-owner %s <host>` records it there; "+
		"if it runs on none, `lv stop %s` settles the record", vm, vm)
}

// inFlightMoveAdvice is the advice of a drain frame skipping vm, whose row
// says migrating.
func (s *Server) inFlightMoveAdvice(ctx context.Context, vm string) string {
	if s.migrationUnresolved(ctx, vm) {
		return fmt.Sprintf("its last move ended without libvirt's answer and the guest may run on the move's target "+
			"(%s, see `lv health`): %s", condMigrationUnresolved, settleMigratingAdvice(vm))
	}
	return "a move of this VM is in flight (an earlier drain's finishing in the background, or a migration); " +
		"re-run drain once it ends (`lv events " + vm + "`)"
}

// inFlightMoveRefusal refuses op (a start, restart or reconfigure of vm on
// this host, or a stop that has not asked the move's target) while vm's row
// says migrating: a move of it is in flight, or ended leaving the row so, and
// the guest may run on the move's target. A start here would make a second
// copy; a stop recorded here would let the next start make one.
func (s *Server) inFlightMoveRefusal(ctx context.Context, op string, vm *corrosion.VMRecord) error {
	if vm.State != "migrating" {
		return nil
	}
	target := migratingToward(vm.StateDetail)
	if target == "" {
		target = "its target"
	}
	why := fmt.Sprintf("a move of it to %s is in flight (`lv events %s`)", target, vm.Name)
	if s.migrationUnresolved(ctx, vm.Name) {
		why = fmt.Sprintf("its move to %s ended without libvirt's answer (%s, see `lv health`)", target, condMigrationUnresolved)
	}
	done := "nothing is started here"
	switch op {
	case "stop":
		done = "it is not recorded stopped here"
	case "reconfigure":
		done = "nothing of it is stopped, redefined or started here"
	}
	return status.Errorf(codes.FailedPrecondition,
		"%s %q refused: its record says migrating, as %s, and the guest may run on %s; %s. "+
			"Once no move of it runs, %s",
		op, vm.Name, why, target, done, settleMigratingAdvice(vm.Name))
}

// movingVMStartRefusal is the refusal EVERY start of a VM's domain passes
// through, whatever asked for it: startVMLocked, and PrepareHardwareForStart
// for the paths that start outside it (the reconciler's and the health
// checker's restarts, a restore). A row recorded migrating is not started.
// The row is read again here, so a caller's stale record does not get past
// it; one that cannot be read refuses the start as retryable, whether a move
// of the VM is in flight being unknown. A VM with no row yet (a restore's,
// written once it runs) is not a moving VM.
//
// Only a move itself brings up the guest of a row recorded migrating, on the
// target, through libvirt's migration, never through a start here: no start
// path is exempt.
func (s *Server) movingVMStartRefusal(ctx context.Context, vm *corrosion.VMRecord) error {
	if vm == nil {
		return nil
	}
	if err := s.inFlightMoveRefusal(ctx, "start", vm); err != nil {
		return err
	}
	if s.db == nil {
		return nil
	}
	row, err := corrosion.GetVM(ctx, s.db, vm.Name)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"start %q: whether a move of it is in flight cannot be read (%v); retry", vm.Name, err)
	}
	if row == nil {
		return nil
	}
	return s.inFlightMoveRefusal(ctx, "start", row)
}

// migratingStopProbeTimeout bounds the ask of a migrating VM's target
// whether the guest runs there (migratingStopRefusal).
const migratingStopProbeTimeout = 15 * time.Second

// migratingStopRefusal is the refusal of op (a stop or a delete) of vm, whose
// row says migrating and whose guest is not running on this host, its source.
// The stop records the VM stopped here, and a later start would then make a
// second copy if the guest runs on the move's target: the target is asked
// first, and op goes ahead only when it has no domain of the VM. A target
// that cannot be asked counts as having none only when it is proven powered
// off — fenced, or no longer a member, over a proof-grade fence
// (corrosion.SharedDiskOwnerProvedOff, as a live firmware move's target is
// judged, fwTargetProvedOff). Any other target refuses.
func (s *Server) migratingStopRefusal(ctx context.Context, op string, vm *corrosion.VMRecord) error {
	target := migratingToward(vm.StateDetail)
	if target == "" || target == s.hostName {
		return status.Errorf(codes.FailedPrecondition,
			"%s %q refused: its record says migrating but names no target to ask whether the guest runs there; "+
				"find where it runs (`virsh list` on each host) and record it with `lv doctor repair-owner %s <host>`",
			op, vm.Name, vm.Name)
	}
	if h, off, perr := corrosion.SharedDiskOwnerProvedOff(ctx, s.db, target); perr == nil {
		if ok, _ := corrosion.SharedDiskOwnerVerdict(target, h, off, nil); ok {
			return nil
		}
	}
	pctx, cancel := context.WithTimeout(ctx, migratingStopProbeTimeout)
	defer cancel()
	state, err := s.CheckPeerVMRuntime(pctx, target, vm.Name)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"%s %q refused: its record says migrating to %s, and %s cannot be asked whether the guest runs there (%v); "+
				"recording it stopped here could let a later start make a second copy. Retry once %s answers. "+
				"If %s is gone for good, power it off and confirm it with `lv host fence-confirm %s` "+
				"(`lv host rm %s --dead` then removes it): once it is proven off, the %s goes ahead",
			op, vm.Name, target, target, err, target, target, target, target, op)
	}
	switch state {
	case health.RuntimeAbsent:
		return nil
	case health.RuntimeRunning:
		return status.Errorf(codes.FailedPrecondition,
			"%s %q refused: its record says migrating, and the guest runs on %s; record it there with "+
				"`lv doctor repair-owner %s %s`, then %s it if you mean to",
			op, vm.Name, target, vm.Name, target, op)
	default:
		return status.Errorf(codes.FailedPrecondition,
			"%s %q refused: its record says migrating, and %s holds a domain of it in state %s (a paused guest reads so too); "+
				"check it there (`virsh domstate %s` on %s): if the guest runs, record it with `lv doctor repair-owner %s %s`",
			op, vm.Name, target, state, vm.Name, target, vm.Name, target)
	}
}

// RaiseLeftMigrating raises vm.migration_unresolved for each VM whose row
// says migrating on this host while no move of it runs here: a daemon that
// stopped mid-move leaves it so, and nothing settles it. A live firmware
// move's VM is its own recovery's (RecoverFirmwareMoves holds its lock), and
// a VM whose lock is held has a move or another operation running. Run at
// start, after the firmware moves' recovery.
func (s *Server) RaiseLeftMigrating(ctx context.Context) {
	if s.db == nil {
		return
	}
	vms, err := corrosion.ListVMs(ctx, s.db, "", s.hostName)
	if err != nil {
		slog.Warn("vm.migration_unresolved: could not list this host's VMs", "error", err)
		return
	}
	for _, vm := range vms {
		if vm.State != "migrating" {
			continue
		}
		if _, held := s.vmLockHolderOf(vm.Name); held {
			continue
		}
		if _, ok, merr := s.fwRecords().GetMarker(vm.Name); ok || merr != nil {
			continue
		}
		target := migratingToward(vm.StateDetail)
		detail := fmt.Sprintf("%s is recorded migrating on %s, and no move of it runs there (its daemon stopped mid-move); "+
			"it may run on %s, so nothing starts or moves it: %s", vm.Name, s.hostName, target, settleMigratingAdvice(vm.Name))
		s.raiseMigrationUnresolved(ctx, vm.Name, target, "", detail)
	}
}

// The ask of the migrating VMs' targets in one failover pass
// (SettleFailedSourceMigrations): each target is asked once, for its whole
// VM inventory, at most migratingProbeConcurrency at a time, each ask bounded
// by migratingProbeTimeout and all of them by migratingProbeBudget. It runs
// inside the coordinator's tick, so a target that does not answer in time
// only holds its VMs until the next poll, and never holds up the rest of the
// recovery for longer than the budget. Vars so tests can shorten them.
var (
	migratingProbeTimeout     = 5 * time.Second
	migratingProbeBudget      = 10 * time.Second
	migratingProbeConcurrency = 4
)

// migratingInventoryHook, when set, replaces the ask of a target's runtime
// inventory (SettleFailedSourceMigrations). Test-only.
var migratingInventoryHook func(ctx context.Context, s *Server, host string) (runtimeInventory, error)

// migratingFirmwareHook, when set, replaces the read of a target's firmware
// move records of a Secure Boot / vTPM VM (SettleFailedSourceMigrations).
// Test-only.
var migratingFirmwareHook func(ctx context.Context, s *Server, host, vm string) (*pb.FirmwareMoveHostRecords, error)

// targetAnswer is one target's answer: its inventory, or why it gave none.
type targetAnswer struct {
	inv runtimeInventory
	err error
}

// askMigrationTargets asks each target once for its runtime inventory, under
// the bounds above, within bctx (the pass's budget). A target not asked
// within it answers with the budget's error.
func (s *Server) askMigrationTargets(bctx context.Context, targets []string) map[string]targetAnswer {
	out := make(map[string]targetAnswer, len(targets))
	if len(targets) == 0 {
		return out
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, migratingProbeConcurrency))
	for _, host := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-bctx.Done():
				mu.Lock()
				out[host] = targetAnswer{err: errors.New("not asked within the poll's time budget for these asks")}
				mu.Unlock()
				return
			}
			pctx, pcancel := context.WithTimeout(bctx, migratingProbeTimeout)
			defer pcancel()
			var a targetAnswer
			if hook := migratingInventoryHook; hook != nil {
				a.inv, a.err = hook(pctx, s, host)
			} else {
				a.inv, a.err = s.getPeerRuntimeInventory(pctx, host, "", "")
			}
			mu.Lock()
			out[host] = a
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

// SettleFailedSourceMigrations is failover's decision on the VMs whose rows
// say migrating on source, a host it is recovering
// (failover.SettleMigratingRows). A migration that cut over in libvirt runs
// the guest on its target; a source that died before the ownership commit
// leaves the row on itself, and a restart elsewhere would be a second running
// copy. So each VM's target is asked (once per target, askMigrationTargets),
// as a stop of such a row asks it (migratingStopRefusal):
//
//   - it runs the guest: the row is re-pointed there, running
//     (RepointMigratedVM, which writes only while the row is still the
//     migration's on source), and nothing is started. A Secure Boot / vTPM
//     VM is held instead: its move is settled by its firmware records;
//   - it has no domain of it, or it is proven powered off: the guest runs
//     nowhere, and the VM is recovered as a running one;
//   - anything else — no target recorded, no answer, a paused or shut-off
//     domain, an incomplete inventory — holds the VM, with
//     vm.migration_unresolved raised naming why and what settles it.
//
// Every ask ends by askBy, the coordinator's one deadline for all of a
// poll's asks, whatever the number of hosts it recovers, and within
// migratingProbeBudget of this call.
func (s *Server) SettleFailedSourceMigrations(ctx context.Context, source string, vms []corrosion.VMRecord, askBy time.Time) map[string]failover.MigratingDecision {
	out := make(map[string]failover.MigratingDecision, len(vms))
	proven := map[string]bool{}
	var ask []string
	for _, vm := range vms {
		target := migratingToward(vm.StateDetail)
		if target == "" || target == source {
			continue
		}
		if _, seen := proven[target]; seen {
			continue
		}
		off := false
		if h, p, perr := corrosion.SharedDiskOwnerProvedOff(ctx, s.db, target); perr == nil {
			off, _ = corrosion.SharedDiskOwnerVerdict(target, h, p, nil)
		}
		proven[target] = off
		if !off {
			ask = append(ask, target)
		}
	}
	bctx, cancel := context.WithTimeout(ctx, migratingProbeBudget)
	defer cancel()
	if !askBy.IsZero() {
		var dcancel context.CancelFunc
		bctx, dcancel = context.WithDeadline(bctx, askBy)
		defer dcancel()
	}
	answers := s.askMigrationTargets(bctx, ask)
	for _, vm := range vms {
		out[vm.Name] = s.settleFailedSourceMigration(ctx, bctx, vm, source, proven, answers)
	}
	return out
}

// settleFailedSourceMigration decides one VM from its target's answer. bctx
// bounds any further ask (a firmware VM's records); ctx carries the writes.
func (s *Server) settleFailedSourceMigration(ctx, bctx context.Context, vm corrosion.VMRecord, source string,
	proven map[string]bool, answers map[string]targetAnswer) failover.MigratingDecision {
	target := migratingToward(vm.StateDetail)
	firmware := corrosion.VMUsesFirmwareState(vm)
	hold := func(why, fix string) failover.MigratingDecision {
		detail := fmt.Sprintf("%s is recorded migrating on %s, which failed, and %s; nothing starts or moves it. %s",
			vm.Name, source, why, fix)
		s.raiseMigrationUnresolvedFrom(ctx, vm.Name, source, target, detail)
		return failover.MigratingDecision{Verdict: failover.MigratingHold, Detail: why + ". " + fix}
	}
	recoverVM := func(why string) failover.MigratingDecision {
		s.resolveMigrationUnresolved(ctx, vm.Name)
		return failover.MigratingDecision{Verdict: failover.MigratingRecover, Detail: why}
	}
	// notRestarted is a Secure Boot / vTPM VM whose guest runs nowhere
	// failover could find: the recovery goes on, and skips it, since failover
	// never restarts one (its firmware state lives on the source and the
	// target). Its condition is raised again, saying what brings it back.
	notRestarted := func(why, fix string) failover.MigratingDecision {
		detail := fmt.Sprintf("%s is recorded migrating on %s, which failed, and %s; failover does not restart it. %s",
			vm.Name, source, why, fix)
		s.raiseMigrationUnresolvedFrom(ctx, vm.Name, source, target, detail)
		return failover.MigratingDecision{Verdict: failover.MigratingRecover, Detail: why + ". " + fix}
	}
	if target == "" || target == source {
		return hold("its record names no target to ask whether the guest runs there",
			fmt.Sprintf("Find where the guest runs (`virsh list --all` on each host): if it runs on a host, "+
				"`lv doctor repair-owner %s <host>` records it there", vm.Name))
	}
	if proven[target] {
		if firmware {
			return notRestarted(fmt.Sprintf("its target %s is proven powered off, and %s", target, fwSettledByRecords),
				firmwareTargetOffAdvice(vm.Name, source, target))
		}
		return recoverVM(fmt.Sprintf("its target %s is proven powered off", target))
	}
	if firmware {
		return s.settleFirmwareMigration(ctx, bctx, vm, source, target, answers[target], hold, notRestarted)
	}
	a := answers[target]
	if a.err != nil {
		return hold(fmt.Sprintf("its target %s cannot be asked whether the guest runs there (%v)", target, a.err),
			fmt.Sprintf("If %s answers again, the next poll settles it by what %s reports. If %s is down, "+
				"once it is powered off, `lv host fence-confirm %s`: the next poll recovers %s elsewhere",
				target, target, target, target, vm.Name))
	}
	switch state := runtimeStateIn(a.inv, corrosion.WorkloadVM, vm.Name); state {
	case health.RuntimeAbsent:
		return recoverVM(fmt.Sprintf("its target %s has no domain of it", target))
	case health.RuntimeRunning:
		//runningcheck:allow ownership handoff after cutover, as RepointMigratedVM's other callers: the guest runs
		// on the target, which reported it so, and the target's convergence marks its own runtime.
		moved, rerr := corrosion.RepointMigratedVM(ctx, s.db, vm.Name, source, target, "running")
		if rerr != nil {
			return hold(fmt.Sprintf("the guest runs on its target %s, and its record could not be moved there (%v)", target, rerr),
				fmt.Sprintf("The next poll tries again; `lv doctor repair-owner %s %s` records it there", vm.Name, target))
		}
		if !moved {
			return failover.MigratingDecision{Verdict: failover.MigratingSettled,
				Detail: "its record changed since it was read; the next recovery reads it again"}
		}
		s.resolveMigrationUnresolved(ctx, vm.Name)
		detail := fmt.Sprintf("%s failed with %s recorded migrating to %s, where the guest runs: its record now names %s. "+
			"Its disk rows still name %s and its replication still runs from there: `lv doctor repair-owner %s %s` moves them",
			source, vm.Name, target, target, source, vm.Name, target)
		s.recordVMEvent(ctx, vm.Name, "vm.failover.repointed", "ok", detail)
		return failover.MigratingDecision{Verdict: failover.MigratingSettled, Detail: detail}
	case health.RuntimeUnknown:
		return hold(fmt.Sprintf("its target %s answered with an incomplete inventory that does not list it", target),
			fmt.Sprintf("The next poll asks again. If the guest runs on %s, `lv doctor repair-owner %s %s` records it there",
				target, vm.Name, target))
	default:
		return hold(fmt.Sprintf("its target %s holds a domain of it in state %s (a guest paused mid-migration reads so too); "+
			"a guest that ran there may hold the only data written since the cutover", target, state),
			fmt.Sprintf("No `lv` command settles this while %s is down: if the guest should run on %s, start or resume it there "+
				"(`virsh start %s` or `virsh resume %s` on %s) and the next poll records it there", source, target, vm.Name, vm.Name, target))
	}
}

// firmwareMoveAdvice is what settles a held Secure Boot / vTPM VM recorded
// migrating from source to target: the firmware move doctor adopts the
// target's paused copy once the source is proven off.
func (s *Server) firmwareMoveAdvice(ctx context.Context, vm, source, target string) string {
	adopt := fmt.Sprintf("`lv doctor firmware-move %s --adopt-target-copy` adopts the copy %s holds paused", vm, target)
	if off, err := corrosion.HostProvedOff(ctx, s.db, source); err == nil && off {
		return adopt
	}
	return fmt.Sprintf("Once %s is powered off, `lv host fence-confirm %s`; then %s", source, source, adopt)
}

// fwSettledByRecords is why a Secure Boot / vTPM VM's hold is its own.
const fwSettledByRecords = "it is a Secure Boot / vTPM VM, whose move is settled by its firmware records"

// fwNeverRestarted is why failover never starts a Secure Boot / vTPM VM
// elsewhere.
const fwNeverRestarted = "failover never restarts a Secure Boot / vTPM VM, because its NVRAM and TPM state live on its source and its target"

// firmwareSourceReturnsAdvice is what happens to a Secure Boot / vTPM VM's
// move, recorded from source to target, once source comes back, by what
// target holds; each step is the one a test takes to one running copy
// (TestFailedFirmwareSource_*).
func firmwareSourceReturnsAdvice(vm, source, target string) string {
	return fmt.Sprintf("When %[2]s comes back, its daemon takes the move up from its own records and asks %[3]s. "+
		"If %[3]s holds the guest, the move finishes there and %[1]s runs on %[3]s. "+
		"If %[3]s holds no copy, the move parks as firmware_migration_source_state_suspect; "+
		"`lv doctor firmware-move %[1]s --accept-source --acknowledge-rollback` then `lv start %[1]s` start it on %[2]s "+
		"from its own firmware state (a move that had not reached libvirt's migration is undone instead, and `lv start %[1]s` "+
		"alone starts it). While %[3]s does not answer, the move stays parked as firmware_migration_target_unreachable, "+
		"and `lv doctor firmware-move %[1]s` shows the phase it parked from: from prepared, `lv host fence-confirm %[3]s` "+
		"once %[3]s is powered off resolves it, recording %[1]s stopped on %[2]s, and `lv start %[1]s` starts it; "+
		"from cutover, no `lv` command handles it yet and a fence of %[3]s does not resolve it, so only %[3]s answering again settles it",
		vm, source, target)
}

// firmwareTargetDownAdvice settles a Secure Boot / vTPM VM held because its
// target does not answer while its source is down.
func firmwareTargetDownAdvice(vm, source, target string) string {
	return fmt.Sprintf("No `lv` command starts it while its source %[2]s and its target %[3]s are both down, and none handles "+
		"this yet: %[4]s. Bring %[3]s back (power it on, or restore its network): the next poll asks it and names the step "+
		"for what it holds. Or bring %[2]s back. %[5]s",
		vm, source, target, fwNeverRestarted, firmwareSourceReturnsAdvice(vm, source, target))
}

// firmwareTargetEmptyAdvice settles a Secure Boot / vTPM VM whose target
// answered with no domain of it while its source is down: only the source's
// firmware state is left.
func firmwareTargetEmptyAdvice(vm, source, target string) string {
	return fmt.Sprintf("No copy of the guest is on %[3]s, and only %[2]s's firmware state is left. No `lv` command starts it "+
		"while %[2]s is down, and none handles this yet: %[4]s. Power %[2]s back on: its daemon takes the move up from its "+
		"own records and asks %[3]s, which holds no copy, so the move parks as firmware_migration_source_state_suspect; "+
		"`lv doctor firmware-move %[1]s --accept-source --acknowledge-rollback` then `lv start %[1]s` start it on %[2]s from "+
		"its own firmware state (a move that had not reached libvirt's migration is undone instead, and `lv start %[1]s` "+
		"alone starts it). If %[2]s cannot come back, its firmware state is lost with it, and no `lv` command handles that",
		vm, source, target, fwNeverRestarted)
}

// firmwareTargetOffAdvice settles a Secure Boot / vTPM VM whose target is
// proven powered off while its source is down.
func firmwareTargetOffAdvice(vm, source, target string) string {
	return fmt.Sprintf("No `lv` command starts it while %[2]s is down, and none handles this yet: %[4]s. Power %[2]s back on: "+
		"its daemon takes the move up from its own records and, with %[3]s not answering, parks it as "+
		"firmware_migration_target_unreachable; `lv doctor firmware-move %[1]s` shows the phase it parked from. From prepared, "+
		"the fence of %[3]s resolves it on the daemon's next pass, within a minute, recording %[1]s stopped on %[2]s, and "+
		"`lv start %[1]s` starts it. From cutover, no `lv` command handles it yet and the fence does not resolve it: "+
		"only %[3]s answering again settles it: when %[3]s holds the guest, the move commits there and %[1]s runs on %[3]s "+
		"(%[2]s keeps its own copy of the state until its cleanup can run, firmware_migration_cleanup_failed saying why); "+
		"when it holds none, the move parks as "+
		"firmware_migration_source_state_suspect, and "+
		"`lv doctor firmware-move %[1]s --accept-source --acknowledge-rollback` then `lv start %[1]s` start it on %[2]s",
		vm, source, target, fwNeverRestarted)
}

// settleFirmwareMigration decides a Secure Boot / vTPM VM recorded migrating
// on source toward target. Its move is settled by its firmware records, never
// by moving the row alone, so it is never re-pointed, and failover never
// restarts it: a target that holds no domain of it lets the recovery go on
// (notRestarted, which skips it), and anything else holds it, with the step
// that settles it picked by what the target holds.
func (s *Server) settleFirmwareMigration(ctx, bctx context.Context, vm corrosion.VMRecord, source, target string, a targetAnswer,
	hold, notRestarted func(why, fix string) failover.MigratingDecision) failover.MigratingDecision {
	const fw = fwSettledByRecords
	if a.err != nil {
		return hold(fmt.Sprintf("its target %s cannot be asked whether the guest runs there (%v), and %s", target, a.err, fw),
			firmwareTargetDownAdvice(vm.Name, source, target))
	}
	if runtimeStateIn(a.inv, corrosion.WorkloadVM, vm.Name) == health.RuntimeAbsent {
		return notRestarted(fmt.Sprintf("its target %s answered and holds no domain of it, and %s", target, fw),
			firmwareTargetEmptyAdvice(vm.Name, source, target))
	}
	// The inventory reads every domain that is not running as stopped; the
	// target's firmware records say which.
	pctx, cancel := context.WithTimeout(bctx, migratingProbeTimeout)
	defer cancel()
	var rec *pb.FirmwareMoveHostRecords
	var err error
	if hook := migratingFirmwareHook; hook != nil {
		rec, err = hook(pctx, s, target, vm.Name)
	} else {
		rec, err = s.inspectFirmwareMoveHost(pctx, target, vm.Name)
	}
	if err != nil {
		return hold(fmt.Sprintf("its target %s holds a domain of it, whose firmware move records cannot be read (%v), and %s", target, err, fw),
			"The next poll asks again")
	}
	td := rec.GetDomain()
	state := domainWord(td)
	why := fmt.Sprintf("its target %s holds a domain of it %s, and %s", target, state, fw)
	switch {
	case !td.GetPresent():
		return hold(fmt.Sprintf("its target %s did not list it as absent, and its firmware records show no domain of it there, and %s", target, fw),
			"The next poll asks again")
	case state == "paused":
		return hold(why, s.firmwareMoveAdvice(ctx, vm.Name, source, target))
	case state == "running":
		return hold(why, fmt.Sprintf("No `lv` command settles a Secure Boot / vTPM VM that runs on its target while its record "+
			"names the failed source. On %s, `virsh suspend %s` pauses the guest; the next poll then names the firmware move "+
			"doctor, whose --adopt-target-copy takes the paused copy, records it on %s and resumes it", target, vm.Name, target))
	case state == "shutoff":
		return hold(why, fmt.Sprintf("No `lv` command settles a Secure Boot / vTPM VM whose copy on its target is shut off while its "+
			"record names the failed source. On %s, `virsh start --paused %s` brings the copy up paused; the next poll then names "+
			"the firmware move doctor, whose --adopt-target-copy takes the paused copy, records it on %s and resumes it",
			target, vm.Name, target))
	default:
		// Active, and neither running nor paused: pm-suspended, shutting down,
		// crashed. `virsh start` refuses an active domain, and no host-side
		// step is known to lead from these to a paused copy safely.
		return hold(why, fmt.Sprintf("No `lv` command settles a Secure Boot / vTPM VM whose copy on its target is %s, and no "+
			"host-side step is known to be safe for a copy in that state: contact the litevirt maintainers before acting on it. "+
			"If the copy on %s comes to run, pause or shut off, the next poll names the step for that state", state, target))
	}
}
