package grpcapi

// The source half of a live firmware (Secure Boot / vTPM) migration (spec
// §6.1): stage A, the marker, Prepare and stage B before any target setup;
// stage C once EnsureDisks has answered; the marker through migrating,
// cutover and Verify before the commit; and Release in place of the NIC
// hand-over after it. migrateOwnedVM drives it under the VM's lock.
//
// One copy of the VM at every moment: the target's guest arrives paused and
// only Release lets it run, after Verify matched and the commit landed. This
// side never resumes a guest whose target may have run. Every outcome other
// than the happy flow keeps both copies: the move is undone before cutover
// only once the target has answered for its hold, and is parked (marker kept,
// condition raised) otherwise.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
)

// liveFirmwareRun is one live firmware move on its source, from the marker on.
type liveFirmwareRun struct {
	target corrosion.HostRecord
	elig   *liveFirmwareEligible
	// marker is the source marker as last written.
	marker fwmig.Marker
	// prepared is when Prepare answered: the target's hold is as old.
	prepared time.Time
	// vfs are the SR-IOV VFs detached from the guest for the move.
	vfs []corrosion.PCIDeviceRecord
	// parked is the parked marker a recovery retry took the move from, while
	// no later phase has been written: a retry that ends unanswered keeps
	// that park (D2-10 m-7), and one that ends in it again with the same
	// detail writes nothing (spec §8.1).
	parked fwmig.Marker
	// parkAction, when set, is the Action of the next park's condition, in
	// place of the generic one.
	parkAction string
	// oneAttempt makes each call to the target one attempt, not a retry for
	// fwLiveRetryFor: the recovery's next pass is its backoff, and the VM's
	// lock is not held between attempts (review D2-13 m-1).
	oneAttempt bool
	// waitCtx, when set, bounds the recovery's waits (a migration job): the
	// daemon's context, where the steps themselves run detached from it.
	waitCtx context.Context
}

// fwLiveSourceState is the Server's test seams for the source half.
type fwLiveSourceState struct {
	// stepHook, when set, is called with each source step as it is reached
	// ("commit", "cleanup"). Test-only.
	stepHook func(step string)
	// recovering counts the goroutines the recovery started, so a test can
	// wait for them.
	recovering sync.WaitGroup
	// recoveryMu guards owedRunning and wired.
	recoveryMu sync.Mutex
	// wired is closed by MarkStartupWired.
	wired chan struct{}
	// owedRunning is set while a pass sends the owed DISCARDs.
	owedRunning bool
	// recoverySlots bounds how many moves the recovery takes at once.
	recoverySlots     chan struct{}
	recoverySlotsOnce sync.Once
}

// pendingFirmwareRecovery is one move RecoverFirmwareMoves locked.
type pendingFirmwareRecovery struct {
	vm     string
	unlock func()
}

func (s *Server) fwLiveStep(step string) {
	if h := s.fwLive.stepHook; h != nil {
		h(step)
	}
}

// liveFirmwareSourceCleanup is the source cleanup (spec §6.7, marker
// released → cleaning → removed), set in migrate_firmware_live_cleanup.go.
// nil leaves the marker released, its start veto in force, for the firmware
// move recovery (FirmwareMoveRecoveryOnce), which checks the target first.
var liveFirmwareSourceCleanup func(s *Server, ctx context.Context, m fwmig.Marker) error

// Timing of the source half; vars so tests can shorten them.
var (
	// liveFirmwareStep4Limit bounds §6.1 step 4 (the target setup between
	// Prepare and the migration). The target's hold sweep may quarantine a
	// hold with no domain once it is heldStaleAfter old and the row is not
	// migrating, so a move whose setup took longer is undone instead of
	// started (D2-9 M-4).
	liveFirmwareStep4Limit = 30 * time.Minute
	// fwLiveCallTimeout bounds one Verify, Release or Abort call; Release
	// polls the NVRAM for up to releaseNvramPollFor on the target.
	fwLiveCallTimeout = time.Minute
	// fwLiveRetryBackoff and fwLiveRetryFor: a Verify or Release that does
	// not answer is retried with backoff for fwLiveRetryFor (§7 V3, R1).
	fwLiveRetryBackoff = time.Second
	fwLiveRetryFor     = 2 * time.Minute
	// fwLiveRecoveryReleaseWait bounds how long a recovery's Release (one
	// attempt per call, oneAttempt) waits out a target that refuses it
	// because the commit has not replicated there yet.
	fwLiveRecoveryReleaseWait = 15 * time.Second
)

// newLiveFirmwareAttemptID is a fresh attempt id (a UUID, spec §4).
func newLiveFirmwareAttemptID() string { return uuid.NewString() }

// fwmigConditionFor is the condition a parked phase raises (spec §14).
var fwmigConditionFor = map[fwmig.Phase]string{
	fwmig.PhaseTargetUnreachable:  condFwmigTargetUnreachable,
	fwmig.PhaseSourceStateMissing: condFwmigSourceStateMissing,
	fwmig.PhaseSourceStateSuspect: condFwmigSourceStateSuspect,
	fwmig.PhaseTargetRan:          condFwmigTargetRan,
	fwmig.PhaseNvramUnconfirmed:   condFwmigNvramUnconfirmed,
	// discard_pending is V1 with the DISCARD unanswered: the target is
	// unreachable, and nothing is unverified-and-discarded yet.
	fwmig.PhaseDiscardPending: condFwmigTargetUnreachable,
	fwmig.PhaseSourcePaused:   condFwmigSourcePaused,
}

// resolveFirmwareMoveParkConditions resolves, as the move ends, every park
// condition of vm that this host raised as a move's source: one raised for
// a park whose marker write failed, or for a park the move left since, has
// no marker to resolve it later (lab2-D2-proof F5). A park another host
// raised as the source of its own move of the VM is that move's (review m1).
func (s *Server) resolveFirmwareMoveParkConditions(ctx context.Context, vm string) {
	if s.db == nil {
		return
	}
	seen := map[string]bool{}
	for _, code := range fwmigConditionFor {
		if seen[code] {
			continue
		}
		seen[code] = true
		row, found, err := corrosion.GetHealthCondition(ctx, s.db, firmwareMigrationEvaluator, code, "vm", vm)
		if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
			continue
		}
		var ev struct {
			Source string `json:"source"`
		}
		if json.Unmarshal([]byte(row.Evidence), &ev) == nil && ev.Source != "" && ev.Source != s.hostName {
			continue
		}
		_ = s.resolveFirmwareMigrationCondition(ctx, code, vm)
	}
}

// putLiveFirmwareMarker writes r's marker in phase p.
func (s *Server) putLiveFirmwareMarker(r *liveFirmwareRun, p fwmig.Phase) error {
	m := r.marker
	m.Phase = p
	if err := s.fwRecords().PutMarker(m); err != nil {
		return status.Errorf(codes.Internal, "VM %q: record live firmware migration %s as %s: %v", m.VM, m.Attempt, p, err)
	}
	r.marker = m
	r.parked = fwmig.Marker{}
	return nil
}

// parkLiveFirmwareMove parks r's move in phase p: the marker kept (with the
// phase it left), its condition raised, nothing deleted anywhere. The error
// is what the caller returns.
func (s *Server) parkLiveFirmwareMove(ctx context.Context, r *liveFirmwareRun, p fwmig.Phase, detail string) error {
	ctx = context.WithoutCancel(ctx)
	if p == fwmig.PhaseTargetUnreachable {
		// A retry of a parked move's blocked call that went unanswered (or was
		// refused for the state the park recorded, D2-10 m-7) learns nothing
		// new: the park stands, with its own condition.
		switch {
		case r.marker.Phase.Parked():
			p = r.marker.Phase
		case r.parked.Phase.Parked():
			p = r.parked.Phase
		}
	}
	if pk := r.parked; pk.Phase == p && pk.Detail == detail && s.fwmigConditionOpenWith(ctx, fwmigConditionFor[p], pk.VM, detail) {
		// A retry that ends where it was parked, for the same reason: the
		// park, its condition and its event stand as written (§8.1).
		r.marker = pk
		slog.Debug("live firmware move: still parked", "vm", pk.VM, "attempt", pk.Attempt, "phase", p, "detail", detail)
		return status.Errorf(codes.FailedPrecondition,
			"VM %q: live firmware migration %s to %s is parked as %s: %s; both copies of its firmware state are kept",
			pk.VM, pk.Attempt, pk.Target, p, detail)
	}
	m, err := r.marker.Park(p)
	if err != nil {
		// A park this marker cannot take keeps it as it is: it still vetoes.
		slog.Error("live firmware move: cannot park the marker; it is kept as it is", "vm", r.marker.VM, "phase", p, "error", err)
		m = r.marker
	} else {
		m.Detail = detail
		if perr := s.fwRecords().PutMarker(m); perr != nil {
			slog.Error("live firmware move: cannot record the park; the marker on disk is kept", "vm", m.VM, "phase", p, "error", perr)
		} else {
			r.marker = m
			r.parked = fwmig.Marker{}
		}
	}
	s.raiseParkCondition(ctx, m, p, detail, r.parkAction)
	r.parkAction = ""
	slog.Error("live firmware move parked", "vm", m.VM, "attempt", m.Attempt, "target", m.Target, "phase", p, "detail", detail)
	s.recordVMEvent(ctx, m.VM, "vm.migrate.firmware", "error", fmt.Sprintf("live firmware migration %s to %s parked as %s: %s", m.Attempt, m.Target, p, detail))
	return status.Errorf(codes.FailedPrecondition,
		"VM %q: live firmware migration %s to %s is parked as %s: %s; both copies of its firmware state are kept",
		m.VM, m.Attempt, m.Target, p, detail)
}

// raiseParkCondition raises the condition of m's move parked as p.
func (s *Server) raiseParkCondition(ctx context.Context, m fwmig.Marker, p fwmig.Phase, detail, action string) {
	code, ok := fwmigConditionFor[p]
	if !ok {
		return
	}
	if action == "" {
		action = "both copies of the firmware state are kept, and nothing is deleted until the move is resolved; " +
			"`lv doctor firmware-move <vm>` shows both records and the actions that resolve it"
	}
	if cerr := s.raiseFirmwareMigrationCondition(ctx, fwmigCondition{
		Code: code, VM: m.VM, Attempt: m.Attempt, Source: s.hostName, Target: m.Target,
		Hashes: map[string]string{"src_permall_sha256": m.SrcPermallSHA256, "src_nvram_sha256": m.SrcNvramSHA256},
		Paths:  []string{s.fw().SwtpmDir(m.UUID), s.fw().NvramPath(m.VM)},
		Detail: detail,
		Action: action,
	}); cerr != nil {
		slog.Warn("live firmware move: raise the condition", "vm", m.VM, "code", code, "error", cerr)
	}
}

// liveFirmwarePeer dials the move's target.
func (s *Server) liveFirmwarePeer(ctx context.Context, target string) (pb.LiteVirtClient, func(), error) {
	return s.dialPeer(ctx, target)
}

// sourceDomainActive reports whether this host's domain of vm is active; an
// unreadable answer is false (so a target disposes of its state by rule Q,
// never rule D).
func (s *Server) sourceDomainActive(vm string) bool {
	if s.virt == nil {
		return false
	}
	active, err := s.virt.DomainIsActive(vm)
	return err == nil && active
}

// ── Steps 2 and 3: the marker, Prepare, stage B ──

// beginLiveFirmwareMove writes the marker (preparing), asks the target to
// hold the move (Prepare) and judges its answer (stage B); the marker is then
// prepared. It returns a run whenever the target may hold the attempt, also
// with an error: the caller's undo then aborts it before cutover (§7 P2). A
// target whose build lacks the RPC wrote nothing, and gets no run.
func (s *Server) beginLiveFirmwareMove(ctx context.Context, vm *corrosion.VMRecord, target *corrosion.HostRecord, elig *liveFirmwareEligible) (*liveFirmwareRun, error) {
	route := fwmig.RouteTunnelled
	if elig.storage {
		route = fwmig.RouteStorageCopy
	}
	r := &liveFirmwareRun{target: *target, elig: elig, marker: fwmig.Marker{
		VM: vm.Name, Binding: fwmig.Binding{UUID: elig.uuid, CreatedAt: vm.CreatedAt, Attempt: newLiveFirmwareAttemptID()},
		Target: target.Name, Route: route, Phase: fwmig.PhasePreparing,
		TPM: elig.applicability.GetTpm(), UEFI: elig.applicability.GetUefi(), Since: time.Now().UTC(),
		CapacityLease: elig.lease, CapacityLeaseHolder: elig.leaseHolder,
	}}
	var nvram []byte
	if r.marker.UEFI {
		b, err := os.ReadFile(s.fw().NvramPath(vm.Name))
		if err != nil {
			return nil, liveFirmwareRefusal(vm.Name, target.Name, "its NVRAM on %s cannot be read: %v", s.hostName, err)
		}
		nvram = b
	}
	if err := s.putLiveFirmwareMarker(r, fwmig.PhasePreparing); err != nil {
		return nil, err
	}
	client, closer, err := s.liveFirmwarePeer(ctx, target.Name)
	sent := err == nil
	var resp *pb.PrepareLiveFirmwareTargetResponse
	if sent {
		cctx, cancel := context.WithTimeout(ctx, fwLiveCallTimeout)
		resp, err = client.PrepareLiveFirmwareTarget(cctx, &pb.PrepareLiveFirmwareTargetRequest{
			VmName: vm.Name, Uuid: elig.uuid, CreatedAt: vm.CreatedAt, AttemptId: r.marker.Attempt,
			ProtocolVersion: liveFirmwareProtocolVersion, SrcRuntime: elig.runtime, SrcApplicability: elig.applicability,
			SourceDomainActive: s.sourceDomainActive(vm.Name), Nvram: nvram,
		})
		cancel()
		closer()
	}
	if !sent || status.Code(err) == codes.Unimplemented {
		// No request reached the target, or an older target without the
		// RPC: nothing was written there (§7 P1), so the move is refused
		// with no marker and no abort.
		if rerr := s.fwRecords().RemoveMarker(vm.Name); rerr != nil {
			return r, status.Errorf(codes.Internal, "VM %q: remove the marker of a refused live firmware migration: %v", vm.Name, rerr)
		}
		return nil, liveFirmwareStageB(vm.Name, target.Name, elig, nil, err)
	}
	r.prepared = time.Now()
	if err := liveFirmwareStageB(vm.Name, target.Name, elig, resp, err); err != nil {
		// The target may hold the attempt (a Prepare that failed after its
		// hold write, or a refused answer): the undo aborts it (§7 P2).
		return r, err
	}
	if err := s.putLiveFirmwareMarker(r, fwmig.PhasePrepared); err != nil {
		return r, err
	}
	slog.Info("live firmware move: target holds the attempt", "vm", vm.Name, "attempt", r.marker.Attempt, "target", target.Name)
	return r, nil
}

// recordLiveFirmwareRoute is §6.1 step 4's record: the route stage C
// allowed and the stubs EnsureDisks reported creating, in the prepared
// marker.
func (s *Server) recordLiveFirmwareRoute(r *liveFirmwareRun, route fwmig.Route, stubs []string) error {
	r.marker.Route = route
	r.marker.CreatedStubs = append([]string(nil), stubs...)
	return s.putLiveFirmwareMarker(r, r.marker.Phase)
}

// startLiveFirmwareMigration is §6.1 step 5: the marker migrating, unless the
// target setup took so long that the target's hold sweep may have disposed
// of its hold.
func (s *Server) startLiveFirmwareMigration(r *liveFirmwareRun) error {
	if took := time.Since(r.prepared); took > liveFirmwareStep4Limit {
		return liveFirmwareRefusal(r.marker.VM, r.target.Name,
			"setting up the target took %s since it began holding the move (limit %s); try again", took.Round(time.Second), liveFirmwareStep4Limit)
	}
	return s.putLiveFirmwareMarker(r, fwmig.PhaseMigrating)
}

// ── Before cutover: abort (§7 P1, P2, M1, M1p) ──

// sendLiveFirmwareAbort sends Abort in mode for the attempt b of vm to
// target, with the stubs it created there. source_domain_active is read live.
func (s *Server) sendLiveFirmwareAbort(ctx context.Context, target, vm string, b fwmig.Binding, mode pb.FirmwareAbortMode, stubs []string) (*pb.AbortLiveFirmwareTargetResponse, error) {
	ctx = context.WithoutCancel(ctx)
	client, closer, err := s.liveFirmwarePeer(ctx, target)
	if err != nil {
		return nil, err
	}
	defer closer()
	cctx, cancel := context.WithTimeout(ctx, fwLiveCallTimeout)
	defer cancel()
	return client.AbortLiveFirmwareTarget(cctx, &pb.AbortLiveFirmwareTargetRequest{
		VmName: vm, Uuid: b.UUID, CreatedAt: b.CreatedAt, AttemptId: b.Attempt,
		Mode: mode, SourceDomainActive: s.sourceDomainActive(vm), CreatedStubs: stubs,
	})
}

// abortLiveFirmwareBeforeCutover sends Abort PRE_CUTOVER for r's attempt and
// decides from its answer (§7 P2, M1). It returns "" once the target answered
// that it holds nothing of the attempt and has no domain of the VM (D2-9
// M-6), and otherwise the phase to park in, with the reason.
//
// guestMayBeThere is set after the migration call (M1): libvirt may have
// left the incoming guest on the target (a Confirm-phase failure, K-3). Its
// Abort refusal decides — never Verify, which before cutover would judge a
// copy against a source that still runs: a domain paused or shut off under a
// prepared hold is discarded at once (the running source is the live,
// current copy). A DISCARD the target refuses parks target_ran; one it does
// not answer parks target_unreachable. Any other domain or refusal is a
// domain this attempt cannot account for, and parks target_ran: both copies
// kept, nothing resumed.
func (s *Server) abortLiveFirmwareBeforeCutover(ctx context.Context, r *liveFirmwareRun, guestMayBeThere bool) (fwmig.Phase, string) {
	m := r.marker
	resp, err := s.sendLiveFirmwareAbort(ctx, r.target.Name, m.VM, m.Binding, pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_PRE_CUTOVER, m.CreatedStubs)
	switch {
	case abortTargetPredatesRPC(err) && !guestMayBeThere:
		// libvirt never had the guest: a target without the RPC holds no
		// domain of the attempt, only stubs (§7 P1).
		slog.Warn("live firmware move: the target's build has no abort; it holds nothing of the attempt", "vm", m.VM, "attempt", m.Attempt, "target", r.target.Name)
		return "", ""
	case abortTargetPredatesRPC(err):
		// After the migration call the incoming domain may be defined there,
		// and a build without the RPCs cannot say (review D2-13 N-2).
		return fwmig.PhaseTargetUnreachable, fmt.Sprintf("%s: %s", r.target.Name, errTargetRolledBack)
	}
	if err != nil {
		return fwmig.PhaseTargetUnreachable, fmt.Sprintf("the abort before cutover was not answered by %s: %v", r.target.Name, err)
	}
	td := resp.GetTargetDomain()
	if !resp.GetRefused() && !td.GetPresent() {
		return "", ""
	}
	seen := fmt.Sprintf("%s answered the abort before cutover with hold %s and domain %s (refused %v): %s",
		r.target.Name, orNone(resp.GetHoldState()), domainWord(td), resp.GetRefused(), resp.GetDetail())
	if !guestMayBeThere || !resp.GetRefused() || !td.GetPresent() ||
		(td.GetState() != "paused" && td.GetState() != "shutoff") || resp.GetHoldState() != string(fwmig.HoldPrepared) {
		return fwmig.PhaseTargetRan, seen + "; the target holds a domain or hold this attempt cannot account for or discard before cutover (not necessarily a guest that ran)"
	}
	d, err := s.sendLiveFirmwareAbort(ctx, r.target.Name, m.VM, m.Binding, pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_DISCARD_UNVERIFIED, m.CreatedStubs)
	switch {
	case err != nil:
		return fwmig.PhaseTargetUnreachable, fmt.Sprintf("%s; the discard of its copy was not answered: %v", seen, err)
	case d.GetRefused():
		return fwmig.PhaseTargetRan, fmt.Sprintf("%s; %s refused the discard of its copy: %s", seen, r.target.Name, d.GetDetail())
	case d.GetTargetDomain().GetPresent():
		return fwmig.PhaseTargetRan, fmt.Sprintf("%s; after the discard a domain of the VM is still defined there (%s)", seen, d.GetTargetDomain().GetState())
	}
	slog.Warn("live firmware move: the target's copy of a migration that failed before cutover was discarded",
		"vm", m.VM, "attempt", m.Attempt, "target", r.target.Name)
	return "", ""
}

// abortTargetPredatesRPC reports an Abort a target answered Unimplemented: its
// build predates the live firmware RPCs. Before the migration call it holds
// nothing of the attempt (§7 P1, review D2-13 m-9); after it, its domain
// cannot be seen (N-2).
func abortTargetPredatesRPC(err error) bool {
	return err != nil && status.Code(err) == codes.Unimplemented
}

// errTargetRolledBack is the detail of a move whose target's build no longer
// has the live firmware RPCs after the migration call. Both copies are kept;
// the target's paused domain, if any, is the move's and is not to be run.
const errTargetRolledBack = "its build no longer has the live firmware RPCs (rolled back?), so whether it holds a paused copy of the guest cannot be seen; " +
	"both copies are kept and neither is run: upgrade the target again, and the move is retried each minute"

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// settleLiveFirmwareAbort ends r's move after an abort before cutover: parked
// in phase when one is given, the marker removed otherwise.
func (s *Server) settleLiveFirmwareAbort(ctx context.Context, r *liveFirmwareRun, phase fwmig.Phase, why string) {
	if phase != "" {
		_ = s.parkLiveFirmwareMove(ctx, r, phase, why)
		return
	}
	s.unmarkLiveFirmwareMove(r, "undone before cutover")
}

// unmarkLiveFirmwareMove removes r's marker once nothing of the move is left
// to resolve.
func (s *Server) unmarkLiveFirmwareMove(r *liveFirmwareRun, how string) {
	s.resolveFirmwareMoveParkConditions(context.Background(), r.marker.VM)
	if err := s.fwRecords().RemoveMarker(r.marker.VM); err != nil {
		slog.Error("live firmware move: resolved, but the marker cannot be removed; restart recovery removes it",
			"vm", r.marker.VM, "attempt", r.marker.Attempt, "how", how, "error", err)
		return
	}
	slog.Info("live firmware move: "+how, "vm", r.marker.VM, "attempt", r.marker.Attempt, "target", r.target.Name)
}

// ── After the migration call ──

// liveFirmwareSourceActive reports whether this host's domain of vm is known
// to be active. An unreadable state is not: the move goes on to cutover,
// whose own check parks it (§7 M1b).
func (s *Server) liveFirmwareSourceActive(vm string) bool {
	if s.virt == nil {
		return false
	}
	active, err := s.virt.DomainIsActive(vm)
	return err == nil && active
}

// errLiveFirmwareSourceActive is the cutover finding the source domain still
// active: the guest did not leave, and the caller handles it as a failed
// migration (§7 M1, M1p).
var errLiveFirmwareSourceActive = errors.New("the migration returned, and the source domain is still active")

// liveFirmwareMigrateFailed is the source's answer to a migration call that
// left its guest here, its domain active (§7 M1, M1p). It returns unmark, to
// call once the caller restored the row (nil when the move parked), and
// keepRow: the row stays migrating because the source guest is not running.
//
//   - Paused (M1p): Abort PRE_CUTOVER; a target with nothing of the attempt
//     lets the source resume its guest first (ResumeFirmwareMoveSource), the
//     row is then restored and the marker removed. A target with a domain
//     parks source_paused, both guests paused.
//   - Running, or any other active state (M1): Abort PRE_CUTOVER, with the
//     automatic DISCARD of a target's paused copy under a prepared hold.
func (s *Server) liveFirmwareMigrateFailed(ctx context.Context, r *liveFirmwareRun, migrateErr error) (unmark func(), keepRow bool) {
	ctx = context.WithoutCancel(ctx)
	st, err := s.virt.DomainStateReason(r.marker.VM)
	if err != nil {
		// Active, but whether it runs or is paused cannot be read: a paused
		// guest must not lose its marker unresumed, so the move parks with
		// both copies kept (an operator's --accept-source resumes it).
		_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourcePaused, fmt.Sprintf(
			"the migration failed (%v), and the active source domain's state cannot be read: %v", migrateErr, err))
		return nil, true
	}
	if st.Reason == "paused" {
		return s.liveFirmwareSourcePaused(ctx, r, migrateErr)
	}
	if phase, why := s.abortLiveFirmwareBeforeCutover(ctx, r, true); phase != "" {
		_ = s.parkLiveFirmwareMove(ctx, r, phase, fmt.Sprintf("the migration failed (%v); %s", migrateErr, why))
		return nil, false
	}
	return func() { s.unmarkLiveFirmwareMove(r, "the migration failed; undone before cutover") }, false
}

// liveFirmwareSourcePaused is §7 M1p: the migration failed and left the
// source guest paused.
func (s *Server) liveFirmwareSourcePaused(ctx context.Context, r *liveFirmwareRun, migrateErr error) (func(), bool) {
	m := r.marker
	resp, err := s.sendLiveFirmwareAbort(ctx, r.target.Name, m.VM, m.Binding, pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_PRE_CUTOVER, m.CreatedStubs)
	switch {
	case abortTargetPredatesRPC(err):
		// The target may hold the paused incoming copy and cannot say: the
		// source guest stays paused (review D2-13 N-2), parked
		// target_unreachable so each pass asks again, and M1p decides once
		// the target answers (re-review 2 I-A).
		_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable, fmt.Sprintf(
			"the migration failed (%v) and left the source guest paused; %s: %s", migrateErr, r.target.Name, errTargetRolledBack))
		return nil, true
	case err != nil:
		_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable, fmt.Sprintf(
			"the migration failed (%v) and left the source guest paused; the abort before cutover was not answered by %s: %v", migrateErr, r.target.Name, err))
		return nil, true
	case resp.GetRefused() || resp.GetTargetDomain().GetPresent():
		_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourcePaused, fmt.Sprintf(
			"the migration failed (%v) and left the source guest paused, and %s holds a domain of the VM (hold %s, domain %s): %s",
			migrateErr, r.target.Name, orNone(resp.GetHoldState()), domainWord(resp.GetTargetDomain()), resp.GetDetail()))
		return nil, true
	}
	// The target holds nothing: the paused source is the only copy. It runs
	// again first; the marker goes only after the row is restored.
	if err := s.virt.ResumeFirmwareMoveSource(m.VM, m.UUID, m.Attempt); err != nil {
		_ = s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourcePaused, fmt.Sprintf(
			"the migration failed (%v) and left the source guest paused; the target holds nothing of it, but the resume failed: %v", migrateErr, err))
		return nil, true
	}
	slog.Info("live firmware move: the paused source guest was resumed after a failed migration", "vm", m.VM, "attempt", m.Attempt)
	return func() { s.unmarkLiveFirmwareMove(r, "the migration failed; the source guest resumed") }, false
}

// ── Step 7 and 8: cutover and Verify ──

// liveFirmwareCutover is §6.1 steps 7 and 8: the source domain confirmed
// inactive, its stop reason and final state read, the marker cutover; then
// Verify, and on MATCH the marker verified. Any other outcome parks the move
// and returns its error; the commit must not follow.
func (s *Server) liveFirmwareCutover(ctx context.Context, r *liveFirmwareRun) error {
	ctx = context.WithoutCancel(ctx)
	vm := r.marker.VM
	active, err := s.virt.DomainIsActive(vm)
	if err != nil {
		// Not known to have stopped, so its state cannot be read as final.
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourceStateMissing,
			fmt.Sprintf("the migration returned, and whether the source domain is still active cannot be read: %v", err))
	}
	if active {
		// The guest did not leave: the caller handles it as a failed
		// migration (§7 M1, M1p), never as a cutover.
		return errLiveFirmwareSourceActive
	}
	reason := "unknown"
	if st, err := s.virt.DomainStateReason(vm); err == nil && st.Reason != "" {
		reason = st.Reason
	}
	fw := s.fw()
	var permall, nvram string
	if r.marker.TPM {
		if permall, err = fw.PermallSHA256(r.marker.UUID); err != nil {
			return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourceStateMissing,
				fmt.Sprintf("the source's final TPM state cannot be read: %v", err))
		}
	}
	if r.marker.UEFI {
		if nvram, err = fw.NvramSHA256(vm); err != nil {
			return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourceStateMissing,
				fmt.Sprintf("the source's final NVRAM cannot be read: %v", err))
		}
	}
	r.marker.SrcPermallSHA256, r.marker.SrcNvramSHA256, r.marker.SrcStopReason = permall, nvram, reason
	if err := s.putLiveFirmwareMarker(r, fwmig.PhaseCutover); err != nil {
		return err
	}
	return s.verifyLiveFirmwareMove(ctx, r)
}

// verifyLiveFirmwareMove sends Verify (retried while unanswered) and judges
// the verdict. MATCH sets the marker verified. Before the commit, every other
// verdict parks the move with both copies kept.
func (s *Server) verifyLiveFirmwareMove(ctx context.Context, r *liveFirmwareRun) error {
	m := r.marker
	var resp *pb.VerifyLiveFirmwareTargetResponse
	err := s.retryLiveFirmwareCall(ctx, r, "verify", func(cctx context.Context, c pb.LiteVirtClient) (err error) {
		resp, err = c.VerifyLiveFirmwareTarget(cctx, &pb.VerifyLiveFirmwareTargetRequest{
			VmName: m.VM, Uuid: m.UUID, AttemptId: m.Attempt, SrcPermallSha256: m.SrcPermallSHA256})
		return err
	})
	if err != nil {
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable, fmt.Sprintf("Verify was not answered by %s: %v", r.target.Name, err))
	}
	td := resp.GetTargetDomain()
	switch resp.GetVerdict() {
	case pb.FirmwareVerdict_FIRMWARE_VERDICT_MATCH:
		if err := s.putLiveFirmwareMarker(r, fwmig.PhaseVerified); err != nil {
			return err
		}
		slog.Info("live firmware move: target verified", "vm", m.VM, "attempt", m.Attempt, "target", r.target.Name)
		return nil
	case pb.FirmwareVerdict_FIRMWARE_VERDICT_TARGET_RAN:
		// V5: the guard failed. Nothing deleted, no further step.
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetRan, resp.GetDetail())
	case pb.FirmwareVerdict_FIRMWARE_VERDICT_MISMATCH, pb.FirmwareVerdict_FIRMWARE_VERDICT_NOT_RUNNING:
		if m.SrcStopReason != fwmig.StopReasonMigrated {
			// V1b: the source domain did not stop as a completed migration
			// stops it: its state may be stale (I6). Both copies are kept.
			return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourceStateSuspect,
				fmt.Sprintf("Verify answered %s after the source stopped with reason %q: %s", resp.GetVerdict(), m.SrcStopReason, resp.GetDetail()))
		}
		// V1: the target's copy is not the source's final state.
		return s.discardUnverifiedLiveFirmware(ctx, r, resp)
	case pb.FirmwareVerdict_FIRMWARE_VERDICT_NOT_HELD:
		if td.GetPresent() {
			// V3: no hold, but a domain of the VM: nothing here decides it.
			return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable,
				fmt.Sprintf("Verify answered NOT_HELD with a domain of the VM on %s (%s): %s", r.target.Name, domainWord(td), resp.GetDetail()))
		}
		// V4: the incoming migration never landed.
		return s.liveFirmwareNeverLanded(ctx, r, resp.GetDetail())
	case pb.FirmwareVerdict_FIRMWARE_VERDICT_BAD_REQUEST:
		// V6: the target lacks a hash this source should have sent (a source
		// bug): the source's final state is what is missing. Hold kept.
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourceStateMissing,
			fmt.Sprintf("Verify answered BAD_REQUEST: %s", resp.GetDetail()))
	default:
		// A verdict this build does not know decides nothing.
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable,
			fmt.Sprintf("Verify answered %s (domain %s): %s", resp.GetVerdict(), domainWord(td), resp.GetDetail()))
	}
}

// discardUnverifiedLiveFirmware is §7 V1: Verify found the target's copy is
// not the source's final state, and the source domain stopped as a completed
// migration stops it, so the source's copy is current. Abort DISCARD; once it
// answers, the row is stopped on the source, the condition raised and the
// marker removed. Unanswered → discard_pending; refused (the target domain
// runs) → target_ran.
func (s *Server) discardUnverifiedLiveFirmware(ctx context.Context, r *liveFirmwareRun, verify *pb.VerifyLiveFirmwareTargetResponse) error {
	m := r.marker
	why := fmt.Sprintf("Verify answered %s: %s", verify.GetVerdict(), verify.GetDetail())
	d, err := s.sendLiveFirmwareAbort(ctx, r.target.Name, m.VM, m.Binding, pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_DISCARD_UNVERIFIED, m.CreatedStubs)
	switch {
	case err != nil:
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseDiscardPending, fmt.Sprintf("%s; the discard of the target's copy was not answered by %s: %v", why, r.target.Name, err))
	case d.GetRefused():
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetRan, fmt.Sprintf("%s; %s refused the discard: %s", why, r.target.Name, d.GetDetail()))
	case d.GetTargetDomain().GetPresent():
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetRan,
			fmt.Sprintf("%s; after the discard a domain of the VM is still defined on %s (%s)", why, r.target.Name, d.GetTargetDomain().GetState()))
	}
	quarantine := fmt.Sprintf("%s:<data_dir>/%s/%s-%s/", r.target.Name, fwmig.QuarantineDir, m.VM, m.Attempt)
	detail := fmt.Sprintf("live firmware migration %s to %s did not verify (%s); the target's copy is quarantined, and the VM is stopped here with its firmware state: `lv start`",
		m.Attempt, r.target.Name, verify.GetVerdict())
	s.stopLiveFirmwareMoveOnSource(ctx, r, detail)
	if cerr := s.raiseFirmwareMigrationCondition(ctx, fwmigCondition{
		Code: condFwmigUnverified, VM: m.VM, Attempt: m.Attempt, Source: s.hostName, Target: r.target.Name,
		Hashes: map[string]string{"src_permall_sha256": m.SrcPermallSHA256, "src_nvram_sha256": m.SrcNvramSHA256,
			"dst_permall_sha256": verify.GetDstPermallSha256()},
		Paths:  []string{quarantine, s.fw().SwtpmDir(m.UUID), s.fw().NvramPath(m.VM)},
		Detail: why,
		Action: "the source's firmware state is kept and the VM is stopped here; `lv start` runs it from that state, and the quarantine on the target is for inspection",
	}); cerr != nil {
		slog.Warn("live firmware move: raise the condition", "vm", m.VM, "code", condFwmigUnverified, "error", cerr)
	}
	s.unmarkLiveFirmwareMove(r, "the target's copy did not verify and was discarded")
	return status.Errorf(codes.FailedPrecondition, "VM %q: %s", m.VM, detail)
}

// liveFirmwareNeverLanded is §7 V4: Verify answered NOT_HELD and the target
// has no domain of the VM, so the incoming migration never landed. The guest
// runs nowhere: the row is stopped on the source, its state kept, the marker
// removed.
func (s *Server) liveFirmwareNeverLanded(ctx context.Context, r *liveFirmwareRun, why string) error {
	m := r.marker
	detail := fmt.Sprintf("live firmware migration %s to %s never landed there (%s); the VM is stopped here with its firmware state: `lv start`",
		m.Attempt, r.target.Name, why)
	s.stopLiveFirmwareMoveOnSource(ctx, r, detail)
	s.unmarkLiveFirmwareMove(r, "the migration never landed on the target")
	return status.Errorf(codes.FailedPrecondition, "VM %q: %s", m.VM, detail)
}

// stopLiveFirmwareMoveOnSource records a move that ended with its guest on
// neither host: the VFs detached for it released (the domain is shut off
// here), the row stopped on the source.
func (s *Server) stopLiveFirmwareMoveOnSource(ctx context.Context, r *liveFirmwareRun, detail string) {
	ctx = context.WithoutCancel(ctx)
	s.reattachVFsOnSource(ctx, r.marker.VM, r.vfs, len(r.vfs) > 0)
	if err := corrosion.UpdateVMState(ctx, s.db, r.marker.VM, "stopped", detail); err != nil {
		s.noteStateWriteFail(corrosion.OpVMState, err)
	}
	s.recordVMEvent(ctx, r.marker.VM, "vm.migrate.firmware", "error", detail)
}

// retryLiveFirmwareCall makes call against r's target until it answers, with
// backoff, for fwLiveRetryFor. A target without the RPC, or one that denies
// this host, is not retried.
func (s *Server) retryLiveFirmwareCall(ctx context.Context, r *liveFirmwareRun, what string, call func(context.Context, pb.LiteVirtClient) error) error {
	deadline := time.Now().Add(fwLiveRetryFor)
	if r.oneAttempt {
		deadline = time.Now()
	}
	wait := fwLiveRetryBackoff
	for {
		client, closer, err := s.liveFirmwarePeer(ctx, r.target.Name)
		if err == nil {
			cctx, cancel := context.WithTimeout(ctx, fwLiveCallTimeout)
			err = call(cctx, client)
			cancel()
			closer()
		}
		if err == nil {
			return nil
		}
		switch status.Code(err) {
		case codes.Unimplemented, codes.PermissionDenied, codes.InvalidArgument:
			return err
		}
		if time.Now().Add(wait).After(deadline) {
			return err
		}
		slog.Warn("live firmware move: retrying", "vm", r.marker.VM, "call", what, "target", r.target.Name, "error", err)
		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait):
		}
		if wait *= 2; wait > 15*time.Second {
			wait = 15 * time.Second
		}
	}
}

// ── Steps 9 to 12: commit, Release, NVRAM, cleanup ──

// liveFirmwareCommitted is §6.1 step 9's record: the commit landed. The
// marker records the VM's disk rows as the commit left them, which the D-5
// return writer's guard compares with (§17 D-5); a read that fails leaves
// them out, and the return then judges the rows as they are.
func (s *Server) liveFirmwareCommitted(r *liveFirmwareRun) error {
	s.fwLiveStep("commit")
	if s.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		disks, err := corrosion.GetVMDisks(ctx, s.db, r.marker.VM)
		cancel()
		if err != nil {
			slog.Warn("live firmware move: the committed disk rows cannot be read; the marker records none", "vm", r.marker.VM, "error", err)
		} else {
			r.marker.CommitDisks = commitDisksOf(disks)
		}
	}
	return s.putLiveFirmwareMarker(r, fwmig.PhaseCommitted)
}

// commitDisksOf is the marker's record of disk rows.
func commitDisksOf(disks []corrosion.DiskRecord) []fwmig.CommitDisk {
	out := make([]fwmig.CommitDisk, 0, len(disks))
	for _, d := range disks {
		out = append(out, fwmig.CommitDisk{Disk: d.DiskName, Host: d.HostName, Path: d.Path, StorageType: d.StorageType, StorageVolume: d.StorageVolume})
	}
	return out
}

// releaseLiveFirmwareMove is §6.1 steps 10 to 12, in place of the NIC
// hand-over (armedMigration.finish): Release (the target puts the NIC
// firewall in force and resumes its guest), the NVRAM confirmation, and the
// source cleanup. An error means the guest is held or parked as it says.
func (s *Server) releaseLiveFirmwareMove(ctx context.Context, r *liveFirmwareRun) error {
	ctx = context.WithoutCancel(ctx)
	m := r.marker
	var nvramFinal []byte
	if m.UEFI {
		// The source domain is inactive, so this is its final NVRAM; Release
		// uses it only for a held guest the target lost (§7 H1), and only
		// with the hash Verify's cutover recorded.
		if b, err := os.ReadFile(s.fw().NvramPath(m.VM)); err == nil && fwBytesSHA256(b) == m.SrcNvramSHA256 {
			nvramFinal = b
		} else {
			slog.Warn("live firmware move: the source's final NVRAM is not as recorded at cutover; Release carries none",
				"vm", m.VM, "attempt", m.Attempt, "error", err)
		}
	}
	var resp *pb.ReleaseLiveFirmwareTargetResponse
	release := func(cctx context.Context, c pb.LiteVirtClient) (err error) {
		resp, err = c.ReleaseLiveFirmwareTarget(cctx, &pb.ReleaseLiveFirmwareTargetRequest{
			VmName: m.VM, Uuid: m.UUID, AttemptId: m.Attempt, CreatedAt: m.CreatedAt,
			SrcNvramSha256: m.SrcNvramSHA256, NvramFinal: nvramFinal})
		return err
	}
	err := s.retryLiveFirmwareCall(ctx, r, "release", release)
	if r.oneAttempt {
		// A recovery commits and releases in one pass, with one attempt per
		// call; a target that has not yet received the commit refuses
		// Release (its row still names this host), and the guest would stay
		// paused there until the next pass, a minute later (lab2-D2-proof
		// F1). That refusal is waited out briefly here.
		// The wait ends with the daemon (the recovery's waitCtx), which
		// keeps the park as it is (review m7).
		done := context.Background().Done()
		if r.waitCtx != nil {
			done = r.waitCtx.Done()
		}
		deadline := time.Now().Add(fwLiveRecoveryReleaseWait)
	wait:
		for wait := fwLiveRetryBackoff; status.Code(err) == codes.FailedPrecondition && time.Now().Add(wait).Before(deadline); wait *= 2 {
			slog.Info("live firmware move: the target refused Release; retrying while the commit replicates", "vm", m.VM, "target", r.target.Name, "error", err)
			t := time.NewTimer(wait)
			select {
			case <-done:
				t.Stop()
				break wait
			case <-t.C:
			}
			err = s.retryLiveFirmwareCall(ctx, r, "release", release)
		}
	}
	if err != nil {
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable, fmt.Sprintf("Release was not answered by %s: %v", r.target.Name, err))
	}
	// Release's refusals are judged here, by the RPC that gave them: after
	// the commit the target holds the only verified copy, so every one parks
	// and none discards it.
	switch v := resp.GetVerdict(); v {
	case pb.FirmwareVerdict_FIRMWARE_VERDICT_UNSPECIFIED:
	case pb.FirmwareVerdict_FIRMWARE_VERDICT_TARGET_RAN:
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetRan, resp.GetDetail())
	case pb.FirmwareVerdict_FIRMWARE_VERDICT_BAD_REQUEST:
		// V6 after the commit: the source sent no NVRAM hash.
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseSourceStateMissing, fmt.Sprintf("Release answered BAD_REQUEST: %s", resp.GetDetail()))
	case pb.FirmwareVerdict_FIRMWARE_VERDICT_NOT_RUNNING:
		// H1 with the held domain gone (held_domain_absent). The target holds
		// the only verified copy: this parks, and never takes V1's DISCARD.
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable,
			fmt.Sprintf("Release answered NOT_RUNNING (domain %s): %s", domainWord(resp.GetTargetDomain()), resp.GetDetail()))
	default:
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseTargetUnreachable,
			fmt.Sprintf("Release answered %s (domain %s): %s", v, domainWord(resp.GetTargetDomain()), resp.GetDetail()))
	}
	if !resp.GetNvramConfirmed() {
		return s.parkLiveFirmwareMove(ctx, r, fwmig.PhaseNvramUnconfirmed, resp.GetDetail())
	}
	if err := s.putLiveFirmwareMarker(r, fwmig.PhaseReleased); err != nil {
		return err
	}
	slog.Info("live firmware move: released on the target", "vm", m.VM, "attempt", m.Attempt, "target", r.target.Name, "nvram", resp.GetNvramSha256())
	s.fwLiveStep("cleanup")
	if liveFirmwareSourceCleanup == nil {
		slog.Info("live firmware move: the source state stays until the source cleanup runs", "vm", m.VM, "attempt", m.Attempt)
		return nil
	}
	return liveFirmwareSourceCleanup(s, ctx, r.marker)
}

// ── Fence-based resolution and owed DISCARDs (§7) ──

// ResolveLiveFirmwareMoveByFence is §7's fence-based resolution of vm's move
// parked target_unreachable or discard_pending. It acts only when the
// target is proved off (HostProvedOff: fenced with a proof-grade fence, or
// fence-confirmed), and only when the VM's row, re-read now, names this host
// for the move's incarnation: the commit never landed, so this host's state is
// the only current copy (the target never ran, I1). It then records the
// DISCARD it owes the target (with the stubs), sets the row from the source
// domain, and removes the marker, so `lv start` works here. A row naming the
// target, or anything it cannot read, leaves the park (its start veto keeps
// the stale source state from booting) for an operator. Reports whether it
// resolved the move.
func (s *Server) ResolveLiveFirmwareMoveByFence(ctx context.Context, vm string) (bool, error) {
	unlock := s.lockVM(vm)
	defer unlock()
	m, ok, err := s.fwRecords().GetMarker(vm)
	if err != nil || !ok {
		return false, err
	}
	return s.resolveLiveFirmwareMoveByFenceLocked(ctx, m)
}

// resolveLiveFirmwareMoveByFenceLocked is ResolveLiveFirmwareMoveByFence for
// the marker m, read under lockVM(m.VM), which the caller holds.
func (s *Server) resolveLiveFirmwareMoveByFenceLocked(ctx context.Context, m fwmig.Marker) (bool, error) {
	vm := m.VM
	if m.Phase != fwmig.PhaseTargetUnreachable && m.Phase != fwmig.PhaseDiscardPending {
		return false, nil
	}
	// The target proved off first: the recovery asks every interval, and
	// only a proved-off target makes the rest worth saying.
	off, err := corrosion.HostProvedOff(ctx, s.db, m.Target)
	if err != nil || !off {
		return false, err
	}
	if !m.BeforeCutover() && m.SrcStopReason != fwmig.StopReasonMigrated {
		// After cutover, a source that did not stop as a completed migration
		// stops it may hold stale TPM state (I6): neither copy is declared
		// current, and no DISCARD is owed (spec amendment 2026-10-16).
		slog.Warn("live firmware move: the target is proved off, but the source stopped with a reason other than migrated; the park stays for an operator",
			"vm", vm, "attempt", m.Attempt, "target", m.Target, "src_stop_reason", m.SrcStopReason)
		return false, nil
	}
	row, err := corrosion.GetVM(ctx, s.db, vm)
	if err != nil || row == nil {
		return false, err
	}
	if row.HostName != s.hostName ||
		!m.Binding.SameIncarnation(fwmig.Binding{UUID: parseFirmwareSpec(row.Spec).UUID, CreatedAt: row.CreatedAt}) {
		slog.Warn("live firmware move: the target is proved off, but the VM's row does not name this host for the move's incarnation; the park stays for an operator",
			"vm", vm, "attempt", m.Attempt, "target", m.Target, "row_host", row.HostName)
		return false, nil
	}
	if err := s.fwRecords().PutOwedDiscard(fwmig.OwedDiscard{VM: vm, Binding: m.Binding, Target: m.Target,
		CreatedStubs: m.CreatedStubs, Since: time.Now().UTC()}); err != nil {
		return false, err
	}
	// The row before the marker: a crash between them leaves the marker,
	// and the next pass resolves it again.
	state, detail := "stopped", fmt.Sprintf("live firmware migration %s to %s was resolved after %s was proved off; the VM's firmware state here is current: `lv start`", m.Attempt, m.Target, m.Target)
	if st, serr := s.sourceDomainState(vm); serr == nil && st == "running" {
		state = "running"
	} else if s.liveFirmwareSourceActive(vm) {
		state = "error"
	}
	if werr := s.publishRunning(ctx, vm, state, func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, s.db, vm, state, detail)
	}); werr != nil {
		return false, werr
	}
	if err := s.fwRecords().RemoveMarker(vm); err != nil {
		return false, err
	}
	s.resolveFirmwareMoveParkConditions(ctx, vm)
	if cerr := s.raiseFirmwareMigrationCondition(ctx, fwmigCondition{
		Code: condFwmigDiscardOwed, VM: vm, Attempt: m.Attempt, Source: s.hostName, Target: m.Target,
		Detail: fmt.Sprintf("%s is proved off; the DISCARD of its copy is sent when it answers", m.Target),
		Action: "nothing: it is sent each interval, and dropped when the host is removed",
	}); cerr != nil {
		slog.Warn("live firmware move: raise the condition", "vm", vm, "code", condFwmigDiscardOwed, "error", cerr)
	}
	s.recordVMEvent(ctx, vm, "vm.migrate.firmware", "ok", detail)
	slog.Warn("live firmware move: resolved by fence; a DISCARD is owed", "vm", vm, "attempt", m.Attempt, "target", m.Target, "row", state)
	return true, nil
}

// RetryOwedFirmwareDiscardsOnce sends each owed DISCARD (§7 fence
// resolution) to its target. Answered → the record goes; refused (the target
// domain runs) → firmware_migration_discard_owed, critical, and it is kept;
// unanswered → kept. A record whose target host is no longer a member is
// dropped: nothing is left to discard.
func (s *Server) RetryOwedFirmwareDiscardsOnce(ctx context.Context) {
	owed, err := s.fwRecords().ListOwedDiscards()
	if err != nil {
		slog.Warn("live firmware move: the owed discards cannot be read", "error", err)
		return
	}
	for _, o := range owed {
		h, err := corrosion.GetHost(ctx, s.db, o.Target)
		if err != nil {
			continue
		}
		if h == nil || h.State == "removed" {
			s.dropOwedDiscard(ctx, o, "its target host was removed from the cluster")
			continue
		}
		resp, err := s.sendLiveFirmwareAbort(ctx, o.Target, o.VM, o.Binding, pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_DISCARD_UNVERIFIED, o.CreatedStubs)
		switch {
		case err != nil:
			slog.Info("live firmware move: the owed discard is not answered yet", "vm", o.VM, "attempt", o.Attempt, "target", o.Target, "error", err)
		case resp.GetRefused():
			if cerr := s.raiseFirmwareMigrationCondition(ctx, fwmigCondition{
				Code: condFwmigDiscardOwed, VM: o.VM, Attempt: o.Attempt, Source: s.hostName, Target: o.Target,
				Severity: corrosion.SeverityCritical, Detail: resp.GetDetail(),
				Action: "`lv doctor firmware-move <vm> --discard-target` quarantines the target's copy (add --stop-target while its guest runs); the DISCARD is retried each interval",
			}); cerr != nil {
				slog.Warn("live firmware move: raise the condition", "vm", o.VM, "code", condFwmigDiscardOwed, "error", cerr)
			}
		case resp.GetTargetDomain().GetPresent() && s.owedDiscardRowNamesSource(ctx, o):
			// Answered, but a domain of the VM is still defined there and no
			// hold of the attempt accounted for it: the record stays.
			if cerr := s.raiseFirmwareMigrationCondition(ctx, fwmigCondition{
				Code: condFwmigDiscardOwed, VM: o.VM, Attempt: o.Attempt, Source: s.hostName, Target: o.Target,
				Severity: corrosion.SeverityCritical,
				Detail:   fmt.Sprintf("%s answered the owed discard, but a domain of the VM is still defined there (%s)", o.Target, domainWord(resp.GetTargetDomain())),
				Action:   "`lv doctor firmware-move <vm> --discard-target` quarantines the target's copy (add --stop-target while its guest runs); the DISCARD is retried each interval",
			}); cerr != nil {
				slog.Warn("live firmware move: raise the condition", "vm", o.VM, "code", condFwmigDiscardOwed, "error", cerr)
			}
		default:
			s.dropOwedDiscard(ctx, o, "the target discarded its copy")
		}
	}
}

// owedDiscardRowNamesSource reports whether the VM's row still names this
// host (or cannot be read): the owed DISCARD's domain on the target is then
// not the VM's current home.
func (s *Server) owedDiscardRowNamesSource(ctx context.Context, o fwmig.OwedDiscard) bool {
	row, err := corrosion.GetVM(ctx, s.db, o.VM)
	return err != nil || row == nil || row.HostName != o.Target
}

func (s *Server) dropOwedDiscard(ctx context.Context, o fwmig.OwedDiscard, why string) {
	if err := s.fwRecords().RemoveOwedDiscard(o.VM, o.Attempt); err != nil {
		slog.Warn("live firmware move: remove the owed discard", "vm", o.VM, "attempt", o.Attempt, "error", err)
		return
	}
	_ = s.resolveFirmwareMigrationCondition(ctx, condFwmigDiscardOwed, o.VM)
	slog.Info("live firmware move: owed discard settled: "+why, "vm", o.VM, "attempt", o.Attempt, "target", o.Target)
}
