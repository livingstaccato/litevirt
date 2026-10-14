package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// defaultStartDomainWait is how long `lv start` waits for libvirt to answer
// its start of a domain before it answers itself. It is not a bound on the
// start: a start libvirt may still complete is never given up, since the VM
// lock would then be let go while the domain comes up. The start goes on
// holding the VM, and its outcome is recorded when libvirt answers. It leaves
// room for a large guest's setup (pinning its memory for passthrough can take
// minutes); past it, the wait only changes when the caller hears, never what
// happens to the VM.
const defaultStartDomainWait = 5 * time.Minute

// startLockPoll is how often a start waiting for its VM's lock looks for a
// start of the VM already past its wait (lockVMForStart).
const startLockPoll = 20 * time.Millisecond

// startFlight is a start of a VM whose StartDomain libvirt has been asked
// for and has not answered. settled is closed once libvirt has answered and
// the outcome is recorded, before the VM's lock is let go.
type startFlight struct {
	since   time.Time
	settled chan struct{}

	// mu guards what follows.
	mu sync.Mutex
	// answered is set once libvirt has answered the start.
	answered bool
	// held is set once the start was not answered within its wait and the
	// caller was answered (startDomainWithin). marked says the row was then
	// written starting (markStartHeld), and prev is the row's state and
	// detail before it, put back if libvirt answers with a failure.
	held       bool
	marked     bool
	prevState  string
	prevDetail string
	// ownsLease says markStartHeld took the VM's start lease itself (a
	// start of a VM failover re-keyed here holds it already, and lets it go
	// with the rest of what it holds); stopRenew ends its renewal.
	ownsLease bool
	stopRenew chan struct{}
	// cancelled is when `lv stop --force` cancelled the start while libvirt
	// had not answered it (cancelHeldStart); zero when it was not.
	cancelled time.Time
}

// heldUnanswered reports whether the flight's caller has been answered past
// its wait and libvirt has still not answered the start: a lifecycle call
// queued behind it would wait as long as libvirt does.
func (f *startFlight) heldUnanswered() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.held && !f.answered
}

func (s *Server) startDomainWaitOrDefault() time.Duration {
	if s.startDomainWait > 0 {
		return s.startDomainWait
	}
	return defaultStartDomainWait
}

func (s *Server) startFlightOf(name string) (*startFlight, bool) {
	s.startFlightsMu.Lock()
	defer s.startFlightsMu.Unlock()
	f, ok := s.startFlights[name]
	return f, ok
}

// startUnanswered reports whether a start of name libvirt has not answered
// yet is under way on this daemon.
// It returns the state a read shows: starting, or stopping once the start
// was cancelled (cancelHeldStart), or "" when there is none.
func (s *Server) startUnanswered(name string) string {
	f, ok := s.startFlightOf(name)
	if !ok {
		return ""
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.answered:
		return ""
	case !f.cancelled.IsZero():
		return "stopping"
	default:
		return "starting"
	}
}

// markAnswered records that libvirt has answered the flight's start.
func (f *startFlight) markAnswered() {
	f.mu.Lock()
	f.answered = true
	f.mu.Unlock()
}

func (s *Server) beginStartFlight(name string) *startFlight {
	f := &startFlight{since: time.Now(), settled: make(chan struct{})}
	s.startFlightsMu.Lock()
	if s.startFlights == nil {
		s.startFlights = map[string]*startFlight{}
	}
	s.startFlights[name] = f
	s.startFlightsMu.Unlock()
	return f
}

func (s *Server) endStartFlight(name string, f *startFlight) {
	s.startFlightsMu.Lock()
	if s.startFlights[name] == f {
		delete(s.startFlights, name)
	}
	s.startFlightsMu.Unlock()
	close(f.settled)
}

// startInFlightError is the answer to a start whose StartDomain libvirt has
// not answered within the wait: Unavailable, and the start goes on. settled
// is closed once it has finished; what the caller holds for the start (the
// VM lock, its admission) is let go only then (heldForStart).
type startInFlightError struct {
	name      string
	since     time.Time
	cancelled time.Time
	settled   <-chan struct{}
}

func (f *startFlight) inFlightError(name string) *startInFlightError {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &startInFlightError{name: name, since: f.since, cancelled: f.cancelled, settled: f.settled}
}

func (e *startInFlightError) Error() string {
	if !e.cancelled.IsZero() {
		return fmt.Sprintf("start %q: libvirt has not answered the start it was asked for at %s (%s ago), "+
			"which `lv stop --force` cancelled at %s; when libvirt answers, a domain it started is destroyed. "+
			"Start the VM again once that is recorded (`lv events %s`)",
			e.name, e.since.UTC().Format(time.RFC3339), time.Since(e.since).Round(time.Second),
			e.cancelled.UTC().Format(time.RFC3339), e.name)
	}
	return fmt.Sprintf("start %q: libvirt has not answered the start it was asked for at %s (%s ago). "+
		"The start was not cancelled and still holds the VM; this daemon records its outcome when libvirt "+
		"answers, unless the daemon restarts first. Check `lv inspect %s` and `lv events %s`",
		e.name, e.since.UTC().Format(time.RFC3339), time.Since(e.since).Round(time.Second), e.name, e.name)
}

func (e *startInFlightError) GRPCStatus() *status.Status {
	return status.New(codes.Unavailable, e.Error())
}

// lockVMForStart is lockVM for a start: while another start of the VM holds
// the lock and libvirt has not answered it within the wait, it answers that
// start's startInFlightError rather than queueing behind it, and asks libvirt
// nothing. It also gives up when ctx is done: the caller is gone.
func (s *Server) lockVMForStart(ctx context.Context, name string) (func(), error) {
	unlock, held, err := s.lockVMUnlessStartHeld(ctx, name)
	if held != nil {
		return nil, held.inFlightError(name)
	}
	return unlock, err
}

// lockVMUnlessStartHeld is lockVM, except that while a start of the VM is
// held past its wait with libvirt not answering it (heldUnanswered), it
// returns that start's flight instead of the lock, rather than queueing
// behind it for as long as libvirt does not answer. A non-nil ctx is watched
// too: when it is done, its error is returned.
//
// The wait for the lock is lockVM's own, in a goroutine, so it queues as
// every other lifecycle call does (a polled TryLock loses to every blocked
// waiter while the mutex is starving). Only the flight is looked at every
// startLockPoll. A lock the goroutine takes after this call has given up is
// let go at once.
func (s *Server) lockVMUnlessStartHeld(ctx context.Context, name string) (func(), *startFlight, error) {
	if unlock, ok := s.tryLockVM(name); ok {
		return unlock, nil, nil
	}
	got, abandon := make(chan func()), make(chan struct{})
	go func() {
		unlock := s.lockVM(name)
		select {
		case got <- unlock:
		case <-abandon:
			unlock()
		}
	}()
	var done <-chan struct{}
	if ctx != nil {
		done = ctx.Done()
	}
	tick := time.NewTicker(startLockPoll)
	defer tick.Stop()
	for {
		select {
		case unlock := <-got:
			return unlock, nil, nil
		case <-done:
			close(abandon)
			return nil, nil, status.FromContextError(ctx.Err()).Err()
		case <-tick.C:
			if f, ok := s.startFlightOf(name); ok && f.heldUnanswered() {
				close(abandon)
				return nil, f, nil
			}
		}
	}
}

// startHeldRefusal is the answer to a stop or restart of a VM whose start is
// held (lockVMUnlessStartHeld), rather than waiting for as long as libvirt
// does not answer it.
func startHeldRefusal(op, name string, f *startFlight) error {
	f.mu.Lock()
	since, cancelled := f.since, f.cancelled
	f.mu.Unlock()
	if !cancelled.IsZero() {
		return status.Errorf(codes.Unavailable,
			"%s %q: its start, asked for at %s, was cancelled at %s and libvirt has still not answered it; "+
				"the VM is stopped once it does (`lv events %s`), and the %s was not applied",
			op, name, since.UTC().Format(time.RFC3339), cancelled.UTC().Format(time.RFC3339), name, op)
	}
	return status.Errorf(codes.Unavailable,
		"%s %q: a start of it is in progress: libvirt has not answered the start asked for at %s (%s ago), and the %s was not applied; "+
			"retry once the start settles (`lv inspect %s`), or cancel the start (`lv stop --force %s`)",
		op, name, since.UTC().Format(time.RFC3339), time.Since(since).Round(time.Second), op, name, name)
}

// cancelHeldStart cancels a start of name held past its wait while libvirt
// has not answered it (`lv stop --force`). libvirt cannot be asked to stop a
// start it has not answered (a destroy waits on the same domain), so the
// cancel is recorded now and carried out when libvirt answers: the row is
// written stopped by its operator (or, for a VM whose row said error before
// the start, put back to that, which keeps its set-aside disk copies held, as
// a stop of an errored VM leaves it), so no start path starts it; and the
// start's late answer (startDomainWithin) destroys a domain it started instead
// of recording it running (finishCancelledStartLocked). The VM stays held —
// its lock, lease and reservation — until then, so nothing starts it twice,
// and the start's outcome is recorded once, when libvirt answers.
//
// It reports done=false when libvirt has answered meanwhile: the start is
// settling, and the caller stops the VM as usual once it has the lock.
func (s *Server) cancelHeldStart(ctx context.Context, name string, f *startFlight) (*pb.VM, bool, error) {
	f.mu.Lock()
	if f.answered {
		f.mu.Unlock()
		return nil, false, nil
	}
	if !f.cancelled.IsZero() {
		f.mu.Unlock()
		out, err := s.vmToProto(ctx, name)
		return out, true, err
	}
	defer f.mu.Unlock()
	fresh, err := corrosion.GetVM(ctx, s.db, name)
	switch {
	case err != nil:
		return nil, true, status.Errorf(codes.Internal, "cancel the start of %q: read it: %v", name, err)
	case fresh == nil:
		return nil, true, status.Errorf(codes.NotFound, "VM %q not found", name)
	case fresh.HostName != s.hostName:
		return nil, true, status.Errorf(codes.Aborted, "ownership of %q moved to %s mid-operation; retry", name, fresh.HostName)
	}
	prevState, prevDetail := fresh.State, fresh.StateDetail
	if f.marked {
		prevState, prevDetail = f.prevState, f.prevDetail
	}
	if prevState != "stopped" && prevState != "error" {
		return nil, true, status.Errorf(codes.FailedPrecondition,
			"cannot cancel the start of %q: it was asked for while the VM was %s, which a stop does not undo; "+
				"retry once the start settles (`lv inspect %s`)", name, prevState, name)
	}
	state, detail := "stopped", "operator-stop"
	if stopNoopKeepsRow[prevState] {
		state, detail = prevState, prevDetail
	}
	now := time.Now()
	if state == "stopped" {
		// The duty to undo the start outlives this daemon (a restart
		// before libvirt answers): recorded on this host first, and the
		// cancel is not made when it cannot be (cancelled_starts.go). A
		// row left error needs none: the reconciler records a running
		// domain under an error row as running.
		if err := s.recordCancelledStart(name, f.since, now); err != nil {
			return nil, true, status.Errorf(codes.Internal, "the start of %q was not cancelled: recording the cancel on this host failed: %v", name, err)
		}
	}
	if err := s.persistVMState(ctx, name, state, detail, corrosion.OpVMState); err != nil {
		if state == "stopped" {
			s.dropCancelledStart(name)
		}
		return nil, true, status.Errorf(codes.Internal, "the start of %q was not cancelled: recording the stop failed: %v", name, err)
	}
	f.cancelled = now
	ev := fmt.Sprintf("start cancelled: libvirt had not answered the start asked for at %s; when it answers, a domain it started is destroyed",
		f.since.UTC().Format(time.RFC3339))
	if state != "stopped" {
		ev += "; the row is left " + state + ", which holds its set-aside disk copies"
	}
	s.recordVMEvent(ctx, name, "vm.stopped", "ok", ev)
	slog.Warn("StopVM: cancelled a start libvirt has not answered; it is undone when libvirt answers", "vm", name,
		"start_asked", f.since.UTC().Format(time.RFC3339))
	pbVM := &pb.VM{Name: name, HostName: s.hostName, State: pb.VMState_VM_STOPPING, StateDetail: ev}
	return pbVM, true, nil
}

// heldStartAlreadyCancelled answers a plain stop of a VM whose held start was
// cancelled already: the stop asked for is recorded, so it succeeds.
func (s *Server) heldStartAlreadyCancelled(ctx context.Context, name string, f *startFlight) (*pb.VM, bool, error) {
	f.mu.Lock()
	cancelled := f.cancelled
	f.mu.Unlock()
	if cancelled.IsZero() {
		return nil, false, nil
	}
	out, err := s.vmToProto(ctx, name)
	return out, true, err
}

// finishCancelledStartLocked records libvirt's late answer to a start
// cancelled while it had not answered (cancelHeldStart). A failed start is
// recorded as one; the row already says what the cancel wrote. A start that
// succeeded is stopped at once (a forced stop, as `lv stop --force` asked),
// and recorded by that stop. If that stop cannot destroy the domain, the VM
// runs: the row is written running, as libvirt says it is, and the failed
// cancel is recorded, so the row never says stopped over a running domain.
// The caller holds the VM lock.
func (s *Server) finishCancelledStartLocked(ctx context.Context, vm *corrosion.VMRecord, startErr error,
	releasePreflight func(), pbVM *pb.VM, hspec *pb.HooksSpec, since, cancelled time.Time) {
	// Handled here, whatever the outcome: the durable record of the cancel
	// is no longer needed (cancelled_starts.go).
	defer s.dropCancelledStart(vm.Name)
	asked := since.UTC().Format(time.RFC3339)
	running := func() bool {
		st, err := s.virt.DomainState(vm.Name)
		return err == nil && st == "running"
	}
	if startErr != nil && !running() {
		releasePreflight()
		s.recordVMEvent(ctx, vm.Name, "vm.started", "error",
			fmt.Sprintf("libvirt answered the start asked for at %s, which was cancelled at %s, late, with a failure: %v; the VM stays stopped",
				asked, cancelled.UTC().Format(time.RFC3339), startErr))
		slog.Info("StopVM: a cancelled start failed late; nothing to undo", "vm", vm.Name, "error", startErr)
		return
	}
	fresh, err := corrosion.GetVM(ctx, s.db, vm.Name)
	if err == nil && fresh == nil {
		err = fmt.Errorf("its row is gone")
	}
	if err == nil {
		note := fmt.Sprintf("start cancelled: libvirt answered the start asked for at %s late, and the domain it started was destroyed", asked)
		if _, err = s.stopVMLockedNote(ctx, fresh, true, 0, note); err == nil {
			slog.Info("StopVM: a cancelled start succeeded late; its domain was destroyed", "vm", vm.Name)
			return
		}
	}
	if running() {
		slog.Error("StopVM: a cancelled start succeeded late and its domain could not be destroyed; the VM runs", "vm", vm.Name, "error", err)
		_, _ = s.finishStartLocked(ctx, vm, nil, releasePreflight, pbVM, hspec) // records running, as libvirt says
		s.recordVMEvent(ctx, vm.Name, "vm.stopped", "error",
			fmt.Sprintf("the start asked for at %s was cancelled, but libvirt started it late and destroying the domain failed: %s; the VM runs (`lv stop --force %s`)",
				asked, status.Convert(err).Message(), vm.Name))
		return
	}
	slog.Error("StopVM: a cancelled start succeeded late; stopping it did not finish", "vm", vm.Name, "error", err)
	s.recordVMEvent(ctx, vm.Name, "vm.stopped", "error",
		fmt.Sprintf("the start asked for at %s was cancelled, and libvirt started it late; its domain is not running, but recording the stop failed: %s",
			asked, status.Convert(err).Message()))
}

// heldForStart is what a start holds — the VM lock first, then what it took
// under it — let go in reverse order when the start returns, or, when it
// returns a start still in flight, once that start has settled.
type heldForStart struct {
	fns   []func()
	after <-chan struct{}
}

func (h *heldForStart) hold(fn func()) { h.fns = append(h.fns, fn) }

// handOff makes release wait for the in-flight start err names, if any.
func (h *heldForStart) handOff(err error) {
	if e, ok := err.(*startInFlightError); ok {
		h.after = e.settled
	}
}

func (h *heldForStart) release() {
	run := func() {
		for i := len(h.fns) - 1; i >= 0; i-- {
			h.fns[i]()
		}
	}
	if h.after == nil {
		run()
		return
	}
	go func() {
		<-h.after
		run()
	}()
}

// startHeldDetail is the state detail of a VM's row while a start libvirt has
// not answered within its wait goes on.
func startHeldDetail(since time.Time) string {
	return fmt.Sprintf("operator start: libvirt has not answered the start asked for at %s", since.UTC().Format(time.RFC3339))
}

// startLeaseRenewEvery is how often a held start re-takes the VM's start
// lease, well within its TTL.
var startLeaseRenewEvery = health.VMStartLeaseTTL / 4

// markStartHeld makes the VM's row say what a start libvirt has not answered
// within its wait is: starting, where it said stopped (or error), so no
// reader takes a VM being started for a stopped one. The row is the one every
// host lists, so it is written, not only shown by this daemon.
//
// A starting row is one the reconciler re-drives (an interrupted start), so
// the VM's start lease is taken first and kept, renewed, until the start
// settles: no start path starts the VM while this one goes on, and a daemon
// that restarts mid-start leaves a starting row whose lease lapses, which the
// reconciler then finishes, recording its outcome. The row is never written
// running here: only libvirt's answer does that (finishStartLocked). When the
// lease cannot be taken, or the row says anything else, the row is left as
// it is, as before.
func (s *Server) markStartHeld(ctx context.Context, vm *corrosion.VMRecord, flight *startFlight) {
	flight.mu.Lock()
	defer flight.mu.Unlock()
	flight.held = true
	if s.db == nil {
		return
	}
	fresh, err := corrosion.GetVM(ctx, s.db, vm.Name)
	if err != nil || fresh == nil || fresh.HostName != s.hostName {
		slog.Warn("StartVM: a start held past its wait is not marked starting: its row could not be read here", "vm", vm.Name, "error", err)
		return
	}
	if fresh.State != "stopped" && fresh.State != "error" {
		return
	}
	holder := health.OperatorStartLockHolder(s.hostName)
	heldBy, err := health.TryVMStartLease(ctx, s.db, holder, vm.Name, time.Now())
	if err != nil || heldBy != holder {
		slog.Warn("StartVM: a start held past its wait is not marked starting: its start lease is not ours",
			"vm", vm.Name, "held_by", heldBy, "error", err)
		return
	}
	// A start of a VM failover re-keyed here took this lease already
	// (StartVM) and lets it go itself.
	owns := !corrosion.IsStoppedRekeyDetail(fresh.StateDetail)
	if err := s.persistVMState(ctx, vm.Name, "starting", startHeldDetail(flight.since), corrosion.OpVMState); err != nil {
		slog.Warn("StartVM: a start held past its wait is not marked starting: the write failed", "vm", vm.Name, "error", err)
		if owns {
			health.ReleaseVMStartLease(ctx, s.db, holder, vm.Name)
		}
		return
	}
	flight.marked, flight.prevState, flight.prevDetail = true, fresh.State, fresh.StateDetail
	flight.ownsLease = owns
	flight.stopRenew = make(chan struct{})
	go func(stop <-chan struct{}) {
		t := time.NewTicker(startLeaseRenewEvery)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if by, err := health.TryVMStartLease(ctx, s.db, holder, vm.Name, time.Now()); err != nil || by != holder {
					slog.Error("StartVM: a held start could not renew the VM's start lease", "vm", vm.Name, "held_by", by, "error", err)
				}
			}
		}
	}(flight.stopRenew)
}

// unmarkStartHeld ends what markStartHeld began once the start has settled
// and its outcome is recorded: the lease renewal, and the lease itself when
// it took it. With restore (libvirt answered with a failure) it first puts
// the row back to what it said before the start.
func (s *Server) unmarkStartHeld(ctx context.Context, name string, flight *startFlight, restore bool) {
	flight.mu.Lock()
	defer flight.mu.Unlock()
	if !flight.marked {
		return
	}
	if restore {
		if err := s.persistVMState(ctx, name, flight.prevState, flight.prevDetail, corrosion.OpVMState); err != nil {
			slog.Error("StartVM: a held start failed and its row could not be put back; it still says starting",
				"vm", name, "state", flight.prevState, "error", err)
		}
	}
	close(flight.stopRenew)
	if flight.ownsLease {
		health.ReleaseVMStartLease(ctx, s.db, health.OperatorStartLockHolder(s.hostName), name)
	}
	flight.marked = false
}

// startDomainWithin asks libvirt to start name and waits up to wait for its
// answer, which finish records. When libvirt has not answered by then, the
// start goes on: its answer is recorded by finish when it comes, under a
// context the caller's return does not cancel, and the caller gets a
// startInFlightError whose settled is closed after that. The caller holds the
// VM lock until then (heldForStart). Nothing starts the VM a second time.
func (s *Server) startDomainWithin(ctx context.Context, vm *corrosion.VMRecord, wait time.Duration,
	finish func(context.Context, error) (*pb.VM, error),
	finishCancelled func(ctx context.Context, startErr error, since, cancelled time.Time)) (*pb.VM, error) {
	name := vm.Name
	flight := s.beginStartFlight(name)
	answered := make(chan error, 1)
	go func() { answered <- s.virt.StartDomain(name) }()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case err := <-answered:
		defer s.endStartFlight(name, flight)
		flight.markAnswered()
		return finish(ctx, err)
	case <-timer.C:
	}
	slog.Warn("StartVM: libvirt has not answered the start; it goes on, holding the VM", "vm", name, "waited", wait)
	bg := context.WithoutCancel(ctx)
	s.markStartHeld(bg, vm, flight)
	go func() {
		defer s.endStartFlight(name, flight)
		startErr := <-answered
		flight.mu.Lock()
		flight.answered = true
		cancelled := flight.cancelled
		flight.mu.Unlock()
		if !cancelled.IsZero() {
			// `lv stop --force` cancelled it meanwhile (cancelHeldStart):
			// the row already says what the cancel wrote.
			finishCancelled(bg, startErr, flight.since, cancelled)
			s.unmarkStartHeld(bg, name, flight, false)
			return
		}
		_, err := finish(bg, startErr)
		// Whether the start failed is libvirt's answer (or, when that is an
		// error, whether the domain runs anyway: finishStartLocked heals
		// that as already running), never finish's own error: a start that
		// succeeded and whose read-back then failed has its row written
		// running, which must not be put back over the running domain.
		failed := startErr != nil
		if failed {
			if st, serr := s.virt.DomainState(name); serr == nil && st == "running" {
				failed = false
			}
		}
		s.unmarkStartHeld(bg, name, flight, failed)
		if !failed && err != nil {
			slog.Warn("StartVM: libvirt answered a start late and the VM runs; reading it back failed",
				"vm", name, "error", status.Convert(err).Message())
			return
		}
		if err != nil {
			msg := status.Convert(err).Message()
			slog.Error("StartVM: libvirt answered a start late, with a failure", "vm", name, "error", msg)
			s.recordVMEvent(bg, name, "vm.started", "error",
				fmt.Sprintf("libvirt answered the start asked for at %s late, with a failure: %s",
					flight.since.UTC().Format(time.RFC3339), msg))
			return
		}
		slog.Info("StartVM: libvirt answered a start late; the VM is running", "vm", name,
			"took", time.Since(flight.since).Round(time.Second))
	}()
	return nil, flight.inFlightError(name)
}
