package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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
	name    string
	since   time.Time
	settled <-chan struct{}
}

func (f *startFlight) inFlightError(name string) *startInFlightError {
	return &startInFlightError{name: name, since: f.since, settled: f.settled}
}

func (e *startInFlightError) Error() string {
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
//
// The wait for the lock is lockVM's own, in a goroutine, so it queues as
// every other lifecycle call does (a polled TryLock loses to every blocked
// waiter while the mutex is starving). Only the flight is looked at every
// startLockPoll. A lock the goroutine takes after this call has given up is
// let go at once.
func (s *Server) lockVMForStart(ctx context.Context, name string) (func(), error) {
	if unlock, ok := s.tryLockVM(name); ok {
		return unlock, nil
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
	tick := time.NewTicker(startLockPoll)
	defer tick.Stop()
	for {
		select {
		case unlock := <-got:
			return unlock, nil
		case <-ctx.Done():
			close(abandon)
			return nil, status.FromContextError(ctx.Err()).Err()
		case <-tick.C:
			if f, ok := s.startFlightOf(name); ok && time.Since(f.since) >= s.startDomainWaitOrDefault() {
				close(abandon)
				return nil, f.inFlightError(name)
			}
		}
	}
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

// startDomainWithin asks libvirt to start name and waits up to wait for its
// answer, which finish records. When libvirt has not answered by then, the
// start goes on: its answer is recorded by finish when it comes, under a
// context the caller's return does not cancel, and the caller gets a
// startInFlightError whose settled is closed after that. The caller holds the
// VM lock until then (heldForStart). Nothing starts the VM a second time.
func (s *Server) startDomainWithin(ctx context.Context, name string, wait time.Duration,
	finish func(context.Context, error) (*pb.VM, error)) (*pb.VM, error) {
	flight := s.beginStartFlight(name)
	answered := make(chan error, 1)
	go func() { answered <- s.virt.StartDomain(name) }()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case err := <-answered:
		defer s.endStartFlight(name, flight)
		return finish(ctx, err)
	case <-timer.C:
	}
	slog.Warn("StartVM: libvirt has not answered the start; it goes on, holding the VM", "vm", name, "waited", wait)
	bg := context.WithoutCancel(ctx)
	go func() {
		defer s.endStartFlight(name, flight)
		if _, err := finish(bg, <-answered); err != nil {
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
