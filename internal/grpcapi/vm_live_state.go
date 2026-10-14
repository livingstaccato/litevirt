package grpcapi

import (
	"errors"
	"fmt"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A read of a local VM (ListVMs, vmToProto) asks libvirt for the domain's live
// state. libvirt does not always answer: a domain whose start hangs on storage
// that does not answer holds its domain lock, and every call naming that
// domain waits with it, so `lv ls` on that host hung while every other host
// answered. The read now waits a bounded time and reports the VM's live state
// as unknown when libvirt has not answered.
//
// The call itself is never cancelled (libvirt has no way to), so it goes on in
// its own goroutine; while it has not returned, a read of the same domain
// joins it rather than asking libvirt again, so a domain that does not answer
// costs one outstanding call, not one per read. Once that call has been
// waited out it is latched: later reads report unknown at once until it
// returns, as storage.Bounded does for a mount.
const (
	// defaultLiveStateWait is how long a read waits for one domain's answer.
	defaultLiveStateWait = 3 * time.Second
	// liveStateBudgetCalls is how many such waits one read spends, at most,
	// before it stops asking: past it, a libvirt that answers nothing costs a
	// list at most this many waits, however many VMs the host has.
	liveStateBudgetCalls = 2
)

// errLiveStateNoAnswer is a live-state read libvirt has not answered.
var errLiveStateNoAnswer = errors.New("libvirt has not answered")

type liveStateCall struct {
	since time.Time
	done  chan struct{}
	state string
	err   error
}

func (s *Server) liveStateWaitOrDefault() time.Duration {
	if s.liveStateWait > 0 {
		return s.liveStateWait
	}
	return defaultLiveStateWait
}

// liveStateBudget is one read's allowance of waits on libvirt (see above).
// Only a wait libvirt did not answer is charged: a libvirt that answers,
// however busy, costs a list nothing from it.
type liveStateBudget struct {
	left time.Duration
}

func (s *Server) newLiveStateBudget() *liveStateBudget {
	return &liveStateBudget{left: liveStateBudgetCalls * s.liveStateWaitOrDefault()}
}

// liveVMStateBounded is liveVMState, waiting at most the live-state wait (and
// no longer than what is left of b) for libvirt's answer. It answers
// errLiveStateNoAnswer when libvirt has not answered.
func (s *Server) liveVMStateBounded(name string, b *liveStateBudget) (string, error) {
	_, st, err := s.boundedVirtCall(name, b, func() (string, error) { return s.liveVMState(name) })
	return st, err
}

// boundedVirtCall makes call, a libvirt call, in its own goroutine and waits
// for its answer at most the live-state wait (and no longer than what is left
// of b, when b is not nil). It answers errLiveStateNoAnswer when libvirt has
// not answered, and returns the call, whose done is closed once it has. While
// a call under key has not returned, a later one joins it rather than asking
// libvirt again; once it has been waited out, it is latched, and a later one
// answers errLiveStateNoAnswer at once until it returns.
func (s *Server) boundedVirtCall(key string, b *liveStateBudget, call func() (string, error)) (*liveStateCall, string, error) {
	wait := s.liveStateWaitOrDefault()
	s.liveStateMu.Lock()
	c, joined := s.liveStateCalls[key]
	if joined && time.Since(c.since) >= wait {
		// Waited out already, by an earlier read: latched until it returns.
		s.liveStateMu.Unlock()
		select {
		case <-c.done:
			return c, c.state, c.err
		default:
			return c, "", errLiveStateNoAnswer
		}
	}
	if b != nil && b.left < wait {
		wait = b.left
	}
	if !joined {
		if wait <= 0 {
			s.liveStateMu.Unlock()
			return nil, "", errLiveStateNoAnswer
		}
		c = &liveStateCall{since: time.Now(), done: make(chan struct{})}
		if s.liveStateCalls == nil {
			s.liveStateCalls = map[string]*liveStateCall{}
		}
		s.liveStateCalls[key] = c
		go func() {
			st, err := call()
			s.liveStateMu.Lock()
			c.state, c.err = st, err
			if s.liveStateCalls[key] == c {
				delete(s.liveStateCalls, key)
			}
			s.liveStateMu.Unlock()
			close(c.done)
		}()
	}
	s.liveStateMu.Unlock()
	t0 := time.Now()
	timer := time.NewTimer(max(wait, 0))
	defer timer.Stop()
	select {
	case <-c.done:
		return c, c.state, c.err
	case <-timer.C:
		if b != nil {
			b.left -= time.Since(t0)
		}
		return c, "", errLiveStateNoAnswer
	}
}

// readVMState is the state a read of vm (ListVMs, vmToProto) shows, and the
// detail that goes with it when the read has one of its own (detail is ""
// otherwise): a start libvirt has not answered under way here shows as
// starting (or stopping, cancelled), and libvirt is not asked; a local VM's
// state is libvirt's, waited for within b, except that a stopped row whose
// domain still runs is shown stopped (a graceful shutdown in progress) or,
// for a drain's cold move still waiting for its guest, stopping; a VM libvirt
// has not answered for is unknown, saying what the record says.
func (s *Server) readVMState(vm *corrosion.VMRecord, b *liveStateBudget) (state, detail string) {
	if vm.HostName != s.hostName {
		return vm.State, ""
	}
	if inFlight := s.startUnanswered(vm.Name); inFlight != "" {
		return inFlight, ""
	}
	if s.virt == nil {
		return vm.State, ""
	}
	liveState, err := s.liveVMStateBounded(vm.Name, b)
	switch {
	case errors.Is(err, errLiveStateNoAnswer):
		detail = s.liveStateUnknownDetail(vm.State)
		if vm.StateDetail != "" {
			detail += " (" + vm.StateDetail + ")"
		}
		return "unknown", detail
	case err != nil:
		return vm.State, ""
	case vm.State == "stopped" && liveState == "running":
		// Graceful shutdown in progress: trust the record, except for a
		// drain's cold move still waiting for its guest.
		if drainStopInProgress(vm) {
			return "stopping", ""
		}
		return vm.State, ""
	default:
		// A running row whose domain is stopped crashed or was stopped
		// out of band: libvirt is trusted.
		return liveState, ""
	}
}

// liveStateUnknownDetail is the state detail of a VM whose live state libvirt
// has not answered for: what the cluster's record says, and why the read does
// not say more.
func (s *Server) liveStateUnknownDetail(recorded string) string {
	return fmt.Sprintf("live state unknown: libvirt on %s has not answered for this VM (waited %s); the cluster's record says %s",
		s.hostName, s.liveStateWaitOrDefault(), recorded)
}
