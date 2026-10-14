package grpcapi

import (
	"errors"
	"fmt"
	"time"
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
	wait := s.liveStateWaitOrDefault()
	s.liveStateMu.Lock()
	c, joined := s.liveStateCalls[name]
	if joined && time.Since(c.since) >= wait {
		// Waited out already, by an earlier read: latched until it returns.
		s.liveStateMu.Unlock()
		select {
		case <-c.done:
			return c.state, c.err
		default:
			return "", errLiveStateNoAnswer
		}
	}
	if b.left < wait {
		wait = b.left
	}
	if !joined {
		if wait <= 0 {
			s.liveStateMu.Unlock()
			return "", errLiveStateNoAnswer
		}
		c = &liveStateCall{since: time.Now(), done: make(chan struct{})}
		if s.liveStateCalls == nil {
			s.liveStateCalls = map[string]*liveStateCall{}
		}
		s.liveStateCalls[name] = c
		go func() {
			st, err := s.liveVMState(name)
			s.liveStateMu.Lock()
			c.state, c.err = st, err
			if s.liveStateCalls[name] == c {
				delete(s.liveStateCalls, name)
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
		b.left -= time.Since(t0)
		return c.state, c.err
	case <-timer.C:
		b.left -= time.Since(t0)
		return "", errLiveStateNoAnswer
	}
}

// liveStateUnknownDetail is the state detail of a VM whose live state libvirt
// has not answered for: what the cluster's record says, and why the read does
// not say more.
func (s *Server) liveStateUnknownDetail(recorded string) string {
	return fmt.Sprintf("live state unknown: libvirt on %s has not answered for this VM (waited %s); the cluster's record says %s",
		s.hostName, s.liveStateWaitOrDefault(), recorded)
}
