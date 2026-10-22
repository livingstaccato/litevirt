package libvirt

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// CaptureRegistry coordinates this host's memory snapshot captures with its
// partition pauser (docs/design/partition-pause.md §3.3). The partition pause
// always wins over a capture:
//
//   - A capture registers its VM for as long as it runs (begin, end).
//   - Before the pauser pauses a VM it takes a hold on it (Hold). When a
//     capture of that VM is in flight, Hold aborts the capture's libvirt job
//     and waits, at most its wait, for libvirt's job cleanup to finish: the
//     cleanup is where libvirt itself resumes a guest that was running when
//     the snapshot began, so the pauser's suspend must land after it.
//   - A capture decides every resume, and its final state, under its VM's
//     settle lock (settle): with a hold, or a pause record, it never resumes
//     and re-suspends a guest it finds running. Otherwise it resumes only a
//     guest it suspended itself.
//
// The pause pass must end within its budget whatever libvirt does, so
// nothing the pauser calls here blocks past Hold's wait: the registry's own
// mutex guards only its maps and is never held across a libvirt call; the
// settle lock is per VM, so one VM's stuck settle cannot delay another's
// Hold, and Hold gives up on it at its deadline; the aborts run in the
// background, one at a time.
//
// One registry per host, shared by the gRPC server (captures), the pauser
// and the reconciler's settle. The hold outlives the capture: it is dropped
// (Release) with the VM's pause record.
type CaptureRegistry struct {
	mu    sync.Mutex // guards the maps below; never held across a libvirt call
	caps  map[string]*captureEntry
	holds map[string]bool
	locks map[string]chan struct{} // per-VM settle lock: a one-slot semaphore
}

type captureEntry struct {
	abort    func() error
	done     chan struct{} // closed when libvirt's create call has returned
	doneOnce sync.Once
}

// NewCaptureRegistry returns an empty registry.
func NewCaptureRegistry() *CaptureRegistry {
	return &CaptureRegistry{caps: map[string]*captureEntry{}, holds: map[string]bool{}, locks: map[string]chan struct{}{}}
}

// vmLock is vm's settle lock.
func (r *CaptureRegistry) vmLock(vm string) chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	l := r.locks[vm]
	if l == nil {
		l = make(chan struct{}, 1)
		r.locks[vm] = l
	}
	return l
}

// InFlight reports whether a capture of vm is running. A VM the capture holds
// paused reads paused, yet is the pauser's to pause.
func (r *CaptureRegistry) InFlight(vm string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.caps[vm] != nil
}

// Hold is the pauser's claim on vm, taken before it records and suspends it:
// from then on no capture of vm resumes it. It returns within wait whatever
// libvirt does. It takes vm's settle lock (so a capture deciding a resume
// finishes first, or sees the hold), sets the hold, and, when a capture of vm
// is in flight, aborts its libvirt job until libvirt's job cleanup has ended.
// captured reports a capture was in flight; settled that the pauser may now
// rely on its suspend: false when the settle lock or the job's end did not
// come within wait (the hold is set regardless; the pauser counts the pause
// as failed, since libvirt or a settle in flight may resume the guest).
func (r *CaptureRegistry) Hold(vm string, wait time.Duration) (captured, settled bool) {
	if r == nil {
		return false, true
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	l := r.vmLock(vm)
	locked := false
	select {
	case l <- struct{}{}: // free: taken even with no wait left
		locked = true
	default:
		select {
		case l <- struct{}{}:
			locked = true
		case <-deadline.C:
		}
	}
	r.mu.Lock()
	r.holds[vm] = true
	e := r.caps[vm]
	r.mu.Unlock()
	if locked {
		<-l
	} else {
		slog.Warn("partition-pause: a memory snapshot's settle of the guest did not finish within the wait; suspending anyway",
			"vm", vm, "wait", wait)
		return e != nil, false
	}
	if e == nil {
		return false, true
	}
	// The abort is repeated until the create call has returned: a capture
	// that checked for a hold just before the hold was taken may start its
	// job after the first abort found none ("no job is active"), and the
	// job admits an abort for its whole length. Each abort runs in the
	// background, one at a time, so an abort libvirt does not answer cannot
	// hold Hold past its wait.
	idle := make(chan struct{}, 1)
	idle <- struct{}{}
	retry := time.NewTicker(abortRetry)
	defer retry.Stop()
	for {
		select {
		case <-idle:
			go func() {
				if err := e.abort(); err != nil {
					slog.Debug("partition-pause: abort of an in-flight memory snapshot", "vm", vm, "error", err)
				}
				idle <- struct{}{}
			}()
		default:
		}
		select {
		case <-e.done:
			return true, true
		case <-deadline.C:
			slog.Warn("partition-pause: a memory snapshot's libvirt job did not end within the wait; suspending anyway, "+
				"and libvirt may resume the guest when the job ends",
				"vm", vm, "wait", wait)
			return true, false
		case <-retry.C:
		}
	}
}

// abortRetry is how often Hold repeats its abort while the capture's create
// call has not returned.
const abortRetry = 10 * time.Millisecond

// Holding reports whether the pauser holds vm.
func (r *CaptureRegistry) Holding(vm string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.holds[vm]
}

// Release drops the pauser's hold on vm: its pause record is gone.
func (r *CaptureRegistry) Release(vm string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.holds, vm)
	r.mu.Unlock()
}

// begin registers a capture of vm whose libvirt job abort aborts.
func (r *CaptureRegistry) begin(vm string, abort func() error) (*captureEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.caps[vm] != nil {
		return nil, fmt.Errorf("a memory snapshot of %q is already in flight", vm)
	}
	e := &captureEntry{abort: abort, done: make(chan struct{})}
	r.caps[vm] = e
	return e, nil
}

// jobDone marks the capture's libvirt create call as returned.
func (e *captureEntry) jobDone() { e.doneOnce.Do(func() { close(e.done) }) }

// end unregisters the capture.
func (r *CaptureRegistry) end(vm string, e *captureEntry) {
	e.jobDone()
	r.mu.Lock()
	if r.caps[vm] == e {
		delete(r.caps, vm)
	}
	r.mu.Unlock()
}

// settle runs fn under vm's settle lock with whether vm is held: by the
// pauser's hold, or by held (the durable pause record). A Hold of vm waits
// for fn (at most its own wait); no other VM's Hold, and no InFlight, does.
func (r *CaptureRegistry) settle(vm string, held func() bool, fn func(held bool)) {
	l := r.vmLock(vm)
	l <- struct{}{}
	defer func() { <-l }()
	r.mu.Lock()
	h := r.holds[vm]
	r.mu.Unlock()
	if !h && held != nil {
		h = held()
	}
	fn(h)
}
