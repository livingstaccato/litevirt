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
//   - A capture decides every resume, and its final state, under the
//     registry's lock (settle): with a hold, or a pause record, it never
//     resumes and re-suspends a guest it finds running. Otherwise it resumes
//     only a guest it suspended itself.
//
// One registry per host, shared by the gRPC server (captures) and the pauser.
// The hold outlives the capture: the pauser drops it (Release) when it drops
// the pause record.
type CaptureRegistry struct {
	mu    sync.Mutex
	caps  map[string]*captureEntry
	holds map[string]bool
}

type captureEntry struct {
	abort    func() error
	done     chan struct{} // closed when libvirt's create call has returned
	doneOnce sync.Once
}

// NewCaptureRegistry returns an empty registry.
func NewCaptureRegistry() *CaptureRegistry {
	return &CaptureRegistry{caps: map[string]*captureEntry{}, holds: map[string]bool{}}
}

// InFlight reports whether a capture of vm is running. A VM the capture holds
// paused reads paused to the pauser, yet is the pauser's to pause.
func (r *CaptureRegistry) InFlight(vm string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.caps[vm] != nil
}

// Hold is the pauser's claim on vm, taken before it records and suspends it:
// from then on no capture of vm resumes it. When a capture of vm is in
// flight, its libvirt job is aborted and Hold waits up to wait for libvirt's
// job cleanup to end. captured reports a capture was in flight; settled that
// its job ended within wait (when it did not, the pauser suspends anyway and
// the capture re-suspends whatever libvirt resumes).
func (r *CaptureRegistry) Hold(vm string, wait time.Duration) (captured, settled bool) {
	if r == nil {
		return false, true
	}
	r.mu.Lock()
	r.holds[vm] = true
	e := r.caps[vm]
	r.mu.Unlock()
	if e == nil {
		return false, true
	}
	// The abort is retried until the create call has returned: a capture
	// that checked for a hold just before the hold was taken may start its
	// job after the first abort found none ("no job is active"), and the
	// job admits an abort for its whole length.
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	retry := time.NewTicker(abortRetry)
	defer retry.Stop()
	for {
		if err := e.abort(); err != nil {
			slog.Debug("partition-pause: abort of an in-flight memory snapshot", "vm", vm, "error", err)
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

// settle runs fn under the registry's lock with whether vm is held: by the
// pauser's hold, or by held (the durable pause record). A pauser's Hold
// cannot interleave with fn.
func (r *CaptureRegistry) settle(vm string, held func() bool, fn func(held bool)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.holds[vm]
	if !h && held != nil {
		h = held()
	}
	fn(h)
}
