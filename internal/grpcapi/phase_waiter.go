package grpcapi

import (
	"fmt"
	"time"
)

// phaseWaiter decides when to stop waiting for a progress stream to reach a
// phase.
//
// It judges STALL, not elapsed wall clock. The budget it replaced was a flat
// 5s from the moment the wait began, which belongs to work the test does not
// control -- runRestoreLiveUntil drives a chunked restore and a VM start -- so
// under `go test ./...` on a loaded machine it expired while the stream was
// still emitting frames:
//
//	born_running_test.go:195: never reached phase STARTED; frames=4
//
// Four frames had arrived. Nothing was broken; the machine was busy. In one
// sync run that reported three unrelated branches as failing, and a flat budget
// large enough to never do so on a loaded machine would be large enough to make
// a genuine stall take minutes to surface.
//
// So the quiet window measures the gap BETWEEN frames. A slow stream defers it
// indefinitely and a stopped one trips it promptly, which is the distinction
// the flat budget could not draw.
type phaseWaiter struct {
	quiet    time.Duration
	hardStop time.Time
	frames   int
	lastMove time.Time
	started  bool
}

// newPhaseWaiter builds a waiter that gives up after quiet without a new frame,
// or at hardStop whichever comes first.
//
// hardStop exists so a stalled stream cannot eat the whole package budget and
// take every later test in the binary down with it. Callers derive it from
// t.Deadline(), so it tracks -timeout instead of being another invented number.
func newPhaseWaiter(quiet time.Duration, hardStop time.Time) *phaseWaiter {
	return &phaseWaiter{quiet: quiet, hardStop: hardStop}
}

// observe records the frame count seen at now and reports whether to give up,
// with the reason. The reason is returned rather than logged because the old
// message ("never reached phase X") described the symptom and sent me reading
// three innocent branches; a caller that can say "no frame for 30s" or "hit the
// test deadline" says which of the two actually happened.
func (w *phaseWaiter) observe(frames int, now time.Time) (bool, string) {
	if !w.started {
		w.started = true
		w.frames = frames
		w.lastMove = now
		return false, ""
	}
	// ANY change counts as progress, not just growth: a recorder a caller
	// resets still proves the producer is alive.
	if frames != w.frames {
		w.frames = frames
		w.lastMove = now
	}
	if !w.hardStop.IsZero() && !now.Before(w.hardStop) {
		return true, fmt.Sprintf("hit the test deadline with %d frame(s)", frames)
	}
	if idle := now.Sub(w.lastMove); idle >= w.quiet {
		return true, fmt.Sprintf("no new frame for %s (%d frame(s) total)", idle.Round(time.Millisecond), frames)
	}
	return false, ""
}
