package watchdog

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// The liveness gate: Heartbeat pets only while the daemon is making progress
// on its state store and in its partition pauser. A daemon wedged on either
// (a lock left held, a deadlock) answers no probe and pauses nothing, and must
// not live on behind a petted watchdog while the majority recovers its
// workloads: the gate stops petting and self-fences instead.
//
// Progress, not timestamps: each side reports a counter that moves on every
// unit of work (a completed DB round trip; a pauser pass and every record it
// handles), and the gate times how long a counter has stood still on the
// monotonic clock. A step of the wall clock (an NTP step at boot, a bad RTC,
// date -s) therefore cannot look like a wedge, and a long but moving pass (a
// dozen container settles after a heal) is not one either.
//
// The gate runs only on a configured, verified, armed hardware watchdog: the
// same condition under which the pauser and the VIP demoter may self-fence.
// In auto mode (watchdog_dev empty), or on a device that is not verified
// (softdog, a BMC that never starts its timer), it does nothing.

// isHardwareWatchdogFn and watchdogTimeLeftFn are the verification ioctls;
// tests stand in for a verified device with a regular file.
var (
	isHardwareWatchdogFn = isHardwareWatchdog
	watchdogTimeLeftFn   = watchdogTimeLeft
)

// procStart anchors monoNow; time.Since reads its monotonic clock.
var procStart = time.Now()

// monoNow is the gate's clock: monotonic, so wall-clock steps do not move it.
var monoNow = func() time.Duration { return time.Since(procStart) }

// wallNow is the wall clock, for stamps an operator reads (the marker). The
// gate never reads it.
var wallNow = time.Now

// livenessWiring is the Controller's gate configuration. Guarded by mu.
type livenessWiring struct {
	mu             sync.RWMutex
	dbProbe        func(context.Context) error
	pauserProgress func() uint64
	stale          time.Duration // 0: the default; <0: off
}

// SetDBProbe wires a database round trip (a Query under a short timeout).
// The gate runs it every pet interval. The timeout bounds the round trip, not
// the wait for the state store's lock: a writer holding that lock past the
// threshold is a lock left held, the wedge the gate exists to catch, so the
// probe waits behind it and the counter stands still. Only a probe that
// returns nil counts as progress: one that returns an error (its timeout, an
// interrupted query, SQLITE_BUSY or SQLITE_LOCKED) leaves the counter where
// it was.
func (c *Controller) SetDBProbe(fn func(context.Context) error) {
	if c == nil {
		return
	}
	c.live.mu.Lock()
	c.live.dbProbe = fn
	c.live.mu.Unlock()
}

// SetPauserProgress wires the partition pauser's progress counter
// (health.PartitionPauser.Progress). Zero means not started, and gates
// nothing until it moves.
func (c *Controller) SetPauserProgress(fn func() uint64) {
	if c == nil {
		return
	}
	c.live.mu.Lock()
	c.live.pauserProgress = fn
	c.live.mu.Unlock()
}

// SetLivenessStale sets how long either counter may stand still before the
// gate self-fences (watchdog.liveness_stale_sec). Zero or less turns the gate
// off. Unset, it is DefaultLivenessStale.
func (c *Controller) SetLivenessStale(d time.Duration) {
	if c == nil {
		return
	}
	if d <= 0 {
		d = -1
	}
	c.live.mu.Lock()
	c.live.stale = d
	c.live.mu.Unlock()
}

// DefaultLivenessStale is twice the hardware timeout Heartbeat sets (60 s at
// the default 15 s pet interval): eight DB probe intervals, while a healthy
// pauser moves its counter at least once a second (its tick) and on every
// step a resume pass takes, each step bounded by R (3 s,
// health.PartitionResumeStepBound). A real wedge reboots the host within
// 120 s + 60 s = 3 min.
const DefaultLivenessStale = 120 * time.Second

// MinLivenessStale is the least a configured threshold may be: twice the
// hardware timeout, so the gate never fires inside the window in which a
// missed pet or two is ordinary.
const MinLivenessStale = 2 * 60 * time.Second

func (c *Controller) liveness() (func(context.Context) error, func() uint64, time.Duration) {
	if c == nil {
		return nil, nil, -1
	}
	c.live.mu.RLock()
	defer c.live.mu.RUnlock()
	stale := c.live.stale
	if stale == 0 {
		stale = DefaultLivenessStale
	}
	return c.live.dbProbe, c.live.pauserProgress, stale
}

// progressMark times how long a counter has stood still.
type progressMark struct {
	started bool
	seen    uint64
	since   time.Duration // monoNow when seen was first observed
}

func (m *progressMark) observe(v uint64, now time.Duration) {
	if !m.started || v != m.seen {
		m.started, m.seen, m.since = true, v, now
	}
}

func (m *progressMark) stillFor(now time.Duration) time.Duration {
	if !m.started {
		return 0
	}
	return now - m.since
}

// livenessGate is one Heartbeat's gate.
type livenessGate struct {
	ctrl   *Controller
	active bool
	stale  time.Duration
	dbDone atomic.Uint64
	db     progressMark
	pauser progressMark
	cancel context.CancelFunc
}

// startLivenessGate starts the DB probe loop when the gate applies. An
// inactive gate's check always passes.
func (c *Controller) startLivenessGate(ctx context.Context, interval time.Duration, applies bool, w controllerWiring) *livenessGate {
	probe, stale := w.probe, w.stale
	g := &livenessGate{ctrl: c, stale: stale, cancel: func() {}}
	if !applies || stale <= 0 {
		return g
	}
	g.active = true
	now := monoNow()
	if probe != nil {
		g.db.observe(0, now)
		lctx, cancel := context.WithCancel(ctx)
		g.cancel = cancel
		go g.runDB(lctx, probe, interval)
	}
	slog.Info("watchdog: liveness gate on", "stale_after", stale)
	return g
}

func (g *livenessGate) stop() { g.cancel() }

// runDB runs probe every interval, synchronously: a probe that never returns,
// or returns only errors, is exactly what a standing counter reports.
func (g *livenessGate) runDB(ctx context.Context, probe func(context.Context) error, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, interval/3)
			err := probe(pctx)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					slog.Warn("watchdog: liveness DB round trip returned an error (not counted as progress)", "error", err)
				}
				continue
			}
			g.dbDone.Add(1)
		}
	}
}

// check says why the daemon is not live, or "".
func (g *livenessGate) check() string {
	if !g.active {
		return ""
	}
	now := monoNow()
	if g.db.started {
		g.db.observe(g.dbDone.Load(), now)
		if still := g.db.stillFor(now); still > g.stale {
			return fmt.Sprintf("no database round trip has completed for %s", still.Round(time.Second))
		}
	}
	if _, progress, _ := g.ctrl.liveness(); progress != nil {
		if v := progress(); v != 0 {
			g.pauser.observe(v, now)
			if still := g.pauser.stillFor(now); still > g.stale {
				return fmt.Sprintf("the partition pauser has made no progress for %s", still.Round(time.Second))
			}
		}
	}
	return ""
}

// LivenessDBProbe returns the wired DB probe (nil for none), so a caller's
// wiring can be tested against the probe the gate actually runs.
func (c *Controller) LivenessDBProbe() func(context.Context) error {
	probe, _, _ := c.liveness()
	return probe
}

// LivenessWiring reports what the gate is wired with, for tests and
// diagnostics: whether a DB probe and pauser progress are set, and the
// threshold (negative: off).
func (c *Controller) LivenessWiring() (db, pauser bool, stale time.Duration) {
	probe, progress, stale := c.liveness()
	return probe != nil, progress != nil, stale
}

// RunDir is the directory the self-fence marker is written to ("" for none).
func (c *Controller) RunDir() string {
	if c == nil {
		return ""
	}
	return c.runDir
}
