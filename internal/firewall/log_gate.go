package firewall

import "sync/atomic"

// LogGate decides whether this host renders log lines (LoaderOptions.Logging):
// only while the kernel loads the logging forms (the probe passed) AND this
// daemon's listener holds the NFLOG group. A group another process holds
// would receive every logged packet's headers, tenant addresses and ports
// included; with the lines not rendered, no record is made at all.
type LogGate struct {
	group    uint16
	probeErr error
	bound    atomic.Bool
	stopped  atomic.Bool
	// rendered is set once a loader has been told logging is on: lines may
	// be in the kernel from then on, whatever the bind says later.
	rendered atomic.Bool
	changed  func()
}

// NewLogGate is the gate for group, after a probe that returned probeErr.
// changed is called on every bind transition, to run a firewall pass that
// adds or removes the lines.
func NewLogGate(group uint16, probeErr error, changed func()) *LogGate {
	return &LogGate{group: group, probeErr: probeErr, changed: changed}
}

// Logging reports whether log lines are rendered, and their group.
func (g *LogGate) Logging() (bool, uint16) {
	on := g.probeErr == nil && g.bound.Load() && !g.stopped.Load()
	if on {
		g.rendered.Store(true)
	}
	return on, g.group
}

// Stop turns logging off for good (the daemon is stopping: once it exits,
// nothing holds the group). It reports whether lines may have been rendered,
// so the caller runs a pass that removes them only then: whenever a loader
// was ever told logging is on, even if the bind was lost since, since the
// pass that bind loss asked for may not have removed them (a cancelled
// context, or one still to run).
func (g *LogGate) Stop() bool {
	was, _ := g.Logging()
	g.stopped.Store(true)
	return was || g.rendered.Load()
}

// OnBind is the listener's bind report (LogListener.OnBind): nil once bound,
// an error when the group cannot be held or was lost.
func (g *LogGate) OnBind(err error) {
	if g.bound.Swap(err == nil) != (err == nil) && g.probeErr == nil && !g.stopped.Load() && g.changed != nil {
		g.changed()
	}
}
