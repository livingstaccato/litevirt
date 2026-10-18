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
	return g.probeErr == nil && g.bound.Load(), g.group
}

// OnBind is the listener's bind report (LogListener.OnBind): nil once bound,
// an error when the group cannot be held or was lost.
func (g *LogGate) OnBind(err error) {
	if g.bound.Swap(err == nil) != (err == nil) && g.changed != nil {
		g.changed()
	}
}
