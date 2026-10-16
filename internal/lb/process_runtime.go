package lb

import (
	"context"
	"os/exec"
)

// ProcessRuntime owns the process effects of Apply. A private manager can
// supply an isolated runtime before first use; production uses host processes.
type ProcessRuntime interface {
	Run(context.Context, string, ...string) ([]byte, error)
	ConntrackdInstalled() bool
	ConfigAlive(string, string) bool
	StopConfig(string, string)
	PIDAlive(string) bool
	StartHAProxy(string, string) error
	StartKeepalived(string, string) error
}

func (m *Manager) SetProcessRuntime(r ProcessRuntime) { m.runtime = r }
func (m *Manager) processes() ProcessRuntime {
	if m.runtime != nil {
		return m.runtime
	}
	return hostProcessRuntime{m}
}

type hostProcessRuntime struct{ m *Manager }

func (r hostProcessRuntime) Run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, bin, args...).CombinedOutput()
}
func (r hostProcessRuntime) ConntrackdInstalled() bool        { return conntrackdInstalled() }
func (r hostProcessRuntime) ConfigAlive(bin, cfg string) bool { return procByConfigAlive(bin, cfg) }
func (r hostProcessRuntime) StopConfig(bin, cfg string)       { killProcByConfig(bin, cfg) }
func (r hostProcessRuntime) PIDAlive(pid string) bool         { return pidAlive(pid) }
func (r hostProcessRuntime) StartHAProxy(cfg, pid string) error {
	return r.m.startOrReloadHAProxy(cfg, pid)
}
func (r hostProcessRuntime) StartKeepalived(cfg, pid string) error {
	return r.m.startOrReloadKeepalived(cfg, pid)
}
