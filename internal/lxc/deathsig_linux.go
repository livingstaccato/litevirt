//go:build linux

package lxc

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The daemon runs under KillMode=process, so a tool it spawned outlives it
// unless told otherwise. A tool working in a staging directory (umoci
// unpacking a replacing pull, lxc-create fetching a recreate's image) gets
// SIGKILL when the daemon dies (dieWithDaemon); what it spawned in turn is
// not covered by that, so the start-up sweep stops any process still
// working inside a staging directory before removing it (stopWorkersIn).

// dieWithDaemon makes cmd receive SIGKILL when the daemon dies. The signal
// is tied to the OS thread that starts cmd, so run it with runPinned.
func dieWithDaemon(cmd *exec.Cmd) *exec.Cmd {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
	return cmd
}

// runPinned runs fn (which starts and waits for a dieWithDaemon command) on
// one locked OS thread, so the thread the parent-death signal is tied to
// lives until the command has exited.
func runPinned(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return fn()
}

// stopWorkersIn sends SIGKILL to every other process whose working
// directory, root or open files lie under dir, and waits up to five seconds
// for them to exit.
func stopWorkersIn(dir string) {
	dir = canonPath(dir)
	under := func(p string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	self := os.Getpid()
	var pids []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		base := filepath.Join("/proc", e.Name())
		hit := false
		for _, l := range []string{"cwd", "root"} {
			if t, err := os.Readlink(filepath.Join(base, l)); err == nil && under(strings.TrimSuffix(t, " (deleted)")) {
				hit = true
			}
		}
		if !hit {
			fds, _ := os.ReadDir(filepath.Join(base, "fd"))
			for _, fd := range fds {
				if t, err := os.Readlink(filepath.Join(base, "fd", fd.Name())); err == nil && under(strings.TrimSuffix(t, " (deleted)")) {
					hit = true
					break
				}
			}
		}
		if hit {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			pids = append(pids, pid)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for _, pid := range pids {
		for time.Now().Before(deadline) {
			if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) || zombie(pid) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func zombie(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true
	}
	s := string(b)
	i := strings.LastIndex(s, ")")
	return i >= 0 && i+2 < len(s) && s[i+2] == 'Z'
}
