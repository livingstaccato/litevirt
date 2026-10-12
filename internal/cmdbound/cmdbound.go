// Package cmdbound makes the context deadline of an external command a real
// bound on how long running it takes (lab 2 F-3).
//
// exec.CommandContext kills only the process it started when the context
// ends, and Wait then waits for the command's output pipes to close. A child
// that process forked holds them open: mount forks mount.nfs, which against
// an NFS server that does not answer keeps retrying for minutes after mount
// itself was killed. The "30 s" mount took three minutes on lab 2, and the
// orphaned mount.nfs could still have mounted the export after the caller
// had given up and reported it unmounted.
//
// Command runs the command in a process group of its own, kills the whole
// group when the context ends, and stops waiting for the pipes WaitDelay
// after that (or after the command exits). It is for short-lived tools
// (mount, iscsiadm, rbd, qemu-img, nft, …), never for one that must leave a
// process running behind it (a daemon it starts): that process is in the
// group, and a timeout kills it too.
package cmdbound

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// WaitDelay is how long Wait waits for a command's output pipes once its
// context has ended or it has exited.
var WaitDelay = 2 * time.Second

// Command is exec.CommandContext with Apply.
func Command(ctx context.Context, name string, args ...string) *exec.Cmd {
	return Apply(exec.CommandContext(ctx, name, args...))
}

// Apply bounds cmd, which must come from exec.CommandContext and not have
// been started: its own process group, the whole group killed when its
// context ends, and WaitDelay.
func Apply(cmd *exec.Cmd) *exec.Cmd {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error {
		// The group's id is the command's pid (Setpgid with Pgid 0).
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		if err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = WaitDelay
	return cmd
}
