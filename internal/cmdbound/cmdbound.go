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
//
// Run, Output and CombinedOutput run such a command and add two things exec
// does not:
//
//   - A command that exits 0 while a child it started still holds its output
//     (cephadm's podman, a modprobe install hook) is a success: exec reports
//     ErrWaitDelay for it, which they treat as success, with the output read
//     so far. The pipe is still released after WaitDelay.
//   - The bound cannot break a process blocked in the kernel (D state, as in
//     a stat or umount on a hard NFS mount whose server does not answer):
//     SIGKILL is not delivered until the call returns, and exec's Wait waits
//     for the process to exit. They stop waiting WaitDelay+ReapGrace after the
//     context ends and return an error; the process, and one goroutine
//     waiting to reap it, remain until the kernel lets it go.
package cmdbound

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ReapGrace is how long, past the context's end and WaitDelay, Run and the
// output helpers wait for a killed command to exit.
var ReapGrace = 2 * time.Second

// errAbandoned marks a command not reaped in time; its output is not read.
var errAbandoned = errors.New("killed at its deadline, but it has not exited (blocked in the kernel, D state?); not waited for")

// Run runs cmd, made by Command with ctx, and waits for it within the bounds
// above.
func Run(ctx context.Context, cmd *exec.Cmd) error {
	return run(ctx, cmd)
}

// CombinedOutput is cmd.CombinedOutput within the bounds above. A command
// abandoned in the kernel returns no output.
func CombinedOutput(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
	var b bytes.Buffer
	cmd.Stdout, cmd.Stderr = &b, &b
	err := run(ctx, cmd)
	if errors.Is(err, errAbandoned) {
		return nil, err
	}
	return b.Bytes(), err
}

// Output is cmd.Output within the bounds above: stdout, and the stderr of a
// command that failed in its *exec.ExitError, as exec does.
func Output(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	captured := cmd.Stderr == nil
	if captured {
		cmd.Stderr = &errb
	}
	err := run(ctx, cmd)
	if errors.Is(err, errAbandoned) {
		return nil, err
	}
	var ee *exec.ExitError
	if captured && errors.As(err, &ee) {
		ee.Stderr = errb.Bytes()
	}
	return out.Bytes(), err
}

// waitForExit is cmd.Wait; a test stands in for a process the kernel does not
// let go.
var waitForExit = func(cmd *exec.Cmd) error { return cmd.Wait() }

func run(ctx context.Context, cmd *exec.Cmd) error {
	wait := waitForExit
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- wait(cmd) }()
	select {
	case err := <-done:
		return successAfterExit(cmd, err)
	case <-ctx.Done():
	}
	t := time.NewTimer(cmd.WaitDelay + ReapGrace)
	defer t.Stop()
	select {
	case err := <-done:
		return successAfterExit(cmd, err)
	case <-t.C:
		return fmt.Errorf("%s: %w: %w", cmd.Path, errAbandoned, ctx.Err())
	}
}

// successAfterExit treats ErrWaitDelay — which Wait returns only for a
// command that exited 0 while its output was still held open — as success.
func successAfterExit(cmd *exec.Cmd, err error) error {
	if errors.Is(err, exec.ErrWaitDelay) {
		slog.Debug("command exited 0; a child it started still held its output, which was let go", "cmd", cmd.Path)
		return nil
	}
	return err
}

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

// CommandSession is Command with the command leading a session of its own
// (Setsid), and the whole session killed when the context ends, not only
// its process group. A child can leave the group (coreutils timeout without
// --foreground calls setpgid(0, 0)), and a group kill then misses it, but it
// cannot leave the session without setsid. The session is read from /proc;
// where there is none, only the group is killed.
func CommandSession(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := Command(ctx, name, args...)
	cmd.SysProcAttr.Setpgid = false
	cmd.SysProcAttr.Setsid = true
	cmd.Cancel = func() error { return killSession(cmd.Process.Pid) }
	return cmd
}

// killSession SIGKILLs session sid: its leader's group, then every process
// /proc lists in the session, twice, so a child forked during the first pass
// is caught by the second.
func killSession(sid int) error {
	gerr := syscall.Kill(-sid, syscall.SIGKILL)
	found := false
	for pass := 0; pass < 2; pass++ {
		for _, pid := range sessionMembers(sid) {
			found = true
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	if errors.Is(gerr, syscall.ESRCH) && !found {
		return os.ErrProcessDone
	}
	return nil
}

// sessionMembers lists the processes /proc shows in session sid, zombies
// included (a kill is harmless to them).
func sessionMembers(sid int) []int {
	dirs, _ := os.ReadDir("/proc")
	var out []int
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + d.Name() + "/stat")
		if err != nil {
			continue
		}
		// After "pid (comm)": state, ppid, pgrp, session.
		k := bytes.LastIndexByte(b, ')')
		if k < 0 {
			continue
		}
		f := strings.Fields(string(b[k+1:]))
		if len(f) >= 4 && f[3] == strconv.Itoa(sid) {
			out = append(out, pid)
		}
	}
	return out
}
