package cmdbound

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// waitForPid reads the pid a test command wrote to file.
func waitForPid(t *testing.T, file string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(file); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no pid in %s", file)
	return 0
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

// A command whose child, in a session of its own, holds the output pipe —
// mount's mount.nfs against a server that does not answer, reparented to
// init once mount is killed — returns within its timeout plus WaitDelay, not
// when the child gives up. Without WaitDelay, CombinedOutput waits for the
// pipe: here for the child's 60 s.
//
// Mutation "no WaitDelay" (Apply leaves cmd.WaitDelay at 0) — red.
func TestCommand_ReturnsWithinItsBoundWhenAChildHoldsThePipe(t *testing.T) {
	prev := WaitDelay
	WaitDelay = 500 * time.Millisecond
	t.Cleanup(func() { WaitDelay = prev })
	pidFile := filepath.Join(t.TempDir(), "pid")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	// setsid puts the sleeper outside the command's process group, as a
	// daemonising child would be: only WaitDelay can end the wait.
	_, err := Command(ctx, "sh", "-c", `setsid sh -c 'echo $$ > "$1"; exec sleep 60' sh "$0" & wait`, pidFile).CombinedOutput()
	took := time.Since(start)
	pid := waitForPid(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	if err == nil {
		t.Fatal("a command killed by its deadline returned no error")
	}
	if took > 5*time.Second {
		t.Fatalf("the command returned after %v; want within its 500ms timeout plus %v WaitDelay", took, WaitDelay)
	}
}

// A child in the command's own process group — mount.nfs, forked by mount —
// is killed with it when the context ends, so it cannot carry on (and mount
// the export) after the caller gave up.
//
// Mutation "kill the leader only" (Cancel kills cmd.Process, not the group) —
// red.
func TestCommand_KillsTheWholeProcessGroupAtItsDeadline(t *testing.T) {
	prev := WaitDelay
	WaitDelay = 500 * time.Millisecond
	t.Cleanup(func() { WaitDelay = prev })
	pidFile := filepath.Join(t.TempDir(), "pid")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	// The child closes its copy of the pipe, so only the group kill ends it.
	_, _ = Command(ctx, "sh", "-c", `sh -c 'echo $$ > "$1"; exec sleep 60' sh "$0" >/dev/null 2>&1 & wait`, pidFile).CombinedOutput()
	pid := waitForPid(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	deadline := time.Now().Add(3 * time.Second)
	for alive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("the command's child %d still runs after the command's deadline", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A command that finishes in time is untouched: its output and exit status
// come back as exec gives them.
func TestCommand_AFinishedCommandIsUnchanged(t *testing.T) {
	out, err := Command(context.Background(), "sh", "-c", "echo hello; exit 3").CombinedOutput()
	if strings.TrimSpace(string(out)) != "hello" {
		t.Fatalf("output %q", out)
	}
	ee, ok := err.(interface{ ExitCode() int })
	if !ok || ee.ExitCode() != 3 {
		t.Fatalf("err %v; want exit status 3", err)
	}
}
