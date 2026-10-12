package cmdbound

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// R1 M-2: a command that exits 0 while a child it started still holds its
// output (cephadm's podman, a modprobe install hook) is a success, with its
// output, and the pipe is let go after WaitDelay rather than when the child
// exits. exec alone reports exec.ErrWaitDelay.
//
// Mutation "ErrWaitDelay is a failure" — red.
func TestCombinedOutput_AnExitZeroWithAChildHoldingStdoutIsASuccess(t *testing.T) {
	prev := WaitDelay
	WaitDelay = 300 * time.Millisecond
	t.Cleanup(func() { WaitDelay = prev })
	t0 := time.Now()
	out, err := CombinedOutput(context.Background(), Command(context.Background(), "sh", "-c", "sleep 5 & echo ok"))
	if err != nil || strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("exit 0 with a child holding stdout = %q, %v; want ok, nil", out, err)
	}
	if took := time.Since(t0); took > 3*time.Second {
		t.Fatalf("returned after %v; want about WaitDelay, not the child's 5 s", took)
	}
	// Output and Run agree.
	if o, err := Output(context.Background(), Command(context.Background(), "sh", "-c", "sleep 5 & echo ok")); err != nil || strings.TrimSpace(string(o)) != "ok" {
		t.Fatalf("Output = %q, %v", o, err)
	}
	if err := Run(context.Background(), Command(context.Background(), "sh", "-c", "sleep 5 & echo ok")); err != nil {
		t.Fatalf("Run = %v", err)
	}
	// A failure is still a failure, with stderr in the ExitError for Output.
	_, err = Output(context.Background(), Command(context.Background(), "sh", "-c", "echo bad >&2; exit 4"))
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 4 || strings.TrimSpace(string(ee.Stderr)) != "bad" {
		t.Fatalf("Output of a failing command = %v; want exit 4 with its stderr", err)
	}
}

// R1 M-2: a command the kernel does not let go (D state: SIGKILL is not
// delivered while it is blocked on a dead hard NFS mount) is not waited for
// past its deadline plus WaitDelay plus ReapGrace.
//
// Mutation "wait for the reap" (run waits on Wait unconditionally) — red.
func TestRun_ACommandThatCannotBeReapedIsNotWaitedFor(t *testing.T) {
	prevW, prevD, prevG := waitForExit, WaitDelay, ReapGrace
	release := make(chan struct{})
	waitForExit = func(cmd *exec.Cmd) error {
		err := cmd.Wait()
		<-release // the process exited, but stands in for one that cannot
		return err
	}
	WaitDelay, ReapGrace = 100*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { close(release); waitForExit, WaitDelay, ReapGrace = prevW, prevD, prevG })
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	out, err := CombinedOutput(ctx, Command(ctx, "sleep", "30"))
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || out != nil {
		t.Fatalf("a command not reaped = %q, %v; want no output and the deadline", out, err)
	}
	if took := time.Since(t0); took > 2*time.Second {
		t.Fatalf("returned after %v; want the deadline plus WaitDelay plus ReapGrace", took)
	}
}
