package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

// heldClient holds each delete or rebuild until its context ends, as a real
// RPC does when its caller cancels, and answers OK if it never does.
type heldClient struct {
	pb.LiteVirtClient
	started chan<- struct{}
}

func (c heldClient) hold(ctx context.Context) error {
	c.started <- struct{}{}
	select {
	case <-ctx.Done():
		return status.FromContextError(ctx.Err()).Err()
	case <-time.After(5 * time.Second):
		return nil
	}
}

func (c heldClient) DeleteVM(ctx context.Context, _ *pb.DeleteVMRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, c.hold(ctx)
}

func (c heldClient) DeleteContainer(ctx context.Context, _ *pb.DeleteContainerRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, c.hold(ctx)
}

func (c heldClient) RebuildVM(ctx context.Context, req *pb.RebuildVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: req.Name}, c.hold(ctx)
}

// dieRecorder stands in for dying by a signal, recording each call.
func dieRecorder() (func(os.Signal), <-chan os.Signal) {
	ch := make(chan os.Signal, 8)
	return func(s os.Signal) { ch <- s }, ch
}

// An interrupt while a delete or rebuild is in flight cancels the command's
// context: the RPC returns Canceled, the command says the operation may still
// complete and names the command that shows it, and the process then dies by
// the signal. A second signal dies at once.
//
// Mutations: execute the root without the context (Execute()) — the RPC is
// never cancelled and the command reports success; do not die after the
// command returns — red; let a second signal do nothing — red.
func TestInterrupt_AnInFlightCommandReportsWhatMayStillCompleteAndDies(t *testing.T) {
	for _, c := range []struct {
		name  string
		args  []string
		sig   syscall.Signal
		want  string
		check string
	}{
		{"lv rm, SIGINT", []string{"rm", "vm1"}, syscall.SIGINT, "the delete may still complete", "`lv ls`"},
		{"lv rm, SIGTERM", []string{"rm", "vm1"}, syscall.SIGTERM, "the delete may still complete", "`lv ls`"},
		{"lv ct rm", []string{"ct", "rm", "ct1"}, syscall.SIGINT, "the delete may still complete", "`lv ct ls`"},
		{"lv rebuild", []string{"rebuild", "vm1"}, syscall.SIGINT, "the rebuild may still complete", "wait until `lv ls` shows it before running `lv rebuild` again"},
	} {
		t.Run(c.name, func(t *testing.T) {
			started := make(chan struct{}, 1)
			orig := cli.Connect
			cli.Connect = func(context.Context) (pb.LiteVirtClient, func(), error) {
				return heldClient{started: started}, func() {}, nil
			}
			t.Cleanup(func() { cli.Connect = orig })

			die, died := dieRecorder()
			in := newInterrupts(context.Background(), time.Minute, die)
			defer in.close()
			go func() {
				<-started
				in.deliver(c.sig)
			}()
			var stderr bytes.Buffer
			code := runRoot(in.ctx, newRootCmd(), c.args, in.caught, die, &stderr)

			if want := 128 + int(c.sig); code != want {
				t.Errorf("exit code = %d, want %d; stderr:\n%s", code, want, stderr.String())
			}
			if out := stderr.String(); !strings.Contains(out, c.want) || !strings.Contains(out, c.check) ||
				!strings.Contains(out, "interrupted before the answer arrived") {
				t.Errorf("stderr = %q, want the interruption reported with %q and %s", out, c.want, c.check)
			}
			select {
			case got := <-died:
				if got != c.sig {
					t.Errorf("died by %v after the command returned, want %v", got, c.sig)
				}
			default:
				t.Error("the process did not die by the signal once the command returned")
			}

			in.deliver(c.sig)
			select {
			case got := <-died:
				if got != c.sig {
					t.Errorf("a second signal died by %v, want %v", got, c.sig)
				}
			case <-time.After(time.Second):
				t.Error("a second signal did not end the process")
			}
		})
	}
}

// A command blocked on something that does not read its context (a y/N
// prompt, a password read, an ssh step) is not left running by the first
// Ctrl-C: the process dies by the signal once the grace runs out.
//
// Mutation: do not arm the grace — red.
func TestInterrupt_ACommandThatIgnoresItsContextDiesAfterTheGrace(t *testing.T) {
	die, died := dieRecorder()
	in := newInterrupts(context.Background(), 100*time.Millisecond, die)
	defer in.close()
	blocked := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	root := &cobra.Command{Use: "lv", SilenceUsage: true, SilenceErrors: true}
	root.AddCommand(&cobra.Command{Use: "stuck", RunE: func(*cobra.Command, []string) error {
		close(blocked)
		<-release // never reads its context
		return nil
	}})
	go runRoot(in.ctx, root, []string{"stuck"}, in.caught, die, &bytes.Buffer{})
	<-blocked
	in.deliver(syscall.SIGINT)
	select {
	case got := <-died:
		if got != syscall.SIGINT {
			t.Errorf("died by %v, want SIGINT", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a command that ignores its context kept the process alive after Ctrl-C")
	}
}

// A streaming command ended by Ctrl-C (`lv logs -f`, `lv events`) prints no
// raw "context canceled": the cancellation is the operator's own.
//
// Mutation: print every error after a signal — red.
func TestInterrupt_ABareCancellationPrintsNothing(t *testing.T) {
	for _, c := range []struct {
		name      string
		err       error
		wantPrint bool
	}{
		{"grpc Canceled", status.FromContextError(context.Canceled).Err(), false},
		{"wrapped context.Canceled", fmt.Errorf("follow: %w", context.Canceled), false},
		{"another failure", errors.New("permission denied"), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			die, _ := dieRecorder()
			in := newInterrupts(context.Background(), time.Minute, die)
			defer in.close()
			in.deliver(syscall.SIGINT)
			root := &cobra.Command{Use: "lv", SilenceUsage: true, SilenceErrors: true}
			root.AddCommand(&cobra.Command{Use: "follow", RunE: func(*cobra.Command, []string) error { return c.err }})
			var stderr bytes.Buffer
			runRoot(in.ctx, root, []string{"follow"}, in.caught, die, &stderr)
			if got := stderr.Len() > 0; got != c.wantPrint {
				t.Errorf("stderr = %q, want printed=%v", stderr.String(), c.wantPrint)
			}
		})
	}
}

// interruptHelperEnv selects the helper process's command: "cancellable"
// returns once its context ends, "clean" returns nil once it ends, "stuck"
// ignores it.
const interruptHelperEnv = "LV_INTERRUPT_HELPER"

// TestInterruptHelperProcess is the process TestInterrupt_TheProcessDiesByTheSignal
// signals: runProcess with a command that prints "ready" and then waits.
func TestInterruptHelperProcess(t *testing.T) {
	mode := os.Getenv(interruptHelperEnv)
	if mode == "" {
		t.Skip("helper process only")
	}
	root := &cobra.Command{Use: "lv", SilenceUsage: true, SilenceErrors: true}
	root.AddCommand(&cobra.Command{Use: "wait", RunE: func(cmd *cobra.Command, _ []string) error {
		fmt.Println("ready")
		switch mode {
		case "stuck":
			time.Sleep(time.Hour) // never reads its context
			return nil
		case "clean":
			<-cmd.Context().Done()
			return nil
		default:
			<-cmd.Context().Done()
			return cmd.Context().Err()
		}
	}})
	os.Exit(runProcess(root, []string{"wait"}, os.Stderr))
}

// The process ends by the signal itself, not by exit 130/143: bash ends a
// loop, and xargs a batch, only for a child the signal killed. That holds
// for a command that returns an error, one that returns cleanly, and one
// that never returns (after the grace). A SIGINT the process inherited as
// ignored (a background job) stays ignored.
//
// Mutation: exit 128+n instead of re-raising — red.
func TestInterrupt_TheProcessDiesByTheSignal(t *testing.T) {
	for _, c := range []struct {
		mode    string
		sig     syscall.Signal
		ignored bool // start with SIGINT ignored
	}{
		{"cancellable", syscall.SIGINT, false},
		{"cancellable", syscall.SIGTERM, false},
		{"clean", syscall.SIGINT, false},
		{"stuck", syscall.SIGINT, false},
		{"stuck", syscall.SIGTERM, false},
		{"cancellable", syscall.SIGTERM, true},
	} {
		t.Run(fmt.Sprintf("%s %v ignored=%v", c.mode, c.sig, c.ignored), func(t *testing.T) {
			if c.sig == syscall.SIGINT && signal.Ignored(syscall.SIGINT) {
				t.Skip("SIGINT is ignored in this process, and a child would inherit that")
			}
			self := []string{os.Args[0], "-test.run=^TestInterruptHelperProcess$", "-test.count=1"}
			var cmd *exec.Cmd
			if c.ignored {
				// trap '' sets SIG_IGN, which exec keeps.
				cmd = exec.Command("/bin/sh", append([]string{"-c", `trap '' INT; exec "$@"`, "sh"}, self...)...)
			} else {
				cmd = exec.Command(self[0], self[1:]...)
			}
			cmd.Env = append(os.Environ(), interruptHelperEnv+"="+c.mode)
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			ready := make(chan bool, 1)
			go func() {
				sc := bufio.NewScanner(out)
				for sc.Scan() {
					if sc.Text() == "ready" {
						ready <- true
					}
				}
			}()
			select {
			case <-ready:
			case <-time.After(30 * time.Second):
				_ = cmd.Process.Kill()
				t.Fatal("the helper never became ready")
			}
			if c.ignored {
				_ = cmd.Process.Signal(syscall.SIGINT)
				time.Sleep(300 * time.Millisecond)
			}
			_ = cmd.Process.Signal(c.sig)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				_ = cmd.Process.Kill()
				t.Fatal("the helper did not end after the signal")
			}
			ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
			if !ws.Signaled() || ws.Signal() != c.sig {
				t.Errorf("helper ended with %v (signaled=%v), want killed by %v", cmd.ProcessState, ws.Signaled(), c.sig)
			}
		})
	}
}

// A real SIGINT reaches the command's context once the watch is installed.
func TestInterrupt_WatchCancelsTheContextOnSIGINT(t *testing.T) {
	if signal.Ignored(syscall.SIGINT) {
		t.Skip("SIGINT is ignored in this process (started in the background); the watch leaves it so")
	}
	die, _ := dieRecorder()
	in := newInterrupts(context.Background(), time.Minute, die)
	stop := in.watch()
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-in.ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("SIGINT did not cancel the command's context")
	}
	if in.caught() != syscall.SIGINT {
		t.Errorf("caught = %v, want SIGINT", in.caught())
	}
}

// The daemon, gitops, top, spice and vnc handle SIGINT/SIGTERM themselves;
// every other command gets the interrupt handler.
//
// Mutation: drop gitops's annotation — red.
func TestInterrupt_OnlyCommandsWithTheirOwnHandlersSkipIt(t *testing.T) {
	root := newRootCmd()
	for _, args := range [][]string{{"daemon"}, {"gitops", "--repo", "x"}, {"top"}, {"spice", "vm1"}, {"vnc", "vm1", "--listen", ":5900"}} {
		if !handlesOwnSignals(root, args) {
			t.Errorf("%v handles its signals itself but would get the CLI's interrupt handler", args)
		}
	}
	for _, args := range [][]string{{"rm", "vm1"}, {"compose", "up", "-f", "x.yaml"}, {"rebuild", "vm1"}, {}} {
		if handlesOwnSignals(root, args) {
			t.Errorf("%v would run without the interrupt handler", args)
		}
	}
}

// A Ctrl-C that fails a firewall macro part way gives the rollback of the
// rows already created its own budget: the grace does not end the process
// while the rollback runs, and does once it is done.
//
// Mutation: drop the grace hold around the rollback — red.
func TestInterrupt_AMacroRollbackOutlivesTheGrace(t *testing.T) {
	die, died := dieRecorder()
	in := newInterrupts(context.Background(), 50*time.Millisecond, die)
	defer in.close()
	spy := &macroSpy{failAt: 2}
	spy.onAdd = func() {
		if spy.adds == 2 {
			in.deliver(syscall.SIGINT)
		}
	}
	diedDuringRollback := false
	spy.onRemove = func() {
		time.Sleep(300 * time.Millisecond) // well past the grace
		select {
		case <-died:
			diedDuringRollback = true
		default:
		}
	}
	_, err := runMacroCLICtx(t, in.ctx, spy, newSGRuleAddCmd(), "web", "--macro", "DNS")
	if err == nil {
		t.Fatal("the interrupted macro answered OK")
	}
	if diedDuringRollback {
		t.Error("the grace ended the process during the macro's rollback")
	}
	if len(spy.removed) != 1 {
		t.Errorf("rolled back %v, want the one row already created", spy.removed)
	}
	select {
	case got := <-died:
		if got != syscall.SIGINT {
			t.Errorf("died by %v after the rollback, want SIGINT", got)
		}
	case <-time.After(time.Second):
		t.Error("the grace, held by the rollback, did not end the process once it was done")
	}
}

// A grace hold is bounded by its budget: a cleanup that never finishes does
// not keep the process alive.
func TestInterrupt_AGraceHoldEndsAtItsBudget(t *testing.T) {
	die, died := dieRecorder()
	in := newInterrupts(context.Background(), 10*time.Millisecond, die)
	defer in.close()
	release := holdInterruptGrace(in.ctx, 200*time.Millisecond)
	defer release()
	start := time.Now()
	in.deliver(syscall.SIGINT)
	select {
	case <-died:
		if d := time.Since(start); d < 150*time.Millisecond {
			t.Errorf("died %v after the signal, inside the hold's budget", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a hold whose cleanup never finished kept the process alive")
	}
}
