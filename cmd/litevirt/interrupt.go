package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ownSignalsAnnotation marks a command that handles SIGINT and SIGTERM
// itself (the daemon's graceful shutdown): it runs with no interrupt handler.
const ownSignalsAnnotation = "litevirt/own-signals"

// interruptSignals cancel a CLI command's context.
var interruptSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM}

// interruptGrace is how long a command has, after the first interrupt
// signal cancelled its context, to return before the process dies by that
// signal anyway: a prompt, a password read or an ssh step does not read the
// context.
const interruptGrace = 2 * time.Second

// interrupts turns the first SIGINT or SIGTERM into a cancel of the command's
// context, so an RPC in flight returns Canceled and the command reports what
// may still complete on the server. The process dies by that signal once the
// command returns, when the grace runs out, or at a second signal, whichever
// comes first.
type interrupts struct {
	ctx    context.Context
	cancel context.CancelFunc
	grace  time.Duration
	die    func(os.Signal)

	mu      sync.Mutex
	first   os.Signal
	timer   *time.Timer
	held    int  // holdInterruptGrace calls not yet released
	expired bool // the grace ran out while held
}

type interruptsKey struct{}

func newInterrupts(parent context.Context, grace time.Duration, die func(os.Signal)) *interrupts {
	in := &interrupts{grace: grace, die: die}
	in.ctx, in.cancel = context.WithCancel(context.WithValue(parent, interruptsKey{}, in))
	return in
}

// deliver handles one signal: the first cancels the context and arms the
// grace, the next dies by the signal.
func (in *interrupts) deliver(sig os.Signal) {
	in.mu.Lock()
	first := in.first == nil
	if first {
		in.first = sig
		in.timer = time.AfterFunc(in.grace, func() { in.graceOver(sig) })
	}
	in.mu.Unlock()
	if first {
		in.cancel()
		return
	}
	in.die(sig)
}

// graceOver dies by sig, unless a bounded cleanup holds the grace: then the
// death waits for its release or for its budget.
func (in *interrupts) graceOver(sig os.Signal) {
	in.mu.Lock()
	held := in.held > 0
	if held {
		in.expired = true
	}
	in.mu.Unlock()
	if !held {
		in.die(sig)
	}
}

// holdInterruptGrace lets a bounded cleanup the command runs after an
// interrupt (a rollback of what it already did) finish within budget instead
// of the grace: until release is called, or budget runs out, the grace does
// not end the process. A second signal still does. It is a no-op outside an
// interrupt-handled command.
func holdInterruptGrace(ctx context.Context, budget time.Duration) (release func()) {
	in, ok := ctx.Value(interruptsKey{}).(*interrupts)
	if !ok {
		return func() {}
	}
	in.mu.Lock()
	in.held++
	in.mu.Unlock()
	var once sync.Once
	unhold := func() {
		once.Do(func() {
			in.mu.Lock()
			in.held--
			die := in.held == 0 && in.expired
			sig := in.first
			in.mu.Unlock()
			if die {
				in.die(sig)
			}
		})
	}
	t := time.AfterFunc(budget, unhold)
	return func() {
		t.Stop()
		unhold()
	}
}

// caught is the first signal delivered, nil if none.
func (in *interrupts) caught() os.Signal {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.first
}

// close disarms the grace and cancels the context.
func (in *interrupts) close() {
	in.mu.Lock()
	if in.timer != nil {
		in.timer.Stop()
	}
	in.mu.Unlock()
	in.cancel()
}

// watch delivers the process's interrupt signals until stop is called. A
// signal the process inherited as ignored (a background job's SIGINT) stays
// ignored.
func (in *interrupts) watch() (stop func()) {
	var sigs []os.Signal
	for _, s := range interruptSignals {
		if !signal.Ignored(s) {
			sigs = append(sigs, s)
		}
	}
	ch := make(chan os.Signal, 2)
	done := make(chan struct{})
	if len(sigs) > 0 {
		signal.Notify(ch, sigs...)
	}
	go func() {
		for {
			select {
			case s := <-ch:
				in.deliver(s)
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
		in.close()
	}
}

// dieBySignal ends the process by sig with its default action, as if the
// signal had never been caught, so a shell loop or xargs running the command
// stops: they stop only for a child that died by the signal. The exit is
// a fallback only.
func dieBySignal(sig os.Signal) {
	if s, ok := sig.(syscall.Signal); ok {
		signal.Reset(s)
		_ = syscall.Kill(syscall.Getpid(), s)
		time.Sleep(time.Second)
	}
	os.Exit(signalExitCode(sig))
}

func signalExitCode(sig os.Signal) int {
	if s, ok := sig.(syscall.Signal); ok {
		return 128 + int(s)
	}
	return 1
}

// handlesOwnSignals reports whether the command args name handles SIGINT and
// SIGTERM itself.
func handlesOwnSignals(root *cobra.Command, args []string) bool {
	c, _, err := root.Find(args)
	return err == nil && c.Annotations[ownSignalsAnnotation] == "true"
}

// runProcess runs root with args as the process does, with the interrupt
// handler unless the command handles its signals itself, and returns the
// exit code. After an interrupt signal it does not return: the process dies
// by the signal.
func runProcess(root *cobra.Command, args []string, stderr io.Writer) int {
	if handlesOwnSignals(root, args) {
		return runRoot(context.Background(), root, args, func() os.Signal { return nil }, dieBySignal, stderr)
	}
	in := newInterrupts(context.Background(), interruptGrace, dieBySignal)
	stop := in.watch()
	defer stop()
	return runRoot(in.ctx, root, args, in.caught, dieBySignal, stderr)
}

// runRoot executes root with args on ctx and returns the process exit code.
// After an interrupt signal (caught) the command's error is printed, unless
// it is only the cancellation itself, and then die is called with the
// signal; when die returns (a test), the code is 128 + the signal's number.
func runRoot(ctx context.Context, root *cobra.Command, args []string, caught func() os.Signal, die func(os.Signal), stderr io.Writer) int {
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	sig := caught()
	code := 0
	if err != nil {
		// A silent typed exit carries the code and has already said
		// everything it wants to say (e.g. `lv health` printed its report;
		// the code IS the answer). Printing a generic Error: line would bury
		// the report.
		var silent bool
		code, silent = exitCodeOf(err)
		if !silent {
			code = 1
			if sig == nil || !isBareCancel(err) {
				fmt.Fprintf(stderr, "Error: %v\n", err)
			}
		}
	}
	if sig != nil {
		die(sig)
		return signalExitCode(sig)
	}
	return code
}

// isBareCancel reports whether err says only that the command's context was
// cancelled (a stream ended by Ctrl-C), with nothing the operator needs.
func isBareCancel(err error) bool {
	return errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled
}
