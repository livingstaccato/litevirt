package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/spf13/cobra"
)

// ownSignalsAnnotation marks a command that handles SIGINT and SIGTERM
// itself (the daemon's graceful shutdown): main installs no interrupt
// handler for it.
const ownSignalsAnnotation = "litevirt/own-signals"

// interruptSignals cancel a CLI command's context.
var interruptSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM}

// interrupts turns the first SIGINT or SIGTERM into a cancel of the command's
// context, so an RPC in flight returns Canceled and the command reports what
// may still complete on the server. A second signal exits at once.
type interrupts struct {
	ctx    context.Context
	cancel context.CancelFunc
	exit   func(int)

	mu    sync.Mutex
	first os.Signal
}

func newInterrupts(parent context.Context, exit func(int)) *interrupts {
	ctx, cancel := context.WithCancel(parent)
	return &interrupts{ctx: ctx, cancel: cancel, exit: exit}
}

// deliver handles one signal: the first cancels the context, the next exits
// with 128 + its number.
func (in *interrupts) deliver(sig os.Signal) {
	in.mu.Lock()
	first := in.first == nil
	if first {
		in.first = sig
	}
	in.mu.Unlock()
	if first {
		in.cancel()
		return
	}
	in.exit(signalExitCode(sig))
}

// caught is the first signal delivered, nil if none.
func (in *interrupts) caught() os.Signal {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.first
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
		in.cancel()
	}
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

// runRoot executes root with args on ctx and returns the process exit code.
// A command that failed after an interrupt signal (caught) exits with
// 128 + that signal's number, after its error is printed.
func runRoot(ctx context.Context, root *cobra.Command, args []string, caught func() os.Signal, stderr io.Writer) int {
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	// A silent typed exit carries the code and has already said everything
	// it wants to say (e.g. `lv health` printed its report; the code IS the
	// answer). Printing a generic Error: line would bury the report.
	code, silent := exitCodeOf(err)
	if !silent {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		code = 1
	}
	if sig := caught(); sig != nil {
		code = signalExitCode(sig)
	}
	return code
}
