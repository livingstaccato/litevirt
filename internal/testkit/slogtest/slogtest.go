// Package slogtest gives tests a safe way to swap slog's default logger.
//
// This package is test-only. It must not be imported by production code.
package slogtest

import (
	"log"
	"log/slog"
	"testing"
)

// SaveRestore saves slog's default logger and the stdlib "log" package's own
// output writer, flags and prefix, and restores all four when the current
// test (or subtest) ends — regardless of what runs in between, including
// code that calls slog.SetDefault itself (e.g. internal/obs.Setup,
// cmd/litevirt's bootstrapDefaultLogger).
//
// Call this before driving code that installs slog's default logger. Use
// [Swap] instead when the test installs the default logger directly.
//
// The naive version of this save/restore, repeated across a dozen test
// files in this tree before this package existed,
//
//	prev := slog.Default()
//	slog.SetDefault(custom)
//	t.Cleanup(func() { slog.SetDefault(prev) })
//
// is not safe. slog.SetDefault rewires the stdlib log package's output to
// track the new handler — UNLESS that handler is slog's own internal stock
// "defaultHandler", in which case the stdlib log package's writer is left
// exactly where it was, to avoid a documented deadlock (see
// $GOROOT/src/log/slog/logger.go, SetDefault). Concretely:
//
//  1. Test starts. slog.Default() is (typically) the stock handler; stdlib
//     log writes to os.Stderr.
//  2. prev := slog.Default() captures the stock-handler logger.
//  3. slog.SetDefault(custom) installs the test's handler AND rewires
//     stdlib log's writer to it, since custom is not the stock handler.
//  4. t.Cleanup runs slog.SetDefault(prev). Since prev wraps the stock
//     handler, this restore is exactly the case SetDefault special-cases:
//     it restores slog.Default() but leaves stdlib log's writer wired to
//     the (now out of scope, often closed) buffer from step 3.
//  5. Every later stdlib log.Print/Fatal call in that process — in any test
//     in the same binary, not just this one — silently writes nowhere
//     useful, or panics on a closed pipe, for the rest of the run.
//
// internal/metrics/server.go documents this same mechanism as the reason it
// injects a logger into the type under test instead of swapping the global
// default; SaveRestore/Swap are for the tests that must exercise the global
// default itself (because the code under test calls slog.SetDefault or
// reads slog.Default() directly) and so cannot avoid the swap.
func SaveRestore(t *testing.T) {
	t.Helper()
	prevLogger := slog.Default()
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	prevPrefix := log.Prefix()
	t.Cleanup(func() {
		slog.SetDefault(prevLogger)
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
	})
}

// Swap installs next as slog's default logger for the rest of the current
// test (or subtest) and restores it — along with the stdlib log package's
// writer, flags and prefix — when the test ends. Equivalent to calling
// [SaveRestore] and then slog.SetDefault(next); see its doc for why both
// must be restored together.
func Swap(t *testing.T, next *slog.Logger) {
	t.Helper()
	SaveRestore(t)
	slog.SetDefault(next)
}
