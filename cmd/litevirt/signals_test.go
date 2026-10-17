package main

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

// kvm001 sat down for about three hours on 2026-07-24 because a SIGHUP — the
// class of signal needrestart and unattended-upgrades send — killed the daemon
// and systemd never restarted it.
//
// The reason is a systemd rule that is easy to miss: systemd.service(5) counts
// termination by SIGHUP, SIGINT, SIGTERM or SIGPIPE as a CLEAN exit, and
// Restart=on-failure explicitly does not restart on those four. So the unit
// reported Result=success with NRestarts=0 and left the node down; libvirtd went
// with it and both VMs stopped. No amount of restart-storm hardening reaches this
// path, because nothing ever fails.
//
// The daemon therefore has to refuse to die on the signal in the first place. It
// installs no SIGHUP handler today, so Go's runtime takes the die-from-signal
// path: none of the graceful shutdown runs — no markRestarting, so peers see an
// abrupt disappearance and briefly consider the node a fence candidate, and the
// DB and libvirt connections close dirty.

// TestSIGHUPDoesNotKillTheProcess is as direct as a signal test can be: if the
// drain is not installed, SIGHUP kills the test binary itself and the whole
// package run dies. There is no way for this to pass vacuously.
func TestSIGHUPDoesNotKillTheProcess(t *testing.T) {
	assertSignalDrained(t, syscall.SIGHUP)
}

// TestSIGPIPEDoesNotKillTheProcess covers the same systemd clean-exit class. A
// daemon that loses a peer mid-write can take SIGPIPE, and systemd would treat
// that death as clean too.
func TestSIGPIPEDoesNotKillTheProcess(t *testing.T) {
	assertSignalDrained(t, syscall.SIGPIPE)
}

func assertSignalDrained(t *testing.T, sig syscall.Signal) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	observed := drainIgnoredSignals(ctx)

	if err := syscall.Kill(os.Getpid(), sig); err != nil {
		t.Fatalf("kill self with %v: %v", sig, err)
	}
	select {
	case got := <-observed:
		if got != sig {
			t.Fatalf("drained %v, want %v", got, sig)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%v was never delivered to the drain; if the handler is not installed "+
			"this test does not fail here — the process is killed outright", sig)
	}
}

type capturedRecord struct {
	level slog.Level
	msg   string
	attrs map[string]any
}

type captureHandler struct {
	mu   sync.Mutex
	recs []capturedRecord
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *captureHandler) WithGroup(string) slog.Handler            { return h }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	rec := capturedRecord{level: r.Level, msg: r.Message, attrs: map[string]any{}}
	r.Attrs(func(a slog.Attr) bool { rec.attrs[a.Key] = a.Value.Any(); return true })
	h.mu.Lock()
	h.recs = append(h.recs, rec)
	h.mu.Unlock()
	return nil
}

// A peer's readiness probe resets the socket before our close_notify, so SIGPIPE
// arrives about five times a minute per node. A burst must produce one summary
// line carrying the count, not one WARN per signal; SIGHUP stays a WARN each time.
func TestSignalLogger_SIGPIPEIsSummarisedAndSIGHUPIsNot(t *testing.T) {
	h := &captureHandler{}
	now := time.Unix(1000, 0)
	l := newSignalLogger(slog.New(h), func() time.Time { return now })

	for i := 0; i < 7; i++ {
		l.observe(syscall.SIGPIPE)
	}
	l.observe(syscall.SIGHUP)
	l.observe(syscall.SIGHUP)

	if len(h.recs) != 2 {
		t.Fatalf("got %d records inside the window, want only the 2 SIGHUP warnings: %+v", len(h.recs), h.recs)
	}
	for _, r := range h.recs {
		if r.level != slog.LevelWarn || r.attrs["signal"] != syscall.SIGHUP.String() {
			t.Fatalf("SIGHUP record = %+v, want WARN with signal=hangup", r)
		}
	}

	now = now.Add(sigpipeSummaryInterval + time.Second)
	l.observe(syscall.SIGPIPE)
	if len(h.recs) != 3 {
		t.Fatalf("got %d records after the window, want exactly one summary: %+v", len(h.recs), h.recs)
	}
	sum := h.recs[2]
	if sum.level != slog.LevelInfo || sum.attrs["count"] != int64(8) {
		t.Fatalf("summary = %+v, want INFO with count=8", sum)
	}

	// The window restarts: another signal right away is counted, not logged.
	l.observe(syscall.SIGPIPE)
	if len(h.recs) != 3 {
		t.Fatalf("second summary inside the window: %+v", h.recs)
	}
	l.flush()
	if len(h.recs) != 4 || h.recs[3].attrs["count"] != int64(1) {
		t.Fatalf("flush = %+v, want one summary with count=1", h.recs)
	}
	l.flush()
	if len(h.recs) != 4 {
		t.Fatalf("flush with nothing pending logged: %+v", h.recs)
	}
}
