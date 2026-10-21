package watchdog

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeWatchdog makes a regular file named like a watchdog node, and a fake
// /sys/class/watchdog reporting state for it ("" = no state file).
func fakeWatchdog(t *testing.T, state string) string {
	t.Helper()
	dir := t.TempDir()
	dev := filepath.Join(dir, "dev", "watchdog0")
	if err := os.MkdirAll(filepath.Dir(dev), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dev, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sys := filepath.Join(dir, "sys")
	if state != "" {
		if err := os.MkdirAll(filepath.Join(sys, "watchdog0"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sys, "watchdog0", "state"), []byte(state+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := sysClassWatchdog
	sysClassWatchdog = sys
	t.Cleanup(func() { sysClassWatchdog = old })
	return dev
}

func readDev(t *testing.T, dev string) []byte {
	t.Helper()
	b, err := os.ReadFile(dev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A timer nobody left running must not be started by boot: opening a watchdog
// starts it, and a boot that then failed would reboot a host whose previous
// run had disarmed cleanly.
func TestKeepBootAlive_DoesNotOpenATimerThatIsNotRunning(t *testing.T) {
	for _, state := range []string{"inactive", ""} {
		dev := fakeWatchdog(t, state)
		if k := KeepBootAlive(dev, 10*time.Millisecond); k != nil {
			k.Abandon()
			t.Fatalf("state %q: KeepBootAlive opened the device; it must only open a timer the kernel reports active", state)
		}
		time.Sleep(30 * time.Millisecond)
		if b := readDev(t, dev); len(b) != 0 {
			t.Fatalf("state %q: device written %q", state, b)
		}
	}
}

// A running timer is petted at once and keeps being petted until the
// heartbeat takes the descriptor over; the heartbeat continues on it.
func TestKeepBootAlive_PetsRunningTimerUntilHeartbeatTakesOver(t *testing.T) {
	dev := fakeWatchdog(t, "active")
	k := KeepBootAlive(dev, 10*time.Millisecond)
	if k == nil {
		t.Fatal("KeepBootAlive returned nil for an active timer")
	}
	if n := len(readDev(t, dev)); n < 1 {
		t.Fatalf("no keepalive at open, got %d bytes", n)
	}
	time.Sleep(60 * time.Millisecond)
	if n := len(readDev(t, dev)); n < 3 {
		t.Fatalf("boot petting did not continue: %d bytes after several intervals", n)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { HeartbeatFrom(ctx, dev, 10*time.Millisecond, nil, k); close(done) }()
	time.Sleep(40 * time.Millisecond)
	cancel()
	<-done
	b := readDev(t, dev)
	if b[len(b)-1] != 'V' {
		t.Fatalf("heartbeat on the handed-over descriptor did not disarm on an unowned shutdown: %q", b)
	}
	if k.Handoff() != nil {
		t.Fatal("the descriptor was handed over twice")
	}
}

// Abandon (boot failed or was cancelled before the heartbeat) never disarms
// and stops petting, so the timer runs on from the last pet exactly as the
// previous run left it.
func TestBootKeeper_AbandonLeavesTimerArmed(t *testing.T) {
	dev := fakeWatchdog(t, "active")
	k := KeepBootAlive(dev, 10*time.Millisecond)
	if k == nil {
		t.Fatal("KeepBootAlive returned nil for an active timer")
	}
	time.Sleep(25 * time.Millisecond)
	k.Abandon()
	after := readDev(t, dev)
	if bytes.ContainsRune(after, 'V') {
		t.Fatalf("Abandon wrote the magic close: %q", after)
	}
	time.Sleep(40 * time.Millisecond)
	if got := readDev(t, dev); len(got) != len(after) {
		t.Fatalf("petting continued after Abandon: %q -> %q", after, got)
	}
	k.Abandon() // idempotent
	var nilK *BootKeeper
	nilK.Abandon()
	if nilK.Handoff() != nil {
		t.Fatal("nil keeper handed over a descriptor")
	}
}

func TestTimerRunning_LegacyDevIsWatchdog0(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "watchdog0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "watchdog0", "state"), []byte("active\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := sysClassWatchdog
	sysClassWatchdog = dir
	t.Cleanup(func() { sysClassWatchdog = old })
	if running, known := timerRunning("/nonexistent/watchdog"); !running || !known {
		t.Fatalf("/dev/watchdog: running=%v known=%v, want watchdog0's state", running, known)
	}
	if _, known := timerRunning("/nonexistent/ipmi0"); known {
		t.Fatal("a path that names no watchdog node must be unknown")
	}
}
