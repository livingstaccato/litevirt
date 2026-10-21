package watchdog

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeWatchdog makes a regular file named like a watchdog node, a fake
// /sys/class/watchdog reporting state for it ("" = no state file), and fast
// boot petting.
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
	oldSys, oldPet := sysClassWatchdog, bootPetIntervalFn
	sysClassWatchdog = sys
	bootPetIntervalFn = func(string) time.Duration { return 10 * time.Millisecond }
	t.Cleanup(func() { sysClassWatchdog, bootPetIntervalFn = oldSys, oldPet })
	return dev
}

// testBootOptions: generous bounds, a private run directory.
func testBootOptions(t *testing.T) BootOptions {
	return BootOptions{RunDir: t.TempDir(), Configured: true, StreakWindow: time.Hour, MaxBoots: 5, MaxDuration: time.Hour}
}

func readDev(t *testing.T, dev string) []byte {
	t.Helper()
	b, err := os.ReadFile(dev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// grows reports whether dev gains bytes over d.
func grows(t *testing.T, dev string, d time.Duration) bool {
	before := len(readDev(t, dev))
	time.Sleep(d)
	return len(readDev(t, dev)) > before
}

// A timer nobody left running must not be started by boot: opening a watchdog
// starts it, and a boot that then failed would reboot a host whose previous
// run had disarmed cleanly.
func TestKeepBootAlive_DoesNotOpenATimerThatIsNotRunning(t *testing.T) {
	for _, state := range []string{"inactive", ""} {
		dev := fakeWatchdog(t, state)
		if k := KeepBootAlive(dev, testBootOptions(t)); k != nil {
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
// heartbeat takes the descriptor over; the heartbeat continues on it, and
// reaching it ends the boot streak.
func TestKeepBootAlive_PetsRunningTimerUntilHeartbeatTakesOver(t *testing.T) {
	dev := fakeWatchdog(t, "active")
	o := testBootOptions(t)
	k := KeepBootAlive(dev, o)
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
	if _, ok := readBootStreak(o.RunDir); !ok {
		t.Fatal("the boot was not counted into the streak")
	}

	ctrl := NewController()
	ctrl.SetRunDir(o.RunDir)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	pre := k.Handoff()
	go func() { HeartbeatFrom(ctx, dev, 10*time.Millisecond, ctrl, pre); close(done) }()
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
	if _, ok := readBootStreak(o.RunDir); ok {
		t.Fatal("reaching the heartbeat did not end the boot streak")
	}
}

// Abandon (boot failed or was cancelled before the heartbeat) never disarms
// and stops petting, so the timer runs on from the last pet exactly as the
// previous run left it.
func TestBootKeeper_AbandonLeavesTimerArmed(t *testing.T) {
	dev := fakeWatchdog(t, "active")
	k := KeepBootAlive(dev, testBootOptions(t))
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

// The streak bound: boots that never reach the heartbeat get boot petting at
// most MaxBoots times, and not once the streak is StreakWindow old, so a
// daemon that cannot boot lets the timer fire within the window plus the
// watchdog timeout, whatever systemd's restart pacing.
//
// Mutations: drop either bound in admitBoot and its case goes red.
func TestKeepBootAlive_StreakBound(t *testing.T) {
	t.Run("max boots", func(t *testing.T) {
		dev := fakeWatchdog(t, "active")
		o := testBootOptions(t)
		for i := 1; i <= o.MaxBoots; i++ {
			k := KeepBootAlive(dev, o)
			if k == nil {
				t.Fatalf("boot %d of %d was refused", i, o.MaxBoots)
			}
			k.Abandon()
		}
		if k := KeepBootAlive(dev, o); k != nil {
			k.Abandon()
			t.Fatalf("boot %d was kept alive past boot_keeper_max_boots=%d", o.MaxBoots+1, o.MaxBoots)
		}
	})
	t.Run("window", func(t *testing.T) {
		dev := fakeWatchdog(t, "active")
		o := testBootOptions(t)
		o.StreakWindow = 300 * time.Second
		if err := writeBootStreak(o.RunDir, bootStreak{first: bootClock() - 301*time.Second, count: 1}); err != nil {
			t.Fatal(err)
		}
		if k := KeepBootAlive(dev, o); k != nil {
			k.Abandon()
			t.Fatal("a boot was kept alive in a streak older than boot_keeper_streak_window_sec")
		}
	})
	t.Run("each keeper stops at max duration", func(t *testing.T) {
		dev := fakeWatchdog(t, "active")
		o := testBootOptions(t)
		o.MaxDuration = 50 * time.Millisecond
		k := KeepBootAlive(dev, o)
		if k == nil {
			t.Fatal("refused")
		}
		defer k.Abandon()
		time.Sleep(80 * time.Millisecond)
		if grows(t, dev, 60*time.Millisecond) {
			t.Fatal("the keeper kept petting past boot_keeper_max_sec")
		}
	})
}

// A host that self-fenced reboots: neither boot nor the heartbeat of any
// later run pets its watchdog, and that run trips its controller at once.
//
// Mutations: ignore the marker in KeepBootAlive, or in HeartbeatFrom, and the
// matching case goes red; drop the marker write in SelfFence and the first
// case goes red.
func TestSelfFenceMarker_BlocksPetting(t *testing.T) {
	dev := fakeWatchdog(t, "active")
	o := testBootOptions(t)

	first := NewController()
	first.SetRunDir(o.RunDir)
	first.SelfFence()
	if !SelfFenceMarked(o.RunDir) {
		t.Fatal("SelfFence did not record the marker")
	}

	if k := KeepBootAlive(dev, o); k != nil {
		k.Abandon()
		t.Fatal("boot pets the watchdog of a host that self-fenced")
	}
	if b := readDev(t, dev); len(b) != 0 {
		t.Fatalf("boot wrote %q to the device", b)
	}

	next := NewController()
	next.SetRunDir(o.RunDir)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { HeartbeatFrom(ctx, dev, 10*time.Millisecond, next, nil); close(done) }()
	time.Sleep(60 * time.Millisecond)
	cancel()
	<-done
	if b := readDev(t, dev); len(b) != 0 {
		t.Fatalf("the heartbeat of a run after a self-fence wrote %q (pet or disarm)", b)
	}
	if !next.Fenced() {
		t.Fatal("a run after a self-fence did not trip its controller")
	}
}

// A daemon wedged on its state store stops petting and self-fences; one whose
// round trips complete keeps petting. Likewise the partition pauser's tick.
//
// Mutation: make staleReason return "" and the wedged cases go red.
func TestHeartbeat_LivenessGate(t *testing.T) {
	run := func(t *testing.T, setup func(*Controller)) (string, *Controller) {
		dev := fakeWatchdog(t, "")
		ctrl := NewController()
		ctrl.SetRunDir(t.TempDir())
		ctrl.setStaleAfterForTest(100 * time.Millisecond)
		setup(ctrl)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go HeartbeatFrom(ctx, dev, 10*time.Millisecond, ctrl, nil)
		return dev, ctrl
	}
	t.Run("wedged DB stops petting", func(t *testing.T) {
		block := make(chan struct{})
		t.Cleanup(func() { close(block) })
		dev, ctrl := run(t, func(c *Controller) {
			c.SetDBProbe(func(context.Context) error { <-block; return nil })
		})
		time.Sleep(300 * time.Millisecond)
		if !ctrl.Fenced() {
			t.Fatal("a wedged DB did not self-fence")
		}
		if grows(t, dev, 60*time.Millisecond) {
			t.Fatal("petting continued with the DB wedged")
		}
		if b := readDev(t, dev); bytes.ContainsRune(b, 'V') {
			t.Fatalf("the liveness fence disarmed the watchdog: %q", b)
		}
		if !SelfFenceMarked(ctrl.runDir) {
			t.Fatal("the liveness fence was not recorded for the next run")
		}
	})
	t.Run("live DB keeps petting", func(t *testing.T) {
		dev, ctrl := run(t, func(c *Controller) {
			c.SetDBProbe(func(context.Context) error { return nil })
		})
		time.Sleep(300 * time.Millisecond)
		if ctrl.Fenced() || !grows(t, dev, 60*time.Millisecond) {
			t.Fatal("a live DB stopped petting")
		}
	})
	t.Run("stalled pauser stops petting", func(t *testing.T) {
		at := time.Now()
		_, ctrl := run(t, func(c *Controller) {
			c.SetPauserTick(func() time.Time { return at })
		})
		time.Sleep(300 * time.Millisecond)
		if !ctrl.Fenced() {
			t.Fatal("a pauser that stopped ticking did not self-fence")
		}
	})
	t.Run("pauser not started gates nothing", func(t *testing.T) {
		dev, ctrl := run(t, func(c *Controller) {
			c.SetPauserTick(func() time.Time { return time.Time{} })
		})
		time.Sleep(300 * time.Millisecond)
		if ctrl.Fenced() || !grows(t, dev, 60*time.Millisecond) {
			t.Fatal("a pauser that has not started stopped petting")
		}
	})
}

func TestBootPetInterval_QuarterOfDeviceTimeout(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "watchdog0"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := sysClassWatchdog
	sysClassWatchdog = dir
	t.Cleanup(func() { sysClassWatchdog = old })
	for timeout, want := range map[string]time.Duration{"8": 2 * time.Second, "2": time.Second, "600": defaultInterval} {
		if err := os.WriteFile(filepath.Join(dir, "watchdog0", "timeout"), []byte(timeout+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := bootPetInterval("/nonexistent/watchdog0"); got != want {
			t.Errorf("timeout %s s: interval %v, want %v", timeout, got, want)
		}
	}
	if got := bootPetInterval("/nonexistent/ipmi0"); got != defaultInterval {
		t.Errorf("no node: %v, want %v", got, defaultInterval)
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
