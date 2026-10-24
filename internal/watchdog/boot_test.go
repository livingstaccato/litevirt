package watchdog

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
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

// verifiedDevice makes HeartbeatFrom treat the fake device as a verified,
// counting hardware watchdog, so the liveness gate applies.
func verifiedDevice(t *testing.T) {
	oldHW, oldLeft := isHardwareWatchdogFn, watchdogTimeLeftFn
	isHardwareWatchdogFn = func(uintptr) (bool, string) { return true, "test watchdog" }
	watchdogTimeLeftFn = func(uintptr) (int, bool) { return 60, true }
	t.Cleanup(func() { isHardwareWatchdogFn, watchdogTimeLeftFn = oldHW, oldLeft })
}

// runGate runs a heartbeat on a fake device with a 100 ms liveness threshold.
func runGate(t *testing.T, dev string, setup func(*Controller)) *Controller {
	ctrl := NewController()
	ctrl.SetRunDir(t.TempDir())
	ctrl.SetLivenessStale(100 * time.Millisecond)
	setup(ctrl)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); <-done })
	go func() { HeartbeatFrom(ctx, dev, 10*time.Millisecond, ctrl, nil); close(done) }()
	return ctrl
}

// counter is a progress counter a test moves.
type counter struct{ n atomic.Uint64 }

func (c *counter) tick(ctx context.Context, every time.Duration) {
	for {
		c.n.Add(1)
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// A daemon wedged on its state store, or whose pauser stops making progress,
// stops petting and self-fences on a verified watchdog; one that keeps making
// progress keeps petting.
//
// Mutation: make check return "" and the wedged cases go red.
func TestHeartbeat_LivenessGate(t *testing.T) {
	t.Run("wedged DB stops petting", func(t *testing.T) {
		verifiedDevice(t)
		dev := fakeWatchdog(t, "")
		block := make(chan struct{})
		t.Cleanup(func() { close(block) })
		ctrl := runGate(t, dev, func(c *Controller) {
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
		if !SelfFenceMarked(ctrl.RunDir()) {
			t.Fatal("the liveness fence was not recorded for the next run")
		}
	})
	t.Run("live DB keeps petting", func(t *testing.T) {
		verifiedDevice(t)
		dev := fakeWatchdog(t, "")
		ctrl := runGate(t, dev, func(c *Controller) {
			c.SetDBProbe(func(context.Context) error { return nil })
		})
		time.Sleep(300 * time.Millisecond)
		if ctrl.Fenced() || !grows(t, dev, 60*time.Millisecond) {
			t.Fatal("a live DB stopped petting")
		}
	})
	t.Run("stalled pauser stops petting", func(t *testing.T) {
		verifiedDevice(t)
		ctrl := runGate(t, fakeWatchdog(t, ""), func(c *Controller) {
			c.SetPauserProgress(func() uint64 { return 7 })
		})
		time.Sleep(300 * time.Millisecond)
		if !ctrl.Fenced() {
			t.Fatal("a pauser that stopped making progress did not self-fence")
		}
	})
	t.Run("moving pauser keeps petting", func(t *testing.T) {
		verifiedDevice(t)
		var c counter
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go c.tick(ctx, 20*time.Millisecond)
		dev := fakeWatchdog(t, "")
		ctrl := runGate(t, dev, func(ctrl *Controller) { ctrl.SetPauserProgress(c.n.Load) })
		time.Sleep(300 * time.Millisecond)
		if ctrl.Fenced() || !grows(t, dev, 60*time.Millisecond) {
			t.Fatal("a pauser making progress stopped petting")
		}
	})
	// Both counters wired, as the daemon wires them. Either one stalling must
	// fence on its own; a "both must stall" gate keeps petting these.
	//
	// Mutation: make check fence only when BOTH the DB and the pauser are
	// stalled, and the two "must self-fence" cases go red.
	t.Run("both wired: wedged DB with a moving pauser self-fences", func(t *testing.T) {
		verifiedDevice(t)
		var c counter
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go c.tick(ctx, 20*time.Millisecond)
		block := make(chan struct{})
		t.Cleanup(func() { close(block) })
		ctrl := runGate(t, fakeWatchdog(t, ""), func(ctrl *Controller) {
			ctrl.SetDBProbe(func(context.Context) error { <-block; return nil })
			ctrl.SetPauserProgress(c.n.Load)
		})
		time.Sleep(300 * time.Millisecond)
		if !ctrl.Fenced() {
			t.Fatal("a wedged DB with a moving pauser did not self-fence")
		}
	})
	t.Run("both wired: live DB with a stalled pauser self-fences", func(t *testing.T) {
		verifiedDevice(t)
		ctrl := runGate(t, fakeWatchdog(t, ""), func(ctrl *Controller) {
			ctrl.SetDBProbe(func(context.Context) error { return nil })
			ctrl.SetPauserProgress(func() uint64 { return 7 })
		})
		time.Sleep(300 * time.Millisecond)
		if !ctrl.Fenced() {
			t.Fatal("a live DB with a stalled pauser did not self-fence")
		}
	})
	t.Run("both wired: both moving keeps petting", func(t *testing.T) {
		verifiedDevice(t)
		var c counter
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go c.tick(ctx, 20*time.Millisecond)
		dev := fakeWatchdog(t, "")
		ctrl := runGate(t, dev, func(ctrl *Controller) {
			ctrl.SetDBProbe(func(context.Context) error { return nil })
			ctrl.SetPauserProgress(c.n.Load)
		})
		time.Sleep(300 * time.Millisecond)
		if ctrl.Fenced() || !grows(t, dev, 60*time.Millisecond) {
			t.Fatal("a live DB and a moving pauser stopped petting")
		}
	})
	t.Run("pauser not started gates nothing", func(t *testing.T) {
		verifiedDevice(t)
		dev := fakeWatchdog(t, "")
		ctrl := runGate(t, dev, func(c *Controller) {
			c.SetPauserProgress(func() uint64 { return 0 })
		})
		time.Sleep(300 * time.Millisecond)
		if ctrl.Fenced() || !grows(t, dev, 60*time.Millisecond) {
			t.Fatal("a pauser that has not started stopped petting")
		}
	})
	t.Run("threshold off gates nothing", func(t *testing.T) {
		verifiedDevice(t)
		dev := fakeWatchdog(t, "")
		block := make(chan struct{})
		t.Cleanup(func() { close(block) })
		ctrl := runGate(t, dev, func(c *Controller) {
			c.SetLivenessStale(0) // watchdog.liveness_stale_sec: 0
			c.SetDBProbe(func(context.Context) error { <-block; return nil })
		})
		if _, _, stale := ctrl.LivenessWiring(); stale >= 0 {
			t.Fatalf("liveness_stale_sec 0 left the gate on, at %s", stale)
		}
		time.Sleep(300 * time.Millisecond)
		if ctrl.Fenced() {
			t.Fatal("the gate fired with liveness_stale_sec 0")
		}
	})
}

// N3: the gate applies only on a configured, verified, armed watchdog, the
// condition under which the pauser and the VIP demoter self-fence. An
// unverified device (softdog, a BMC that never starts its timer) and auto
// mode (watchdog_dev empty) keep petting a wedged daemon, as before the gate.
//
// Mutations: drop "configured" or "ctrl.Armed()" from the gate's condition in
// HeartbeatFrom, and the matching case goes red.
func TestHeartbeat_LivenessGateOnlyOnAVerifiedConfiguredWatchdog(t *testing.T) {
	wedged := func(t *testing.T) func(*Controller) {
		block := make(chan struct{})
		t.Cleanup(func() { close(block) })
		return func(c *Controller) { c.SetDBProbe(func(context.Context) error { <-block; return nil }) }
	}
	t.Run("unverified device", func(t *testing.T) {
		dev := fakeWatchdog(t, "") // a regular file: no hardware identity
		ctrl := runGate(t, dev, wedged(t))
		time.Sleep(300 * time.Millisecond)
		if ctrl.Fenced() || !grows(t, dev, 60*time.Millisecond) {
			t.Fatal("the gate fired on an unverified watchdog")
		}
	})
	t.Run("auto mode", func(t *testing.T) {
		verifiedDevice(t)
		dev := fakeWatchdog(t, "")
		old := defaultDev
		defaultDev = dev
		t.Cleanup(func() { defaultDev = old })
		ctrl := runGate(t, "", wedged(t))
		time.Sleep(300 * time.Millisecond)
		if ctrl.Fenced() || !grows(t, dev, 60*time.Millisecond) {
			t.Fatal("the gate fired in auto mode (watchdog_dev empty)")
		}
	})
}

// N1: a forward step of the wall clock larger than the threshold (an NTP step
// at boot, a bad RTC, date -s) is not a wedge. The gate times its counters on
// the monotonic clock and never reads the wall clock.
//
// Mutation: time the gate with wallNow instead of monoNow and this goes red.
func TestHeartbeat_LivenessGateIgnoresWallClockSteps(t *testing.T) {
	verifiedDevice(t)
	var step atomic.Int64
	oldWall := wallNow
	wallNow = func() time.Time { return time.Now().Add(time.Duration(step.Load())) }
	t.Cleanup(func() { wallNow = oldWall })
	var c counter
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// The counter moves well inside the threshold, but not on every check,
	// so a step between two checks lands while it stands still.
	go c.tick(ctx, 100*time.Millisecond)
	dev := fakeWatchdog(t, "")
	ctrl := runGate(t, dev, func(ctrl *Controller) {
		ctrl.SetLivenessStale(400 * time.Millisecond)
		ctrl.SetPauserProgress(c.n.Load)
	})
	time.Sleep(150 * time.Millisecond)
	step.Store(int64(10 * time.Minute)) // the wall clock jumps 10 minutes ahead
	time.Sleep(400 * time.Millisecond)
	if ctrl.Fenced() || !grows(t, dev, 60*time.Millisecond) {
		t.Fatal("a forward wall-clock step self-fenced a live daemon")
	}
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
