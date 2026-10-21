package watchdog

import (
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// BootKeeper keeps a watchdog that is ALREADY RUNNING petted while the daemon
// boots, until Heartbeat takes the descriptor over.
//
// A previous run can leave the timer counting: a crash or OOM kill closes the
// descriptor without the magic 'V', which a WDIOF_MAGICCLOSE or nowayout driver
// (i6300esb, iTCO) does not treat as a stop, and a stop that abandons running
// workloads leaves it armed on purpose (Controller.SetOwnershipCheck). The timer
// then runs from that run's last pet. Heartbeat used to open the device only
// after the state store, schema, boot writes and much else, so a boot that was
// slow, or that failed and was restarted by systemd, let that timer fire and
// rebooted the host with every VM on it.
//
// The keeper changes WHEN the timer is petted, never WHETHER it runs:
//   - it opens the device only when the kernel reports the timer active, so it
//     never starts a timer a previous run disarmed;
//   - it never disarms: Abandon leaves the device exactly as armed as it was;
//   - it hands the same descriptor to Heartbeat, which applies every rule it
//     always did (arm, verify, ownership-gated disarm, self-fence).
//
// The zero value and a nil *BootKeeper are inert.
type BootKeeper struct {
	devPath string

	mu   sync.Mutex
	f    *os.File
	stop chan struct{}
	done chan struct{}
}

// sysClassWatchdog is where the watchdog core publishes each device's state.
var sysClassWatchdog = "/sys/class/watchdog"

var watchdogNodeName = regexp.MustCompile(`^watchdog[0-9]+$`)

// timerRunning reports whether the kernel says the device's timer is running.
// known=false when that cannot be read: a legacy non-framework driver
// (ipmi_watchdog), a kernel without CONFIG_WATCHDOG_SYSFS, or a path that does
// not name a watchdog node. The legacy /dev/watchdog is always watchdog0.
func timerRunning(devPath string) (running, known bool) {
	name := filepath.Base(devPath)
	if resolved, err := filepath.EvalSymlinks(devPath); err == nil {
		name = filepath.Base(resolved)
	}
	if name == "watchdog" {
		name = "watchdog0"
	}
	if !watchdogNodeName.MatchString(name) {
		return false, false
	}
	b, err := os.ReadFile(filepath.Join(sysClassWatchdog, name, "state"))
	if err != nil {
		return false, false
	}
	return strings.TrimSpace(string(b)) == "active", true
}

// KeepBootAlive opens and pets the watchdog at devPath (the default device when
// empty, as Heartbeat does) if, and only if, the kernel reports its timer
// already running, and keeps petting it every interval until Handoff or
// Abandon. It returns nil when there is nothing to keep alive. Call it before
// any boot work that can be slow or fail.
func KeepBootAlive(devPath string, interval time.Duration) *BootKeeper {
	if devPath == "" {
		devPath = defaultDev
	}
	running, known := timerRunning(devPath)
	switch {
	case !known:
		slog.Debug("watchdog: cannot tell whether the timer is running; it is opened at the usual point of boot",
			"dev", devPath)
		return nil
	case !running:
		return nil
	}
	return KeepBootAliveRunning(devPath, interval)
}

// KeepBootAliveRunning is KeepBootAlive for a caller that already knows the
// timer is running. It skips the kernel state check, so a caller that is wrong
// starts a timer nobody asked for; production goes through KeepBootAlive.
func KeepBootAliveRunning(devPath string, interval time.Duration) *BootKeeper {
	if interval <= 0 {
		interval = defaultInterval
	}
	f, err := os.OpenFile(devPath, os.O_WRONLY, 0)
	if err != nil {
		slog.Error("watchdog: the timer a previous run left armed is running, but the device cannot be opened to pet it during boot; "+
			"a boot slower than the remaining timeout reboots this host",
			"dev", devPath, "error", err)
		return nil
	}
	k := &BootKeeper{devPath: devPath, f: f, stop: make(chan struct{}), done: make(chan struct{})}
	if err := petFile(f); err != nil {
		slog.Error("watchdog: boot keepalive failed", "dev", devPath, "error", err)
	}
	slog.Info("watchdog: a previous run left the timer running; petting it through boot", "dev", devPath, "interval", interval)
	go k.loop(f, interval)
	return k
}

// petFile resets the timer by the ioctl, falling back to the keepalive byte,
// the same choice Heartbeat makes.
func petFile(f *os.File) error {
	if err := petWatchdog(f.Fd()); err == nil {
		return nil
	}
	_, err := f.Write([]byte{keepaliveByte})
	return err
}

// loop is given f rather than reading k.f, which take clears under k.mu.
func (k *BootKeeper) loop(f *os.File, interval time.Duration) {
	defer close(k.done)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-k.stop:
			return
		case <-t.C:
			if err := petFile(f); err != nil {
				slog.Error("watchdog: boot keepalive failed", "dev", k.devPath, "error", err)
			}
		}
	}
}

// take stops the petting goroutine and returns the descriptor, at most once.
func (k *BootKeeper) take() *os.File {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	f := k.f
	if f == nil {
		return nil
	}
	k.f = nil
	close(k.stop)
	<-k.done
	return f
}

// Handoff stops boot petting and returns the open descriptor for Heartbeat
// (HeartbeatFrom). Nil when there is none or it was already taken.
func (k *BootKeeper) Handoff() *os.File { return k.take() }

// Abandon ends boot petting without handing over, because boot failed or was
// cancelled before Heartbeat started. The timer is left running from the last
// pet, exactly as the previous run left it: boot petting only ever bought time,
// and giving it back must not cost the guarantee that timer carried. No-op after
// Handoff.
func (k *BootKeeper) Abandon() {
	f := k.take()
	if f == nil {
		return
	}
	leaveArmed(f, k.devPath, "watchdog left ARMED: boot ended before the heartbeat started; "+
		"a successor daemon must resume petting before the timeout or the host reboots", false)
}
