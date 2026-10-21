package watchdog

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
// And it is bounded (BootOptions), so a daemon that cannot finish booting does
// not keep a host up for ever: a boot that hangs stops petting after
// MaxDuration, and a streak of boots that never reach Heartbeat stops after
// MaxBoots or StreakWindow, whichever comes first. The timer a previous run
// left running then fires, as it did before the keeper, at most StreakWindow
// plus the watchdog timeout after the first such boot. A host that
// self-fenced is never petted at all (SelfFenceMarked).
//
// The zero value and a nil *BootKeeper are inert.
type BootKeeper struct {
	devPath string

	mu   sync.Mutex
	f    *os.File
	stop chan struct{}
	done chan struct{}
}

// BootOptions bounds a BootKeeper (config watchdog.boot_keeper_*).
type BootOptions struct {
	// RunDir holds the self-fence marker and the boot streak. It must be a
	// tmpfs (/run/litevirt) so a reboot clears both. Empty: no marker is read
	// and no streak is kept, which disables the keeper.
	RunDir string
	// Configured is true when watchdog_dev names the device explicitly; only
	// then is a device that cannot be opened an Error.
	Configured bool
	// StreakWindow, MaxBoots and MaxDuration: see BootKeeper. Zero in any
	// disables the keeper.
	StreakWindow time.Duration
	MaxBoots     int
	MaxDuration  time.Duration
}

// RunDir is where the daemon keeps the watchdog's state across its own
// restarts and no longer: /run is a tmpfs, emptied by a reboot.
const RunDir = "/run/litevirt"

const (
	selfFenceMarkerName = "self-fenced"
	bootStreakName      = "watchdog-boot-streak"
)

// SelfFenceMarked reports whether a run of this daemon since the host last
// booted self-fenced. Such a host must reboot: nothing pets its watchdog
// again until the reboot clears /run. Empty runDir: never.
func SelfFenceMarked(runDir string) bool {
	if runDir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(runDir, selfFenceMarkerName))
	return err == nil
}

// markSelfFenced records the self-fence for every later run until the host
// reboots. Best effort: a run that cannot write it still stops petting.
func markSelfFenced(runDir, why string) {
	if runDir == "" {
		return
	}
	if err := os.MkdirAll(runDir, 0o755); err == nil {
		err = os.WriteFile(filepath.Join(runDir, selfFenceMarkerName),
			[]byte(fmt.Sprintf("%s %s\n", wallNow().UTC().Format(time.RFC3339), why)), 0o644)
		if err == nil {
			return
		}
		slog.Error("watchdog: could not record the self-fence; a restarted daemon would pet the watchdog again",
			"dir", runDir, "error", err)
		return
	}
	slog.Error("watchdog: could not create the run directory for the self-fence marker", "dir", runDir)
}

// bootStreak is the boots since the last one that reached Heartbeat: when the
// first of them started (CLOCK_BOOTTIME) and how many there were.
type bootStreak struct {
	first time.Duration
	count int
}

func readBootStreak(runDir string) (bootStreak, bool) {
	b, err := os.ReadFile(filepath.Join(runDir, bootStreakName))
	if err != nil {
		return bootStreak{}, false
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return bootStreak{}, false
	}
	first, err1 := strconv.ParseInt(f[0], 10, 64)
	count, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil {
		return bootStreak{}, false
	}
	return bootStreak{first: time.Duration(first), count: count}, true
}

func writeBootStreak(runDir string, s bootStreak) error {
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(runDir, bootStreakName),
		[]byte(fmt.Sprintf("%d %d\n", int64(s.first), s.count)), 0o644)
}

// clearBootStreak ends the streak: this run reached Heartbeat.
func clearBootStreak(runDir string) {
	if runDir == "" {
		return
	}
	if err := os.Remove(filepath.Join(runDir, bootStreakName)); err != nil && !os.IsNotExist(err) {
		slog.Warn("watchdog: could not clear the boot streak", "dir", runDir, "error", err)
	}
}

// admitBoot counts this boot into the streak and reports whether the keeper
// may still pet. A streak it cannot record is refused: an unbounded keeper is
// the one thing this exists to prevent.
func admitBoot(o BootOptions) (bool, string) {
	now := bootClock()
	s, ok := readBootStreak(o.RunDir)
	if !ok || s.first > now {
		s = bootStreak{first: now}
	}
	s.count++
	if err := writeBootStreak(o.RunDir, s); err != nil {
		return false, "the boot streak cannot be recorded: " + err.Error()
	}
	if age := now - s.first; age >= o.StreakWindow {
		return false, fmt.Sprintf("boots have failed to reach the heartbeat for %s (limit %s)", age.Round(time.Second), o.StreakWindow)
	}
	if s.count > o.MaxBoots {
		return false, fmt.Sprintf("this is boot %d without reaching the heartbeat (limit %d)", s.count, o.MaxBoots)
	}
	return true, ""
}

// sysClassWatchdog is where the watchdog core publishes each device's state.
var sysClassWatchdog = "/sys/class/watchdog"

var watchdogNodeName = regexp.MustCompile(`^watchdog[0-9]+$`)

// sysNode names the device's directory under /sys/class/watchdog, or "" when
// the path names no watchdog node. The legacy /dev/watchdog is watchdog0.
func sysNode(devPath string) string {
	name := filepath.Base(devPath)
	if resolved, err := filepath.EvalSymlinks(devPath); err == nil {
		name = filepath.Base(resolved)
	}
	if name == "watchdog" {
		name = "watchdog0"
	}
	if !watchdogNodeName.MatchString(name) {
		return ""
	}
	return name
}

// timerRunning reports whether the kernel says the device's timer is running.
// known=false when that cannot be read: a legacy non-framework driver
// (ipmi_watchdog), a kernel without CONFIG_WATCHDOG_SYSFS, or a path that does
// not name a watchdog node.
func timerRunning(devPath string) (running, known bool) {
	name := sysNode(devPath)
	if name == "" {
		return false, false
	}
	b, err := os.ReadFile(filepath.Join(sysClassWatchdog, name, "state"))
	if err != nil {
		return false, false
	}
	return strings.TrimSpace(string(b)) == "active", true
}

// bootPetIntervalFn is bootPetInterval; tests shorten it.
var bootPetIntervalFn = bootPetInterval

// bootPetInterval pets at a quarter of the timeout the device reports, which
// may be the firmware's own and shorter than Heartbeat's, and never less
// often than Heartbeat does.
func bootPetInterval(devPath string) time.Duration {
	name := sysNode(devPath)
	if name == "" {
		return defaultInterval
	}
	b, err := os.ReadFile(filepath.Join(sysClassWatchdog, name, "timeout"))
	if err != nil {
		return defaultInterval
	}
	secs, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || secs <= 0 {
		return defaultInterval
	}
	d := time.Duration(secs) * time.Second / 4
	if d < time.Second {
		d = time.Second
	}
	if d > defaultInterval {
		d = defaultInterval
	}
	return d
}

// KeepBootAlive opens and pets the watchdog at devPath (the default device when
// empty, as Heartbeat does) if, and only if, the kernel reports its timer
// already running, this host has not self-fenced, and the boot streak is
// within its bounds; it keeps petting until Handoff, Abandon or
// o.MaxDuration. It returns nil when there is nothing to keep alive. Call it
// before any boot work that can be slow or fail.
func KeepBootAlive(devPath string, o BootOptions) *BootKeeper {
	if devPath == "" {
		devPath = defaultDev
	}
	if o.RunDir == "" || o.StreakWindow <= 0 || o.MaxBoots <= 0 || o.MaxDuration <= 0 {
		return nil
	}
	if SelfFenceMarked(o.RunDir) {
		slog.Error("watchdog: this host self-fenced since it last booted; boot does not pet the watchdog, and the host reboots at its timeout",
			"dev", devPath, "marker", filepath.Join(o.RunDir, selfFenceMarkerName))
		return nil
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
	if ok, why := admitBoot(o); !ok {
		slog.Error("watchdog: boot no longer pets the timer a previous run left running; the host reboots at its timeout unless this boot reaches the heartbeat first",
			"dev", devPath, "reason", why)
		return nil
	}
	return keepBootAlive(devPath, bootPetIntervalFn(devPath), o.MaxDuration, o.Configured)
}

// KeepBootAliveRunning is KeepBootAlive for a caller that already knows the
// timer is running and is within its bounds. It skips every check, so a
// caller that is wrong starts a timer nobody asked for; production goes
// through KeepBootAlive.
func KeepBootAliveRunning(devPath string, interval, maxDuration time.Duration) *BootKeeper {
	return keepBootAlive(devPath, interval, maxDuration, true)
}

func keepBootAlive(devPath string, interval, maxDuration time.Duration, configured bool) *BootKeeper {
	if interval <= 0 {
		interval = defaultInterval
	}
	f, err := os.OpenFile(devPath, os.O_WRONLY, 0)
	if err != nil {
		log := slog.Debug // auto mode: systemd's RuntimeWatchdogSec may hold it
		if configured {
			log = slog.Error
		}
		log("watchdog: the timer a previous run left armed is running, but the device cannot be opened to pet it during boot; "+
			"a boot slower than the remaining timeout reboots this host",
			"dev", devPath, "error", err)
		return nil
	}
	k := &BootKeeper{devPath: devPath, f: f, stop: make(chan struct{}), done: make(chan struct{})}
	if err := petFile(f); err != nil {
		slog.Error("watchdog: boot keepalive failed", "dev", devPath, "error", err)
	}
	slog.Info("watchdog: a previous run left the timer running; petting it through boot",
		"dev", devPath, "interval", interval, "at_most", maxDuration)
	go k.loop(f, interval, maxDuration)
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
func (k *BootKeeper) loop(f *os.File, interval, maxDuration time.Duration) {
	defer close(k.done)
	t := time.NewTicker(interval)
	defer t.Stop()
	expire := time.NewTimer(maxDuration)
	defer expire.Stop()
	for {
		select {
		case <-k.stop:
			return
		case <-expire.C:
			slog.Error("watchdog: boot has not reached the heartbeat; it stops petting, and the host reboots at the watchdog timeout unless it does",
				"dev", k.devPath, "after", maxDuration)
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
// (HeartbeatFrom). Nil when there is none or it was already taken. Call it
// synchronously before starting the heartbeat goroutine, so a Run that
// returns at once cannot Abandon the descriptor out from under it.
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
