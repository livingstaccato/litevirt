package daemon

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/watchdog"
)

// A previous run left the watchdog timer running (crash, or a stop that held
// workloads). Boot must pet it before any boot step runs and keep petting
// through a slow step, and a failing boot must leave it armed, never disarmed.
// Restoring the old order (boot first, heartbeat later) lets the previous
// run's timer fire during a slow or failing boot and reboot the host.
func TestBootUnderWatchdog_PetsBeforeAndThroughSlowFailingBoot(t *testing.T) {
	const interval = 10 * time.Millisecond
	dev := filepath.Join(t.TempDir(), "watchdog0")
	if err := os.WriteFile(dev, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	read := func() []byte {
		b, err := os.ReadFile(dev)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	bootErr := errors.New("init schema: database or disk is full")
	var atStart, atEnd int
	_, err := bootUnderWatchdog(
		func() *watchdog.BootKeeper { return watchdog.KeepBootAliveRunning(dev, interval, time.Hour) },
		func(*watchdog.BootKeeper) (*Daemon, error) {
			atStart = len(read())
			time.Sleep(10 * interval) // a slow boot step
			atEnd = len(read())
			return nil, bootErr
		},
	)
	if !errors.Is(err, bootErr) {
		t.Fatalf("err = %v, want the boot error", err)
	}
	if atStart < 1 {
		t.Fatalf("the watchdog was not petted before the first boot step (%d keepalives)", atStart)
	}
	if atEnd-atStart < 3 {
		t.Fatalf("the watchdog was not kept petted through a slow boot step (%d -> %d keepalives)", atStart, atEnd)
	}
	final := read()
	if bytes.ContainsRune(final, 'V') {
		t.Fatalf("a failed boot disarmed the watchdog: %q", final)
	}
	time.Sleep(4 * interval)
	if got := read(); len(got) != len(final) {
		t.Fatalf("petting continued after the failed boot returned: %d -> %d", len(final), len(got))
	}
}

// A Run that returns before the heartbeat starts must abandon the boot
// keeper: its petting stops and the timer runs on from the last pet, as the
// previous run left it. A Run that kept petting from a dead daemon would hold
// a host up that nothing manages.
//
// Mutation: drop Run's deferred Abandon and petting goes on after Run returns.
func TestRun_FailingEarlyAbandonsTheBootKeeper(t *testing.T) {
	const interval = 10 * time.Millisecond
	dev := filepath.Join(t.TempDir(), "watchdog0")
	if err := os.WriteFile(dev, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{DataDir: t.TempDir()}
	cfg.Migration.Network = "not-a-network" // the first boot step that can fail
	d := &Daemon{cfg: cfg, bootWatchdog: watchdog.KeepBootAliveRunning(dev, interval, time.Hour)}
	if err := d.Run(context.Background()); err == nil {
		t.Fatal("Run with an invalid migration.network returned nil")
	}
	after, _ := os.ReadFile(dev)
	time.Sleep(6 * interval)
	if got, _ := os.ReadFile(dev); len(got) != len(after) {
		t.Fatalf("boot petting went on after Run returned: %d -> %d keepalives", len(after), len(got))
	}
	if d.bootWatchdog.Handoff() != nil {
		t.Fatal("the keeper still holds its descriptor after Run returned")
	}
}
