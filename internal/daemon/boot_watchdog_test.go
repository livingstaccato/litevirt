package daemon

import (
	"bytes"
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
		func() *watchdog.BootKeeper { return watchdog.KeepBootAliveRunning(dev, interval) },
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
