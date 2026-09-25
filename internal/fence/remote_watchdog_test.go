package fence

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A watchdog fence is a SELF-fence. Dispatching it at a remote host arms the
// wrong machine and calls it a verified power-off.
//
// fenceWatchdog opens WatchdogDev on the CALLING node and closes it without the
// magic-close byte, then reports Success: true with "system will reboot". The
// failover coordinator hands the FAILED REMOTE host's HostConfig to this same
// generic fencer, so for a remote target with fence_strategy = watchdog it
// either arms the coordinator's own hardware watchdog -- rebooting a healthy
// node that is mid-recovery -- or fails on a missing device. In the first case
// the coordinator then treats a started LOCAL countdown as proof the REMOTE
// host is off, and reschedules its VMs onto shared storage the original may
// still be writing to.
func TestExecute_RefusesAWatchdogFenceAimedAtAnotherHost(t *testing.T) {
	// A WRITABLE file stands in for /dev/watchdog. A path that does not exist
	// would make this pass for the wrong reason -- the open fails and Success is
	// false whatever the dispatch did -- and the hazard only exists on a host
	// that HAS a watchdog device. An openable path reproduces it portably.
	dev := filepath.Join(t.TempDir(), "watchdog")
	if err := os.WriteFile(dev, nil, 0o600); err != nil {
		t.Fatalf("seed fake watchdog device: %v", err)
	}

	res := Execute(context.Background(), HostConfig{
		Name:          "node-b",
		FenceStrategy: "watchdog",
		WatchdogDev:   dev,
		// IsSelf deliberately left false: the coordinator is fencing a peer.
	})

	if res.Success {
		t.Fatalf("a watchdog fence aimed at a remote host reported Success=true (%q); the "+
			"coordinator reads that as a verified power-off and reschedules the host's VMs "+
			"while it may still be running", res.Detail)
	}
	if !strings.Contains(strings.ToLower(res.Detail), "self") {
		t.Errorf("Detail = %q; it must say the strategy is self-only, or an operator cannot "+
			"tell this from a device that was merely missing", res.Detail)
	}
}

// The local case still has to work, or a node can no longer self-fence.
//
// The device is absent here, so this asserts the REFUSAL is not what happened:
// a self-fence reaching the open() is the behaviour being preserved, and its
// failure names the device rather than the dispatch.
func TestExecute_SelfWatchdogStillReachesTheDevice(t *testing.T) {
	res := Execute(context.Background(), HostConfig{
		Name:          "node-a",
		FenceStrategy: "watchdog",
		WatchdogDev:   "/dev/does-not-exist",
		IsSelf:        true,
	})

	if res.Method != "watchdog" {
		t.Fatalf("Method = %q, want watchdog: a self-fence must still dispatch to the watchdog", res.Method)
	}
	if strings.Contains(strings.ToLower(res.Detail), "self-only") {
		t.Fatalf("a self-targeted watchdog fence was refused as remote: %q", res.Detail)
	}
	if !strings.Contains(res.Detail, "/dev/does-not-exist") {
		t.Errorf("Detail = %q, want it to name the device it could not open", res.Detail)
	}
}

// Every other strategy is unaffected: this narrows watchdog alone, and a
// remote IPMI or SSH fence is exactly what the coordinator should be doing.
func TestExecute_RemoteNonWatchdogStrategiesAreUnaffected(t *testing.T) {
	res := Execute(context.Background(), HostConfig{
		Name:          "node-b",
		FenceStrategy: "manual",
	})
	if res.Method != "manual" {
		t.Errorf("Method = %q, want manual; the refusal must not have swallowed other strategies", res.Method)
	}
}
