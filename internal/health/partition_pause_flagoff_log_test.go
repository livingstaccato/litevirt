package health

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/testkit/slogtest"
)

// capturePauseLogs routes slog through a buffer for the test and returns the
// partition-pause lines logged so far.
func capturePauseLogs(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var buf bytes.Buffer
	slogtest.Swap(t, slog.New(slog.NewTextHandler(&lockedWriter{mu: &mu, w: &buf}, nil)))
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		var out []string
		for _, l := range strings.Split(buf.String(), "\n") {
			if strings.Contains(l, "partition-pause:") {
				out = append(out, l)
			}
		}
		return out
	}
}

// TestPartitionPause_FlagOffDoesNotAnnounceAPause: with
// enforcement.partition_pause false the host pauses nothing
// (docs/design/partition-pause.md §5, "a host whose flag is off pauses
// nothing"), so it must not log that it is about to. On the kvm003 lab (drill
// 4, main-b3368d7c) node-4 with the flag off logged "pausing recoverable
// workloads if it does not return" on losing the majority while its VM and
// container ran on untouched — the line read as the pause acting. It now says
// the flag is off, once per loss.
//
// Mutation: log the pausing line whatever the flag — red on the first check;
// drop the flag-off line — red on the second.
func TestPartitionPause_FlagOffDoesNotAnnounceAPause(t *testing.T) {
	logs := capturePauseLogs(t)
	f := newPauseFixture(t)
	f.p.SetEnabled(func() bool { return false })
	f.loseFor(QuorumNo, 2*PartitionPauseAfter)
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s with enforcement.partition_pause off", st)
	}
	var off int
	for _, l := range logs() {
		if strings.Contains(l, "pausing recoverable workloads") {
			t.Fatalf("a host with the flag off announced a pause: %s", l)
		}
		if strings.Contains(l, "enforcement.partition_pause is off") {
			off++
		}
	}
	if off != 1 {
		t.Fatalf("the flag-off line was logged %d times over one loss, want once: %q", off, logs())
	}

	// With the flag on, the announcement is unchanged.
	f.regain()
	f.p.SetEnabled(func() bool { return true })
	f.loseFor(QuorumNo, time.Second)
	var on int
	for _, l := range logs() {
		if strings.Contains(l, "pausing recoverable workloads") {
			on++
		}
	}
	if on != 1 {
		t.Fatalf("the pausing line was logged %d times with the flag on, want once", on)
	}
}
