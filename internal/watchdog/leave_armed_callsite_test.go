package watchdog

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/testkit/slogtest"
)

// recordingHandler keeps every slog record so a test can read back what the
// operator would have been told.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

// leftArmed returns the attrs of the one "left ARMED" record Heartbeat logged.
func (h *recordingHandler) leftArmed(t *testing.T) map[string]slog.Value {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	var found []map[string]slog.Value
	for _, r := range h.records {
		attrs := map[string]slog.Value{}
		r.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value
			return true
		})
		if _, ok := attrs["reboot_guaranteed"]; ok {
			found = append(found, attrs)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one left-ARMED record carrying reboot_guaranteed, got %d", len(found))
	}
	return found[0]
}

func captureSlog(t *testing.T) *recordingHandler {
	t.Helper()
	h := &recordingHandler{}
	slogtest.Swap(t, slog.New(h))
	return h
}

func runHeartbeatUntil(t *testing.T, ctrl *Controller, stop func(context.CancelFunc)) {
	t.Helper()
	// A regular file stands in for the device. Its WDIOC_GETSUPPORT fails, so
	// the driver's MAGICCLOSE flag is unknown and the descriptor is RETAINED,
	// which is the case armedGuarantee exists to distinguish.
	dev := filepath.Join(t.TempDir(), "fake-watchdog")
	if err := os.WriteFile(dev, nil, 0o600); err != nil {
		t.Fatalf("create fake watchdog: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		Heartbeat(ctx, dev, 10*time.Second, ctrl)
		close(done)
	}()
	stop(cancel)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Heartbeat did not return")
	}
}

// TestHeartbeat_ShutdownWithWorkloads_DoesNotPromiseReboot pins the CALL SITE
// of armedGuarantee on the shutdown-with-workloads path, not just the helper.
//
// That path leaves the device armed and then daemon.Run returns, so the process
// exits and the kernel closes the retained descriptor. On a driver without
// WDIOF_MAGICCLOSE that close stops the timer, so the log must not claim the
// reboot is guaranteed. TestArmedGuarantee covers the decision table; only a
// test that drives Heartbeat notices if this caller passes processSurvives=true.
func TestHeartbeat_ShutdownWithWorkloads_DoesNotPromiseReboot(t *testing.T) {
	h := captureSlog(t)
	ctrl := NewController()
	ctrl.SetOwnershipCheck(func() bool { return true })

	runHeartbeatUntil(t, ctrl, func(cancel context.CancelFunc) { cancel() })

	attrs := h.leftArmed(t)
	if got := attrs["descriptor"].String(); got != "retained" {
		t.Fatalf("descriptor = %q, want retained (a regular file has no readable MAGICCLOSE flag)", got)
	}
	if attrs["reboot_guaranteed"].Bool() {
		t.Fatal("the shutdown-with-workloads path claimed a guaranteed reboot while the process " +
			"is about to exit and the kernel will close the retained descriptor; on a " +
			"non-MAGICCLOSE driver that close stops the timer")
	}
	if _, ok := attrs["caveat"]; !ok {
		t.Error("an unguaranteed reboot must carry the caveat telling the operator to drain instead")
	}
}

// TestHeartbeat_SelfFence_PromisesReboot is the other caller. The daemon keeps
// running after a self-fence until the watchdog resets it, so the retained
// descriptor really does stay open and the reboot is guaranteed.
func TestHeartbeat_SelfFence_PromisesReboot(t *testing.T) {
	h := captureSlog(t)
	ctrl := NewController()

	runHeartbeatUntil(t, ctrl, func(context.CancelFunc) { ctrl.SelfFence() })

	attrs := h.leftArmed(t)
	if !attrs["reboot_guaranteed"].Bool() {
		t.Fatal("the self-fence path must report the reboot as guaranteed: the process survives, " +
			"so the retained descriptor stays open")
	}
	if _, ok := attrs["caveat"]; ok {
		t.Errorf("self-fence must carry no caveat, got %v", attrs["caveat"])
	}
}
