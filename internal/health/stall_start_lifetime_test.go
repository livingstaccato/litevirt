package health

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

// Start completion must include the actual child even when it has not entered
// runStallHeartbeat yet, or is inside stallTick before its persisted-condition
// read. A canceled context alone does not release either schedule.
func TestCheckerStartJoinsStallHeartbeat(t *testing.T) {
	for _, tlsReady := range []bool{false, true} {
		name := "tls-retry"
		if tlsReady {
			name = "tls-ready"
		}
		t.Run(name, func(t *testing.T) {
			for _, schedule := range []string{"delayed-entry", "in-flight-tick"} {
				t.Run(schedule, func(t *testing.T) {
					db := testCheckerDB(t)
					dir := t.TempDir()
					if tlsReady {
						ca, key := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
						if err := pki.GenerateCA(ca, key); err != nil {
							t.Fatal(err)
						}
						if err := pki.GenerateHostCert(ca, key, filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), "host-a", net.ParseIP("127.0.0.1")); err != nil {
							t.Fatal(err)
						}
					}
					c := NewChecker("host-a", dir, db)
					held, release, exited, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
					var releaseOnce sync.Once
					unblock := func() { releaseOnce.Do(func() { close(release) }) }
					hold := func() { close(held); <-release }
					var clockHeld atomic.Bool
					c.SetStallHeartbeatHooksForTests(func() {
						if schedule == "delayed-entry" {
							hold()
						}
					}, func() { close(exited) })
					if schedule == "in-flight-tick" {
						c.SetClockForTests(func() time.Time {
							if clockHeld.CompareAndSwap(false, true) {
								hold()
							}
							return time.Now()
						})
					}
					ctx, cancel := context.WithCancel(context.Background())
					t.Cleanup(func() {
						cancel()
						unblock()
						select {
						case <-done:
						case <-time.After(5 * time.Second):
							t.Error("checker did not finish after heartbeat release")
						}
						select {
						case <-exited:
						case <-time.After(5 * time.Second):
							t.Error("actual heartbeat did not exit")
						}
					})
					go func() { defer close(done); c.Start(ctx) }()
					select {
					case <-held:
					case <-time.After(5 * time.Second):
						t.Fatal("actual heartbeat did not reach hold")
					}
					cancel()
					select {
					case <-done:
						t.Error("Start returned before held heartbeat exit")
					case <-time.After(200 * time.Millisecond):
					}
					select {
					case <-exited:
						t.Fatal("heartbeat exited while held")
					default:
					}
					unblock()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Fatal("Start did not join released heartbeat")
					}
					select {
					case <-exited:
					default:
						t.Fatal("Start completion preceded actual heartbeat exit")
					}
				})
			}
		})
	}
}
