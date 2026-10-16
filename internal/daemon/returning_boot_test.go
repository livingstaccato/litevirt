package daemon

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hostboot"
)

// TestReturningHostBootWiring: the daemon of a host the cluster recorded
// fenced, offline, in maintenance, draining or joining starts. Its boot write
// records the host 'upgrading', the boot starts the serving check, and the
// host turns 'active' once this daemon answers its own Ping, not before.
//
// Mutations: have hostboot.BootState skip returningBoot — the boot write
// records 'active' at once; delete `go d.awaitServingThenActivate(ctx)` from
// writeBootState — the host stays 'upgrading'.
func TestReturningHostBootWiring(t *testing.T) {
	old := pingPollInterval
	pingPollInterval = time.Millisecond
	defer func() { pingPollInterval = old }()
	for _, st := range []string{"fenced", "offline", "maintenance", "draining", corrosion.HostStateJoining} {
		t.Run(st, func(t *testing.T) {
			var checks bootChecks
			defer checks.wait(t) // after cancel
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			db := corrosion.NewTestClientT(t)
			if err := corrosion.InitSchema(ctx, db); err != nil {
				t.Fatalf("InitSchema: %v", err)
			}
			if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
				Name: "h", Address: "127.0.0.1", SSHUser: "root", CertSerial: "s", State: "active",
			}); err != nil {
				t.Fatalf("InsertHost: %v", err)
			}
			if err := corrosion.UpdateHostState(ctx, db, "h", st); err != nil {
				t.Fatal(err)
			}
			stateOf := func() string {
				h, err := corrosion.GetHost(ctx, db, "h")
				if err != nil || h == nil {
					t.Fatalf("GetHost: %v", err)
				}
				return h.State
			}
			dir := t.TempDir()
			d := &Daemon{cfg: &Config{HostName: "h", DataDir: dir}, db: db}
			serving := make(chan struct{})
			d.selfPinger = checks.pinger(&gatedPinger{open: serving})
			d.writeBootState(ctx, 0, 0, 0, false)
			if got := stateOf(); got != "upgrading" {
				t.Fatalf("the boot write of a host recorded %s recorded %q, want upgrading", st, got)
			}
			time.Sleep(50 * time.Millisecond)
			if got := stateOf(); got != "upgrading" {
				t.Fatalf("before this daemon serves the host is %q, want upgrading", got)
			}
			close(serving)
			for deadline := time.Now().Add(3 * time.Second); stateOf() != "active"; time.Sleep(10 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatalf("this daemon serves, and the host is still %q: the boot did not start the serving check", stateOf())
				}
			}
			for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				if _, err := os.Stat(hostboot.AwaitingPath(dir)); os.IsNotExist(err) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("this daemon serves, and the boot's awaiting-serving note is still there")
				}
			}
		})
	}
}
