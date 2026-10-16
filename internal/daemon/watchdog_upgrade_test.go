package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hostboot"
	"github.com/litevirt/litevirt/internal/upgrade"
)

func TestDecideWatchdog(t *testing.T) {
	cases := []struct {
		name                            string
		pingOK, shuttingDown, oldExists bool
		attempt                         int
		want                            watchdogOutcome
	}{
		{"healthy", true, false, true, 0, wdConfirm},
		{"healthy even mid-shutdown", true, true, true, 0, wdConfirm},
		{"unhealthy during shutdown -> no rollback", false, true, true, 0, wdShutdown},
		{"unhealthy first time with .old -> rollback", false, false, true, 0, wdRollback},
		{"unhealthy but already rolled back -> giveup", false, false, true, 1, wdGiveUp},
		{"unhealthy but no .old -> giveup", false, false, false, 0, wdGiveUp},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideWatchdog(tc.pingOK, tc.shuttingDown, tc.oldExists, tc.attempt); got != tc.want {
				t.Fatalf("decideWatchdog(%v,%v,%v,%d) = %d, want %d",
					tc.pingOK, tc.shuttingDown, tc.oldExists, tc.attempt, got, tc.want)
			}
		})
	}
}

// TestRollbackToOld proves a rollback restores .old over the binary, bumps the
// sentinel attempt (so the restored binary won't roll back again), and exits
// non-zero.
func TestRollbackToOld(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "litevirt")
	if err := os.WriteFile(bin, []byte("NEW-broken"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin+".old", []byte("OLD-good"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := upgrade.Arm(bin, "v1.0.30"); err != nil {
		t.Fatal(err)
	}
	s, _ := upgrade.Read(bin)

	var exitCode = -1
	d := &Daemon{exitFunc: func(c int) { exitCode = c }}
	d.rollbackToOld(bin, s)

	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	got, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("read restored binary: %v", err)
	}
	if string(got) != "OLD-good" {
		t.Fatalf("binary content after rollback = %q, want OLD-good (.old not restored)", got)
	}
	if _, err := os.Stat(bin + ".old"); !os.IsNotExist(err) {
		t.Fatalf(".old should be consumed by the rename, stat err=%v", err)
	}
	s2, ok := upgrade.Read(bin)
	if !ok || s2.Attempt != 1 {
		t.Fatalf("sentinel after rollback: ok=%v attempt=%d, want true/1 (flap guard)", ok, s2.Attempt)
	}
}

// TestConfirmUpgradeHealthy proves the confirm path (Ping succeeded): the
// sentinel is cleared and the host flips upgrading→active.
func TestConfirmUpgradeHealthy(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "h", Address: "127.0.0.1", SSHUser: "root", CertSerial: "s", State: "upgrading",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	bin := filepath.Join(t.TempDir(), "litevirt")
	if err := upgrade.Arm(bin, "v-old"); err != nil {
		t.Fatalf("Arm: %v", err)
	}

	d := &Daemon{cfg: &Config{HostName: "h"}, db: db}
	d.confirmUpgradeHealthy(bin)

	if _, ok := upgrade.Read(bin); ok {
		t.Fatal("sentinel must be cleared after a healthy confirm")
	}
	h, err := corrosion.GetHost(ctx, db, "h")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %v", err)
	}
	if h.State != "active" {
		t.Fatalf("host state = %q after confirm, want active", h.State)
	}
}

// TestConfirmUpgradeHealthy_KeepsAFenceRecordedMeanwhile proves the confirm
// never overwrites a state another writer recorded while the host was
// upgrading: a host fenced (or drained) before its new binary answered stays
// fenced. The binary is healthy, so the sentinel is still cleared.
func TestConfirmUpgradeHealthy_KeepsAFenceRecordedMeanwhile(t *testing.T) {
	for _, recorded := range []string{"fenced", "draining", "offline"} {
		t.Run(recorded, func(t *testing.T) {
			ctx := context.Background()
			db, err := corrosion.NewTestClient()
			if err != nil {
				t.Fatalf("NewTestClient: %v", err)
			}
			t.Cleanup(func() { db.Close() })
			if err := corrosion.InitSchema(ctx, db); err != nil {
				t.Fatalf("InitSchema: %v", err)
			}
			if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
				Name: "h", Address: "127.0.0.1", SSHUser: "root", CertSerial: "s", State: recorded,
			}); err != nil {
				t.Fatalf("InsertHost: %v", err)
			}
			bin := filepath.Join(t.TempDir(), "litevirt")
			if err := upgrade.Arm(bin, "v-old"); err != nil {
				t.Fatalf("Arm: %v", err)
			}

			d := &Daemon{cfg: &Config{HostName: "h"}, db: db}
			d.confirmUpgradeHealthy(bin)

			h, err := corrosion.GetHost(ctx, db, "h")
			if err != nil || h == nil {
				t.Fatalf("GetHost: %v", err)
			}
			if h.State != recorded {
				t.Fatalf("host state = %q after confirm, want %q kept", h.State, recorded)
			}
			if _, ok := upgrade.Read(bin); ok {
				t.Fatal("sentinel must be cleared: the new binary answered")
			}
		})
	}
}

// TestConfirmUpgradeHealthy_RetainsSentinelOnWriteFailure proves the sentinel is
// NOT cleared when the active-state write fails — so a transient DB error can't
// strand the host in 'upgrading' with no watchdog; the next boot re-confirms.
func TestConfirmUpgradeHealthy_RetainsSentinelOnWriteFailure(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	// Force the state write to fail by removing the table it targets.
	if err := db.Execute(ctx, `DROP TABLE hosts`); err != nil {
		t.Fatalf("drop hosts: %v", err)
	}

	bin := filepath.Join(t.TempDir(), "litevirt")
	if err := upgrade.Arm(bin, "v-old"); err != nil {
		t.Fatalf("Arm: %v", err)
	}

	d := &Daemon{cfg: &Config{HostName: "h"}, db: db}
	d.confirmUpgradeHealthy(bin)

	if _, ok := upgrade.Read(bin); !ok {
		t.Fatal("sentinel must be RETAINED when the active-state write fails (so the next boot retries)")
	}
}

// TestStartUpgradeWatchdog_Disabled confirms the watchdog is inert when disabled
// and never sets upgradePending.
func TestStartUpgradeWatchdog_Disabled(t *testing.T) {
	d := &Daemon{cfg: &Config{UpgradeWatchdogEnabled: false}}
	d.startUpgradeWatchdog(t.Context())
	if d.upgradePending {
		t.Fatal("disabled watchdog must not set upgradePending")
	}
}

// fakePinger fails the first failN Pings, then succeeds.
type fakePinger struct {
	calls int
	failN int
}

func (f *fakePinger) Ping(ctx context.Context, _ *pb.PingRequest, _ ...grpc.CallOption) (*pb.PingResponse, error) {
	f.calls++
	if f.calls <= f.failN {
		return nil, errors.New("not serving yet")
	}
	return &pb.PingResponse{}, nil
}

func TestPingUntil_SucceedsAfterRetries(t *testing.T) {
	old := pingPollInterval
	pingPollInterval = time.Millisecond
	defer func() { pingPollInterval = old }()

	p := &fakePinger{failN: 3}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if !pingUntil(ctx, p) {
		t.Fatal("pingUntil should return true once Ping succeeds")
	}
	if p.calls != 4 {
		t.Fatalf("expected 4 ping attempts (3 fail + 1 ok), got %d", p.calls)
	}
}

func TestPingUntil_DeadlineReturnsFalse(t *testing.T) {
	old := pingPollInterval
	pingPollInterval = time.Millisecond
	defer func() { pingPollInterval = old }()

	p := &fakePinger{failN: 1 << 30} // never succeeds
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if pingUntil(ctx, p) {
		t.Fatal("pingUntil must return false when the deadline elapses without a successful Ping")
	}
}

// TestLocalGRPCClient_BadPKI: a missing PKI dir surfaces an error (no rollback —
// runUpgradeWatchdog treats this as environmental and skips).
func TestLocalGRPCClient_BadPKI(t *testing.T) {
	d := &Daemon{cfg: &Config{PKIDir: filepath.Join(t.TempDir(), "nonexistent"), GRPCPort: 7443}}
	if _, _, err := d.localGRPCClient(); err == nil {
		t.Fatal("expected an error building the local gRPC client with a bad PKI dir")
	}
}

// TestActivateOnceServing: after a graceful restart the host stays
// 'upgrading' until this daemon answers its own Ping. If it never does, it is
// LEFT 'upgrading' — there is nothing to roll back to — and the coordinator
// fences it once the upgrading timeout passes; if it does, it is recorded
// active. A host recorded fenced meanwhile is not flipped.
//
// Mutations: record the host active when the deadline passes — the
// never-serving host turns active; stop checking at the deadline — the host
// that serves after it stays 'upgrading'.
func TestActivateOnceServing(t *testing.T) {
	old := pingPollInterval
	pingPollInterval = time.Millisecond
	defer func() { pingPollInterval = old }()
	for _, tc := range []struct {
		name  string
		start string
		failN int
		want  string
	}{
		{"never serves", "upgrading", 1 << 30, "upgrading"},
		{"serves", "upgrading", 3, "active"},
		// Answers only after the 50 ms deadline: a healthy host that came up
		// late, which must not be left 'upgrading' for good.
		{"serves after the deadline", "upgrading", 200, "active"},
		{"fenced meanwhile", "fenced", 0, "fenced"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := corrosion.NewTestClientT(t)
			if err := corrosion.InitSchema(ctx, db); err != nil {
				t.Fatalf("InitSchema: %v", err)
			}
			if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
				Name: "h", Address: "127.0.0.1", SSHUser: "root", CertSerial: "s", State: tc.start,
			}); err != nil {
				t.Fatalf("InsertHost: %v", err)
			}
			d := &Daemon{cfg: &Config{HostName: "h"}, db: db}
			// The check runs until the daemon answers or shuts down; this
			// context is the shutdown. Made here, after the fixture, so a slow
			// setup (under -race) does not spend it.
			checkCtx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			d.activateOnceServing(checkCtx, &fakePinger{failN: tc.failN}, 50*time.Millisecond)
			h, err := corrosion.GetHost(ctx, db, "h")
			if err != nil || h == nil {
				t.Fatalf("GetHost: %v", err)
			}
			if h.State != tc.want {
				t.Fatalf("host is %q after the restart's serving check, want %q", h.State, tc.want)
			}
		})
	}
}

// TestGracefulRestartWiring drives the daemon's own wiring: markRestarting on
// the SIGTERM, then the boot write (writeBootState), which must start the
// check that records the host active once this daemon answers its own Ping.
// Without that goroutine every graceful restart would leave its host
// 'upgrading' until the coordinator fenced it.
//
// Mutations: delete `go d.awaitServingThenActivate(ctx)` from writeBootState —
// the host stays 'upgrading'; call corrosion.UpdateHostState instead of
// hostboot.MarkRestarting in markRestarting — no marker, the boot is 'active'
// straight away and the first assertion fails.
func TestGracefulRestartWiring(t *testing.T) {
	old := pingPollInterval
	pingPollInterval = time.Millisecond
	defer func() { pingPollInterval = old }()
	var checks bootChecks
	defer checks.wait(t) // after cancel, before the restore
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
	stateOf := func() string {
		h, err := corrosion.GetHost(ctx, db, "h")
		if err != nil || h == nil {
			t.Fatalf("GetHost: %v", err)
		}
		return h.State
	}
	d := &Daemon{cfg: &Config{HostName: "h", DataDir: t.TempDir()}, db: db}

	d.markRestarting() // the SIGTERM
	if got := stateOf(); got != "upgrading" {
		t.Fatalf("after the SIGTERM the host is %q, want upgrading", got)
	}

	// The next boot. Its gRPC server answers once `serving` is closed; until
	// then the host must stay 'upgrading'.
	serving := make(chan struct{})
	p := &gatedPinger{open: serving}
	d.selfPinger = checks.pinger(p)
	d.writeBootState(ctx, 0, 0, 0, false)
	time.Sleep(50 * time.Millisecond)
	if got := stateOf(); got != "upgrading" {
		t.Fatalf("before this daemon serves the host is %q, want upgrading", got)
	}
	close(serving)
	deadline := time.Now().Add(3 * time.Second)
	for stateOf() != "active" {
		if time.Now().After(deadline) {
			t.Fatalf("this daemon serves, and the host is still %q: the boot did not start the serving check", stateOf())
		}
		time.Sleep(10 * time.Millisecond)
	}

	if _, err := os.Stat(hostboot.AwaitingPath(d.cfg.DataDir)); !os.IsNotExist(err) {
		t.Fatalf("this daemon serves, and the boot's awaiting-serving note is still there: %v", err)
	}
}

// TestUncleanBootWiring: a boot with no graceful stop before it (a crash, a
// kill) keeps an active host 'upgrading' until this daemon serves. If that
// daemon never serves, the next boot is 'active' at once, and still notes
// once it serves that a daemon served, so the next crash awaits serving again.
//
// Mutations: start no check in writeBootState for a boot that does not await
// serving — the note stays and the last boot is 'active'; drop
// hostboot.Served from activateOnceServing — the note stays after the first
// boot serves, and the crash after it boots 'active'.
func TestUncleanBootWiring(t *testing.T) {
	old := pingPollInterval
	pingPollInterval = time.Millisecond
	defer func() { pingPollInterval = old }()
	var checks bootChecks
	defer checks.wait(t) // after cancel, before the restore
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
	stateOf := func() string {
		h, err := corrosion.GetHost(ctx, db, "h")
		if err != nil || h == nil {
			t.Fatalf("GetHost: %v", err)
		}
		return h.State
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(3 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s (host %q)", what, stateOf())
			}
		}
	}
	dir := t.TempDir()
	note := func() bool {
		_, err := os.Stat(hostboot.AwaitingPath(dir))
		return err == nil
	}
	d := &Daemon{cfg: &Config{HostName: "h", DataDir: dir}, db: db}

	// A crash: no markRestarting. This boot serves once `serving` closes.
	serving := make(chan struct{})
	d.selfPinger = checks.pinger(&gatedPinger{open: serving})
	bctx, bcancel := context.WithCancel(ctx)
	d.writeBootState(bctx, 0, 0, 0, false)
	time.Sleep(50 * time.Millisecond)
	if got := stateOf(); got != "upgrading" {
		t.Fatalf("before this daemon serves after a crash the host is %q, want upgrading", got)
	}
	close(serving)
	waitFor("the crashed host to turn active once it serves", func() bool { return stateOf() == "active" && !note() })
	bcancel()

	// Another crash, and this daemon never serves.
	never := make(chan struct{})
	d.selfPinger = checks.pinger(&gatedPinger{open: never})
	bctx, bcancel = context.WithCancel(ctx)
	d.writeBootState(bctx, 0, 0, 0, false)
	time.Sleep(50 * time.Millisecond)
	if got := stateOf(); got != "upgrading" || !note() {
		t.Fatalf("after the second crash the host is %q (note=%v), want upgrading, noted", got, note())
	}
	bcancel() // it dies

	// The next boot follows a daemon that never served: 'active' at once.
	serving = make(chan struct{})
	d.selfPinger = checks.pinger(&gatedPinger{open: serving})
	d.writeBootState(ctx, 0, 0, 0, false)
	if got := stateOf(); got != "active" {
		t.Fatalf("the boot after a daemon that never served recorded %q, want active", got)
	}
	time.Sleep(50 * time.Millisecond)
	if !note() {
		t.Fatal("the note went before this daemon served")
	}
	close(serving)
	waitFor("the note to go once this daemon serves", func() bool { return !note() })
	if got := stateOf(); got != "active" {
		t.Fatalf("host is %q after serving, want active", got)
	}
}

// TestQuarantinedBootWritesNothing: a WAL-quarantined daemon's boot after a
// crash decides 'upgrading' like any other, but writes nothing — neither the
// boot state nor 'active' once it serves. The host stays as the cluster
// recorded it.
//
// Mutation: drop the quarantine refusal from corrosion's replicated write
// path — the host is recorded 'upgrading', then 'active'.
func TestQuarantinedBootWritesNothing(t *testing.T) {
	old := pingPollInterval
	pingPollInterval = time.Millisecond
	defer func() { pingPollInterval = old }()
	var checks bootChecks
	defer checks.wait(t) // after cancel, before the restore
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
	h0, err := corrosion.GetHost(ctx, db, "h")
	if err != nil || h0 == nil {
		t.Fatalf("GetHost: %v", err)
	}
	db.SetWriteQuarantine(func() string { return "rolled back below latched token(s): test" })
	if !db.WALQuarantined() {
		t.Fatal("fixture: not quarantined")
	}
	d := &Daemon{cfg: &Config{HostName: "h", DataDir: t.TempDir()}, db: db}
	served := make(chan struct{})
	var once sync.Once
	d.selfPinger = checks.pinger(pingerFunc(func() error { once.Do(func() { close(served) }); return nil }))
	d.writeBootState(ctx, 0, 0, 0, false)
	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("the quarantined boot started no serving check")
	}
	time.Sleep(50 * time.Millisecond)
	h, err := corrosion.GetHost(ctx, db, "h")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %v", err)
	}
	if h.State != "active" || h.UpdatedAt != h0.UpdatedAt {
		t.Fatalf("a quarantined boot wrote its host: %q at %s, was %q at %s", h.State, h.UpdatedAt, h0.State, h0.UpdatedAt)
	}
}

// pingerFunc answers every Ping with fn's error.
type pingerFunc func() error

func (f pingerFunc) Ping(context.Context, *pb.PingRequest, ...grpc.CallOption) (*pb.PingResponse, error) {
	if err := f(); err != nil {
		return nil, err
	}
	return &pb.PingResponse{}, nil
}

// gatedPinger fails every Ping until open is closed.
type gatedPinger struct{ open chan struct{} }

// bootChecks counts the serving checks a test's boots start, so the test can
// wait for them to end before it restores the package timings they read: a
// check that outlives its test races that restore, and the next test's.
type bootChecks struct{ wg sync.WaitGroup }

// pinger is the selfPinger for one boot. The boot's check is counted from
// here until it closes its client.
func (b *bootChecks) pinger(p pinger) func() (pinger, func(), error) {
	b.wg.Add(1)
	var once sync.Once
	return func() (pinger, func(), error) { return p, func() { once.Do(b.wg.Done) }, nil }
}

// wait waits, bounded, for every counted check to end. Cancel their contexts
// first.
func (b *bootChecks) wait(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() { b.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("a boot's serving check did not end once its context was cancelled")
	}
}

func (g *gatedPinger) Ping(ctx context.Context, _ *pb.PingRequest, _ ...grpc.CallOption) (*pb.PingResponse, error) {
	select {
	case <-g.open:
		return &pb.PingResponse{}, nil
	default:
		return nil, errors.New("not serving yet")
	}
}
