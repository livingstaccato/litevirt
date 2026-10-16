package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
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
	checks.start(d, ctx, 0, 0, 0, false)
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
// daemon never serves, the next boot writes nothing (hostboot's Deferred): the
// host stays 'upgrading' from the earlier write, and once this daemon serves
// its boot report and 'active' are written together and the note goes, so the
// next crash awaits serving again.
//
// Mutations: make the deferred boot write as before (UpdateHostStartup) — the
// host's row moves at the boot; start no check for a deferred boot — the host
// stays 'upgrading'; confirm a deferred boot with hostboot.ConfirmServing —
// the version is not reported; drop hostboot.Served from activateOnceServing —
// the note stays after the first boot serves, and the crash after it is
// deferred.
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
	checks.start(d, bctx, 0, 0, 0, false)
	time.Sleep(50 * time.Millisecond)
	if got := stateOf(); got != "upgrading" {
		t.Fatalf("before this daemon serves after a crash the host is %q, want upgrading", got)
	}
	close(serving)
	waitFor("the crashed host to turn active once it serves", func() bool { return stateOf() == "active" && !note() })
	bcancel()
	checks.wait(t)

	// Another crash, and this daemon never serves.
	never := make(chan struct{})
	d.selfPinger = checks.pinger(&gatedPinger{open: never})
	bctx, bcancel = context.WithCancel(ctx)
	checks.start(d, bctx, 0, 0, 0, false)
	time.Sleep(50 * time.Millisecond)
	if got := stateOf(); got != "upgrading" || !note() {
		t.Fatalf("after the second crash the host is %q (note=%v), want upgrading, noted", got, note())
	}
	bcancel() // it dies
	checks.wait(t)

	// The next boot follows a daemon that never served: it writes nothing
	// until it serves.
	h0, err := corrosion.GetHost(ctx, db, "h")
	if err != nil || h0 == nil {
		t.Fatalf("GetHost: %v", err)
	}
	d.cfg.Version = "v-deferred"
	serving = make(chan struct{})
	d.selfPinger = checks.pinger(&gatedPinger{open: serving})
	checks.start(d, ctx, 2, 3, 4, true)
	time.Sleep(50 * time.Millisecond)
	h, err := corrosion.GetHost(ctx, db, "h")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %v", err)
	}
	if h.State != "upgrading" || h.UpdatedAt != h0.UpdatedAt {
		t.Fatalf("the boot after a daemon that never served wrote its host: %q at %s, was %q at %s", h.State, h.UpdatedAt, h0.State, h0.UpdatedAt)
	}
	if !note() {
		t.Fatal("the note went before this daemon served")
	}
	close(serving)
	waitFor("the deferred boot report once this daemon serves", func() bool {
		h, err := corrosion.GetHost(ctx, db, "h")
		return err == nil && h != nil && h.State == "active" && h.Version == "v-deferred" && h.CPUTotal == 2 && !note()
	})
}

// TestBootAfterAQuarantinedStopWiring is lab 1's ReleaseTokenRollbackRule
// cleanup (2026-10-16): a crash boot records the host 'upgrading' and is
// stopped before it serves; the next boot is WAL-quarantined, writes nothing,
// and its SIGTERM cannot record a graceful stop either; then the binary is
// upgraded again and the daemon boots unquarantined. That boot followed a
// daemon that never served, recorded node-5 'active' 23 s before it
// listened, and node-2 SSH-fenced it 16 s later. It must leave the host
// 'upgrading' — without re-arming the timeout — until it serves, and then
// record it active.
//
// Mutation: return 'active' for a boot that follows a never-served one
// (hostboot's rule before this change) — the host is 'active' before it
// serves.
func TestBootAfterAQuarantinedStopWiring(t *testing.T) {
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
	host := func() *corrosion.HostRecord {
		h, err := corrosion.GetHost(ctx, db, "h")
		if err != nil || h == nil {
			t.Fatalf("GetHost: %v", err)
		}
		return h
	}
	d := &Daemon{cfg: &Config{HostName: "h", DataDir: t.TempDir(), Version: "v-up"}, db: db}
	never := make(chan struct{})

	// A crash boot that is stopped before it serves.
	d.selfPinger = checks.pinger(&gatedPinger{open: never})
	bctx, bcancel := context.WithCancel(ctx)
	checks.start(d, bctx, 0, 0, 0, false)
	if got := host().State; got != "upgrading" {
		t.Fatalf("fixture: the crash boot recorded %q, want upgrading", got)
	}
	bcancel()
	checks.wait(t)
	h0 := host()

	// The rolled-back binary: quarantined, it writes nothing, boot or stop.
	var quarantined atomic.Bool
	quarantined.Store(true)
	db.SetWriteQuarantine(func() string {
		if quarantined.Load() {
			return "rolled back below latched token(s): test"
		}
		return ""
	})
	d.selfPinger = checks.pinger(&gatedPinger{open: never})
	bctx, bcancel = context.WithCancel(ctx)
	checks.start(d, bctx, 0, 0, 0, false)
	d.markRestarting()
	bcancel()
	checks.wait(t)

	// Upgraded again: the cleanup boot.
	quarantined.Store(false)
	d.cfg.Version = "v-up2"
	serving := make(chan struct{})
	d.selfPinger = checks.pinger(&gatedPinger{open: serving})
	checks.start(d, ctx, 0, 0, 0, false)
	time.Sleep(50 * time.Millisecond)
	if h := host(); h.State != "upgrading" || h.UpdatedAt != h0.UpdatedAt {
		t.Fatalf("the boot after a quarantined stop recorded %q at %s before it served; want 'upgrading' as at %s, not rewritten",
			h.State, h.UpdatedAt, h0.UpdatedAt)
	}
	close(serving)
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if h := host(); h.State == "active" && h.Version == "v-up2" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("this daemon serves, and the host is %+v, want active with its boot report", host())
		}
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
	checks.start(d, ctx, 0, 0, 0, false)
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

// bootChecks owns the actual workers started by a test, including boots that
// never construct a client. Cancellation and join precede timing restoration.
type bootChecks struct{ done []<-chan struct{} }

func (b *bootChecks) pinger(p pinger) func() (pinger, func(), error) {
	return func() (pinger, func(), error) { return p, func() {}, nil }
}

func (b *bootChecks) start(d *Daemon, ctx context.Context, cpu, mem, disk int, resources bool) <-chan struct{} {
	done := d.writeBootState(ctx, cpu, mem, disk, resources)
	b.done = append(b.done, done)
	return done
}

func (b *bootChecks) wait(t *testing.T) {
	t.Helper()
	for _, done := range b.done {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("a boot's actual serving worker did not finish after cancellation")
		}
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

// bootTestDaemon is a daemon over a fresh database holding host h, recorded
// active, for the boot-write tests.
func bootTestDaemon(t *testing.T, ctx context.Context) (*Daemon, func() *corrosion.HostRecord) {
	t.Helper()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "h", Address: "127.0.0.1", SSHUser: "root", CertSerial: "s", State: "active",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	host := func() *corrosion.HostRecord {
		h, err := corrosion.GetHost(ctx, db, "h")
		if err != nil || h == nil {
			t.Fatalf("GetHost: %v", err)
		}
		return h
	}
	return &Daemon{cfg: &Config{HostName: "h", DataDir: t.TempDir(), Version: "v-boot"}, db: db}, host
}

// TestBootWriteKeepsAFenceRecordedAfterTheDecision: a fence recorded between
// hostboot's read of the host and the boot write is kept — the write is
// guarded on the state the decision read (hostboot.Boot.From) — and once
// this daemon serves it is not recorded active over the fence.
//
// Mutation: write the boot state with corrosion.UpdateHostStartup
// (unguarded) — the fenced host is recorded 'upgrading', then 'active'.
func TestBootWriteKeepsAFenceRecordedAfterTheDecision(t *testing.T) {
	old := pingPollInterval
	pingPollInterval = time.Millisecond
	defer func() { pingPollInterval = old }()
	var checks bootChecks
	defer checks.wait(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, host := bootTestDaemon(t, ctx)
	beforeBootWrite = func() {
		if err := corrosion.UpdateHostState(ctx, d.db, "h", "fenced"); err != nil {
			t.Errorf("the fence: %v", err)
		}
	}
	t.Cleanup(func() { beforeBootWrite = nil })
	served := make(chan struct{})
	var once sync.Once
	d.selfPinger = checks.pinger(pingerFunc(func() error { once.Do(func() { close(served) }); return nil }))
	checks.start(d, ctx, 0, 0, 0, false) // a crash boot of an active host
	if got := host().State; got != "fenced" {
		t.Fatalf("the boot write overwrote a fence recorded after its decision: %q", got)
	}
	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("the boot started no serving check")
	}
	time.Sleep(100 * time.Millisecond)
	if got := host().State; got != "fenced" {
		t.Fatalf("serving recorded the fenced host %q", got)
	}
}

// TestBootWithoutALocalClientIsNotActiveBeforeItServes: a boot whose local
// gRPC client cannot be built (its certificate is not there yet) leaves the
// host 'upgrading' — it used to record it active at once — and keeps
// retrying; once the client builds and this daemon answers, the host is
// recorded active.
//
// Mutation: confirm at once when dialSelf fails (the code before) — the host
// is 'active' while the client still cannot be built.
func TestBootWithoutALocalClientIsNotActiveBeforeItServes(t *testing.T) {
	old, oldRetry := pingPollInterval, dialSelfRetry
	pingPollInterval, dialSelfRetry = time.Millisecond, 5*time.Millisecond
	defer func() { pingPollInterval, dialSelfRetry = old, oldRetry }()
	var checks bootChecks
	defer checks.wait(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, host := bootTestDaemon(t, ctx)
	dial := checks.pinger(pingerFunc(func() error { return nil }))
	var dialable atomic.Bool
	var tries atomic.Int32
	d.selfPinger = func() (pinger, func(), error) {
		tries.Add(1)
		if !dialable.Load() {
			return nil, nil, errors.New("no host certificate yet")
		}
		return dial()
	}
	checks.start(d, ctx, 0, 0, 0, false) // a crash boot of an active host
	for deadline := time.Now().Add(3 * time.Second); tries.Load() < 5; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the boot retried building its client %d times", tries.Load())
		}
	}
	if got := host().State; got != "upgrading" {
		t.Fatalf("with no local client the host is %q, want upgrading until it serves", got)
	}
	dialable.Store(true)
	for deadline := time.Now().Add(3 * time.Second); host().State != "active"; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the client builds and this daemon serves, and the host is %q", host().State)
		}
	}
}

// TestBootThatCannotRecordItselfWritesNothingUntilItServes: a crash boot whose
// data dir cannot take its unclean-boot history (a full or read-only disk)
// could not bound a crash loop. It used to record the host 'active' at once;
// it now writes nothing until this daemon serves, and then records it active
// with its boot report, through the guard.
//
// Mutation: return 'active' for a failed history in hostboot (the rule
// before) — the host's row is rewritten at the boot.
func TestBootThatCannotRecordItselfWritesNothingUntilItServes(t *testing.T) {
	old := pingPollInterval
	pingPollInterval = time.Millisecond
	defer func() { pingPollInterval = old }()
	var checks bootChecks
	defer checks.wait(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, host := bootTestDaemon(t, ctx)
	d.cfg.DataDir = filepath.Join(t.TempDir(), "missing")
	h0 := host()
	serving := make(chan struct{})
	d.selfPinger = checks.pinger(&gatedPinger{open: serving})
	checks.start(d, ctx, 2, 3, 4, true)
	time.Sleep(50 * time.Millisecond)
	if h := host(); h.State != "active" || h.UpdatedAt != h0.UpdatedAt || h.Version == "v-boot" {
		t.Fatalf("the boot that cannot record itself wrote its host before serving: %+v (was at %s)", h, h0.UpdatedAt)
	}
	close(serving)
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if h := host(); h.State == "active" && h.Version == "v-boot" && h.CPUTotal == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("this daemon serves, and the host is %+v, want active with its boot report", host())
		}
	}
}

// TestDeferredBootOfAFencedHostKeepsTheFence: a crash boot of a host recorded
// fenced whose data dir cannot take its unclean-boot history writes nothing,
// and once this daemon serves it is not recorded active over the fence.
//
// Mutation: confirm a deferred boot from any recorded state in hostboot — the
// fenced host turns active once it serves.
func TestDeferredBootOfAFencedHostKeepsTheFence(t *testing.T) {
	old := pingPollInterval
	pingPollInterval = time.Millisecond
	defer func() { pingPollInterval = old }()
	var checks bootChecks
	defer checks.wait(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, host := bootTestDaemon(t, ctx)
	if err := corrosion.UpdateHostState(ctx, d.db, "h", "fenced"); err != nil {
		t.Fatal(err)
	}
	d.cfg.DataDir = filepath.Join(t.TempDir(), "missing")
	served := make(chan struct{})
	var once sync.Once
	d.selfPinger = checks.pinger(pingerFunc(func() error { once.Do(func() { close(served) }); return nil }))
	checks.start(d, ctx, 0, 0, 0, false)
	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("the boot started no serving check")
	}
	time.Sleep(100 * time.Millisecond)
	if got := host().State; got != "fenced" {
		t.Fatalf("a deferred boot of a fenced host recorded it %q once serving, want the fence kept", got)
	}
}

// Cancellation before any successful dial must finish the actual serving
// worker. No client close callback can account for this lifetime.
func TestBootDialCancellationJoinsWorker(t *testing.T) {
	old := dialSelfRetry
	dialSelfRetry = time.Millisecond
	defer func() { dialSelfRetry = old }()
	ctx, cancel := context.WithCancel(context.Background())
	var checks bootChecks
	defer checks.wait(t)
	defer cancel()
	d, host := bootTestDaemon(t, ctx)
	var tries atomic.Int32
	d.selfPinger = func() (pinger, func(), error) {
		tries.Add(1)
		return nil, nil, errors.New("private fixture certificate unavailable")
	}
	done := checks.start(d, ctx, 0, 0, 0, false)
	for deadline := time.Now().Add(3 * time.Second); tries.Load() < 5; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no repeated dial attempts")
		}
	}
	before := host()
	if before.State != "upgrading" {
		t.Fatalf("before cancel: %+v", before)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("actual worker did not finish on dial cancellation")
	}
	// Read through an independent live context after cancellation.
	h, err := corrosion.GetHost(context.Background(), d.db, "h")
	if err != nil || h == nil || h.State != "upgrading" || h.UpdatedAt != before.UpdatedAt {
		t.Fatalf("cancelled dial changed the host: %+v err=%v", h, err)
	}
}
