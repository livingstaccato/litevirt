package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/hostboot"
	"github.com/litevirt/litevirt/internal/metrics"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/upgrade"
)

// startUpgradeWatchdog arms the post-upgrade health watchdog when a prior upgrade
// staged this binary and left a sentinel next to it. It runs independently and is
// armed FIRST in Run (before any potentially-hanging init), so a boot that hangs
// before the gRPC server can serve is still caught.
//
// Scope: only binary-INTRINSIC faults trigger a rollback — the new binary cannot
// make local gRPC answer Ping. Environmental faults (libvirt down, replication
// backlog, broken PKI) are deliberately NOT gated here: they'd break the previous
// binary equally, so rolling back would just flap. systemd's existing
// OnFailure=litevirt-rollback.service still handles crash-loops (a binary that
// exits non-zero); this fills the gap where the binary stays up but is dead.
func (d *Daemon) startUpgradeWatchdog(ctx context.Context) {
	if !d.cfg.UpgradeWatchdogEnabled || os.Getenv("LITEVIRT_UNSAFE_NO_UPGRADE_WATCHDOG") == "1" {
		return
	}
	binaryPath := upgrade.ResolveBinaryPath()
	sentinel, ok := upgrade.Read(binaryPath)
	if !ok {
		return // normal boot — nothing to verify
	}
	d.upgradePending = true // gate the host's upgrading→active flip on confirmation

	deadline := time.Duration(d.cfg.UpgradeHealthDeadlineSec) * time.Second
	if deadline <= 0 {
		deadline = 120 * time.Second
	}
	go d.runUpgradeWatchdog(ctx, binaryPath, sentinel, deadline)
}

// watchdogOutcome is the decision the watchdog reaches after probing health.
type watchdogOutcome int

const (
	wdConfirm  watchdogOutcome = iota // healthy → clear sentinel, mark active
	wdShutdown                        // daemon stopping before confirm → leave sentinel, no rollback
	wdGiveUp                          // unhealthy but can't safely roll back → defer to systemd/operator
	wdRollback                        // unhealthy, rollback available → restore .old + exit
)

// decideWatchdog maps the probe result to an action. Pure + unit-tested. A
// rollback happens ONLY when the new binary never became pingable, the daemon
// isn't shutting down, no rollback has been made yet (flap guard), and a .old
// binary exists to restore.
func decideWatchdog(pingOK, shuttingDown, oldExists bool, attempt int) watchdogOutcome {
	switch {
	case pingOK:
		return wdConfirm
	case shuttingDown:
		return wdShutdown
	case attempt >= 1 || !oldExists:
		return wdGiveUp
	default:
		return wdRollback
	}
}

func (d *Daemon) runUpgradeWatchdog(ctx context.Context, binaryPath string, sentinel upgrade.Sentinel, deadline time.Duration) {
	slog.Info("post-upgrade watchdog armed",
		"deadline", deadline, "prev_version", sentinel.PrevVersion, "attempt", sentinel.Attempt)

	client, conn, err := d.localGRPCClient()
	if err != nil {
		// A PKI/TLS-config failure is environmental (shared with .old), so do NOT
		// roll back on it — just skip the health check.
		slog.Warn("post-upgrade watchdog: cannot build local gRPC client; skipping health check (NOT rolling back)", "error", err)
		return
	}
	defer conn.Close()

	dctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	pingOK := pingUntil(dctx, client)

	switch decideWatchdog(pingOK, ctx.Err() != nil, fileExists(binaryPath+".old"), sentinel.Attempt) {
	case wdConfirm:
		d.confirmUpgradeHealthy(binaryPath)
	case wdShutdown:
		slog.Info("post-upgrade watchdog: daemon shutting down before health confirmed; leaving sentinel for next boot")
	case wdGiveUp:
		slog.Error("post-upgrade watchdog: new binary unhealthy but cannot safely roll back (already rolled back once, or no .old) — leaving to systemd/operator",
			"prev_version", sentinel.PrevVersion, "attempt", sentinel.Attempt)
		metrics.UpgradeWatchdogOutcome("giveup")
	case wdRollback:
		d.rollbackToOld(binaryPath, sentinel)
	}
}

// confirmUpgradeHealthy is the success action: flip the host upgrading→active,
// then clear the sentinel. Extracted so it's directly testable without standing
// up a gRPC server for the Ping loop.
//
// Order matters: the active-state write happens FIRST and the sentinel is
// cleared only if it succeeds. Clearing first would strand the host in
// 'upgrading' with no watchdog if that (transient) write failed; by keeping the
// sentinel, the next boot's watchdog re-confirms and retries the flip.
func (d *Daemon) confirmUpgradeHealthy(binaryPath string) {
	mctx, mcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer mcancel()
	// Only from 'upgrading' (hostboot.ConfirmServing): a host fenced, put in
	// maintenance or isolated while it upgraded keeps that state. The binary
	// is healthy either way, so the sentinel goes.
	_, state, err := hostboot.ConfirmServing(mctx, d.db, d.cfg.HostName)
	switch {
	case errors.Is(err, hostboot.ErrNotUpgrading):
		slog.Warn("post-upgrade watchdog: confirmed healthy; host is no longer recorded upgrading, leaving its state as it is", "state", state)
	case err != nil:
		slog.Warn("post-upgrade watchdog: confirmed healthy but failed to mark host active — keeping sentinel for retry next boot", "error", err)
		metrics.UpgradeWatchdogOutcome("confirm_failed")
		return
	}
	upgrade.Clear(binaryPath)
	slog.Info("post-upgrade watchdog: new binary healthy (local gRPC ping ok)", "build_version", d.cfg.Version)
	metrics.UpgradeWatchdogOutcome("confirmed")
}

// awaitServingThenActivate is the boot after a graceful stop, or after a
// crash of an active host (hostboot.BootState): the host stays 'upgrading' until this daemon answers
// its own Ping over mTLS, and is then recorded active. There is no binary to
// roll back to. If it never answers within the upgrade health deadline the
// host is LEFT 'upgrading', and the failover coordinator fences it once
// hostboot.UpgradingTimeout has passed since the boot write: a daemon that
// cannot serve is a failed host.
//
// confirm records the host active once it serves; nil is ConfirmServing (or
// the test hook), a deferred boot's is ConfirmServingReport.
func (d *Daemon) awaitServingThenActivate(ctx context.Context, confirm confirmFunc) {
	deadline := time.Duration(d.cfg.UpgradeHealthDeadlineSec) * time.Second
	if deadline <= 0 {
		deadline = 120 * time.Second
	}
	client, closeFn, err := d.dialSelf()
	if err != nil {
		client, closeFn = d.dialSelfUntil(ctx, err)
		if client == nil {
			return // shutting down
		}
	}
	defer closeFn()
	d.activateOnceServingWith(ctx, client, deadline, confirm)
}

// dialSelfRetry is how often a boot whose local gRPC client cannot be built
// tries again; a var so tests can shrink it.
var dialSelfRetry = 5 * time.Second

// dialSelfUntil retries dialSelf after it failed with err, until it succeeds
// or the daemon shuts down (nil). Nothing shows this daemon serves until
// then, so the host is not recorded active: it stays as the boot left it
// ('upgrading', or as recorded), and past its upgrading window it raises
// upgrading_unconfirmed with the cause, as an unanswered Ping does.
func (d *Daemon) dialSelfUntil(ctx context.Context, err error) (pinger, func()) {
	slog.Error("restart: cannot build the local gRPC client to confirm serving; the host is not recorded active until this daemon can confirm it serves. "+
		"Past its upgrading window it raises upgrading_unconfirmed; 'lv host undrain' records it active. Still retrying.",
		"error", err, "retry_every", dialSelfRetry)
	var u unconfirmed
	checked := time.Now()
	for {
		select {
		case <-ctx.Done():
			return nil, nil
		case <-time.After(dialSelfRetry):
		}
		client, closeFn, derr := d.dialSelf()
		if derr == nil {
			slog.Info("restart: the local gRPC client builds now; checking that this daemon serves")
			return client, closeFn
		}
		err = derr
		if time.Since(checked) >= unconfirmedCheckEvery {
			d.noteUnconfirmed(ctx, &u, "cannot build this daemon's local gRPC client: "+err.Error())
			checked = time.Now()
		}
	}
}

// confirmFunc records the host active once this daemon serves:
// hostboot.ConfirmServing, or a deferred boot's ConfirmServingReport.
type confirmFunc func(ctx context.Context) (bool, string, error)

// awaitServingThenNote is the boot that follows one that never served, and is
// recorded active at once (hostboot.BootState): once this daemon answers its
// own Ping it clears the note, so the next crash awaits serving again.
func (d *Daemon) awaitServingThenNote(ctx context.Context) {
	client, closeFn, err := d.dialSelf()
	if err != nil {
		slog.Warn("boot: cannot build the local gRPC client to confirm serving; the awaiting-serving note stays", "error", err)
		return
	}
	defer closeFn()
	if pingUntil(ctx, client) {
		hostboot.Served(d.cfg.DataDir)
	}
}

// dialSelf is the client the boot checks ping this daemon through: the local
// mTLS client, or selfPinger in tests.
func (d *Daemon) dialSelf() (pinger, func(), error) {
	if d.selfPinger != nil {
		return d.selfPinger()
	}
	client, conn, err := d.localGRPCClient()
	if err != nil {
		return nil, nil, err
	}
	return client, func() { _ = conn.Close() }, nil
}

// activateOnceServing pings this daemon until it answers, and then records the
// host active (confirmActive). Until it answers the host stays 'upgrading' —
// there is no previous binary to roll back to.
//
// The deadline only times the error log. Pinging goes on past it, until the
// daemon answers or shuts down: a daemon that comes up late is a healthy host,
// and nothing else would ever record it active again (recoverHosts revives
// only offline and fenced hosts), so stopping at the deadline left it
// 'upgrading' — unplaceable, shown draining — until an operator undrained it.
// ConfirmServing still refuses a host fenced or otherwise moved on meanwhile.
//
// Whether the cluster fences such a host depends on its peers, not on this
// check: one they cannot reach either is fenced once its upgrading timeout
// passes; one they reach is not, and stays 'upgrading'. Past that timeout the
// host raises upgrading_unconfirmed about itself (noteUnconfirmed), so that
// case is visible.
func (d *Daemon) activateOnceServing(ctx context.Context, client pinger, deadline time.Duration) {
	d.activateOnceServingWith(ctx, client, deadline, nil)
}

// activateOnceServingWith is activateOnceServing recording the host active
// with confirm (nil: ConfirmServing).
func (d *Daemon) activateOnceServingWith(ctx context.Context, client pinger, deadline time.Duration, confirm confirmFunc) {
	start := time.Now()
	checked := start
	var u unconfirmed
	logged := false
	for {
		pctx, pcancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := client.Ping(pctx, &pb.PingRequest{})
		pcancel()
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return // shutting down
		}
		if !logged && time.Since(start) >= deadline {
			slog.Error("restart: this daemon has not answered its own Ping; the host stays 'upgrading'. "+
				"Peers that cannot reach it either fence it once its upgrading timeout passes; peers that reach it do not, "+
				"and it stays unplaceable (shown draining) until this daemon answers or an operator runs 'lv host undrain'. Still checking.",
				"deadline", deadline, "timeout", hostboot.UpgradingTimeout, "error", err)
			logged = true
		}
		if time.Since(checked) >= unconfirmedCheckEvery {
			d.noteUnconfirmed(ctx, &u, "this daemon has not answered its own Ping: "+err.Error())
			checked = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(pingPollInterval):
		}
	}
	if logged {
		slog.Info("restart: this daemon answered its own Ping after the deadline", "deadline", deadline)
	}
	d.confirmActiveWith(ctx, &u, true, confirm)
}

// unconfirmedCheckEvery is how often a ping loop that is not answered reads
// whether the host is past its upgrading window (noteUnconfirmed), rather than
// on every poll; a var so tests can shrink it.
var unconfirmedCheckEvery = 5 * time.Second

// confirmRetryFirst is the first backoff between attempts to record the host
// active; a var so tests can shrink it.
var confirmRetryFirst = time.Second

// confirmRetryMax caps the backoff between attempts to record the host active
// once this daemon serves; a var so tests can shrink it.
var confirmRetryMax = time.Minute

// unconfirmedAfter is how long the host may be recorded 'upgrading' before a
// daemon that runs raises upgrading_unconfirmed: the coordinator's upgrading
// timeout. A var so tests can shrink it.
var unconfirmedAfter = hostboot.UpgradingTimeout

// confirmActive records the host active after a restart, if it is still
// recorded 'upgrading', retrying a failed write with backoff (1 s doubling to
// confirmRetryMax, each attempt bounded to 5 s) until it lands, the host is
// recorded as something else, or the daemon shuts down. A write that fails is
// logged on every attempt and, past the upgrading timeout, raises
// upgrading_unconfirmed.
//
// served says this daemon answered its own Ping: the awaiting-serving note is
// cleared after the first attempt, whatever it did — after it, so a crash
// between the two leaves the note and the next boot is 'active'; whatever it
// did, because a WAL-quarantined daemon's write is refused on every attempt
// and must not make the boot after it 'active'.
func (d *Daemon) confirmActive(ctx context.Context, u *unconfirmed, served bool) {
	d.confirmActiveWith(ctx, u, served, nil)
}

// confirmActiveWith is confirmActive recording the host active with confirm:
// nil is the confirmServing test hook, or else hostboot.ConfirmServing.
func (d *Daemon) confirmActiveWith(ctx context.Context, u *unconfirmed, served bool, confirm confirmFunc) {
	if confirm == nil {
		confirm = d.confirmServing
	}
	if confirm == nil {
		confirm = func(ctx context.Context) (bool, string, error) {
			return hostboot.ConfirmServing(ctx, d.db, d.cfg.HostName)
		}
	}
	backoff := confirmRetryFirst
	for first := true; ; first = false {
		mctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, state, err := confirm(mctx)
		cancel()
		if first && served {
			hostboot.Served(d.cfg.DataDir)
		}
		switch {
		case errors.Is(err, hostboot.ErrNotUpgrading), errors.Is(err, hostboot.ErrMovedOn):
			slog.Info("restart: serving; this host's recorded state moved on since the boot, leaving it", "state", state, "detail", err)
			d.clearUnconfirmed(u)
			return
		case err == nil:
			slog.Info("restart: serving; host recorded active")
			d.clearUnconfirmed(u)
			return
		}
		if ctx.Err() != nil {
			return
		}
		slog.Warn("restart: recording the host active failed; it stays 'upgrading' until a retry lands",
			"error", err, "retry_in", backoff)
		d.noteUnconfirmed(ctx, u, "recording the host active failed: "+err.Error())
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > confirmRetryMax {
			backoff = confirmRetryMax
		}
	}
}

// unconfirmed is one serving check's upgrading_unconfirmed state.
type unconfirmed struct {
	raised  bool
	cause   string    // the cause the open condition carries
	wroteAt time.Time // when it was last written
	cleared bool      // a leftover from an earlier process was looked for
}

// unconfirmedRefresh is how often an open upgrading_unconfirmed whose cause has
// not changed is written again (its last_seen); a var so tests can shrink it.
var unconfirmedRefresh = 10 * time.Minute

// noteUnconfirmed raises upgrading_unconfirmed, and sets its metric, once the
// host has been recorded 'upgrading' for unconfirmedAfter while this check
// still has not recorded it active. cause names why. The condition is a
// replicated write, so it is written again only when the cause changes or
// unconfirmedRefresh has passed. A host no longer recorded 'upgrading' (an
// operator undrained it, it was fenced) has nothing to show: an open
// condition is resolved and the metric cleared.
func (d *Daemon) noteUnconfirmed(ctx context.Context, u *unconfirmed, cause string) {
	since, upgrading, err := hostboot.UpgradingState(ctx, d.db, d.cfg.HostName)
	if err != nil {
		return
	}
	if !upgrading {
		if u.raised || !u.cleared {
			d.clearUnconfirmed(u)
		}
		return
	}
	if since.IsZero() || time.Since(since) < unconfirmedAfter {
		return
	}
	metrics.SetUpgradingUnconfirmed(true)
	if u.raised && cause == u.cause && time.Since(u.wroteAt) < unconfirmedRefresh {
		return
	}
	if !u.raised || cause != u.cause {
		slog.Error("restart: this host has been 'upgrading' past its upgrading window while its daemon runs; peers that reach it do not fence it, and it stays unplaceable",
			"since", since.UTC().Format(time.RFC3339), "cause", cause, "remedy", hostboot.UnconfirmedRemedy)
	}
	if err := hostboot.RaiseUpgradingUnconfirmed(ctx, d.db, d.cfg.HostName, cause, since, time.Now()); err != nil {
		slog.Warn("restart: could not record the upgrading_unconfirmed condition (retried)", "error", err)
		return
	}
	u.raised, u.cause, u.wroteAt = true, cause, time.Now()
}

// clearUnconfirmed resolves upgrading_unconfirmed, including one an earlier
// process left, and clears its metric.
func (d *Daemon) clearUnconfirmed(u *unconfirmed) {
	metrics.SetUpgradingUnconfirmed(false)
	mctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := hostboot.ResolveUpgradingUnconfirmed(mctx, d.db, d.cfg.HostName, time.Now()); err != nil {
		slog.Warn("restart: could not resolve the upgrading_unconfirmed condition", "error", err)
		return
	}
	u.raised, u.cause, u.cleared = false, "", true
}

// rollbackToOld restores <binary>.old over the running binary path and exits
// non-zero so systemd restarts the restored binary. The attempt counter is
// bumped first so the restored binary's watchdog won't roll back again.
func (d *Daemon) rollbackToOld(binaryPath string, sentinel upgrade.Sentinel) {
	upgrade.BumpAttempt(binaryPath, sentinel)
	slog.Error("post-upgrade watchdog: NEW BINARY UNHEALTHY (local gRPC never pingable within deadline) — ROLLING BACK to previous binary",
		"prev_version", sentinel.PrevVersion)
	metrics.UpgradeWatchdogOutcome("rollback")
	// Linux permits renaming over the currently-executing file; the restored
	// binary content is what systemd execs on restart.
	if err := os.Rename(binaryPath+".old", binaryPath); err != nil {
		slog.Error("post-upgrade watchdog: rollback rename failed; exiting non-zero for systemd to retry", "error", err)
	}
	d.exit(1)
}

// localGRPCClient dials this node's own gRPC endpoint over real mTLS (the local
// host cert/CA — the host cert includes 127.0.0.1), the same TLS/auth shape a
// peer or CLI uses. No insecure bypass.
func (d *Daemon) localGRPCClient() (pb.LiteVirtClient, *grpc.ClientConn, error) {
	tlsCfg, err := pki.ClientTLSConfig(d.cfg.PKIDir)
	if err != nil {
		return nil, nil, err
	}
	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", d.cfg.GRPCPort),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, nil, err
	}
	return pb.NewLiteVirtClient(conn), conn, nil
}

// pinger is the slice of the gRPC client pingUntil needs — narrowed so tests can
// drive it without a live server. *pb.LiteVirtClient (the interface returned by
// localGRPCClient) satisfies it.
type pinger interface {
	Ping(ctx context.Context, in *pb.PingRequest, opts ...grpc.CallOption) (*pb.PingResponse, error)
}

// pingPollInterval is how often pingUntil retries; a var so tests can shrink it.
var pingPollInterval = 2 * time.Second

// pingUntil polls the local gRPC Ping until it succeeds or ctx (the deadline)
// expires. Returns true on the first successful Ping.
func pingUntil(ctx context.Context, client pinger) bool {
	ticker := time.NewTicker(pingPollInterval)
	defer ticker.Stop()
	for {
		pctx, pcancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := client.Ping(pctx, &pb.PingRequest{})
		pcancel()
		if err == nil {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

// exit terminates the process (overridable in tests).
func (d *Daemon) exit(code int) {
	// Flush telemetry (bounded) before an abnormal exit — os.Exit bypasses the
	// deferred ShutdownTelemetry in Run, so the last spans/logs (e.g. the rollback
	// itself) would otherwise be lost.
	if d.flushTelemetry != nil {
		d.flushTelemetry()
	}
	if d.exitFunc != nil {
		d.exitFunc(code)
		return
	}
	os.Exit(code)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
