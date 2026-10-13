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

// awaitServingThenActivate is the boot after a graceful stop
// (hostboot.BootState): the host stays 'upgrading' until this daemon answers
// its own Ping over mTLS, and is then recorded active. There is no binary to
// roll back to. If it never answers within the upgrade health deadline the
// host is LEFT 'upgrading', and the failover coordinator fences it once
// hostboot.UpgradingTimeout has passed since the boot write: a daemon that
// cannot serve is a failed host.
func (d *Daemon) awaitServingThenActivate(ctx context.Context) {
	deadline := time.Duration(d.cfg.UpgradeHealthDeadlineSec) * time.Second
	if deadline <= 0 {
		deadline = 120 * time.Second
	}
	dial := d.selfPinger
	if dial == nil {
		dial = func() (pinger, func(), error) {
			client, conn, err := d.localGRPCClient()
			if err != nil {
				return nil, nil, err
			}
			return client, func() { _ = conn.Close() }, nil
		}
	}
	client, closeFn, err := dial()
	if err != nil {
		// Environmental, and it would never let the host turn active: record
		// it active now, as the boot write did before.
		slog.Warn("restart: cannot build the local gRPC client to confirm serving; recording the host active now", "error", err)
		d.activateAfterRestart()
		return
	}
	defer closeFn()
	d.activateOnceServing(ctx, client, deadline)
}

// activateOnceServing pings this daemon until it answers, and then records the
// host active. Until it answers the host stays 'upgrading' — there is no
// previous binary to roll back to — and the coordinator fences it once its
// upgrading timeout has passed.
//
// The deadline only times the error log. Pinging goes on past it, until the
// daemon answers or shuts down: a daemon that comes up late is a healthy host,
// and nothing else would ever record it active again (recoverHosts revives
// only offline and fenced hosts), so stopping at the deadline left it
// 'upgrading' — unplaceable, shown draining — until an operator undrained it.
// ConfirmServing still refuses a host fenced or otherwise moved on meanwhile.
func (d *Daemon) activateOnceServing(ctx context.Context, client pinger, deadline time.Duration) {
	dctx, cancel := context.WithTimeout(ctx, deadline)
	answered := pingUntil(dctx, client)
	cancel()
	if !answered {
		if ctx.Err() != nil {
			return // shutting down
		}
		slog.Error("restart: this daemon has not answered its own Ping; the host stays 'upgrading', and the cluster fences it once its upgrading timeout passes. Still checking.",
			"deadline", deadline, "timeout", hostboot.UpgradingTimeout)
		if !pingUntil(ctx, client) {
			return // shutting down
		}
		slog.Info("restart: this daemon answered its own Ping after the deadline", "deadline", deadline)
	}
	d.activateAfterRestart()
}

// activateAfterRestart records the host active after a graceful restart, if it
// is still recorded 'upgrading'.
func (d *Daemon) activateAfterRestart() {
	mctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, state, err := hostboot.ConfirmServing(mctx, d.db, d.cfg.HostName)
	switch {
	case errors.Is(err, hostboot.ErrNotUpgrading):
		slog.Info("restart: serving; host is recorded as something other than upgrading, leaving it", "state", state)
	case err != nil:
		slog.Error("restart: serving, but recording the host active failed; it stays 'upgrading'", "error", err)
	default:
		slog.Info("restart: serving; host recorded active")
	}
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
