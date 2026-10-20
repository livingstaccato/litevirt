package daemon

import (
	"context"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"log/slog"
	"sync"
	"time"
)

type daemonStopReason uint8

const (
	daemonContextStop daemonStopReason = iota
	daemonReExecStop
	daemonUninstallStop
)

// dbWorkerCoordinator owns the daemon's LB, release-use and firmware
// producer loops. Startup calls remain at their existing points in Run.
type dbWorkerCoordinator struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	svc    *grpcapi.Server
}

func newDBWorkerCoordinator(ctx context.Context, svc *grpcapi.Server) *dbWorkerCoordinator {
	ctx, cancel := context.WithCancel(ctx)
	return &dbWorkerCoordinator{ctx: ctx, cancel: cancel, svc: svc}
}
func (c *dbWorkerCoordinator) startSweep() {
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.svc.RunReleaseUseSweep(c.ctx) }()
}
func (c *dbWorkerCoordinator) startLB(interval time.Duration) {
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.svc.RunLBReconciler(c.ctx, interval) }()
}
func (c *dbWorkerCoordinator) shutdown(ctx context.Context, reexec, shutdown <-chan struct{}, prepare func(daemonStopReason), stopServing, cleanup func()) {
	var reason daemonStopReason
	select {
	case <-ctx.Done():
		reason = daemonContextStop
	case <-reexec:
		reason = daemonReExecStop
	case <-shutdown:
		reason = daemonUninstallStop
	}
	c.svc.StopDeleteVMAdmission()
	c.svc.StopFirewallTagAdmission()
	c.svc.StopMigrationAdmission()
	prepare(reason)
	c.cancel()
	stopServing()
	// The bounded stop above is not handler quiescence. Keep dependencies open
	// even when Run reaches its existing process-exit timeout while we wait.
	c.wait()
	cleanup()
}

// wait follows cancellation and stop-serving. Joining producers first means
// no recovery pass can call recovering.Add concurrently with the final wait.
// Recovery children can detach from cancellation and launch announcements, so
// their actual terminal precedes the announcement join and dependency cleanup.
func (c *dbWorkerCoordinator) wait() {
	c.wg.Wait()
	c.svc.WaitFirmwareMoveRecovery()
	c.svc.WaitFirewallTagWork()
	c.svc.WaitDeleteVMWork()
	c.svc.WaitGatewayAnnouncements()
}

// stopStartup is used only when Run returns before transferring ownership to
// the normal shutdown goroutine. No dependency is closed on this path. A
// blocked detached child retains those dependencies after the outer bound.
func (c *dbWorkerCoordinator) stopStartup(bound time.Duration) {
	c.svc.StopDeleteVMAdmission()
	c.svc.StopFirewallTagAdmission()
	c.svc.StopMigrationAdmission()
	c.cancel()
	done := make(chan struct{})
	go func() { c.wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(bound):
		slog.Warn("startup worker cleanup is still running; leaving its dependencies open")
	}
}

// The initial call still takes VM locks synchronously at the journal barrier.
// Its children and all later producers use the same owned context, including
// reexec/uninstall, where Run's outer context can remain live.
func (c *dbWorkerCoordinator) recoverFirmwareMoves(_ context.Context) {
	c.svc.RecoverFirmwareMoves(c.ctx)
}
func (c *dbWorkerCoordinator) startFirmwareSweeps(_ context.Context) {
	c.wg.Add(2)
	go func() { defer c.wg.Done(); c.svc.RunFirmwareHoldSweep(c.ctx) }()
	go func() { defer c.wg.Done(); c.svc.RunFirmwareRetainedSweep(c.ctx) }()
}
func (c *dbWorkerCoordinator) startFirmwareMoveRecovery(_ context.Context) {
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.svc.RunFirmwareMoveRecovery(c.ctx) }()
}
func (c *dbWorkerCoordinator) startReplicaOrphanSweep(_ context.Context) {
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.svc.RunReplicaOrphanSweep(c.ctx) }()
}
