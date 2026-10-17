package daemon

import (
	"context"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"sync"
	"time"
)

type daemonStopReason uint8

const (
	daemonContextStop daemonStopReason = iota
	daemonReExecStop
	daemonUninstallStop
)

// dbWorkerCoordinator is the daemon's ownership of its LB and release-use
// loops. Startup calls remain at their existing points in Run.
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
	prepare(reason)
	c.cancel()
	stopServing()
	// The bounded stop above is not handler quiescence. Keep dependencies open
	// even when Run reaches its existing process-exit timeout while we wait.
	c.wg.Wait()
	c.svc.WaitFirewallTagWork()
	c.svc.WaitDeleteVMWork()
	cleanup()
}
