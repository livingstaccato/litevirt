package daemon

import (
	"context"
	"sync"

	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/metrics"
)

// wirePeerHAState sets fc.PeerHAState from the server's recorded Ready
// answers. No-op until HA disarm is implemented.
func (d *Daemon) wirePeerHAState(fc *failover.Coordinator, svc *grpcapi.Server) {}

// wireFenceCandidates installs the server's fence-candidate hook. No-op until
// HA disarm is implemented.
func (d *Daemon) wireFenceCandidates(svc *grpcapi.Server) {}

// startHAPolicyCache starts the refresher of the server's HA policy cache,
// which Ready answers from, and this node's HA conditions and
// litevirt_ha_disarmed with it.
func (d *Daemon) startHAPolicyCache(ctx context.Context, svc *grpcapi.Server) {
	svc.SetHADisarmedGauge(d.haMetrics().Disarmed)
	go svc.RunHAPolicyCache(ctx)
}

// haMetrics is the HA policy's gauges, registered once.
func (d *Daemon) haMetrics() *metrics.HADisarmMetrics {
	haMetricsOnce.Do(func() { haMetricsSingleton = metrics.NewHADisarmMetrics() })
	return haMetricsSingleton
}

var (
	haMetricsOnce      sync.Once
	haMetricsSingleton *metrics.HADisarmMetrics
)

// startHADisarmPreRecord starts the lease holder's first-use record of
// ha_disarm. No-op until HA disarm is implemented.
func (d *Daemon) startHADisarmPreRecord(ctx context.Context, fc *failover.Coordinator) {}
