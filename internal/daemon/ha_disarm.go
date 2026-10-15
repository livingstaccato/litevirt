package daemon

import (
	"context"
	"sync"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/metrics"
)

// wirePeerHAState gives the failover coordinator the HA-disarm peer veto: each
// peer's latest Ready answer about the HA policy, the set of voters this node's
// quorum counts live, and litevirt_ha_peer_veto.
func (d *Daemon) wirePeerHAState(fc *failover.Coordinator, svc *grpcapi.Server) {
	fc.PeerHAState = func(peer string) (failover.PeerHAAnswer, bool) {
		asked, known, disarmed, policyAt, ok := svc.PeerHAAnswer(peer)
		return failover.PeerHAAnswer{Asked: asked, Known: known, Disarmed: disarmed, PolicyAt: policyAt}, ok
	}
	fc.LiveVoters = d.checker.LiveVoters
	fc.HAPeerVetoGauge = d.haMetrics().PeerVeto
}

// wireFenceCandidates installs the server's fence-candidate hook. No-op until
// HA disarm's RPCs are implemented.
func (d *Daemon) wireFenceCandidates(svc *grpcapi.Server) {}

// startHAPolicyCache starts the refresher of the server's HA policy cache,
// which Ready answers from, and this node's HA conditions and
// litevirt_ha_disarmed with it.
func (d *Daemon) startHAPolicyCache(ctx context.Context, svc *grpcapi.Server) {
	svc.SetHADisarmedGauge(d.haMetrics().Disarmed)
	go svc.RunHAPolicyCache(ctx)
}

// startHADisarmPreRecord starts the lease holder's first-use record of
// ha_disarm: once release_2026_11_v1 has latched, the lease holder records
// the use with no data write, so the first disarm does not need every host
// reachable. Its own goroutine, never inside a coordinator cycle.
func (d *Daemon) startHADisarmPreRecord(ctx context.Context, fc *failover.Coordinator) {
	info, ok := capabilities.LookupFeature(capabilities.FeatureHADisarm)
	if !ok {
		return
	}
	p := &failover.HAPreRecorder{
		HoldsLease: fc.HoldsLease,
		Latched:    func() bool { return d.checker.DurablyLatched(info.Token) },
		Paid: func(ctx context.Context) (bool, error) {
			present, acked, err := corrosion.ReleaseFeatureState(ctx, d.db, info.Token, string(capabilities.FeatureHADisarm))
			return present && acked, err
		},
		Record: func(ctx context.Context) error { return failover.HADisarmPreRecord(ctx, d.checker.WithFeature) },
	}
	go p.Run(ctx)
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
