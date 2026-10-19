package grpcapi

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// SeedFirewallSynfloodLoop records the founder's genesis decision
// (decisionPath, written by the daemon when it founded the cluster: on) as
// the cluster's SYN-flood policy, on at the defaults
// (corrosion.SeedFirewallSynflood), audits it, and only then removes the
// decision. Its write needs the firewall_synflood release feature, refused
// until release_2026_11_v1 has latched, so it retries every `every` through
// those refusals, on its own decision file and loop: the enforcement seed
// lands as soon as the cluster_policies gate opens, which may be long before.
// A row already recorded (an operator's, or a peer's) ends it without a
// write. With no decision on disk — a joiner, a rejoiner, a host of a
// cluster that upgraded — it records nothing, and protection stays off.
func (s *Server) SeedFirewallSynfloodLoop(ctx context.Context, every time.Duration, decisionPath string) {
	b, err := os.ReadFile(decisionPath)
	if err != nil {
		return
	}
	if v := strings.TrimSpace(string(b)); v != corrosion.SynfloodOn {
		slog.Warn("firewall: ignoring an unreadable initial SYN-flood decision", "path", decisionPath, "value", v)
		return
	}
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, recorded, _ := corrosion.GetFirewallSynflood(ctx, s.db, ""); recorded {
			_ = os.Remove(decisionPath)
			return
		}
		var wrote bool
		err := s.WithReleaseFeature(ctx, capabilities.FeatureFirewallSynflood, func(ctx context.Context, g capabilities.FeatureGrant) error {
			var err error
			wrote, err = corrosion.SeedFirewallSynflood(ctx, s.db, g, s.hostName)
			return err
		})
		switch {
		case err != nil:
			slog.Debug("firewall: the initial SYN-flood policy is not recorded yet", "error", err)
		case wrote:
			slog.Info("firewall: recorded the cluster's initial SYN-flood protection", "rate", corrosion.SynfloodDefaultRate,
				"burst", corrosion.SynfloodDefaultBurst)
			s.auditAs(ctx, "litevirt", "firewall.synflood", corrosion.FirewallSynfloodScopeCluster,
				corrosion.AuditChange(corrosion.AuditStateUnset, synfloodAuditText(corrosion.FirewallSynflood{
					Mode: corrosion.SynfloodOn, Rate: corrosion.SynfloodDefaultRate, Burst: corrosion.SynfloodDefaultBurst}, true, nil))+
					" (initial, at genesis)", "ok")
			_ = os.Remove(decisionPath)
			s.reconcileLocal(ctx)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
