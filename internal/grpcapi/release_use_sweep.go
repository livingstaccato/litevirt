package grpcapi

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The release use sweep records a release feature's use found in replicated
// data. A row of a feature's data can arrive with no recorded use: one
// written through an entry daemon that predates the gate, by a client other
// than lv. Unrecorded, a later rollback below the release would not
// quarantine, and the rolled-back build would run over data it drops. So the
// failover lease holder looks, every releaseUseSweepInterval once the
// feature's release token has latched, for each probed feature's data, and
// records the use of any present but unrecorded — through the gate, with no
// data write, as a write of the data would have.

// releaseUseProbe reports whether one release feature's data is present in
// this replica.
type releaseUseProbe struct {
	feature capabilities.Feature
	present func(ctx context.Context, db *corrosion.Client) (bool, error)
}

// releaseUseProbes are the features the sweep looks for, one data probe each.
var releaseUseProbes []releaseUseProbe

// releaseUseSweepInterval is how often the lease holder sweeps.
const releaseUseSweepInterval = 5 * time.Minute

// RunReleaseUseSweep runs the release use sweep until ctx ends.
func (s *Server) RunReleaseUseSweep(ctx context.Context) {
	s.runReleaseUseSweep(ctx, releaseUseSweepInterval, releaseUseProbes)
}

func (s *Server) runReleaseUseSweep(ctx context.Context, every time.Duration, probes []releaseUseProbe) {
	if len(probes) == 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweepReleaseUses(ctx, probes)
		}
	}
}

// sweepReleaseUses is one pass: on the failover lease holder only, for each
// probe whose feature is available (its release token has durably latched
// here) and not recorded as used, whose data is present, it records the use.
func (s *Server) sweepReleaseUses(ctx context.Context, probes []releaseUseProbe) {
	held, err := corrosion.IsLeaseHolder(ctx, s.db, corrosion.LeaseKeyFailover, s.hostName, time.Now())
	if err != nil || !held {
		return
	}
	for _, p := range probes {
		if !s.ReleaseFeatureAvailable(p.feature) {
			continue
		}
		info, ok := capabilities.LookupFeature(p.feature)
		if !ok {
			continue
		}
		used, err := corrosion.ReleaseFeatureUsed(ctx, s.db, info.Token, string(p.feature))
		if err != nil || used {
			continue
		}
		present, err := p.present(ctx, s.db)
		if err != nil {
			slog.Warn("release use sweep: could not read a feature's data", "feature", p.feature, "error", err)
			continue
		}
		if !present {
			continue
		}
		if err := s.WithReleaseFeature(ctx, p.feature, func(context.Context, capabilities.FeatureGrant) error { return nil }); err != nil {
			slog.Info("release use sweep: could not record a use found in data yet; retrying next sweep",
				"feature", p.feature, "error", err)
			continue
		}
		slog.Info("release use sweep: recorded a use found in replicated data", "feature", p.feature)
	}
}
