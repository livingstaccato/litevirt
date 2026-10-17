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
var releaseUseProbes = []releaseUseProbe{
	{feature: capabilities.FeatureFirewallTagGroups, present: corrosion.FirewallTagGroupsDataPresent},
}

// releaseUseSweepInterval is how often the lease holder sweeps.
const releaseUseSweepInterval = 5 * time.Minute

// RunReleaseUseSweep runs the release use sweep until ctx ends.
func (s *Server) RunReleaseUseSweep(ctx context.Context) {
	s.runReleaseUseSweep(ctx, releaseUseSweepInterval, releaseUseProbes)
}

func (s *Server) runReleaseUseSweep(ctx context.Context, every time.Duration, probes []releaseUseProbe) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweepReleaseUses(ctx, probes)
			s.sweepFirewallTagOrphans(ctx, time.Now())
			s.sweepVMScheduleOrphans(ctx, time.Now())
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
		if err != nil {
			slog.Warn("release use sweep: could not read a feature's used record", "feature", p.feature, "error", err)
			continue
		}
		if used {
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

// firewallTagsOrphanGrace is how long a firewall-tags row whose identity no
// live workload holds is kept: it covers a move or re-create in flight, which
// leaves no live row for a moment (spec §4.3).
const firewallTagsOrphanGrace = 24 * time.Hour

// sweepFirewallTagOrphans is the firewall-tags orphan sweep (spec §4.3, m-4):
// on the failover lease holder, once firewall_tag_groups is recorded used, it
// clears every tags row corrosion.FirewallTagsOrphans selects at now — no live
// workload holds its identity, and the newest tombstone holding it, or the
// row itself when nothing holds it, is older than the grace. So every orphan
// is cleared within the grace plus one sweep interval. A clear is hygiene: an
// orphan row already matches no workload.
func (s *Server) sweepFirewallTagOrphans(ctx context.Context, now time.Time) {
	held, err := corrosion.IsLeaseHolder(ctx, s.db, corrosion.LeaseKeyFailover, s.hostName, time.Now())
	if err != nil || !held {
		return
	}
	info, _ := capabilities.LookupFeature(capabilities.FeatureFirewallTagGroups)
	if used, err := corrosion.ReleaseFeatureUsed(ctx, s.db, info.Token, string(capabilities.FeatureFirewallTagGroups)); err != nil || !used {
		return
	}
	orphans, err := corrosion.FirewallTagsOrphans(ctx, s.db, now, firewallTagsOrphanGrace)
	if err != nil {
		slog.Warn("firewall tags sweep: could not read the rows", "error", err)
		return
	}
	if len(orphans) == 0 {
		return
	}
	if err := s.WithReleaseFeature(ctx, capabilities.FeatureFirewallTagGroups, func(ctx context.Context, g capabilities.FeatureGrant) error {
		for _, o := range orphans {
			if err := corrosion.ClearFirewallTags(ctx, s.db, g, o.Kind, o.FWID); err != nil {
				slog.Warn("firewall tags sweep: could not clear an orphan row", "kind", o.Kind, "fw_id", o.FWID, "error", err)
				continue
			}
			slog.Info("firewall tags sweep: cleared the tags of an identity no workload holds",
				"kind", o.Kind, "fw_id", o.FWID, "name", o.Name)
		}
		return nil
	}); err != nil {
		slog.Info("firewall tags sweep: the release gate refused; retrying next sweep", "error", err)
	}
}

// sweepVMScheduleOrphans is the vm-schedule orphan sweep: on the failover
// lease holder, it tombstones every schedule corrosion.OrphanedVMSchedules
// selects at now — a schedule of a VM deleted more than
// VMScheduleOrphanGrace ago, written no later than its tombstone. A delete
// removes the VM's schedules itself (deleteVMSchedules); this clears what a
// delete left: one by an older build, or one that failed to remove them.
func (s *Server) sweepVMScheduleOrphans(ctx context.Context, now time.Time) {
	held, err := corrosion.IsLeaseHolder(ctx, s.db, corrosion.LeaseKeyFailover, s.hostName, time.Now())
	if err != nil || !held {
		return
	}
	orphans, err := corrosion.OrphanedVMSchedules(ctx, s.db, now, corrosion.VMScheduleOrphanGrace)
	if err != nil {
		slog.Warn("schedule sweep: could not read the schedules of deleted VMs", "error", err)
		return
	}
	for _, o := range orphans {
		if err := s.deleteScheduleRow(ctx, o.VMName, o.Repo); err != nil {
			slog.Warn("schedule sweep: could not remove the schedule of a deleted VM", "vm", o.VMName, "repo", o.Repo, "error", err)
			continue
		}
		slog.Info("schedule sweep: removed the schedule of a deleted VM", "vm", o.VMName, "repo", o.Repo)
	}
}

// SweepVMScheduleOrphansForTest runs one pass of the vm-schedule orphan sweep.
func (s *Server) SweepVMScheduleOrphansForTest(ctx context.Context, now time.Time) {
	s.sweepVMScheduleOrphans(ctx, now)
}
