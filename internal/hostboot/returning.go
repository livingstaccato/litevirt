package hostboot

import (
	"context"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// returning reports whether a host recorded state returns to service by
// booting: the cluster recorded it down (fenced, offline), out of service
// (maintenance, draining) or not yet started (joining). Its boot ends that
// state, as it always has, so no `lv host undrain` is needed after a reboot.
func returning(state string) bool {
	switch state {
	case "fenced", "offline", "maintenance", "draining", corrosion.HostStateJoining:
		return true
	}
	return false
}

// returningBoot is the boot of a host recorded in a returning state: it
// records the host 'upgrading' until its daemon serves (ConfirmServing), not
// 'active' at once, once the returning_boot release feature is open
// (Boot.Returning, WriteReturningBoot); until then the daemon writes
// Fallback, 'active' at once. An 'active' boot write starts the host's new life
// (corrosion.HostsActiveSince), and once a whole failing run has passed since
// it, the coordinator fences on the failures its observers counted while the
// daemon was still starting; 'upgrading' is skipped for UpgradingTimeout from
// the write and fenced after it if the daemon never serves.
//
// It applies whatever the marker, the unclean-boot history or AwaitingPath
// say, which the boot consumes and records as for any boot: those bound how
// often a host recorded 'active' or 'upgrading' is written 'upgrading', and
// this write needs no such bound. It is made only over a returning state,
// which the host's own daemon never writes for itself, so it happens once per
// fence, drain or admission: a crash of this boot before it serves finds the
// host 'upgrading', which the restart rules decide.
//
// The write ends the returning state as the 'active' one did: a recorded
// fence's authority to resume a recovery (the coordinator resumes only from
// 'fenced' or 'offline'), and the maintenance or drain. The host's isolation
// is kept. The write is guarded on the state read here (From): readHost
// resolves the state from the same copy the guard checks (the membership row
// when it exists), so a fence, undrain or drain recorded between the read and
// the write is kept, and nothing else refuses it. ok=false, and the boot is
// decided as before, for any other state and for a record this boot cannot
// read. A fenced or offline host whose boot cannot record its unclean-boot
// history keeps the fence instead (Deferred, no write).
func returningBoot(ctx context.Context, db *corrosion.Client, host, dataDir string, marked bool, now time.Time) (Boot, bool) {
	h, err := readHost(ctx, db, host)
	if err != nil || h == nil || !returning(h.State) {
		return Boot{}, false
	}
	if !marked && dataDir != "" {
		// Counted like any boot without the marker, so a crash loop that
		// follows is judged on its whole history.
		if _, herr := recordUncleanBoot(dataDir, now); herr != nil && (h.State == "fenced" || h.State == "offline") {
			// A host that cannot record its own boot history keeps a fence
			// the cluster recorded: no boot write, and none once it serves
			// (ConfirmServingReport keeps fenced and offline). An operator
			// returns it (`lv host undrain`). Whether or not returning_boot
			// is open.
			return Boot{State: h.State, AwaitServing: true, Deferred: true, KeptFence: true, Cause: herr.Error(),
				Reason: "recorded " + h.State + ", and recording this unclean boot failed (" + herr.Error() + "); the fence is kept until an operator returns this host"}, true
		}
	}
	// Bounded by the returning state itself, so written whether or not the
	// note can be left.
	return noteAwaiting(dataDir, Boot{State: "upgrading", AwaitServing: true, From: h.State, Returning: true,
		Reason: "recorded " + h.State + "; returning to service, active once this daemon serves"}, now, true), true
}

// WriteReturningBoot is a returning boot's write (Boot.Returning): host
// 'upgrading', with the boot report, only while it is still recorded from,
// checked in the write's own transaction. It is the returning_boot release
// feature's data: a failover leader on the previous release clears a fenced
// host from its handled cache only once the host is 'active', so until every
// host runs this release, an 'upgrading' over a returning state could leave a
// host that never serves unfenced and its parked recovery dropped. g is the
// release gate's grant (health.Checker.WithFeature).
func WriteReturningBoot(ctx context.Context, db *corrosion.Client, host string, g capabilities.FeatureGrant, from string, r Report) (bool, error) {
	if err := g.Check(capabilities.FeatureReturningBoot); err != nil {
		return false, err
	}
	return corrosion.UpdateHostStartupFrom(ctx, db, host, from, "upgrading", r.Version, r.CPUs, r.MemMiB, r.DiskGiB, r.HasResources)
}

// Fallback is a returning boot whose returning_boot feature is not open: the
// boot write records the host 'active' at once, as before this release, still
// guarded on the state it read. Any other boot is returned unchanged.
func (b Boot) Fallback(why string) Boot {
	if !b.Returning {
		return b
	}
	return Boot{State: "active", From: b.From,
		Reason: "recorded " + b.From + "; returning to service, active at once as before (" + why + ")"}
}
