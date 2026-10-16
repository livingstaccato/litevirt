package hostboot

import (
	"context"
	"time"

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
// 'active' at once. An 'active' boot write starts the host's new life
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
// read.
func returningBoot(ctx context.Context, db *corrosion.Client, host, dataDir string, marked bool, now time.Time) (Boot, bool) {
	h, err := readHost(ctx, db, host)
	if err != nil || h == nil || !returning(h.State) {
		return Boot{}, false
	}
	if !marked && dataDir != "" {
		// Counted like any boot without the marker, so a crash loop that
		// follows is judged on its whole history. Best effort: this boot's
		// decision does not depend on it.
		_, _ = recordUncleanBoot(dataDir, now)
	}
	// Bounded by the returning state itself, so written whether or not the
	// note can be left.
	return noteAwaiting(dataDir, Boot{State: "upgrading", AwaitServing: true, From: h.State,
		Reason: "recorded " + h.State + "; returning to service, active once this daemon serves"}, now, true), true
}
