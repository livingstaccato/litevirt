package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// lxcLabelInterval is how often the daemon re-asserts its litevirt.lxc label.
const lxcLabelInterval = time.Minute

// assertLXCLabel writes this host's litevirt.lxc label (corrosion.LabelLXCCapable)
// from the runtime probe: "true" where lxc-create is found, else "false".
// SetHostLabel writes nothing when the label already says so.
func assertLXCLabel(ctx context.Context, db *corrosion.Client, host string, available func() bool) (string, error) {
	capable := "false"
	if available() {
		capable = "true"
	}
	return capable, corrosion.SetHostLabel(ctx, db, host, corrosion.LabelLXCCapable, capable)
}

// keepLXCLabel re-asserts the label every interval until ctx ends; the daemon
// asserts it once at start, before this runs.
//
// Placement is strict (corrosion.HostRunsContainers): a host whose record does
// not say litevirt.lxc=true runs no container. Written once at start, a write
// that failed — or that found no host row yet, or a label a concurrent
// read-modify-write of the labels column replaced — left a capable host
// refusing every container until its next restart. Re-asserting heals each of
// those within one interval, and also follows a runtime installed or removed
// while the daemon runs. A failure is logged once per run of failures.
func keepLXCLabel(ctx context.Context, db *corrosion.Client, host string, available func() bool, interval time.Duration) {
	failing := false
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		capable, err := assertLXCLabel(ctx, db, host, available)
		switch {
		case err != nil && !failing && ctx.Err() == nil:
			slog.Warn("set LXC capability host label failed; retrying — until it lands, placement puts no container on this host",
				"capable", capable, "retry_in", interval, "error", err)
			failing = true
		case err == nil && failing:
			slog.Info("set LXC capability host label", "capable", capable)
			failing = false
		}
	}
}
