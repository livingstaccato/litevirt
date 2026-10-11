package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// capabilityLabelInterval is how often the daemon re-asserts its capability
// labels.
const capabilityLabelInterval = time.Minute

// capabilityLabel is one host label the daemon publishes from a probe of its
// own runtime: "true" where the probe finds the capability, else "false".
type capabilityLabel struct {
	key     string
	capable func() bool
}

// assertCapabilityLabels writes every label from its probe, in one write of
// the labels column and none when they already say so (SetHostLabels).
func assertCapabilityLabels(ctx context.Context, db *corrosion.Client, host string, labels []capabilityLabel) (map[string]string, error) {
	set := make(map[string]string, len(labels))
	for _, l := range labels {
		set[l.key] = "false"
		if l.capable() {
			set[l.key] = "true"
		}
	}
	return set, corrosion.SetHostLabels(ctx, db, host, set, nil)
}

// keepCapabilityLabels re-asserts the labels every interval until ctx ends; the
// daemon asserts them once at start, before this runs.
//
// Placement is strict about each of them: a host whose record does not say
// litevirt.lxc=true runs no container (corrosion.HostRunsContainers), and one
// that does not say litevirt.tpm / litevirt.secureboot=true gets no vTPM or
// Secure Boot VM. Written once at start, a label was lost until the next
// restart whenever:
//   - the start-time write found no host row yet (the UPDATE matched nothing);
//   - a concurrent read-modify-write of the labels column replaced it;
//   - the host was re-added while its data directory still held its old
//     database. At start its own row there already carried every label, so
//     nothing was written; then the re-admission's row, whose labels are
//     reset, won on every node (host_readmit.go, THE INCARNATION), this one
//     included.
//
// Re-asserting heals each of those within one interval, and also follows a
// runtime installed or removed while the daemon runs. A failure is logged once
// per run of failures.
func keepCapabilityLabels(ctx context.Context, db *corrosion.Client, host string, labels []capabilityLabel, interval time.Duration) {
	failing := false
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		set, err := assertCapabilityLabels(ctx, db, host, labels)
		switch {
		case err != nil && !failing && ctx.Err() == nil:
			slog.Warn("set capability host labels failed; retrying — until they land, placement may put no "+
				"container, vTPM or Secure Boot VM on this host",
				"labels", set, "retry_in", interval, "error", err)
			failing = true
		case err == nil && failing:
			slog.Info("set capability host labels", "labels", set)
			failing = false
		}
	}
}
