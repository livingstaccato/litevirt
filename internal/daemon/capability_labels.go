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

// probeCapabilityLabels is every label's value from its probe.
func probeCapabilityLabels(labels []capabilityLabel) map[string]string {
	set := make(map[string]string, len(labels))
	for _, l := range labels {
		set[l.key] = "false"
		if l.capable() {
			set[l.key] = "true"
		}
	}
	return set
}

// assertCapabilityLabels is the start-time publication: every label from its
// probe, in one write of the labels column and none when they already say so
// (SetHostLabels). It returns what it published, which keepCapabilityLabels
// takes as this daemon's own values.
func assertCapabilityLabels(ctx context.Context, db *corrosion.Client, host string, labels []capabilityLabel) (map[string]string, error) {
	set := probeCapabilityLabels(labels)
	return set, corrosion.SetHostLabels(ctx, db, host, set, nil)
}

// keepCapabilityLabels re-asserts the labels every interval until ctx ends; the
// daemon asserts them once at start (assertCapabilityLabels), and asserted is
// what that published, or nil if that write failed.
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
// So each interval a MISSING label is written again. A label that is present
// is written only while it still holds the value this daemon published last,
// so it follows a runtime installed or removed while the daemon runs. A
// different value is an operator's override (`lv host label`) and stands until
// the operator changes it; the next start publishes the probe again, as it
// always has. A failure is logged once per run of failures.
func keepCapabilityLabels(ctx context.Context, db *corrosion.Client, host string, labels []capabilityLabel, asserted map[string]string, interval time.Duration) {
	own := make(map[string]string, len(asserted))
	for k, v := range asserted {
		own[k] = v
	}
	failing := false
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		set, err := reassertCapabilityLabels(ctx, db, host, labels, own)
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

// reassertCapabilityLabels writes the labels that are missing, or that still
// hold this daemon's own last value and whose probe now says otherwise, and
// records what it wrote in own.
func reassertCapabilityLabels(ctx context.Context, db *corrosion.Client, host string, labels []capabilityLabel, own map[string]string) (map[string]string, error) {
	h, err := corrosion.GetHost(ctx, db, host)
	if err != nil || h == nil {
		return nil, err // no row yet: nothing to label; the next interval retries
	}
	set := map[string]string{}
	for key, want := range probeCapabilityLabels(labels) {
		cur, ok := h.Labels[key]
		switch {
		case !ok:
			set[key] = want
		case cur != want && (own[key] == "" || cur == own[key]):
			// own is empty for a label the start-time write did not land:
			// the value there is not known to be an override, so the probe's
			// stands, as a retry of that write.
			set[key] = want
		}
	}
	if len(set) == 0 {
		return set, nil
	}
	if err := corrosion.SetHostLabels(ctx, db, host, set, nil); err != nil {
		return set, err
	}
	for k, v := range set {
		own[k] = v
	}
	return set, nil
}
