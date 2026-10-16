package failover

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// HADisarmPreRecord records the first use of ha_disarm with NO data write, so
// the first `lv cluster ha disarm` during an incident does not need every host
// reachable (docs/migration-failover.md). with is the release-feature gate
// (health.Checker.WithFeature). Nothing writes the `ha` row: operators are its
// only writers, so nothing automatic can overwrite their choice.
func HADisarmPreRecord(ctx context.Context, with func(context.Context, capabilities.Feature,
	func(context.Context, capabilities.FeatureGrant) error) error) error {
	return with(ctx, capabilities.FeatureHADisarm, func(context.Context, capabilities.FeatureGrant) error { return nil })
}

// HAPreRecorder pays the first use of ha_disarm on the lease holder, in its own
// goroutine, never inside a coordinator cycle.
type HAPreRecorder struct {
	// Name is the feature, for the log ("ha_disarm" when empty). The same
	// recorder pays other features used by default (returning_boot).
	Name string
	// HoldsLease, Latched (release_2026_11_v1 durably latched here) and Paid
	// (the used record is present and acknowledged) decide whether to try.
	HoldsLease func() bool
	Latched    func() bool
	Paid       func(ctx context.Context) (bool, error)
	// Record is HADisarmPreRecord over the gate.
	Record func(ctx context.Context) error
	// Timeout bounds each attempt (above the release gate's own 30 s
	// acknowledgement wait); Poll is the wait between checks; Backoff the
	// first wait after a failed attempt, doubled up to MaxBackoff.
	Timeout, Poll, Backoff, MaxBackoff time.Duration
}

// Run tries until the use is paid or ctx ends.
func (p *HAPreRecorder) Run(ctx context.Context) {
	timeout, poll, backoff, maxBackoff := p.Timeout, p.Poll, p.Backoff, p.MaxBackoff
	if timeout <= 0 {
		timeout = 35 * time.Second
	}
	if poll <= 0 {
		poll = 30 * time.Second
	}
	if backoff <= 0 {
		backoff = 30 * time.Second
	}
	if maxBackoff <= 0 {
		maxBackoff = 10 * time.Minute
	}
	wait := poll
	delay := backoff
	for {
		if paid, err := p.Paid(ctx); err == nil && paid {
			return
		}
		if p.HoldsLease() && p.Latched() {
			actx, cancel := context.WithTimeout(ctx, timeout)
			err := p.Record(actx)
			cancel()
			if err == nil {
				if p.Name == "" || p.Name == string(capabilities.FeatureHADisarm) {
					slog.Info("ha-disarm: the first use is recorded; a disarm no longer needs every host reachable")
				} else {
					slog.Info("release feature: the first use is recorded", "feature", p.Name)
				}
				return
			}
			slog.Info("release feature: could not record the first use yet; retrying", "feature", p.featureName(), "error", err, "retry_in", delay)
			wait = delay
			if delay *= 2; delay > maxBackoff {
				delay = maxBackoff
			}
		} else {
			wait = poll
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// featureName is the feature the recorder pays, for the log.
func (p *HAPreRecorder) featureName() string {
	if p.Name == "" {
		return string(capabilities.FeatureHADisarm)
	}
	return p.Name
}
