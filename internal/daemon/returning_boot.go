package daemon

import (
	"context"
	"errors"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/hostboot"
)

// releaseGate is health.Checker.WithFeature's shape.
type releaseGate func(ctx context.Context, feature capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error

// returningGateTimeout bounds the boot's wait on the release gate. The gate
// asks no peer once the feature's use is recorded and acknowledged, which the
// lease holder pays soon after the release latches
// (startReturningBootPreRecord); a first use the boot would have to pay
// itself cannot be acknowledged this early, and the boot then falls back.
const returningGateTimeout = 5 * time.Second

// returningBootGate is the gate a returning boot's write goes through: the
// checker's, or nil before there is one (the boot then falls back).
func (d *Daemon) returningBootGate() releaseGate {
	if d.returningGate != nil {
		return d.returningGate
	}
	if d.checker == nil {
		return nil
	}
	return d.checker.WithFeature
}

// writeReturningBoot makes a returning boot's 'upgrading' write through the
// returning_boot release feature's gate. wrote=false, with the gate's
// refusal, when the gate did not run the write: the caller then records the
// host 'active', as before this release (Boot.Fallback). Otherwise applied and
// err are the guarded write's.
func (d *Daemon) writeReturningBoot(ctx context.Context, boot hostboot.Boot, r hostboot.Report) (wrote, applied bool, err error) {
	gate := d.returningBootGate()
	if gate == nil {
		return false, false, errors.New("no release gate yet")
	}
	gctx, cancel := context.WithTimeout(ctx, returningGateTimeout)
	defer cancel()
	var werr error
	gerr := gate(gctx, capabilities.FeatureReturningBoot, func(ctx context.Context, g capabilities.FeatureGrant) error {
		wrote = true
		applied, werr = hostboot.WriteReturningBoot(ctx, d.db, d.cfg.HostName, g, boot.From, r)
		return werr
	})
	if !wrote {
		if gerr == nil {
			gerr = errors.New("the release gate ran no write")
		}
		return false, false, gerr
	}
	return true, applied, werr
}

// startReturningBootPreRecord starts the lease holder's first-use record of
// returning_boot: once release_2026_11_v1 has latched, it records the use
// with no data write, so a returning boot, which cannot wait for every
// recipient's acknowledgement, finds it recorded. Its own goroutine.
func (d *Daemon) startReturningBootPreRecord(ctx context.Context, fc *failover.Coordinator) {
	info, ok := capabilities.LookupFeature(capabilities.FeatureReturningBoot)
	if !ok {
		return
	}
	p := &failover.HAPreRecorder{
		Name:       string(capabilities.FeatureReturningBoot),
		HoldsLease: fc.HoldsLease,
		Latched:    func() bool { return d.checker.FeatureAvailable(capabilities.FeatureReturningBoot) },
		Paid: func(ctx context.Context) (bool, error) {
			present, acked, err := corrosion.ReleaseFeatureState(ctx, d.db, info.Token, string(capabilities.FeatureReturningBoot))
			return present && acked, err
		},
		Record: func(ctx context.Context) error {
			return d.checker.WithFeature(ctx, capabilities.FeatureReturningBoot,
				func(context.Context, capabilities.FeatureGrant) error { return nil })
		},
	}
	go p.Run(ctx)
}
