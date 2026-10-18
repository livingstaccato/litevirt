package daemon

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// The own-row hold (corrosion/own_row_hold.go), the daemon's side: it is
// configured before this host's first own-row write, re-evaluated whenever an
// apply changes the own row (and every ownRowPoll), surfaced as the
// own_row_held health condition, and when it opens — or when the own row moves
// to a later incarnation — the own-row reconcile re-runs this host's own
// writes on the row the cluster holds.

// CondOwnRowHeld is raised while this host's own-row hold is engaged.
const CondOwnRowHeld = "own_row_held"

// ownRowPoll re-evaluates the hold even without an apply. A var for tests.
var ownRowPoll = 30 * time.Second

// ownRowReport is how often a hold that has not opened is reported.
const ownRowReport = time.Minute

// bootResources are the boot report's resource figures, kept for the
// reconcile's re-run of the boot write.
type bootResources struct {
	mu                    sync.Mutex
	cpus, memMiB, diskGiB int
	hasResources          bool
}

// configureOwnRowHold evaluates the hold against the certificate this host
// serves, before registerHost. The certificate is re-read at every
// evaluation, so a live `lv host renew-cert` is seen at once.
func (d *Daemon) configureOwnRowHold(ctx context.Context) {
	d.ownRowWake = make(chan struct{}, 1)
	d.db.SetOwnRowChangeHook(func() {
		select {
		case d.ownRowWake <- struct{}{}:
		default:
		}
	})
	src := d.installedCert
	if d.ownRowCertSource != nil {
		src = d.ownRowCertSource
	}
	st, err := d.db.ConfigureOwnRowHold(ctx, src)
	if err != nil {
		slog.Warn("could not evaluate this host's own-row hold", "error", err)
	}
	if st.Held {
		slog.Warn("this host's own row is not the cluster's admission for its certificate; its own-row writes "+
			"are held until that admission reaches this node",
			"host", d.cfg.HostName, "arm", st.Arm, "installed_serial", st.InstalledSerial,
			"recorded_serial", st.RecordedSerial)
	}
}

// installedCert is the certificate this daemon serves, and the serial it
// renewed (corrosion.InstalledCert).
func (d *Daemon) installedCert() (string, string) {
	cert, err := pki.ServedHostCertificate(d.cfg.PKIDir)
	if err != nil {
		return "", ""
	}
	prev, _ := pki.RenewedFromSerial(cert)
	return strings.ToLower(cert.SerialNumber.Text(16)), prev
}

// ownKey is the own row's identity as the reconcile tracks it.
type ownKey struct {
	n       int64
	serial  string
	deleted bool
}

func (d *Daemon) readOwnKey(ctx context.Context) (ownKey, bool) {
	n, _, serial, deleted, found, err := corrosion.HostIncarnationOf(ctx, d.db, d.cfg.HostName)
	if err != nil || !found {
		return ownKey{}, false
	}
	return ownKey{n: n, serial: strings.ToLower(serial), deleted: deleted}, true
}

// ownRowLoop is runOwnRowHold's state between evaluations.
type ownRowLoop struct {
	prev        ownKey
	wasHeld     bool
	wasTimedOut bool
	lastReport  time.Time
}

// runOwnRowHold re-evaluates the hold on every own-row change and poll, and
// runs ownRowStep.
func (d *Daemon) runOwnRowHold(ctx context.Context) {
	if d.ownRowWake == nil {
		return
	}
	l := &ownRowLoop{}
	l.prev, _ = d.readOwnKey(ctx)
	l.wasHeld = d.db.OwnRowHold().Held
	tick := time.NewTicker(ownRowPoll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.ownRowWake:
		case <-tick.C:
		}
		d.ownRowStep(ctx, l)
	}
}

// ownRowStep is one evaluation: keep own_row_held in step with the hold, and
// run the own-row reconcile when the hold opens, times out (only a hold raised
// at start over a row at incarnation 0 can), or the own row moves to another
// incarnation or serial while no hold is engaged.
func (d *Daemon) ownRowStep(ctx context.Context, l *ownRowLoop) {
	st, err := d.db.EvaluateOwnRowHold(ctx, corrosion.OwnRowHeldSuperseded)
	if err != nil {
		slog.Warn("could not re-evaluate this host's own-row hold", "error", err)
		return
	}
	cur, _ := d.readOwnKey(ctx)
	switch {
	case st.Held && !l.wasHeld:
		slog.Error("this host's own row no longer names its certificate; its own-row writes are held",
			"host", d.cfg.HostName, "reason", st.Reason, "installed_serial", st.InstalledSerial,
			"recorded_serial", st.RecordedSerial)
		l.lastReport = time.Time{}
	case !st.Held && l.wasHeld:
		slog.Info("this host's own row is the cluster's admission for its certificate; the own-row hold is open",
			"host", d.cfg.HostName, "incarnation", cur.n)
		d.writeSelfConditionAs(ctx, auditHoldEvaluator, CondOwnRowHeld, false, "", nil)
		d.runOwnRowReconcile(ctx)
	case !st.Held && cur != l.prev && !cur.deleted:
		d.runOwnRowReconcile(ctx)
	}
	if st.Held && time.Since(l.lastReport) >= ownRowReport {
		l.lastReport = time.Now()
		d.writeSelfConditionAs(ctx, auditHoldEvaluator, CondOwnRowHeld, true, corrosion.SeverityWarning,
			map[string]any{
				"reason": st.Reason, "arm": st.Arm, "held_for": time.Since(st.Since).Round(time.Second).String(),
				"timed_out": st.TimedOut, "installed_serial": st.InstalledSerial, "recorded_serial": st.RecordedSerial,
			})
	}
	if st.Held && st.TimedOut && !l.wasTimedOut {
		slog.Error("this host's own-row hold timed out; falling back to the writes the previous release makes",
			"host", d.cfg.HostName, "reason", st.Reason, "after", corrosion.OwnRowHoldTimeout)
		d.runOwnRowReconcile(ctx)
	}
	l.wasHeld, l.wasTimedOut, l.prev = st.Held, st.TimedOut, cur
}

// runOwnRowReconcile runs the reconcile once at a time: a re-run while one is
// in flight is dropped (the in-flight one reads the row as it is by then).
func (d *Daemon) runOwnRowReconcile(ctx context.Context) {
	if !d.ownRowReconciling.CompareAndSwap(false, true) {
		return
	}
	defer d.ownRowReconciling.Store(false)
	if d.ownRowReconciler != nil {
		d.ownRowReconciler(ctx)
		return
	}
	d.reconcileOwnRow(ctx)
}

// reconcileOwnRow re-runs this host's own writes on the row the cluster holds:
// registration, the address and gRPC port, and the boot report.
func (d *Daemon) reconcileOwnRow(ctx context.Context) {
	if err := d.registerHost(ctx); err != nil {
		slog.Warn("own-row reconcile: registration", "error", err)
	}
	if err := d.reconcileOwnEndpoint(ctx); err != nil {
		slog.Warn("own-row reconcile: address and port", "error", err)
	}
	d.bootRes.mu.Lock()
	cpus, mem, disk, has := d.bootRes.cpus, d.bootRes.memMiB, d.bootRes.diskGiB, d.bootRes.hasResources
	d.bootRes.mu.Unlock()
	d.writeBootState(ctx, cpus, mem, disk, has)
}

// reconcileOwnEndpoint corrects this host's recorded address and gRPC port.
// On an own row at a counted incarnation (a re-admission recorded them as
// `lv host add` saw them) through the host_incarnation feature's statement,
// which waits for this host's own latch; otherwise the address alone, as
// before (reconcileHostAddress).
func (d *Daemon) reconcileOwnEndpoint(ctx context.Context) error {
	h, err := corrosion.GetHost(ctx, d.db, d.cfg.HostName)
	if err != nil || h == nil {
		return err
	}
	k, ok := d.readOwnKey(ctx)
	want := d.hostAddress()
	if !ok || k.n < 1 || d.checker == nil {
		return d.reconcileHostAddress(ctx)
	}
	if h.Address == want && h.GRPCPort == d.cfg.GRPCPort {
		return nil
	}
	return d.checker.WithFeature(ctx, capabilities.FeatureHostIncarnation,
		func(ctx context.Context, g capabilities.FeatureGrant) error {
			slog.Warn("recording this host's own address and gRPC port over the ones its admission recorded",
				"host", d.cfg.HostName, "address", want, "grpc_port", d.cfg.GRPCPort,
				"was_address", h.Address, "was_grpc_port", h.GRPCPort)
			return corrosion.WriteOwnEndpoint(ctx, d.db, d.cfg.HostName, want, d.cfg.GRPCPort, g)
		})
}
