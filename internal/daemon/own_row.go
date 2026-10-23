package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/secretfile"
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
	if d.cfg.PKIDir != "" {
		d.db.SetOwnAdmissionMemory(&admissionFile{path: filepath.Join(d.cfg.PKIDir, OwnAdmissionFileName), host: d.cfg.HostName})
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
	// wasJoining: the own row read 'joining' at the last evaluation.
	wasJoining bool
	lastReport time.Time
}

// ownRowState is this host's own recorded state, resolved as every reader
// resolves it (the membership row when it exists); "" when it cannot be read.
func (d *Daemon) ownRowState(ctx context.Context) string {
	h, err := corrosion.GetHost(ctx, d.db, d.cfg.HostName)
	if err != nil || h == nil {
		return ""
	}
	return h.State
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
	l.wasJoining = d.ownRowState(ctx) == corrosion.HostStateJoining
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
// at start over a row at incarnation 0 can), the own row moves to another
// incarnation or serial while no hold is engaged, or it comes to read
// 'joining' while no hold is engaged.
//
// 'joining' is the state an admission records, and the boot report is what
// ends it. Anti-entropy carries the hosts row and its host_membership row
// separately, so a re-admission's hosts row can open the hold while the
// membership row still holds the removed machine's state: the reconcile then
// reads that, and leaves the boot report to a serving check that finds the
// admission's 'joining' when it arrives, and leaves it (lab 2 drill F1). The
// trigger is 'joining' alone: the reconcile's boot report also returns a
// fenced, drained or offline host to service, which a fence or drain recorded
// while this daemon runs must never be.
func (d *Daemon) ownRowStep(ctx context.Context, l *ownRowLoop) {
	st, err := d.db.EvaluateOwnRowHold(ctx, corrosion.OwnRowHeldSuperseded)
	if err != nil {
		slog.Warn("could not re-evaluate this host's own-row hold", "error", err)
		return
	}
	cur, _ := d.readOwnKey(ctx)
	// The state this evaluation read: a reconcile it runs writes the boot
	// report only over this state (reconcileBootReport).
	state := d.ownRowState(ctx)
	joining := state == corrosion.HostStateJoining
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
		d.runOwnRowReconcile(ctx, state)
	case !st.Held && cur != l.prev && !cur.deleted:
		d.runOwnRowReconcile(ctx, state)
	case !st.Held && joining && !l.wasJoining:
		slog.Info("this host's own row is recorded joining; writing its boot report", "host", d.cfg.HostName,
			"incarnation", cur.n)
		d.runOwnRowReconcile(ctx, state)
	}
	l.wasJoining = joining
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
		d.runOwnRowReconcile(ctx, state)
	}
	l.wasHeld, l.wasTimedOut, l.prev = st.Held, st.TimedOut, cur
}

// runOwnRowReconcile runs the reconcile once at a time: a re-run while one is
// in flight is dropped (the in-flight one reads the row as it is by then).
// from is the state the evaluation that ran it read.
func (d *Daemon) runOwnRowReconcile(ctx context.Context, from string) {
	if !d.ownRowReconciling.CompareAndSwap(false, true) {
		return
	}
	defer d.ownRowReconciling.Store(false)
	if d.ownRowReconciler != nil {
		d.ownRowReconciler(ctx, from)
		return
	}
	d.reconcileOwnRow(ctx, from)
}

// reconcileOwnRow re-runs this host's own writes on the row the cluster holds:
// registration, the address and gRPC port, and the boot report over from, the
// state the evaluation that ran it read.
func (d *Daemon) reconcileOwnRow(ctx context.Context, from string) {
	if err := d.registerHost(ctx); err != nil {
		slog.Warn("own-row reconcile: registration", "error", err)
	}
	if err := d.reconcileOwnEndpoint(ctx); err != nil {
		slog.Warn("own-row reconcile: address and port", "error", err)
	}
	d.reconcileBootReport(ctx, from)
}

// reconcileBootReport writes this running daemon's boot report on its row
// without re-running the boot's own decision for a host the boot already
// brought up. That decision belongs to the boot: a post-upgrade boot's
// 'upgrading', whose watchdog confirms it once, would otherwise be written
// again for the life of the process, and nothing would confirm it twice.
//
//   - recorded 'active': its version and resources, keeping the state and
//     when it became active;
//   - recorded 'upgrading': nothing; the boot's serving check or the upgrade
//     watchdog records it active, with the report;
//   - recorded anything else (joining after a re-admission, fenced, offline,
//     draining, maintenance): it returns to service as a boot's would
//     (writeBootState), without the post-upgrade sentinel.
//
// from is the state the evaluation that ran the reconcile read. The boot
// write returns the host to service only over that state, checked on the
// read its own decision and write guard use (writeBootStateWith's
// expectFrom): a fence, drain or maintenance recorded since (registerHost and
// the endpoint reconcile run in between, and the latter can wait on peers)
// is kept.
func (d *Daemon) reconcileBootReport(ctx context.Context, from string) {
	d.bootRes.mu.Lock()
	cpus, mem, disk, has := d.bootRes.cpus, d.bootRes.memMiB, d.bootRes.diskGiB, d.bootRes.hasResources
	d.bootRes.mu.Unlock()
	h, err := corrosion.GetHost(ctx, d.db, d.cfg.HostName)
	if err != nil || h == nil {
		slog.Warn("own-row reconcile: read this host's row for its boot report", "error", err)
		return
	}
	switch h.State {
	case "upgrading":
	case "active":
		if d.cfg.Version != "" {
			if err := corrosion.UpdateHostVersion(ctx, d.db, d.cfg.HostName, d.cfg.Version); err != nil {
				slog.Warn("own-row reconcile: version", "error", err)
			}
		}
		if has {
			if err := corrosion.UpdateHostResources(ctx, d.db, d.cfg.HostName, cpus, mem, disk); err != nil {
				slog.Warn("own-row reconcile: resources", "error", err)
			}
		}
	default:
		d.writeBootStateWith(ctx, cpus, mem, disk, has, false, from)
	}
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

// OwnAdmissionFileName is this host's record of the admission it was last
// admitted under, in its PKI directory (corrosion.AdmissionMemory).
const OwnAdmissionFileName = "own-admission.json"

// admissionFile is corrosion.AdmissionMemory kept in a file, written whole
// through a temporary file and a rename.
type admissionFile struct {
	path, host string
}

type admissionRecord struct {
	Host        string `json:"host"`
	Incarnation int64  `json:"incarnation"`
	CreatedAt   string `json:"created_at"`
}

func (f *admissionFile) Load() (int64, string, bool) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		return 0, "", false
	}
	var r admissionRecord
	if json.Unmarshal(data, &r) != nil || r.Host != f.host || r.Incarnation < 1 || r.CreatedAt == "" {
		return 0, "", false
	}
	return r.Incarnation, r.CreatedAt, true
}

// Store makes the record durable before it returns: secretfile.Write writes a
// uniquely named temporary file, fsyncs it and renames it over the record, and
// the directory is then fsynced so the rename itself survives a power loss.
// Every step's error is returned, and the hold logs it. A record that did not
// reach the file is stored again at the next evaluation; one whose directory
// sync failed is in the file but may not survive a power loss, which fails
// closed (the host is held as if it had no record).
func (f *admissionFile) Store(n int64, createdAt string) error {
	data, err := json.MarshalIndent(admissionRecord{Host: f.host, Incarnation: n, CreatedAt: createdAt}, "", "  ")
	if err != nil {
		return err
	}
	if err := secretfile.Write(f.path, data, 0o600); err != nil {
		return err
	}
	return syncDir(filepath.Dir(f.path))
}

// syncDir fsyncs a directory, so a rename into it is durable. A var for tests.
var syncDir = func(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open %s: %w", dir, err)
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dir, err)
	}
	return nil
}
