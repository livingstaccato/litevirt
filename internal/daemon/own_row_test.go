package daemon

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hostboot"
)

// The daemon half of the own-row hold (own_row.go).

// ownRowDaemon is a daemon for the test client's own host ("test-node"),
// whose row names recorded, serving the certificate cert reports, with the
// reconcile counted rather than run.
func ownRowDaemon(t *testing.T, recorded string, cert *[2]string) (*Daemon, *atomic.Int32) {
	t.Helper()
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	host := db.HostName()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: host, Address: "10.0.0.15", SSHUser: "root",
		SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: recorded}); err != nil {
		t.Fatal(err)
	}
	var reconciles atomic.Int32
	d := &Daemon{cfg: &Config{HostName: host}, db: db}
	d.ownRowCertSource = func() (string, string) { return cert[0], cert[1] }
	d.ownRowReconciler = func(context.Context, string) { reconciles.Add(1) }
	d.configureOwnRowHold(ctx)
	return d, &reconciles
}

func ownRowCondition(t *testing.T, d *Daemon) (open bool) {
	t.Helper()
	row, found, err := corrosion.GetHealthCondition(context.Background(), d.db, auditHoldEvaluator, CondOwnRowHeld, "host", d.cfg.HostName)
	if err != nil {
		t.Fatal(err)
	}
	return found && row.Lifecycle != corrosion.ConditionResolved
}

// I-1: a live `lv host renew-cert` raises no hold and no condition; the own
// row's writes go on.
func TestOwnRow_ALiveRenewalRaisesNoHold(t *testing.T) {
	ctx := context.Background()
	cert := [2]string{"01old", ""}
	d, _ := ownRowDaemon(t, "01old", &cert)
	l := &ownRowLoop{}
	d.ownRowStep(ctx, l)
	cert = [2]string{"02new", "01old"} // renewed in place
	d.ownRowStep(ctx, l)
	if st := d.db.OwnRowHold(); st.Held {
		t.Fatalf("a live renewal raised the hold: %+v", st)
	}
	if _, err := corrosion.RecordOwnCertSerial(ctx, d.db, d.cfg.HostName, "02new"); err != nil {
		t.Fatalf("the renewal's re-record: %v", err)
	}
	d.ownRowStep(ctx, l)
	if st := d.db.OwnRowHold(); st.Held || ownRowCondition(t, d) {
		t.Fatalf("held, or own_row_held raised, after a live renewal: %+v", st)
	}
	if err := corrosion.UpdateHostState(ctx, d.db, d.cfg.HostName, "draining"); err != nil {
		t.Errorf("drain's own-row write after a live renewal: %v", err)
	}
}

// I-1: a boot after a renewal made while the host was down is not held.
func TestOwnRow_ABootAfterAnOfflineRenewalIsNotHeld(t *testing.T) {
	cert := [2]string{"02new", "01old"}
	d, _ := ownRowDaemon(t, "01old", &cert)
	if st := d.db.OwnRowHold(); st.Held {
		t.Fatalf("held at boot after an offline renewal: %+v", st)
	}
}

// Open, then reconcile: a hold at start opens once the admission arrives, the
// condition resolves, and the reconcile runs once.
func TestOwnRow_OpenThenReconcile(t *testing.T) {
	ctx := context.Background()
	cert := [2]string{"02new", ""}
	d, reconciles := ownRowDaemon(t, "01old", &cert)
	l := &ownRowLoop{wasHeld: d.db.OwnRowHold().Held}
	if !l.wasHeld {
		t.Fatal("not held at start")
	}
	d.ownRowStep(ctx, l)
	if !ownRowCondition(t, d) {
		t.Error("own_row_held not raised while held")
	}
	if reconciles.Load() != 0 {
		t.Fatal("reconciled while held")
	}
	// The re-admission arrives.
	if _, err := d.db.DB().Exec(`UPDATE hosts SET cert_serial = '02new', incarnation = 1 WHERE name = ?`, d.cfg.HostName); err != nil {
		t.Fatal(err)
	}
	d.ownRowStep(ctx, l)
	if reconciles.Load() != 1 {
		t.Errorf("reconciles = %d after the hold opened, want 1", reconciles.Load())
	}
	if ownRowCondition(t, d) {
		t.Error("own_row_held not resolved after the hold opened")
	}
}

// I-2: a superseded hold past the timeout never runs the fallback reconcile:
// a write stamped with the winner's key would be accepted everywhere.
func TestOwnRow_ASupersededHoldNeverFallsBack(t *testing.T) {
	ctx := context.Background()
	old := corrosion.OwnRowHoldTimeout
	corrosion.OwnRowHoldTimeout = 10 * time.Millisecond
	t.Cleanup(func() { corrosion.OwnRowHoldTimeout = old })
	cert := [2]string{"02new", ""}
	d, reconciles := ownRowDaemon(t, "02new", &cert)
	l := &ownRowLoop{}
	d.ownRowStep(ctx, l)
	// Another admission at the same name supersedes this machine.
	if _, err := d.db.DB().Exec(`UPDATE hosts SET cert_serial = 'yy09', incarnation = 1 WHERE name = ?`, d.cfg.HostName); err != nil {
		t.Fatal(err)
	}
	d.ownRowStep(ctx, l)
	before := reconciles.Load()
	time.Sleep(30 * time.Millisecond)
	d.ownRowStep(ctx, l)
	d.ownRowStep(ctx, l)
	if st := d.db.OwnRowHold(); !st.Held || st.TimedOut || st.Reason != corrosion.OwnRowHeldSuperseded {
		t.Fatalf("hold = %+v, want superseded and never timed out", st)
	}
	if reconciles.Load() != before {
		t.Error("a superseded hold ran the fallback reconcile")
	}
}

// m-3: the daemon wires the caught-up check, the quorum gate and the
// currency pull into its gRPC server before it serves. Each fails open when
// unwired (grpcapi/host_incarnation.go), so a refactor that dropped one would
// silently remove a check.
func TestDaemonWiresTheHostWriteChecksBeforeServing(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	pos := map[string]token.Pos{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := sel.Sel.Name
		switch name {
		case "SetHostWriteCurrencyCheck":
			if len(call.Args) == 1 {
				if id, ok := call.Args[0].(*ast.Ident); ok && id.Name == "true" {
					pos[name] = call.Pos()
				}
			}
		case "SetGate", "SetAntiEntropy":
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "svc" {
				pos[name] = call.Pos()
			}
		case "Serve":
			if x, ok := sel.X.(*ast.SelectorExpr); ok && x.Sel.Name == "grpcSrv" {
				pos[name] = call.Pos()
			}
		}
		return true
	})
	for _, name := range []string{"SetHostWriteCurrencyCheck", "SetGate", "SetAntiEntropy", "Serve"} {
		if pos[name] == token.NoPos {
			t.Fatalf("daemon.go does not call %s as expected", name)
		}
	}
	for _, name := range []string{"SetHostWriteCurrencyCheck", "SetGate", "SetAntiEntropy"} {
		if pos[name] > pos["Serve"] {
			t.Errorf("%s is wired after the gRPC server serves", name)
		}
	}
	if !strings.Contains(fset.Position(pos["Serve"]).Filename, "daemon.go") {
		t.Error("Serve not found in daemon.go")
	}
}

// Re-review I-1: a hold raised at start over a row at 0 that moves to another
// admission at 1 never runs the fallback reconcile.
func TestOwnRow_AStartHoldWhoseRowIsReadmittedNeverFallsBack(t *testing.T) {
	ctx := context.Background()
	old := corrosion.OwnRowHoldTimeout
	corrosion.OwnRowHoldTimeout = 10 * time.Millisecond
	t.Cleanup(func() { corrosion.OwnRowHoldTimeout = old })
	cert := [2]string{"02new", ""}
	d, reconciles := ownRowDaemon(t, "01old", &cert)
	l := &ownRowLoop{wasHeld: d.db.OwnRowHold().Held}
	if !l.wasHeld {
		t.Fatal("not held at start")
	}
	if _, err := d.db.DB().Exec(`UPDATE hosts SET cert_serial = 'yy09', incarnation = 1 WHERE name = ?`, d.cfg.HostName); err != nil {
		t.Fatal(err)
	}
	d.ownRowStep(ctx, l)
	time.Sleep(30 * time.Millisecond)
	d.ownRowStep(ctx, l)
	d.ownRowStep(ctx, l)
	if st := d.db.OwnRowHold(); !st.Held || st.TimedOut {
		t.Fatalf("hold = %+v, want held and never timed out", st)
	}
	if reconciles.Load() != 0 {
		t.Error("the fallback reconcile ran over another admission's row")
	}
}

// Re-review 2, I-1: the admission record survives a restart and is this
// host's alone.
func TestAdmissionFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	f := &admissionFile{path: dir + "/" + OwnAdmissionFileName, host: "node-a"}
	if _, _, ok := f.Load(); ok {
		t.Fatal("a missing file loaded")
	}
	if err := f.Store(2, "2026-01-01T00:00:00.000000000Z"); err != nil {
		t.Fatal(err)
	}
	again := &admissionFile{path: f.path, host: "node-a"}
	if n, at, ok := again.Load(); !ok || n != 2 || at != "2026-01-01T00:00:00.000000000Z" {
		t.Errorf("Load = (%d, %q, %v)", n, at, ok)
	}
	if _, _, ok := (&admissionFile{path: f.path, host: "node-b"}).Load(); ok {
		t.Error("another host's record loaded")
	}
}

// Re-review 3, m-5: the daemon installs its admission record. With PKIDir set,
// configureOwnRowHold stores the own counted row's key in own-admission.json,
// and a certificate reissued outside the renewal flow over that admission is
// not held. Without the wiring the record is never written, and the
// trust_rotated_peer_certs recovery at a counted incarnation is held again.
func TestOwnRow_TheDaemonInstallsItsAdmissionRecord(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	host := db.HostName()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: host, Address: "10.0.0.15", SSHUser: "root",
		SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "01cur"}); err != nil {
		t.Fatal(err)
	}
	const at = "2026-01-01T00:00:00.000000000Z"
	if _, err := db.DB().Exec(`UPDATE hosts SET incarnation = 1, created_at = ? WHERE name = ?`, at, host); err != nil {
		t.Fatal(err)
	}
	pkiDir := t.TempDir()
	cert := [2]string{"01cur", ""}
	d := &Daemon{cfg: &Config{HostName: host, PKIDir: pkiDir}, db: db}
	d.ownRowCertSource = func() (string, string) { return cert[0], cert[1] }
	d.ownRowReconciler = func(context.Context, string) {}
	d.configureOwnRowHold(ctx)

	rec := &admissionFile{path: filepath.Join(pkiDir, OwnAdmissionFileName), host: host}
	if n, got, ok := rec.Load(); !ok || n != 1 || got != at {
		t.Fatalf("own-admission.json = (%d, %q, %v), want (1, %q)", n, got, ok, at)
	}
	// The PKI directory is regenerated: an unrelated serial, not a renewal.
	cert = [2]string{"09reissued", ""}
	st, err := d.db.EvaluateOwnRowHold(ctx, corrosion.OwnRowHeldSuperseded)
	if err != nil {
		t.Fatal(err)
	}
	if st.Held {
		t.Errorf("held over its own remembered admission: %+v", st)
	}
}

// Re-review 3, m-2: Store returns the directory fsync's error, so a record
// whose rename may not survive a power loss is not reported as stored.
func TestAdmissionFile_StoreSyncsTheDirectory(t *testing.T) {
	dir := t.TempDir()
	f := &admissionFile{path: filepath.Join(dir, OwnAdmissionFileName), host: "node-a"}
	var synced []string
	old := syncDir
	t.Cleanup(func() { syncDir = old })
	syncDir = func(d string) error { synced = append(synced, d); return nil }
	if err := f.Store(1, "2026-01-01T00:00:00.000000000Z"); err != nil {
		t.Fatal(err)
	}
	if len(synced) != 1 || synced[0] != dir {
		t.Errorf("directories synced = %v, want [%s]", synced, dir)
	}
	boom := errors.New("eio")
	syncDir = func(string) error { return boom }
	if err := f.Store(2, "2026-02-01T00:00:00.000000000Z"); !errors.Is(err, boom) {
		t.Errorf("Store with a failing directory sync = %v, want it returned", err)
	}
	// No temporary file is left beside the record.
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != OwnAdmissionFileName {
		t.Errorf("directory holds %v, want only %s", ents, OwnAdmissionFileName)
	}
	// The real directory sync works on a real directory.
	if err := old(dir); err != nil {
		t.Errorf("syncDir(%s): %v", dir, err)
	}
}

// Lab test 26, F6: an own-row reconcile in a process a post-upgrade re-exec
// started, after its watchdog confirmed the upgrade, keeps the host active.
// Re-running the boot's decision wrote 'upgrading' again, and nothing
// confirmed it a second time.
func TestReconcileBootReport_APostUpgradeProcessStaysActive(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "h", Address: "127.0.0.1", SSHUser: "root", CertSerial: "s", State: "active", Version: "v1",
	}); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{cfg: &Config{HostName: "h", DataDir: t.TempDir(), Version: "v2"}, db: db, upgradePending: true}
	d.reconcileBootReport(ctx, "active")
	h, err := corrosion.GetHost(ctx, db, "h")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %v", err)
	}
	if h.State != "active" || h.Version != "v2" {
		t.Errorf("after the reconcile the host is (%s, %s), want (active, v2)", h.State, h.Version)
	}
}

// ownRowMembership records host's state on its host_membership row, as a
// re-admission's or a fence's membership statement does, without touching
// the hosts row: anti-entropy carries the two tables separately.
func ownRowMembership(t *testing.T, d *Daemon, state string) {
	t.Helper()
	if _, err := d.db.DB().Exec(`INSERT INTO host_membership (host_name, state, isolation_epoch, isolation_reason, updated_at, deleted_at)
		VALUES (?, ?, 0, '', ?, NULL)
		ON CONFLICT(host_name) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at, deleted_at = NULL`,
		d.cfg.HostName, state, d.db.NowTS()); err != nil {
		t.Fatal(err)
	}
	if h, err := corrosion.GetHost(context.Background(), d.db, d.cfg.HostName); err != nil || h == nil || h.State != state {
		t.Fatalf("own row reads %+v (%v), want state %s", h, err, state)
	}
}

// Lab 2 drill F1: a re-added host restarted during its own-row hold. The
// re-admission's hosts row reached it by anti-entropy before its
// host_membership row: the hold opened, and the reconcile read the removed
// machine's 'upgrading' and left the boot report to the serving check. Then
// 'joining' arrived, the serving check found the state moved on, and the host
// stayed joining until its next restart. The admission's 'joining' arriving
// after the hold opened runs the reconcile again.
func TestOwnRow_JoiningAfterTheHoldOpenedReconciles(t *testing.T) {
	ctx := context.Background()
	cert := [2]string{"02new", ""}
	d, reconciles := ownRowDaemon(t, "01old", &cert)
	ownRowMembership(t, d, "upgrading") // the removed machine's graceful stop
	l := &ownRowLoop{wasHeld: d.db.OwnRowHold().Held}
	if !l.wasHeld {
		t.Fatal("not held at start")
	}
	// The re-admission's hosts row arrives alone.
	if _, err := d.db.DB().Exec(`UPDATE hosts SET cert_serial = '02new', incarnation = 1 WHERE name = ?`, d.cfg.HostName); err != nil {
		t.Fatal(err)
	}
	d.ownRowStep(ctx, l)
	if reconciles.Load() != 1 {
		t.Fatalf("reconciles = %d after the hold opened, want 1", reconciles.Load())
	}
	// Its membership row follows.
	ownRowMembership(t, d, "joining")
	d.ownRowStep(ctx, l)
	if reconciles.Load() != 2 {
		t.Fatalf("reconciles = %d after the admission's 'joining' arrived, want 2", reconciles.Load())
	}
	// Once: a host that stays joining (its address is another's) is not
	// re-run on every evaluation.
	d.ownRowStep(ctx, l)
	d.ownRowStep(ctx, l)
	if reconciles.Load() != 2 {
		t.Errorf("reconciles = %d while it stays joining, want 2", reconciles.Load())
	}
}

// F1's trigger is 'joining' alone. The reconcile's boot report returns a
// fenced, drained or offline host to service, which is right once, at the
// hold's opening, and never at runtime: a fence or a drain recorded while
// the daemon runs is kept.
func TestOwnRow_AFenceOrDrainAtRuntimeDoesNotReconcile(t *testing.T) {
	ctx := context.Background()
	cert := [2]string{"02new", ""}
	d, reconciles := ownRowDaemon(t, "02new", &cert)
	l := &ownRowLoop{}
	l.prev, _ = d.readOwnKey(ctx)
	d.ownRowStep(ctx, l)
	for _, state := range []string{"draining", "maintenance", "fenced", "offline", "upgrading", "active"} {
		ownRowMembership(t, d, state)
		d.ownRowStep(ctx, l)
	}
	if reconciles.Load() != 0 {
		t.Errorf("reconciles = %d over runtime state changes, want 0", reconciles.Load())
	}
}

// The trigger never runs while the hold is engaged: a 'joining' on a row that
// names another certificate is another machine's admission.
func TestOwnRow_JoiningWhileHeldDoesNotReconcile(t *testing.T) {
	ctx := context.Background()
	cert := [2]string{"02new", ""}
	d, reconciles := ownRowDaemon(t, "01old", &cert)
	l := &ownRowLoop{wasHeld: d.db.OwnRowHold().Held}
	ownRowMembership(t, d, "joining")
	d.ownRowStep(ctx, l)
	d.ownRowStep(ctx, l)
	if reconciles.Load() != 0 {
		t.Errorf("reconciles = %d while held, want 0", reconciles.Load())
	}
}

// bootReportDaemon is a daemon whose own row ("h") is recorded state on its
// membership row, for the reconcile's boot report.
func bootReportDaemon(t *testing.T, state string) (*Daemon, context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel) // ends the serving check a boot write starts
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "h", Address: "127.0.0.1", SSHUser: "root", CertSerial: "s", State: "active", Version: "v1",
	}); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{cfg: &Config{HostName: "h", DataDir: t.TempDir(), Version: "v2"}, db: db}
	ownRowMembership(t, d, state)
	return d, ctx
}

func ownState(t *testing.T, d *Daemon) string {
	t.Helper()
	h, err := corrosion.GetHost(context.Background(), d.db, d.cfg.HostName)
	if err != nil || h == nil {
		t.Fatalf("GetHost: %+v %v", h, err)
	}
	return h.State
}

// Round 1, finding 3: a reconcile writes the boot report only over the state
// the evaluation that ran it read. A fence, drain or maintenance recorded
// after that read (registerHost and the endpoint reconcile run in between,
// and the latter can wait on peers) is kept, never returned to service.
func TestReconcileBootReport_AStateRecordedAfterTheTriggerIsKept(t *testing.T) {
	for _, now := range []string{"draining", "fenced", "maintenance", "offline"} {
		d, ctx := bootReportDaemon(t, now)
		d.reconcileBootReport(ctx, corrosion.HostStateJoining)
		if got := ownState(t, d); got != now {
			t.Errorf("read joining, %s recorded since: the reconcile wrote %s over it", now, got)
		}
	}
	// The state the trigger read is acted on.
	d, ctx := bootReportDaemon(t, corrosion.HostStateJoining)
	d.reconcileBootReport(ctx, corrosion.HostStateJoining)
	if got := ownState(t, d); got == corrosion.HostStateJoining {
		t.Error("read joining and still joining: the boot report was not written")
	}
}

// The boot write itself checks it: the decision is taken from the state it
// reads in the same read that guards its write, and is made only when that is
// the state the caller expects.
func TestWriteBootStateWith_AnotherStateThanExpectedWritesNothing(t *testing.T) {
	for _, now := range []string{"draining", "fenced", "maintenance", "offline"} {
		d, ctx := bootReportDaemon(t, now)
		d.writeBootStateWith(ctx, 1, 2, 3, true, false, corrosion.HostStateJoining)
		if got := ownState(t, d); got != now {
			t.Errorf("expected joining, read %s: the boot write recorded %s", now, got)
		}
	}
	// A boot (no expectation) decides from what it reads, as before.
	d, ctx := bootReportDaemon(t, "draining")
	d.writeBootStateWith(ctx, 1, 2, 3, true, false, "")
	if got := ownState(t, d); got == "draining" {
		t.Error("a boot over draining wrote nothing")
	}
}

// Each trigger hands the reconcile the state its evaluation read.
func TestOwnRow_EachTriggerPassesTheStateItRead(t *testing.T) {
	ctx := context.Background()
	cert := [2]string{"02new", ""}
	d, _ := ownRowDaemon(t, "01old", &cert)
	var froms []string
	d.ownRowReconciler = func(_ context.Context, from string) { froms = append(froms, from) }
	ownRowMembership(t, d, "upgrading")
	l := &ownRowLoop{wasHeld: d.db.OwnRowHold().Held}
	if _, err := d.db.DB().Exec(`UPDATE hosts SET cert_serial = '02new', incarnation = 1 WHERE name = ?`, d.cfg.HostName); err != nil {
		t.Fatal(err)
	}
	d.ownRowStep(ctx, l) // the hold opens
	ownRowMembership(t, d, corrosion.HostStateJoining)
	d.ownRowStep(ctx, l) // joining
	ownRowMembership(t, d, "fenced")
	if _, err := d.db.DB().Exec(`UPDATE hosts SET incarnation = 2 WHERE name = ?`, d.cfg.HostName); err != nil {
		t.Fatal(err)
	}
	d.ownRowStep(ctx, l) // the incarnation moved
	want := []string{"upgrading", corrosion.HostStateJoining, "fenced"}
	if strings.Join(froms, ",") != strings.Join(want, ",") {
		t.Errorf("reconciles ran over %v, want %v", froms, want)
	}
}

// Round 2, item 1: a reconcile with no state read ("") never writes a boot
// report. "" was also a plain boot's "no expectation", so a trigger whose
// read failed ran the boot write unguarded and recorded a fenced host active
// (the re-review's TestZZReview_EmptyFromIsUnguarded, kept).
func TestReconcileBootReport_NoStateReadWritesNothing(t *testing.T) {
	for _, now := range []string{"fenced", "offline", "draining", "maintenance", corrosion.HostStateJoining} {
		d, ctx := bootReportDaemon(t, now)
		d.reconcileBootReport(ctx, "")
		if got := ownState(t, d); got != now {
			t.Errorf("a reconcile with no state read wrote %s over %s", got, now)
		}
	}
}

// failOwnStateReads makes the evaluation's own-state read fail while *fail.
func failOwnStateReads(t *testing.T, fail *bool) {
	t.Helper()
	old := readOwnState
	readOwnState = func(d *Daemon, ctx context.Context) (string, bool) {
		if *fail {
			return "", false
		}
		return old(d, ctx)
	}
	t.Cleanup(func() { readOwnState = old })
}

// An evaluation whose state read fails runs no reconcile, and the next one
// that reads the state runs it over that state: the hold-open, incarnation
// and timed-out triggers are retried, never run unguarded.
func TestOwnRow_AFailedStateReadDefersEveryTrigger(t *testing.T) {
	ctx := context.Background()
	t.Run("hold open", func(t *testing.T) {
		cert := [2]string{"02new", ""}
		d, _ := ownRowDaemon(t, "01old", &cert)
		var froms []string
		d.ownRowReconciler = func(_ context.Context, from string) { froms = append(froms, from) }
		ownRowMembership(t, d, "fenced")
		fail := true
		failOwnStateReads(t, &fail)
		l := &ownRowLoop{wasHeld: d.db.OwnRowHold().Held}
		if _, err := d.db.DB().Exec(`UPDATE hosts SET cert_serial = '02new', incarnation = 1 WHERE name = ?`, d.cfg.HostName); err != nil {
			t.Fatal(err)
		}
		d.ownRowStep(ctx, l)
		if len(froms) != 0 {
			t.Fatalf("a reconcile ran with no state read: %v", froms)
		}
		fail = false
		d.ownRowStep(ctx, l)
		if strings.Join(froms, ",") != "fenced" {
			t.Errorf("after the read recovered, reconciles ran over %v, want [fenced]", froms)
		}
	})
	t.Run("incarnation", func(t *testing.T) {
		cert := [2]string{"02new", ""}
		d, _ := ownRowDaemon(t, "02new", &cert)
		var froms []string
		d.ownRowReconciler = func(_ context.Context, from string) { froms = append(froms, from) }
		l := &ownRowLoop{}
		l.prev, _ = d.readOwnKey(ctx)
		d.ownRowStep(ctx, l)
		fail := true
		failOwnStateReads(t, &fail)
		if _, err := d.db.DB().Exec(`UPDATE hosts SET incarnation = 2 WHERE name = ?`, d.cfg.HostName); err != nil {
			t.Fatal(err)
		}
		d.ownRowStep(ctx, l)
		if len(froms) != 0 {
			t.Fatalf("a reconcile ran with no state read: %v", froms)
		}
		fail = false
		d.ownRowStep(ctx, l)
		if strings.Join(froms, ",") != "active" {
			t.Errorf("after the read recovered, reconciles ran over %v, want [active]", froms)
		}
	})
	t.Run("timed out", func(t *testing.T) {
		old := corrosion.OwnRowHoldTimeout
		corrosion.OwnRowHoldTimeout = 10 * time.Millisecond
		t.Cleanup(func() { corrosion.OwnRowHoldTimeout = old })
		cert := [2]string{"02new", ""}
		d, _ := ownRowDaemon(t, "01old", &cert)
		var froms []string
		d.ownRowReconciler = func(_ context.Context, from string) { froms = append(froms, from) }
		l := &ownRowLoop{wasHeld: d.db.OwnRowHold().Held}
		time.Sleep(30 * time.Millisecond)
		fail := true
		failOwnStateReads(t, &fail)
		d.ownRowStep(ctx, l)
		if len(froms) != 0 {
			t.Fatalf("a reconcile ran with no state read: %v", froms)
		}
		fail = false
		d.ownRowStep(ctx, l)
		if strings.Join(froms, ",") != "active" {
			t.Errorf("after the read recovered, reconciles ran over %v, want [active]", froms)
		}
	})
}

// Round 2, item 2 (Ma): the timed-out fallback hands the reconcile the state
// its evaluation read.
func TestOwnRow_TheTimedOutFallbackPassesTheStateItRead(t *testing.T) {
	ctx := context.Background()
	old := corrosion.OwnRowHoldTimeout
	corrosion.OwnRowHoldTimeout = 10 * time.Millisecond
	t.Cleanup(func() { corrosion.OwnRowHoldTimeout = old })
	cert := [2]string{"02new", ""}
	d, _ := ownRowDaemon(t, "01old", &cert)
	ownRowMembership(t, d, "draining")
	var froms []string
	d.ownRowReconciler = func(_ context.Context, from string) { froms = append(froms, from) }
	l := &ownRowLoop{wasHeld: d.db.OwnRowHold().Held}
	time.Sleep(30 * time.Millisecond)
	d.ownRowStep(ctx, l)
	if st := d.db.OwnRowHold(); !st.TimedOut {
		t.Fatalf("the hold did not time out: %+v", st)
	}
	if strings.Join(froms, ",") != "draining" {
		t.Errorf("the timed-out fallback ran over %v, want [draining]", froms)
	}
}

// Round 2, item 2 (Mb): a deferred boot decided from the expected state still
// does what a deferred boot does. A fenced host whose unclean boot cannot be
// recorded keeps the fence and raises boot_kept_fence, from the reconcile as
// from a boot.
func TestWriteBootStateWith_ADeferredBootOverTheExpectedStateIsWired(t *testing.T) {
	d, ctx := bootReportDaemon(t, "fenced")
	// A data dir that is a file: the unclean-boot history cannot be written.
	bad := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(bad, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	d.cfg.DataDir = bad
	d.writeBootStateWith(ctx, 1, 2, 3, true, false, "fenced")
	if got := ownState(t, d); got != "fenced" {
		t.Fatalf("the kept fence was written %s", got)
	}
	open, err := hostboot.FenceKeptOpen(ctx, d.db, d.cfg.HostName)
	if err != nil || !open {
		t.Errorf("boot_kept_fence open = %v (%v), want raised", open, err)
	}
}

// Round 2, item 3: a boot write the guard refuses leaves no trace on disk:
// no awaiting-serving note, no unclean-boot entry, and a marker or note an
// earlier boot left is kept as it was.
func TestWriteBootStateWith_ARefusedWriteLeavesNoTrace(t *testing.T) {
	t.Run("nothing before", func(t *testing.T) {
		d, ctx := bootReportDaemon(t, "draining")
		d.writeBootStateWith(ctx, 1, 2, 3, true, false, corrosion.HostStateJoining)
		for _, f := range []string{hostboot.AwaitingPath(d.cfg.DataDir), filepath.Join(d.cfg.DataDir, hostboot.UncleanHistoryName),
			hostboot.MarkerPath(d.cfg.DataDir)} {
			if _, err := os.Lstat(f); err == nil {
				t.Errorf("a refused boot write left %s", filepath.Base(f))
			}
		}
	})
	t.Run("files before", func(t *testing.T) {
		d, ctx := bootReportDaemon(t, "draining")
		was := map[string]string{
			hostboot.AwaitingPath(d.cfg.DataDir):                      "2026-10-23T00:00:00Z",
			filepath.Join(d.cfg.DataDir, hostboot.UncleanHistoryName): time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano) + "\n",
			hostboot.MarkerPath(d.cfg.DataDir):                        time.Now().UTC().Format(time.RFC3339Nano),
		}
		for f, b := range was {
			if err := os.WriteFile(f, []byte(b), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		d.writeBootStateWith(ctx, 1, 2, 3, true, false, corrosion.HostStateJoining)
		for f, b := range was {
			got, err := os.ReadFile(f)
			if err != nil || string(got) != b {
				t.Errorf("%s = %q (%v), want %q kept", filepath.Base(f), got, err, b)
			}
		}
	})
	// A write the guard lets through still leaves its trace, as a boot's.
	t.Run("accepted", func(t *testing.T) {
		d, ctx := bootReportDaemon(t, corrosion.HostStateJoining)
		d.writeBootStateWith(ctx, 1, 2, 3, true, false, corrosion.HostStateJoining)
		if _, err := os.Lstat(filepath.Join(d.cfg.DataDir, hostboot.UncleanHistoryName)); err != nil {
			t.Errorf("an accepted reconcile boot write recorded no unclean boot: %v", err)
		}
	})
}

// A failed state read defers the reconcile, not the report: a hold stays
// visible as own_row_held.
func TestOwnRow_AFailedStateReadStillReportsTheHold(t *testing.T) {
	cert := [2]string{"02new", ""}
	d, _ := ownRowDaemon(t, "01old", &cert)
	fail := true
	failOwnStateReads(t, &fail)
	l := &ownRowLoop{wasHeld: d.db.OwnRowHold().Held}
	d.ownRowStep(context.Background(), l)
	if !ownRowCondition(t, d) {
		t.Error("own_row_held not raised while held and the state read fails")
	}
}
