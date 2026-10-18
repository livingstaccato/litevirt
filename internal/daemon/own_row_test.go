package daemon

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
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
	d.ownRowReconciler = func(context.Context) { reconciles.Add(1) }
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
