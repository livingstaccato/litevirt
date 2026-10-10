package daemon

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"testing"
	"time"
)

// TestRun_EveryStartSourceAfterTheStartGuard (re-review R2-I2, m3): a host
// boots with empty nft tables, and a VM started before the daemon has wired
// the libvirt start guard and run a first firewall pass runs with none of its
// per-NIC rules. The start guard's own wait covers only guarded VMs, so what
// keeps an unguarded VM's start from waiting on it — and a guarded VM's from
// running unguarded — is this order in Run: the guard, the reconciler and the
// first pass, then every source of a runtime start or resume (the runtime
// loops, the drain cold-move recovery, onboot, the held-guest resumer, the
// gRPC server).
func TestRun_EveryStartSourceAfterTheStartGuard(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var run *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "Run" && fd.Recv != nil {
			run = fd
		}
	}
	if run == nil {
		t.Fatal("no (*Daemon).Run in daemon.go")
	}
	first := map[string]token.Pos{}
	ast.Inspect(run.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var b bytes.Buffer
		_ = printer.Fprint(&b, fset, call.Fun)
		if _, seen := first[b.String()]; !seen {
			first[b.String()] = call.Pos()
		}
		return true
	})
	pos := func(name string) token.Pos {
		t.Helper()
		p, ok := first[name]
		if !ok {
			t.Fatalf("Run no longer calls %s; update this test with what replaced it", name)
		}
		return p
	}
	wiring := []string{"d.virt.SetStartGuard", "svc.SetFirewallReconciler", "bootFirewallPass"}
	sources := []string{"vmChecker.Start", "reconciler.Start", "svc.RunDrainColdMoveRecovery",
		"reconciler.StartOnbootVMs", "svc.RunHeldGuestResumer", "d.grpcSrv.Serve"}
	for _, w := range wiring {
		for _, s := range sources {
			if pos(w) >= pos(s) {
				t.Errorf("%s (%s) runs after the start source %s (%s)", w, fset.Position(pos(w)), s, fset.Position(pos(s)))
			}
		}
	}
}

type hangingReconciler struct{}

func (hangingReconciler) Reconcile(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

// TestBootFirewallPass_HasADeadline (re-review m3): the first firewall pass
// at boot runs before any start and before the gRPC server; an nft that
// hangs must not hold the whole daemon start, guarded or not.
func TestBootFirewallPass_HasADeadline(t *testing.T) {
	done := make(chan error, 1)
	go func() { done <- bootFirewallPass(context.Background(), hangingReconciler{}, 100*time.Millisecond) }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a pass that never finished reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the boot firewall pass has no deadline")
	}
}
