package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The failover coordinator's stall alert reaches operators only through the
// notifier the daemon wires: fc.OnRecoveryStalled = svc.NotifyRecoveryStalled.
// Run opens libvirt, binds sockets and joins gossip, so the wiring is asserted
// against the source, as the drain-recovery ordering test does.
//
// Mutation: delete the assignment — this test fails.
func TestRunWiresTheRecoveryStalledNotifier(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "daemon.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon.go: %v", err)
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		lhs, ok1 := as.Lhs[0].(*ast.SelectorExpr)
		rhs, ok2 := as.Rhs[0].(*ast.SelectorExpr)
		if !ok1 || !ok2 {
			return true
		}
		lx, _ := lhs.X.(*ast.Ident)
		rx, _ := rhs.X.(*ast.Ident)
		if lx != nil && rx != nil && lx.Name == "fc" && lhs.Sel.Name == "OnRecoveryStalled" &&
			rx.Name == "svc" && rhs.Sel.Name == "NotifyRecoveryStalled" {
			found = true
		}
		return true
	})
	if !found {
		t.Error("daemon.go does not wire fc.OnRecoveryStalled = svc.NotifyRecoveryStalled: stall alerts would notify nobody")
	}
}
