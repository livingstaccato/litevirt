package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Settle destroys a copy this host's partition pause holds paused only under
// the pauser's mark lock (health.PartitionPauser.SettleDestroy), so the
// reconciler must hold the guard of the very pauser that Run starts, and must
// hold it before its first pass: the guard is a plain field, and setting it
// after `go reconciler.Start` is a data race and leaves the first passes
// unguarded. Asserted against the source, as the other Run wiring tests are.
//
// Mutations: set the guard after `go reconciler.Start` — red; drop the call,
// or pass another pauser's guard — red.
func TestRunWiresThePauseGuardBeforeTheReconcilerStarts(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon.go: %v", err)
	}
	var guard, reconcilerStart, pauserStart token.Pos
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.GoStmt:
			if s, ok := n.Call.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "Start" {
				if x, ok := s.X.(*ast.Ident); ok {
					switch x.Name {
					case "reconciler":
						reconcilerStart = n.Pos()
					case "pauser":
						pauserStart = n.Pos()
					}
				}
			}
		case *ast.CallExpr:
			s, ok := n.Fun.(*ast.SelectorExpr)
			if !ok || s.Sel.Name != "SetPauseGuard" || len(n.Args) != 1 {
				return true
			}
			recv, _ := s.X.(*ast.Ident)
			arg, ok := n.Args[0].(*ast.SelectorExpr)
			if recv == nil || recv.Name != "reconciler" || !ok || arg.Sel.Name != "SettleDestroy" {
				return true
			}
			if a, _ := arg.X.(*ast.Ident); a != nil && a.Name == "pauser" {
				guard = n.Pos()
			}
		}
		return true
	})
	if guard == 0 {
		t.Fatal("daemon.go does not call reconciler.SetPauseGuard(pauser.SettleDestroy)")
	}
	if reconcilerStart == 0 || guard > reconcilerStart {
		t.Error("reconciler.SetPauseGuard(pauser.SettleDestroy) comes after go reconciler.Start: a data race, and its first passes settle unguarded")
	}
	if pauserStart == 0 || pauserStart < guard {
		t.Error("the guarded pauser is not the one Run starts after it")
	}
}
