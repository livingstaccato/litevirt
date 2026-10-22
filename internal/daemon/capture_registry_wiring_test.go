package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// One capture registry per host: Run hands d.captureReg to the reconciler
// (its settle drops the pauser's hold with a pause record), the gRPC server
// (its captures) and the partition pauser. Two registries split the host and
// the pause no longer wins over a capture. Run opens libvirt, binds sockets
// and joins gossip, so the wiring is asserted against the source, as the
// other Run wiring tests do; the reconciler's must come before it starts.
//
// Mutations: drop any of the three calls, or give one a fresh registry — red.
func TestRunSharesOneCaptureRegistry(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon.go: %v", err)
	}
	set := map[string]token.Pos{}
	var made, reconcilerStart token.Pos
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) == 1 && len(n.Rhs) == 1 {
				if l, ok := n.Lhs[0].(*ast.SelectorExpr); ok && l.Sel.Name == "captureReg" {
					if c, ok := n.Rhs[0].(*ast.CallExpr); ok {
						if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "NewCaptureRegistry" {
							made = n.Pos()
						}
					}
				}
			}
		case *ast.GoStmt:
			if s, ok := n.Call.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "Start" {
				if x, ok := s.X.(*ast.Ident); ok && x.Name == "reconciler" {
					reconcilerStart = n.Pos()
				}
			}
		case *ast.CallExpr:
			s, ok := n.Fun.(*ast.SelectorExpr)
			if !ok || s.Sel.Name != "SetCaptureRegistry" || len(n.Args) != 1 {
				return true
			}
			recv, _ := s.X.(*ast.Ident)
			arg, ok := n.Args[0].(*ast.SelectorExpr)
			if recv == nil || !ok || arg.Sel.Name != "captureReg" {
				return true
			}
			if a, _ := arg.X.(*ast.Ident); a != nil && a.Name == "d" {
				set[recv.Name] = n.Pos()
			}
		}
		return true
	})
	if made == 0 {
		t.Fatal("daemon.go does not build d.captureReg with NewCaptureRegistry")
	}
	for _, who := range []string{"reconciler", "svc", "pauser"} {
		pos, ok := set[who]
		if !ok {
			t.Errorf("daemon.go does not call %s.SetCaptureRegistry(d.captureReg): the host's captures and its partition pause would not share a registry", who)
			continue
		}
		if pos < made {
			t.Errorf("%s.SetCaptureRegistry(d.captureReg) comes before d.captureReg is built", who)
		}
	}
	if reconcilerStart == 0 || set["reconciler"] == 0 || set["reconciler"] > reconcilerStart {
		t.Error("the reconciler's capture registry is not set before go reconciler.Start")
	}
}
