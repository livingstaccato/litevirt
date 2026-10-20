package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// A row a daemon left migrating (it died mid-move) is named by
// vm.migration_unresolved when the daemon starts again: Run calls
// RaiseLeftMigrating, after RecoverFirmwareMoves has taken the locks of the
// VMs whose live firmware moves it resumes, so those are left to it.
//
// Asserted against the source, as TestRunAwaitsTheFirstVTPMPassBeforeAnyVMStart
// is: Run opens libvirt, binds sockets and joins gossip.
//
// Mutation: the call dropped from Run, or moved before RecoverFirmwareMoves —
// red.
func TestRunRaisesLeftMigratingAfterFirmwareMoveRecovery(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "daemon.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon.go: %v", err)
	}
	var run *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "Run" && fn.Recv != nil {
			run = fn
		}
	}
	if run == nil {
		t.Fatal("no (*Daemon).Run in daemon.go")
	}
	first := map[string]token.Pos{}
	ast.Inspect(run, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if _, seen := first[sel.Sel.Name]; !seen {
				first[sel.Sel.Name] = call.Pos()
			}
		}
		return true
	})
	recover, ok := first["RecoverFirmwareMoves"]
	if !ok {
		t.Fatal("(*Daemon).Run no longer calls RecoverFirmwareMoves")
	}
	raise, ok := first["RaiseLeftMigrating"]
	if !ok {
		t.Fatal("(*Daemon).Run does not call RaiseLeftMigrating: a row left migrating by a crash raises no condition")
	}
	if raise < recover {
		t.Errorf("RaiseLeftMigrating (%s) runs before RecoverFirmwareMoves (%s)", fset.Position(raise), fset.Position(recover))
	}
}
