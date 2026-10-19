package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Codex I4: the first pass over the swtpm tree (vtpm_state_sync) completes,
// or runs past its wait and raises vtpm_state_not_durable, before anything
// on this host can start a VM. The vTPM capability label orders placement
// only; an onboot start, a restart policy, a cutover or operation recovery,
// a drain recovery or an API start on this host does not ask it, so Run
// waits for the pass before it launches any of them.
//
// Asserted against the source, as TestRunLaunchesDrainRecoveryAfterTheStartupBarrier
// is: Run opens libvirt, binds sockets and joins gossip.
//
// Mutation: move awaitFirstVTPMPass back to the capability labels, after
// the runtime loops start, and this goes red.
func TestRunAwaitsTheFirstVTPMPassBeforeAnyVMStart(t *testing.T) {
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
	first := map[string]int{}
	ast.Inspect(run, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			name = fn.Name
		case *ast.SelectorExpr:
			name = fn.Sel.Name
			if x, ok := fn.X.(*ast.Ident); ok && name == "Start" {
				name = x.Name + ".Start"
			}
		default:
			return true
		}
		if _, seen := first[name]; !seen {
			first[name] = int(call.Pos())
		}
		return true
	})
	at, ok := first["awaitFirstVTPMPass"]
	if !ok {
		t.Fatal("(*Daemon).Run never awaits the first vTPM pass")
	}
	for _, starter := range []string{
		"resumeVMReplaceCleanups", "runOperationRecovery", "SetStartGuard",
		"vmChecker.Start", "reconciler.Start", "StartOnbootVMs", "RunDrainColdMoveRecovery",
		"RunHeldGuestResumer", "fc.Start", "Serve",
	} {
		pos, ok := first[starter]
		if !ok {
			t.Fatalf("(*Daemon).Run no longer calls %s; update this test's list of VM starters", starter)
		}
		if pos < at {
			t.Errorf("%s (%s) runs before the first vTPM pass is awaited (%s)",
				starter, fset.Position(token.Pos(pos)), fset.Position(token.Pos(at)))
		}
	}
}
