package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The drain cold-move recovery starts VMs, so Run must launch it only once the
// daemon is fully wired: after the startup recovery barrier (host networks,
// the operation journal, device leases), after every late setter its starts
// read (the VM-start observer), and with the runtime loops that start VMs —
// never in the window the gate comment in Run rules out.
//
// A behavioural test cannot reach this: Run opens libvirt, binds sockets and
// joins gossip. The call order is the finding, so it is asserted against the
// source, as TestRunHealsTheClusterRecordAfterInitSchema does.
//
// Mutation: launch the recovery where round 2 did, right after
// ResumeVMReplaceCleanups — it then precedes the barrier and goes red.
func TestRunLaunchesDrainRecoveryAfterTheStartupBarrier(t *testing.T) {
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
	var recoveryAt int
	recoveryInGo := false
	ast.Inspect(run, func(n ast.Node) bool {
		if g, ok := n.(*ast.GoStmt); ok {
			if sel, ok := g.Call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "RunDrainColdMoveRecovery" {
				recoveryInGo = true
			}
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := sel.Sel.Name
		if x, ok := sel.X.(*ast.Ident); ok && name == "Start" {
			name = x.Name + ".Start"
		}
		if _, seen := first[name]; !seen {
			first[name] = int(call.Pos())
		}
		if sel.Sel.Name == "RunDrainColdMoveRecovery" {
			recoveryAt = int(call.Pos())
		}
		return true
	})
	if recoveryAt == 0 || !recoveryInGo {
		t.Fatal("(*Daemon).Run never launches RunDrainColdMoveRecovery in a goroutine — a drain cold move a crash interrupted is never finished")
	}
	for _, before := range []string{
		"RecoverHostNetworks", "runOperationRecovery", "RecoverDeviceLeases",
		"SetVMStartObserver", "ResumeVMReplaceCleanups", "reconciler.Start",
	} {
		at, ok := first[before]
		if !ok {
			t.Fatalf("(*Daemon).Run no longer calls %s; re-check where the drain recovery belongs", before)
		}
		if recoveryAt < at {
			t.Errorf("Run launches the drain cold-move recovery before %s", before)
		}
	}
}
