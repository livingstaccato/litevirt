package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// A row left migrating is named after the owned synchronous firmware recovery
// took its VM locks. Both calls stay unconditional direct steps of the verified
// owned startup continuation. The coordinator's owned context
// and delegation are part of the guarantee, not merely its method's spelling.
// Mutation: drop/reorder/nest either Run call, duplicate/bypass recovery, make
// its coordinator delegation asynchronous, or pass the unowned caller context.
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
	run, err = executionOwnedRun(run)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	ast.Inspect(run.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				counts[sel.Sel.Name]++
			}
		}
		return true
	})
	if counts["recoverFirmwareMoves"] != 1 || counts["RaiseLeftMigrating"] != 1 || counts["RecoverFirmwareMoves"] != 0 {
		t.Fatal("Run must recover once through its coordinator and raise once, without raw recovery", counts)
	}
	recoveryIndex, raiseIndex := -1, -1
	for i, stmt := range run.Body.List {
		expr, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := expr.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		receiver, ok := sel.X.(*ast.Ident)
		if !ok {
			continue
		}
		if sel.Sel.Name != "recoverFirmwareMoves" && sel.Sel.Name != "RaiseLeftMigrating" {
			continue
		}
		if len(call.Args) != 1 {
			t.Fatal("startup recovery/raise call must take ctx once")
		}
		ctx, ok := call.Args[0].(*ast.Ident)
		if !ok || ctx.Name != "ctx" {
			t.Fatal("unexpected startup call context")
		}
		if sel.Sel.Name == "recoverFirmwareMoves" && receiver.Name == "dbWorkers" {
			recoveryIndex = i
		}
		if sel.Sel.Name == "RaiseLeftMigrating" && receiver.Name == "svc" {
			raiseIndex = i
		}
	}
	if recoveryIndex < 0 || raiseIndex < 0 {
		t.Fatal("coordinator recovery and raise must be direct owned startup statements")
	}
	if raiseIndex <= recoveryIndex {
		t.Fatal("RaiseLeftMigrating must follow synchronous coordinator recovery")
	}

	workers, err := parser.ParseFile(fset, "db_workers.go", nil, 0)
	if err != nil {
		t.Fatalf("parse db_workers.go: %v", err)
	}
	var recovery *ast.FuncDecl
	for _, decl := range workers.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "recoverFirmwareMoves" || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		kind, ok := star.X.(*ast.Ident)
		if ok && kind.Name == "dbWorkerCoordinator" {
			recovery = fn
		}
	}
	if recovery == nil || recovery.Body == nil || len(recovery.Body.List) != 1 {
		t.Fatal("coordinator recovery must directly delegate exactly once")
	}
	expr, ok := recovery.Body.List[0].(*ast.ExprStmt)
	if !ok {
		t.Fatal("coordinator recovery must be synchronous, not go/defer/conditional")
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		t.Fatal("coordinator recovery must call service exactly once")
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "RecoverFirmwareMoves" {
		t.Fatal("coordinator must delegate actual service recovery")
	}
	service, ok := sel.X.(*ast.SelectorExpr)
	if !ok || service.Sel.Name != "svc" {
		t.Fatal("coordinator must use its owned service")
	}
	owner, ok := service.X.(*ast.Ident)
	if !ok || owner.Name != "c" {
		t.Fatal("coordinator service owner changed")
	}
	ownedCtx, ok := call.Args[0].(*ast.SelectorExpr)
	if !ok || ownedCtx.Sel.Name != "ctx" {
		t.Fatal("coordinator must use its owned context")
	}
	ctxOwner, ok := ownedCtx.X.(*ast.Ident)
	if !ok || ctxOwner.Name != "c" {
		t.Fatal("coordinator context owner changed")
	}
}
