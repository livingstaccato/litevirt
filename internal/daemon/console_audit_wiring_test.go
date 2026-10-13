package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// A graceful stop writes every open console session's close row before the
// database closes (docs/audit-log.md "Console sessions"). Run's shutdown is
// reached by no behavioural test (it opens libvirt and binds sockets), so the
// order is asserted against the source:
//
//	MarkConsoleShutdown < GracefulStop < FlushConsoleAudit < repl.Stop < db.Close
//
// grpcapi's TestConsoleAudit_DaemonStop* test what the two calls do.
//
// Mutation: delete either call, or move the flush after db.Close — red.
func TestRunFlushesConsoleAuditBeforeTheDatabaseCloses(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "daemon.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon.go: %v", err)
	}
	var run *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil && fn.Name.Name == "Run" {
			run = fn
		}
	}
	if run == nil {
		t.Fatal("no (*Daemon).Run in daemon.go")
	}
	// The last position of each call in Run: the shutdown is at its end.
	pos := map[string]token.Pos{}
	ast.Inspect(run, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := sel.Sel.Name
		switch x := sel.X.(type) {
		case *ast.Ident:
			name = x.Name + "." + name
		case *ast.SelectorExpr:
			name = x.Sel.Name + "." + name
		}
		pos[name] = c.Pos()
		return true
	})
	order := []string{"svc.MarkConsoleShutdown", "grpcSrv.GracefulStop", "svc.FlushConsoleAudit", "repl.Stop", "db.Close"}
	for i, name := range order {
		if pos[name] == token.NoPos {
			t.Fatalf("Run never calls %s", name)
		}
		if i > 0 && pos[order[i-1]] >= pos[name] {
			t.Errorf("Run calls %s after %s; want %v in that order", order[i-1], name, order)
		}
	}
}
