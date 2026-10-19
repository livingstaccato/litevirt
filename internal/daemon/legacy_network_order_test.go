package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The legacy network-name pass rewrites VM specs as desired-spec edits, which
// carry their owner epoch only once the corrosion gates are wired, so Run must
// call it after wireCorrosionGates — and before repl.Start, so no peer's
// write is applied ahead of it. A fleet test sets the order up itself and
// cannot see Run's, so the order is asserted against the source, as
// TestRunLaunchesDrainRecoveryAfterTheStartupBarrier does (review L1).
//
// Mutation: move MigrateLegacyNetworkNames back above wireCorrosionGates —
// red.
func TestRunMigratesLegacyNetworkNamesAfterTheGates(t *testing.T) {
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
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := sel.Sel.Name
		if x, ok := sel.X.(*ast.Ident); ok && name == "Start" {
			name = x.Name + ".Start"
		}
		if _, seen := first[name]; !seen {
			first[name] = call.Pos()
		}
		return true
	})
	migrate, ok := first["MigrateLegacyNetworkNames"]
	if !ok {
		t.Fatal("(*Daemon).Run no longer calls MigrateLegacyNetworkNames; re-check where it belongs")
	}
	gates, ok := first["wireCorrosionGates"]
	if !ok {
		t.Fatal("(*Daemon).Run no longer calls wireCorrosionGates")
	}
	start, ok := first["repl.Start"]
	if !ok {
		t.Fatal("(*Daemon).Run no longer calls repl.Start")
	}
	if migrate < gates {
		t.Error("Run migrates legacy network names before wireCorrosionGates: its spec edits go out without their owner epoch")
	}
	if migrate > start {
		t.Error("Run migrates legacy network names after repl.Start")
	}
}
