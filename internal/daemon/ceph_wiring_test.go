package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// n1 (ceph re-review 4). Three pieces of the ceph VM-disk work exist only as
// wiring in daemon.go, which no behavioural test reaches (Run opens libvirt,
// binds sockets and joins gossip), so it is asserted against the source:
//
//   - the reconciler asks the Server whether a start would be deferred before
//     it does any work for it (SetStartDeferral(svc.CephStartDeferral));
//   - the trash purges a previous run left are resumed (ResumeCephPurges),
//     before the reconciler starts;
//   - the ceph secret loop scans the pools' trash for entries no purge here
//     tracks (ScanCephTrash), the first time when it starts.
//
// Mutation: delete any one of the three calls and this goes red.
func TestRunWiresTheCephStartDeferralAndTrash(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "daemon.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon.go: %v", err)
	}
	funcs := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil {
			funcs[fn.Name.Name] = fn
		}
	}
	run, loop := funcs["Run"], funcs["runCephSecretReconcile"]
	if run == nil || loop == nil {
		t.Fatal("no (*Daemon).Run or runCephSecretReconcile in daemon.go")
	}
	type call struct {
		pos  token.Pos
		args []ast.Expr
	}
	calls := func(fn *ast.FuncDecl) map[string]call {
		out := map[string]call{}
		ast.Inspect(fn, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := c.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			names := []string{sel.Sel.Name}
			if x, ok := sel.X.(*ast.Ident); ok {
				names = append(names, x.Name+"."+sel.Sel.Name)
			}
			for _, name := range names {
				if _, seen := out[name]; !seen {
					out[name] = call{c.Pos(), c.Args}
				}
			}
			return true
		})
		return out
	}
	inRun := calls(run)
	start, ok := inRun["reconciler.Start"]
	if !ok {
		t.Fatal("Run no longer calls reconciler.Start; re-check this test")
	}
	sd, ok := inRun["reconciler.SetStartDeferral"]
	if !ok || len(sd.args) != 1 {
		t.Fatal("Run does not wire reconciler.SetStartDeferral: a ceph start with no time left is half-started")
	}
	if sel, ok := sd.args[0].(*ast.SelectorExpr); !ok || sel.Sel.Name != "CephStartDeferral" {
		t.Fatal("reconciler.SetStartDeferral is not given the Server's CephStartDeferral")
	}
	if sd.pos > start.pos {
		t.Error("the start deferral is wired after the reconciler starts")
	}
	if rp, ok := inRun["storage.ResumeCephPurges"]; !ok {
		t.Error("Run does not resume the ceph trash purges a previous run left")
	} else if rp.pos > start.pos {
		t.Error("the ceph trash purges are resumed after the reconciler starts")
	}
	if _, ok := calls(loop)["ScanCephTrash"]; !ok {
		t.Error("runCephSecretReconcile never scans the pools' trash (ScanCephTrash)")
	}
}
