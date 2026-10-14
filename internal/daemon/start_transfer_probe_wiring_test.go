package daemon

import (
	"go/ast"
	"testing"
)

// Re-review m-4: a cancel of a start records whether it was a proof-less
// transfer by asking the reconciler (Reconciler.IsDeferredTransfer). Run
// must wire the gRPC server's probe to the reconciler it runs — the one it
// also hands the server's start deferral — or every cancel of a parked
// transfer records a local start.
//
// Mutation: the wiring line dropped, or given another function — red.
func TestRunWiresTheStartTransferProbe(t *testing.T) {
	run := parseRun(t)
	var probeRecv, deferralRecv *ast.Object
	var probeArg ast.Expr
	ast.Inspect(run.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "SetStartTransferProbe":
			if len(c.Args) == 1 {
				probeArg = c.Args[0]
			}
		case "SetStartDeferral":
			deferralRecv = runVar(sel.X)
		}
		return true
	})
	arg, ok := probeArg.(*ast.SelectorExpr)
	if !ok || arg.Sel.Name != "IsDeferredTransfer" {
		t.Fatalf("Run does not wire SetStartTransferProbe to a reconciler's IsDeferredTransfer (got %s)", exprString(probeArg))
	}
	probeRecv = runVar(arg.X)
	if probeRecv == nil || probeRecv != deferralRecv {
		t.Fatalf("the probe reads %s, not the reconciler Run wires the start deferral on", exprString(arg.X))
	}
}
