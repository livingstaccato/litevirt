package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The pit_overlay gate of the production reconciler and the failover
// coordinator's WAL-quarantine reader are wired only in Run, which opens
// libvirt and binds sockets, so the wiring is asserted against the source (as
// TestRunWiresTheRecoveryStalledNotifier does).
//
// Mutations: drop reconciler.SetPITOverlayFeature(svc.PITOverlayFeature) —
// every overlay found at define is held forever; drop
// fc.PeerWALQuarantined = svc.PeerReportsWALQuarantined — a quarantined peer
// is a recovery target until it is recorded isolated. Each — red.
func TestRunWiresThePITOverlayGates(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "daemon.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon.go: %v", err)
	}
	sel := func(e ast.Expr) (string, string) {
		s, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", ""
		}
		x, _ := s.X.(*ast.Ident)
		if x == nil {
			return "", ""
		}
		return x.Name, s.Sel.Name
	}
	var reconcilerGate, fcQuarantine bool
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			if x, m := sel(v.Fun); x == "reconciler" && m == "SetPITOverlayFeature" && len(v.Args) == 1 {
				if ax, am := sel(v.Args[0]); ax == "svc" && am == "PITOverlayFeature" {
					reconcilerGate = true
				}
			}
		case *ast.AssignStmt:
			if len(v.Lhs) == 1 && len(v.Rhs) == 1 {
				lx, lm := sel(v.Lhs[0])
				rx, rm := sel(v.Rhs[0])
				if lx == "fc" && lm == "PeerWALQuarantined" && rx == "svc" && rm == "PeerReportsWALQuarantined" {
					fcQuarantine = true
				}
			}
		}
		return true
	})
	if !reconcilerGate {
		t.Error("daemon.go does not call reconciler.SetPITOverlayFeature(svc.PITOverlayFeature): every overlay found at define would be held forever")
	}
	if !fcQuarantine {
		t.Error("daemon.go does not wire fc.PeerWALQuarantined = svc.PeerReportsWALQuarantined")
	}
}
