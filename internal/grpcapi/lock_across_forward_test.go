package grpcapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// A per-VM lock must never be held across a peer RPC.
//
// lockVM hands back a plain sync.Mutex with no context, so waiting on it cannot
// be interrupted or timed out. Holding it across a forward pins the lock for the
// whole remote call — minutes for a memory snapshot, indefinitely if the peer
// hangs — and blocks every other lifecycle RPC for that VM on this node.
//
// Worse, it deadlocks on divergent vms.host_name replicas: A believes B owns the
// VM and B believes A does, so A locks, calls B, B locks, calls A, and A's inner
// handler blocks forever on the mutex it already holds. Neither call returns and
// the VM is permanently wedged on A.
//
// StartVM shows the correct shape — read the row, authorize, forward if remote,
// and only then lock and re-read — and says so in a comment. AttachDevice and
// DetachDevice place the lock after the forward for the same reason.
func TestNoPerVMLockIsHeldAcrossAPeerForward(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	var violations []string
	forwards := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			lockPos := firstCallPos(fn, func(sel *ast.SelectorExpr) bool { return sel.Sel.Name == "lockVM" })
			if !lockPos.IsValid() {
				continue
			}
			// The forward's receiver is whatever peerClient/dialPeer was assigned
			// to, NOT a fixed name. Matching the literal identifier "client" made
			// the scan blind to every handler that spells it otherwise —
			// snapshot_container.go uses `c`, reseed.go uses `peer` — so an
			// entire class of forwards was invisible and a new handler naming its
			// client anything else got no coverage at all.
			peerVars := peerClientVars(fn)
			if len(peerVars) == 0 {
				continue
			}
			// DEFERRED unlocks do not count: `defer unlock()` runs at RETURN, not
			// where it is written, so a deferred release sitting above a forward
			// releases nothing while that forward is in flight. Counting it was
			// the bug in the first version of this scan, and it made the whole
			// test pass against code that was plainly holding the lock.
			var unlockPositions []token.Pos
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if _, isDefer := n.(*ast.DeferStmt); isDefer {
					return false
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "unlock" {
					unlockPositions = append(unlockPositions, call.Pos())
				}
				return true
			})
			// Every peer forward in this function.
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				recv, ok := sel.X.(*ast.Ident)
				if !ok || !peerVars[recv.Name] {
					return true
				}
				forwards++
				if call.Pos() < lockPos {
					return true // forwarded before taking the lock: the correct shape
				}
				for _, u := range unlockPositions {
					if u < call.Pos() {
						return true // released before forwarding
					}
				}
				// A BOUNDED context is tolerated. Holding the lock across a
				// remote call is only unbounded-bad when the remote call itself
				// is unbounded: DeleteVM deliberately proxies under a 2-minute
				// proxyCtx and probes under a 15-second probeCtx, so its lock is
				// held for a known maximum and the cycle breaks on its own. A
				// forward handed the raw handler ctx has no such bound and waits
				// forever on a hung peer.
				if len(call.Args) > 0 {
					if id, ok := call.Args[0].(*ast.Ident); ok && id.Name != "ctx" {
						return true
					}
				}
				violations = append(violations,
					name+":"+itoa(fset.Position(call.Pos()).Line)+" in "+fn.Name.Name+
						" → "+recv.Name+"."+sel.Sel.Name)
				return true
			})
		}
	}

	if forwards == 0 {
		t.Fatal("found no peer forwards at all; the matcher is broken, not the code")
	}
	for _, v := range violations {
		t.Errorf("%s: a per-VM lock is still held while forwarding to a peer. lockVM is an "+
			"uninterruptible sync.Mutex, so this pins the VM's lock for the whole remote "+
			"call and deadlocks outright when two nodes each believe the other owns the VM. "+
			"Release before forwarding, as StartVM does.", v)
	}
}

func firstCallPos(fn *ast.FuncDecl, match func(*ast.SelectorExpr) bool) token.Pos {
	var out token.Pos
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if out.IsValid() {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && match(sel) {
			out = call.Pos()
			return false
		}
		return true
	})
	return out
}

// peerClientVars returns the identifiers in fn that hold a peer client — the
// left-hand side of an assignment from peerClient or dialPeer.
func peerClientVars(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "peerClient", "dialPeer":
		default:
			return true
		}
		if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
			out[id.Name] = true
		}
		return true
	})
	return out
}
