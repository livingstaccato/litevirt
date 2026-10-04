package ui

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestNoUIHandlerAnswersRPCErrorWith500 is a source-level guard.
//
// Every UI write goes through its gRPC twin with the session's bearer, so the
// daemon decides whether the caller may make it. When it refuses, the gRPC code
// says why: PermissionDenied, InvalidArgument, NotFound, FailedPrecondition. A
// handler that answers every error with a hard-coded 500 turns each of those
// into a server fault — a Viewer's refused delete reads, in the browser, in the
// access log and on any alert keyed on 5xx, as the daemon breaking, and a test
// asserting the refusal cannot tell it from a crash.
//
// So an error returned by a s.grpc call must reach the browser through
// httpStatusFor, or through rpcWriteFailed, which is built on it. The guard
// finds every `if err != nil` whose err came from a s.grpc call (in the if's own
// init, or in the statement just before it) and fails on a WriteHeader or
// http.Error inside it that names 500 directly.
func TestNoUIHandlerAnswersRPCErrorWith500(t *testing.T) {
	for _, off := range rpcErrorAnswered500(t, ".") {
		t.Errorf("%s: an error from %s is answered with a hard-coded 500; use "+
			"rpcWriteFailed(w, what, err) or w.WriteHeader(httpStatusFor(err)), so the "+
			"daemon's refusal reaches the browser as the 4xx it is, not as a server fault",
			off.pos, off.rpc)
	}
}

type rpc500Offence struct {
	pos string
	rpc string
}

// rpcErrorAnswered500 parses every non-test Go file in dir and returns the
// places where an s.grpc call's error is answered with a literal 500.
func rpcErrorAnswered500(t *testing.T, dir string) []rpc500Offence {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	var out []rpc500Offence
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, dir+"/"+name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			blk, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for i, st := range blk.List {
				ifs, ok := st.(*ast.IfStmt)
				if !ok {
					continue
				}
				errName := nilCheckedIdent(ifs.Cond)
				if errName == "" {
					continue
				}
				rpc := grpcCallAssigning(ifs.Init, errName)
				// Otherwise the nearest earlier statement in the block that
				// assigns it — `_, rerr := stream.Recv()` is often followed by
				// an io.EOF check before the error branch.
				for j := i - 1; rpc == "" && j >= 0; j-- {
					if assignsIdent(blk.List[j], errName) {
						rpc = grpcCallAssigning(blk.List[j], errName)
						break
					}
				}
				if rpc == "" {
					continue
				}
				for _, p := range hardCoded500s(ifs.Body) {
					out = append(out, rpc500Offence{pos: fset.Position(p).String(), rpc: rpc})
				}
			}
			return true
		})
	}
	return out
}

func assignsIdent(st ast.Stmt, name string) bool {
	as, ok := st.(*ast.AssignStmt)
	if !ok {
		return false
	}
	for _, l := range as.Lhs {
		if isIdent(l, name) {
			return true
		}
	}
	return false
}

// nilCheckedIdent returns x for a condition `x != nil`, or one that begins
// `x != nil && ...` (as `err != nil && !errors.Is(err, io.EOF)` does).
func nilCheckedIdent(cond ast.Expr) string {
	b, ok := cond.(*ast.BinaryExpr)
	if ok && b.Op == token.LAND {
		return nilCheckedIdent(b.X)
	}
	if !ok || b.Op != token.NEQ {
		return ""
	}
	x, ok := b.X.(*ast.Ident)
	if !ok {
		return ""
	}
	if y, ok := b.Y.(*ast.Ident); !ok || y.Name != "nil" {
		return ""
	}
	return x.Name
}

// grpcCallAssigning returns the RPC name when st assigns errName from a call
// to s.grpc.<RPC>(...).
func grpcCallAssigning(st ast.Stmt, errName string) string {
	as, ok := st.(*ast.AssignStmt)
	if !ok || len(as.Rhs) != 1 {
		return ""
	}
	assigns := false
	for _, l := range as.Lhs {
		if id, ok := l.(*ast.Ident); ok && id.Name == errName {
			assigns = true
		}
	}
	if !assigns {
		return ""
	}
	// Anywhere in the right-hand side, so an RPC wrapped in a closure (a
	// paging helper, a first-frame wait) still counts.
	var rpc string
	ast.Inspect(as.Rhs[0], func(n ast.Node) bool {
		if rpc != "" {
			return false
		}
		if name := grpcCallName(n); name != "" {
			rpc = name
		}
		return true
	})
	return rpc
}

// grpcCallName names the RPC behind n when n is a call to s.grpc.<RPC>(...),
// or a receive on a gRPC stream — where a streaming RPC's refusal arrives.
func grpcCallName(n ast.Node) string {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if sel.Sel.Name == "Recv" || sel.Sel.Name == "CloseAndRecv" {
		return "stream." + sel.Sel.Name
	}
	recv, ok := sel.X.(*ast.SelectorExpr)
	if !ok || recv.Sel.Name != "grpc" || !isIdent(recv.X, "s") {
		return ""
	}
	return "s.grpc." + sel.Sel.Name
}

// hardCoded500s finds w.WriteHeader(500) and http.Error(w, msg, 500), with 500
// spelled either way, anywhere under body.
func hardCoded500s(body ast.Node) []token.Pos {
	var out []token.Pos
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		var code ast.Expr
		switch {
		case sel.Sel.Name == "WriteHeader" && len(call.Args) == 1:
			code = call.Args[0]
		case sel.Sel.Name == "Error" && isIdent(sel.X, "http") && len(call.Args) == 3:
			code = call.Args[2]
		default:
			return true
		}
		if is500(code) {
			out = append(out, call.Pos())
		}
		return true
	})
	return out
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

func is500(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.BasicLit:
		return v.Kind == token.INT && v.Value == "500"
	case *ast.SelectorExpr:
		return isIdent(v.X, "http") && v.Sel.Name == "StatusInternalServerError"
	}
	return false
}
