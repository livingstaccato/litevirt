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
	for _, off := range rpcErrorAnswered(t, ".", is500) {
		t.Errorf("%s: an error from %s is answered with a hard-coded 500; use "+
			"rpcWriteFailed(w, what, err) or w.WriteHeader(httpStatusFor(err)), so the "+
			"daemon's refusal reaches the browser as the 4xx it is, not as a server fault",
			off.pos, off.rpc)
	}
}

// TestNoUIHandlerAnswersRPCErrorWith200 is the same guard for the opposite
// flattening: a refusal answered 200 with an error toast. Under htmx 2's default
// responseHandling a 2xx is swapped into the target, so a refused Delete
// replaced its own button with the empty body (and the VM page pushed /vms into
// history as if the VM were gone), while the status told the access log the
// write had worked. A 4xx is not swapped, and htmx fires the HX-Trigger toast
// whatever the status, so rpcWriteFailed loses nothing.
//
// rpcErrorAnswered200Allowed names the handlers where 200 is deliberate; each
// carries its reason beside the WriteHeader.
func TestNoUIHandlerAnswersRPCErrorWith200(t *testing.T) {
	for _, off := range rpcErrorAnswered(t, ".", is200) {
		if reason, ok := rpcErrorAnswered200Allowed[off.fn]; ok && reason != "" {
			continue
		}
		t.Errorf("%s (%s): an error from %s is answered with a hard-coded 200; use "+
			"rpcWriteFailed(w, what, err), so a refused write is not reported as a success "+
			"and its empty body is not swapped into the page", off.pos, off.fn, off.rpc)
	}
}

// rpcErrorAnswered200Allowed: handler -> why a failed RPC is answered 200.
var rpcErrorAnswered200Allowed = map[string]string{
	"handleTestNotifyTarget": "Unavailable means the notification endpoint refused or timed out; " +
		"the page and the caller's permission worked, so the toast reports the endpoint and the " +
		"status stays 200. Every other code still goes through httpStatusFor.",
}

type rpc500Offence struct {
	pos string
	rpc string
	fn  string
}

// rpcWrappers are Server methods whose error is an RPC's error, for the guard's
// purposes: the call that returns it is not spelled s.grpc.X at the handler.
var rpcWrappers = map[string]bool{
	"streamUpload": true, // UploadStoragePoolContent's client stream
}

// rpcErrorAnswered parses every non-test Go file in dir and returns the places
// where an s.grpc call's error is answered with a literal status code that
// matches literal.
func rpcErrorAnswered(t *testing.T, dir string, literal func(ast.Expr) bool) []rpc500Offence {
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
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			out = append(out, rpcErrorAnsweredIn(fset, fd, literal)...)
		}
	}
	return out
}

func rpcErrorAnsweredIn(fset *token.FileSet, fd *ast.FuncDecl, literal func(ast.Expr) bool) []rpc500Offence {
	var out []rpc500Offence
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		// A switch or select case holds its statements in a bare list, not a
		// BlockStmt; an if directly under `case "file":` is still a handler's.
		var list []ast.Stmt
		switch b := n.(type) {
		case *ast.BlockStmt:
			list = b.List
		case *ast.CaseClause:
			list = b.Body
		case *ast.CommClause:
			list = b.Body
		default:
			return true
		}
		for i, st := range list {
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
				if assignsIdent(list[j], errName) {
					rpc = grpcCallAssigning(list[j], errName)
					break
				}
			}
			if rpc == "" {
				continue
			}
			for _, p := range hardCodedStatus(ifs.Body, literal) {
				out = append(out, rpc500Offence{pos: fset.Position(p).String(), rpc: rpc, fn: fd.Name.Name})
			}
		}
		return true
	})
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
	if isIdent(sel.X, "s") && rpcWrappers[sel.Sel.Name] {
		return "s." + sel.Sel.Name
	}
	recv, ok := sel.X.(*ast.SelectorExpr)
	if !ok || recv.Sel.Name != "grpc" || !isIdent(recv.X, "s") {
		return ""
	}
	return "s.grpc." + sel.Sel.Name
}

// hardCodedStatus finds w.WriteHeader(code) and http.Error(w, msg, code) where
// literal(code) holds, anywhere under body.
func hardCodedStatus(body ast.Node, literal func(ast.Expr) bool) []token.Pos {
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
		if literal(code) {
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

func is200(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.BasicLit:
		return v.Kind == token.INT && v.Value == "200"
	case *ast.SelectorExpr:
		return isIdent(v.X, "http") && v.Sel.Name == "StatusOK"
	}
	return false
}
