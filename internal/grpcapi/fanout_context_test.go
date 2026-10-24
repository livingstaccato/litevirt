package grpcapi

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fanoutTestKey struct{}

// The point of the helper: survive the handler, keep everything else.
func TestDetachedFanout_SurvivesHandlerCancellationAndKeepsValues(t *testing.T) {
	parent := context.WithValue(context.Background(), fanoutTestKey{}, "caller-identity")
	parent, cancelParent := context.WithCancel(parent)

	fctx, cancel := detachedFanout(parent)
	defer cancel()

	// The handler returns: gRPC cancels its context here.
	cancelParent()

	if err := fctx.Err(); err != nil {
		t.Fatalf("fan-out context died with its handler (%v); the peer call would fail "+
			"with codes.Canceled and the failure would only be logged", err)
	}
	if got := fctx.Value(fanoutTestKey{}); got != "caller-identity" {
		t.Errorf("value = %v, want it carried through: dropping values re-authenticates the "+
			"peer call as somebody else", got)
	}
	if _, ok := fctx.Deadline(); !ok {
		t.Error("no deadline: an unreachable peer would hold the goroutine open indefinitely, " +
			"because the lazy dial returns immediately and the RPC is what blocks")
	}
}

// The wiring guard follows the actual owned callbacks and FDB goroutine. A
// detached context elsewhere in the file cannot excuse a raw handler-context
// call, a missing cancellation/connection close, or bypassing the owned worker.
func peerFanoutProblems(file string, src []byte) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, parser.SkipObjectResolution)
	if err != nil {
		return []string{fmt.Sprintf("parse %s: %v", file, err)}
	}
	isHost := func(fn *ast.FuncLit) bool {
		if fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
			return false
		}
		p := fn.Type.Params.List[0]
		typ, ok := p.Type.(*ast.Ident)
		return ok && typ.Name == "string" && len(p.Names) == 1 && p.Names[0].Name == "host"
	}
	parents := map[*ast.FuncLit]*ast.FuncDecl{}
	for _, declaration := range f.Decls {
		if fd, ok := declaration.(*ast.FuncDecl); ok && fd.Body != nil {
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if fn, ok := n.(*ast.FuncLit); ok && isHost(fn) {
					parents[fn] = fd
				}
				return true
			})
		}
	}
	owned, asynchronous := map[*ast.FuncLit]bool{}, map[*ast.FuncLit]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "startNetworkWork" && len(call.Args) == 1 {
				if callback, ok := call.Args[0].(*ast.FuncLit); ok {
					ast.Inspect(callback.Body, func(n ast.Node) bool {
						if fn, ok := n.(*ast.FuncLit); ok && isHost(fn) {
							owned[fn] = true
						}
						return true
					})
				}
			}
		}
		if goStmt, ok := n.(*ast.GoStmt); ok {
			if fn, ok := goStmt.Call.Fun.(*ast.FuncLit); ok && isHost(fn) {
				asynchronous[fn] = true
			}
		}
		return true
	})
	var problems []string
	count := 0
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncLit)
		if !ok || !isHost(fn) {
			return true
		}
		count++
		problem := func(reason string) {
			problems = append(problems, fmt.Sprintf("%s: %s", fset.Position(fn.Pos()), reason))
		}
		if file != "fdb.go" && !owned[fn] {
			problem("fanout bypasses registered network-work owner")
		}
		if file == "fdb.go" && !asynchronous[fn] {
			problem("FDB fanout no longer identifies its asynchronous boundary")
		}
		bindingIn := func(body *ast.BlockStmt) (string, string, *ast.AssignStmt) {
			for _, statement := range body.List {
				a, ok := statement.(*ast.AssignStmt)
				if !ok || len(a.Lhs) != 2 || len(a.Rhs) != 1 {
					continue
				}
				call, ok := a.Rhs[0].(*ast.CallExpr)
				if !ok {
					continue
				}
				valid := false
				if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "detachedFanout" && len(call.Args) == 1 {
					parent, ok := call.Args[0].(*ast.Ident)
					valid = ok && parent.Name == "ctx"
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "WithTimeout" && len(call.Args) == 2 {
					pkg, ok := sel.X.(*ast.Ident)
					background, bok := call.Args[0].(*ast.CallExpr)
					duration, dok := call.Args[1].(*ast.BinaryExpr)
					if ok && pkg.Name == "context" && bok && len(background.Args) == 0 && dok && duration.Op == token.MUL {
						bg, bgok := background.Fun.(*ast.SelectorExpr)
						value, vok := duration.X.(*ast.BasicLit)
						unit, uok := duration.Y.(*ast.SelectorExpr)
						if bgok && vok && uok {
							bctx, bcok := bg.X.(*ast.Ident)
							clock, cok := unit.X.(*ast.Ident)
							seconds, e := strconv.Atoi(value.Value)
							valid = bcok && bctx.Name == "context" && bg.Sel.Name == "Background" && cok && clock.Name == "time" && unit.Sel.Name == "Second" && e == nil && seconds > 0 && seconds <= 30
						}
					}
				}
				if !valid {
					continue
				}
				c, cok := a.Lhs[0].(*ast.Ident)
				stop, sok := a.Lhs[1].(*ast.Ident)
				if cok && sok {
					return c.Name, stop.Name, a
				}
			}
			return "", "", nil
		}
		detached, cancel, binding := bindingIn(fn.Body)
		external := false
		if detached == "" {
			if parent := parents[fn]; parent != nil {
				detached, cancel, binding = bindingIn(parent.Body)
				external = detached != ""
			}
		}
		if detached == "" || cancel == "" {
			problem("fanout has no detached handler-context binding")
		}
		cancelled, closed, peer, rpc, done := false, false, false, false, false
		if external {
			wait := false
			for _, statement := range parents[fn].Body.List {
				if d, ok := statement.(*ast.DeferStmt); ok {
					if id, ok := d.Call.Fun.(*ast.Ident); ok && id.Name == cancel {
						cancelled = true
					}
				}
				if e, ok := statement.(*ast.ExprStmt); ok {
					if c, ok := e.X.(*ast.CallExpr); ok {
						if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Wait" {
							if id, ok := sel.X.(*ast.Ident); ok && id.Name == "wg" {
								wait = true
							}
						}
					}
				}
			}
			if !wait {
				problem("outer detached context is not joined before handler exit")
			}
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if a, ok := n.(*ast.AssignStmt); ok && a != binding && detached != "" {
				for _, lhs := range a.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name == detached {
						problem("detached context is reassigned")
					}
				}
			}
			if d, ok := n.(*ast.DeferStmt); ok {
				if sel, ok := d.Call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Done" {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "wg" {
						done = true
					}
				}
				if id, ok := d.Call.Fun.(*ast.Ident); ok && id.Name == cancel {
					cancelled = true
				}
				if sel, ok := d.Call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Close" {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "conn" {
						closed = true
					}
				}
			}
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			if first, ok := call.Args[0].(*ast.Ident); ok && first.Name == "ctx" {
				id, exception := call.Fun.(*ast.Ident)
				if !exception || id.Name != "detachedFanout" {
					problem("fanout call uses the handler context")
				}
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			receiver, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			relevant := receiver.Name == "s" && sel.Sel.Name == "peerClient"
			if relevant {
				peer = true
			}
			if receiver.Name == "client" && (sel.Sel.Name == "ApplyLB" || sel.Sel.Name == "SyncVTEP" || sel.Sel.Name == "UpdateFDB" || sel.Sel.Name == "RemoveLB" || sel.Sel.Name == "RefreshLB") {
				relevant, rpc = true, true
			}
			if relevant {
				ctx, ok := call.Args[0].(*ast.Ident)
				if !ok || detached == "" || ctx.Name != detached {
					problem("peer call is not bound to the detached context")
				}
			}
			return true
		})
		if external && !done {
			problem("joined fanout has no deferred completion")
		}
		if !cancelled {
			problem("fanout has no deferred context cancellation")
		}
		if !closed {
			problem("fanout has no deferred peer connection close")
		}
		if !peer || !rpc {
			problem("fanout no longer identifies both peer dial and RPC")
		}
		return true
	})
	if count == 0 {
		problems = append(problems, file+": no host fanout found")
	}
	return problems
}

func TestPeerFanouts_DoNotUseTheHandlerContext(t *testing.T) {
	for _, file := range []string{"lb.go", "networks.go", "fdb.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, problem := range peerFanoutProblems(file, src) {
			t.Error(problem)
		}
	}
}

// Mutate actual current callbacks, leaving other detached calls intact. Each
// valid parsed bad path must fail for its intended safety boundary.
func TestPeerFanouts_RejectUnsafeCurrentCallbacks(t *testing.T) {
	for _, file := range []string{"lb.go", "networks.go", "fdb.go"} {
		original, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		mutations := []struct{ name, before, after, want string }{
			{"attached-context", "detachedFanout(ctx)", "context.WithCancel(ctx)", "no detached handler-context binding"},
			{"raw-handler-peer-call", "s.peerClient(fctx, host)", "s.peerClient(ctx, host)", "uses the handler context"},
			{"lost-cancel", "defer cancel()", "cancel()", "no deferred context cancellation"},
			{"lost-peer-close", "defer conn.Close()", "conn.Close()", "no deferred peer connection close"},
		}
		if file != "fdb.go" {
			mutations = append(mutations, struct{ name, before, after, want string }{"unowned-work", "s.startNetworkWork(", "s.unownedNetworkWork(", "bypasses registered network-work owner"})
		}
		if file == "lb.go" {
			mutations = append(mutations,
				struct{ name, before, after, want string }{"background-unbounded", "context.WithTimeout(context.Background(), 15*time.Second)", "context.WithCancel(context.Background())", "no detached handler-context binding"},
				struct{ name, before, after, want string }{"raw-background-peer-call", "s.peerClient(rctx, host)", "s.peerClient(ctx, host)", "uses the handler context"},
				struct{ name, before, after, want string }{"raw-joined-peer-call", "s.peerClient(remoteCtx, host)", "s.peerClient(ctx, host)", "uses the handler context"},
				struct{ name, before, after, want string }{"lost-join", "wg.Wait()", "wg.Add(0)", "not joined before handler exit"},
			)
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, original, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		type span struct{ begin, end int }
		var callbacks []span
		var joinedParent span
		ast.Inspect(parsed, func(n ast.Node) bool {
			add := false
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "startNetworkWork" {
					add = true
				}
			}
			if _, ok := n.(*ast.GoStmt); ok {
				add = true
			}
			if add {
				hostCallback := false
				ast.Inspect(n, func(child ast.Node) bool {
					fn, ok := child.(*ast.FuncLit)
					if !ok || fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
						return true
					}
					param := fn.Type.Params.List[0]
					typ, ok := param.Type.(*ast.Ident)
					if ok && typ.Name == "string" && len(param.Names) == 1 && param.Names[0].Name == "host" {
						hostCallback = true
					}
					return true
				})
				if hostCallback {
					callbacks = append(callbacks, span{fset.Position(n.Pos()).Offset, fset.Position(n.End()).Offset})
				}
			}
			if fd, ok := n.(*ast.FuncDecl); ok && fd.Name.Name == "removeLBForStack" {
				joinedParent = span{fset.Position(fd.Pos()).Offset, fset.Position(fd.End()).Offset}
			}
			return true
		})
		if want := map[string]int{"lb.go": 6, "networks.go": 1, "fdb.go": 1}[file]; len(callbacks) != want {
			t.Fatalf("current host-callback inventory changed: %d, want %d", len(callbacks), want)
		}
		for _, mutation := range mutations {
			var offsets []int
			for offset := 0; offset < len(original); {
				relative := strings.Index(string(original[offset:]), mutation.before)
				if relative < 0 {
					break
				}
				offset += relative
				spans := callbacks
				if mutation.name == "lost-join" {
					spans = []span{joinedParent}
				}
				for _, area := range spans {
					if offset >= area.begin && offset < area.end {
						offsets = append(offsets, offset)
						break
					}
				}
				offset += len(mutation.before)
			}
			if len(offsets) == 0 {
				t.Fatalf("mutation %s did not reach current callback", mutation.name)
			}
			for occurrence, offset := range offsets {
				t.Run(fmt.Sprintf("%s/%s/%d", file, mutation.name, occurrence), func(t *testing.T) {
					changed := string(original[:offset]) + mutation.after + string(original[offset+len(mutation.before):])
					got := strings.Join(peerFanoutProblems(file, []byte(changed)), "\n")
					if strings.Contains(got, "parse ") || !strings.Contains(got, mutation.want) {
						t.Fatalf("wrong guard failure: %s, want %q", got, mutation.want)
					}
				})
			}
		}
	}
	if got := strings.Join(peerFanoutProblems("lb.go", []byte("package grpcapi")), "\n"); !strings.Contains(got, "no host fanout found") {
		t.Fatalf("empty match accepted: %s", got)
	}
}

func TestPeerFanouts_OwnedWorkJoinsThenQuiesces(t *testing.T) {
	s := &Server{}
	entered, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(release) }) }
	defer stop()
	s.startNetworkWork(func() { close(entered); <-release })
	<-entered
	go func() { s.WaitNetworkWork(); close(joined) }()
	select {
	case <-joined:
		t.Fatal("owned callback was reported quiescent before exit")
	case <-time.After(20 * time.Millisecond):
	}
	stop()
	select {
	case <-joined:
	case <-time.After(2 * time.Second):
		t.Fatal("owned callback was not joined after exit")
	}
	if generation := s.WaitNetworkWork(); generation != 1 {
		t.Fatalf("registration generation=%d, want 1", generation)
	}
}
