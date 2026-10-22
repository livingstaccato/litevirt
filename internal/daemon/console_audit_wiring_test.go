package daemon

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder records the shutdown steps in the order they happen.
type recorder struct {
	mu    sync.Mutex
	steps []string
	stop  chan struct{} // GracefulStop blocks until Stop when set
	hang  chan struct{} // GracefulStop and Stop both block on it when set: a stop stuck behind a handler in the kernel
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	r.steps = append(r.steps, s)
	r.mu.Unlock()
}

func (r *recorder) GracefulStop() {
	r.add("GracefulStop")
	if r.hang != nil {
		<-r.hang
		return
	}
	if r.stop != nil {
		<-r.stop
	}
}
func (r *recorder) Stop() {
	r.add("Stop")
	if r.hang != nil {
		<-r.hang
		return
	}
	if r.stop != nil {
		close(r.stop)
	}
}
func (r *recorder) MarkConsoleShutdown() { r.add("Mark") }
func (r *recorder) FlushConsoleAudit()   { r.add("Flush") }

func (r *recorder) got() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.steps, " ")
}

// afterStop is the afterStop Run would pass: it records "after", or
// "after(stopped still open)" when stopServing has not yet closed stopped
// for Run's awaitServe.
func (r *recorder) afterStop(stopped <-chan struct{}) func() {
	return func() {
		select {
		case <-stopped:
			r.add("after")
		default:
			r.add("after(stopped still open)")
		}
	}
}

// runStopServing runs stopServing and fails, instead of hanging the package,
// when it does not return within limit.
func runStopServing(t *testing.T, r *recorder, graceful, forced, limit time.Duration) time.Duration {
	t.Helper()
	stopped := make(chan struct{})
	done := make(chan struct{})
	start := time.Now()
	go func() {
		stopServing(r, r, graceful, forced, stopped, r.afterStop(stopped))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("stopServing did not return within %s (graceful %s, forced %s); steps so far %q",
			limit, graceful, forced, r.got())
	}
	select {
	case <-stopped:
	default:
		t.Fatal("stopServing returned without closing stopped: Run's awaitServe would wait on Serve unbounded")
	}
	return time.Since(start)
}

// stopServing marks the console audit before the gRPC server stops, closes
// stopped for Run's awaitServe once the stop has returned or been given up
// on, and flushes after that and after afterStop. The flush is the last
// step, so the caller's database close comes after it.
//
// Mutation "flush before the server stops" — red. Mutation "no Mark" — red.
// Mutation "no close(stopped)" — red. Mutation "Stop waited on unbounded"
// (lab 2 N-5) — red, in "the stop never returns".
func TestStopServing_MarksThenStopsThenFlushes(t *testing.T) {
	t.Run("graceful", func(t *testing.T) {
		r := &recorder{}
		runStopServing(t, r, time.Second, time.Second, 5*time.Second)
		if got := r.got(); got != "Mark GracefulStop after Flush" {
			t.Fatalf("steps = %q", got)
		}
	})
	t.Run("a console holds the graceful stop", func(t *testing.T) {
		r := &recorder{stop: make(chan struct{})}
		if d := runStopServing(t, r, 50*time.Millisecond, 50*time.Millisecond, 5*time.Second); d > 2*time.Second {
			t.Fatalf("stopServing took %s with a 50ms graceful bound", d)
		}
		if got := r.got(); got != "Mark GracefulStop Stop after Flush" {
			t.Fatalf("steps = %q", got)
		}
	})
	t.Run("the stop never returns", func(t *testing.T) {
		// A handler stuck in the kernel holds GracefulStop, and Stop blocks
		// behind it (lab 2 N-5): the shutdown must give up on both, still
		// close stopped and still flush, within graceful+forced.
		r := &recorder{hang: make(chan struct{})}
		t.Cleanup(func() { close(r.hang) })
		const graceful, forced = 50 * time.Millisecond, 50 * time.Millisecond
		if d := runStopServing(t, r, graceful, forced, 5*time.Second); d > graceful+forced+time.Second {
			t.Fatalf("stopServing took %s with graceful %s + forced %s", d, graceful, forced)
		}
		if got := r.got(); got != "Mark GracefulStop Stop after Flush" {
			t.Fatalf("steps = %q", got)
		}
	})
}

// Run's shutdown goes through stopServing, before the replicator stops and
// the database closes. (What stopServing does is TestStopServing_*; this
// only pins that Run uses it there. Run opens libvirt and binds sockets, so
// no behavioural test reaches it.)
//
// Mutation: Run without stopServing, or closing the database before it — red.
// Closing libvirt before the database — red.
func TestRunStopsServingBeforeTheDatabaseCloses(t *testing.T) {
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
	// The shutdown goroutine: the func literal that calls stopServing.
	var shutdown *ast.FuncLit
	ast.Inspect(run, func(n ast.Node) bool {
		if fl, ok := n.(*ast.FuncLit); ok {
			ast.Inspect(fl.Body, func(m ast.Node) bool {
				if c, ok := m.(*ast.CallExpr); ok {
					if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "stopServing" && shutdown == nil {
						shutdown = fl
					}
				}
				return true
			})
		}
		return true
	})
	if shutdown == nil {
		t.Fatal("Run never calls stopServing")
	}
	// Top-level statements of that goroutine, in order: stopServing must be
	// a direct statement (not in a branch) before repl.Stop and the database
	// close, d.closeDatabase (which closes it once the pressure sampler is
	// joined: TestDaemonClosesDatabaseThroughCloseDatabase).
	idx := map[string]int{}
	for i, st := range shutdown.Body.List {
		es, ok := st.(*ast.ExprStmt)
		if !ok {
			continue
		}
		c, ok := es.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		switch f := c.Fun.(type) {
		case *ast.Ident:
			idx[f.Name] = i
		case *ast.SelectorExpr:
			name := f.Sel.Name
			switch x := f.X.(type) {
			case *ast.Ident:
				name = x.Name + "." + name
			case *ast.SelectorExpr:
				name = x.Sel.Name + "." + name
			}
			idx[name] = i
		}
	}
	for _, name := range []string{"stopServing", "repl.Stop", "d.closeDatabase"} {
		if _, ok := idx[name]; !ok {
			t.Fatalf("%s is not a direct statement of Run's shutdown goroutine", name)
		}
	}
	if !(idx["stopServing"] < idx["repl.Stop"] && idx["repl.Stop"] < idx["d.closeDatabase"]) {
		t.Fatalf("shutdown order: stopServing %d, repl.Stop %d, closeDatabase %d", idx["stopServing"], idx["repl.Stop"], idx["d.closeDatabase"])
	}
	// The database closes before libvirt (mainconn review I-2): closing
	// libvirt fails the calls waiting on it, and their error paths must not
	// write what that failure is not.
	if v, ok := idx["virt.Close"]; !ok || v < idx["d.closeDatabase"] {
		t.Fatalf("shutdown order: closeDatabase %d, virt.Close %d (present %v), want the database closed first", idx["d.closeDatabase"], v, ok)
	}
}

// Lab 2 N-5 at Run's level: Serve returns only once a stop has finished, and
// a stop can be stuck behind a handler in the kernel, so Run must stop
// waiting on Serve once stopServing's stop is over. That rests on one channel
// crossing a function boundary: the one stopServing closes is the one
// awaitServe waits on. Run opens libvirt and binds sockets, so no behavioural
// test reaches it; this pins the wiring in its source:
//
//   - stopServing's stopped argument and awaitServe's stopped argument are
//     the same variable of Run (not a fresh channel, not a shadowed one);
//   - Run never closes it itself (stopServing does, once);
//   - Serve runs only in a goroutine, which sends its answer on the channel
//     awaitServe reads.
//
// Mutations: stopServing given make(chan struct{}) — red; awaitServe given a
// different channel — red; grpcStopped shadowed in the shutdown goroutine —
// red; Serve called synchronously — red; Run closing grpcStopped — red.
func TestRunWiresItsStopToItsServeWait(t *testing.T) {
	run := parseRun(t)
	var stopped, awaited, serveChan ast.Expr
	var closed []ast.Expr
	var serves, goServes int
	ast.Inspect(run.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.GoStmt:
			ast.Inspect(x.Call, func(m ast.Node) bool {
				if s, ok := m.(*ast.SendStmt); ok {
					if c, ok := s.Value.(*ast.CallExpr); ok && isMethodCall(c, "Serve") {
						goServes++
						serveChan = s.Chan
					}
				}
				return true
			})
		case *ast.CallExpr:
			switch {
			case isFuncCall(x, "stopServing"):
				if len(x.Args) < 5 {
					t.Fatalf("stopServing called with %d arguments", len(x.Args))
				}
				stopped = x.Args[4]
			case isFuncCall(x, "awaitServe"):
				if len(x.Args) < 2 {
					t.Fatalf("awaitServe called with %d arguments", len(x.Args))
				}
				awaited = x.Args[1]
				if a, b := runVar(x.Args[0]), runVar(serveChan); a == nil || a != b {
					t.Errorf("awaitServe does not read the channel Serve's goroutine answers on")
				}
			case isFuncCall(x, "close") && len(x.Args) == 1:
				closed = append(closed, x.Args[0])
			case isMethodCall(x, "Serve"):
				serves++
			}
		}
		return true
	})
	if stopped == nil || awaited == nil {
		t.Fatalf("Run calls stopServing (%v) and awaitServe (%v)", stopped != nil, awaited != nil)
	}
	obj := runVar(stopped)
	if obj == nil || obj != runVar(awaited) {
		t.Fatalf("stopServing closes %s, awaitServe waits on %s, and they are not the same variable of Run: Run would wait on Serve past the stop (lab 2 N-5)",
			exprString(stopped), exprString(awaited))
	}
	for _, c := range closed {
		if runVar(c) == obj {
			t.Errorf("Run closes %s itself; stopServing does, once the stop is over", obj.Name)
		}
	}
	if serves != 1 || goServes != 1 {
		t.Errorf("Serve is called %d times, %d of them in a goroutine sending on a channel: want once, in a goroutine, so Run can stop waiting on it", serves, goServes)
	}
}

// parseRun parses daemon.go and returns (*Daemon).Run.
func parseRun(t *testing.T) *ast.FuncDecl {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "daemon.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon.go: %v", err)
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil && fn.Name.Name == "Run" {
			return fn
		}
	}
	t.Fatal("no (*Daemon).Run in daemon.go")
	return nil
}

func isFuncCall(c *ast.CallExpr, name string) bool {
	id, ok := c.Fun.(*ast.Ident)
	return ok && id.Name == name
}

func isMethodCall(c *ast.CallExpr, name string) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == name
}

// runVar is the variable e names, as the parser resolved it (one object per
// declaration, so a shadowing declaration is another object); nil when e is
// not a plain variable.
func runVar(e ast.Expr) *ast.Object {
	id, ok := e.(*ast.Ident)
	if !ok || id.Obj == nil || id.Obj.Kind != ast.Var {
		return nil
	}
	return id.Obj
}

func exprString(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return fmt.Sprintf("%T", e)
}
