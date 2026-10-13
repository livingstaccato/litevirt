package daemon

import (
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
	// a direct statement (not in a branch) before repl.Stop and db.Close.
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
	for _, name := range []string{"stopServing", "repl.Stop", "db.Close"} {
		if _, ok := idx[name]; !ok {
			t.Fatalf("%s is not a direct statement of Run's shutdown goroutine", name)
		}
	}
	if !(idx["stopServing"] < idx["repl.Stop"] && idx["repl.Stop"] < idx["db.Close"]) {
		t.Fatalf("shutdown order: stopServing %d, repl.Stop %d, db.Close %d", idx["stopServing"], idx["repl.Stop"], idx["db.Close"])
	}
}
