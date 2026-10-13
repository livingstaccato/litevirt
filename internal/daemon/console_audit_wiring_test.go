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
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	r.steps = append(r.steps, s)
	r.mu.Unlock()
}

func (r *recorder) GracefulStop() {
	r.add("GracefulStop")
	if r.stop != nil {
		<-r.stop
	}
}
func (r *recorder) Stop() {
	r.add("Stop")
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

// stopServing marks the console audit before the gRPC server stops, and
// flushes it after the server has stopped (outright, when a console holds
// the graceful stop) and after afterStop. The flush is the last step, so the
// caller's database close comes after it.
//
// Mutation "flush before the server stops" — red. Mutation "no Mark" — red.
func TestStopServing_MarksThenStopsThenFlushes(t *testing.T) {
	t.Run("graceful", func(t *testing.T) {
		r := &recorder{}
		stopServing(r, r, time.Second, func() { r.add("after") })
		if got := r.got(); got != "Mark GracefulStop after Flush" {
			t.Fatalf("steps = %q", got)
		}
	})
	t.Run("a console holds the graceful stop", func(t *testing.T) {
		r := &recorder{stop: make(chan struct{})}
		start := time.Now()
		stopServing(r, r, 50*time.Millisecond, func() { r.add("after") })
		if got := r.got(); got != "Mark GracefulStop Stop after Flush" {
			t.Fatalf("steps = %q", got)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("stopServing took %s with a 50ms grace", d)
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
