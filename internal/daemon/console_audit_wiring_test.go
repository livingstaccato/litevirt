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

// Run gives its actual worker coordinator distinct stop-serving and cleanup
// callbacks. The coordinator stops serving, joins its owned work, then calls
// cleanup (TestDaemonDBWorkers_AllStopTriggersHoldCleanup exercises that actual
// lifecycle). Here pin the callback identities and direct dependency-close
// order; bounded gRPC stopping alone is not permission to close a worker's DB.
func TestRunStopsServingBeforeTheDatabaseCloses(t *testing.T) {
	if err := daemonShutdownWiringError(parseRun(t)); err != nil {
		t.Fatal(err)
	}
}

// Inspect actual parser-resolved variables and the actual callback arguments,
// not an arbitrary function literal that happens to contain a matching call.
func daemonShutdownWiringError(run *ast.FuncDecl) error {
	var worker, repl *ast.Object
	var workerContext, service ast.Expr
	for _, statement := range run.Body.List {
		assignment, ok := statement.(*ast.AssignStmt)
		if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			continue
		}
		id, ok := assignment.Lhs[0].(*ast.Ident)
		if !ok {
			continue
		}
		if id.Name == "repl" {
			repl = runVar(id)
		}
		call, ok := assignment.Rhs[0].(*ast.CallExpr)
		if !ok || !isFuncCall(call, "newDBWorkerCoordinator") {
			continue
		}
		if worker != nil || len(call.Args) != 2 || runVar(id) == nil {
			return fmt.Errorf("Run must create one worker coordinator with context and service")
		}
		worker, workerContext, service = runVar(id), call.Args[0], call.Args[1]
	}
	if worker == nil || repl == nil || runVar(workerContext) == nil || runVar(service) == nil {
		return fmt.Errorf("Run's actual coordinator, context, service or replicator is missing")
	}
	var shutdown *ast.CallExpr
	started := map[string]int{}
	for _, statement := range run.Body.List {
		if expression, ok := statement.(*ast.ExprStmt); ok {
			if call, ok := expression.X.(*ast.CallExpr); ok {
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok && runVar(selector.X) == worker {
					started[selector.Sel.Name]++
				}
			}
		}
		goroutine, ok := statement.(*ast.GoStmt)
		if !ok {
			continue
		}
		selector, ok := goroutine.Call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "shutdown" {
			continue
		}
		if shutdown != nil || runVar(selector.X) != worker {
			return fmt.Errorf("shutdown must run once on the same worker coordinator")
		}
		shutdown = goroutine.Call
	}
	if started["startSweep"] != 1 || started["startLB"] != 1 || shutdown == nil || len(shutdown.Args) != 6 {
		return fmt.Errorf("actual worker starts and direct shutdown goroutine must share one coordinator")
	}
	if err := daemonShutdownContextError(run, shutdown, workerContext); err != nil {
		return err
	}
	for i, name := range []string{"ReExecCh", "ShutdownCh"} {
		selector, ok := shutdown.Args[i+1].(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != name || runVar(selector.X) != runVar(service) {
			return fmt.Errorf("shutdown %s must belong to the coordinator's actual service", name)
		}
	}
	callbacks := make([]*ast.FuncLit, 3)
	for i := range callbacks {
		callback, ok := shutdown.Args[i+3].(*ast.FuncLit)
		if !ok {
			return fmt.Errorf("shutdown callback %d must be its actual function literal", i)
		}
		callbacks[i] = callback
	}
	if run.Recv == nil || len(run.Recv.List) != 1 || len(run.Recv.List[0].Names) != 1 {
		return fmt.Errorf("Run's daemon receiver is missing")
	}
	daemon := runVar(run.Recv.List[0].Names[0])
	if daemon == nil {
		return fmt.Errorf("Run's daemon receiver must resolve to its actual variable")
	}
	callName := func(call *ast.CallExpr) string {
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "stopServing" && (id.Obj == nil || id.Obj.Kind == ast.Fun) {
			return "stopServing"
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		if selector.Sel.Name == "Stop" && runVar(selector.X) == repl {
			return "repl.Stop"
		}
		if selector.Sel.Name == "closeDatabase" && runVar(selector.X) == daemon {
			return "closeDatabase"
		}
		field, ok := selector.X.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == "Close" && runVar(field.X) == daemon && (field.Sel.Name == "db" || field.Sel.Name == "virt") {
			return field.Sel.Name + ".Close"
		}
		return ""
	}
	// Each dependency close must appear exactly once in Run and as a direct
	// cleanup statement. The database goes through closeDatabase, which stops
	// the pressure sampler first. A hidden earlier helper or raw database
	// close in prepare/stop is unsafe too.
	counts := map[string]int{}
	ast.Inspect(run.Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			counts[callName(call)]++
		}
		return true
	})
	direct := func(body *ast.BlockStmt) (map[string]int, map[string]*ast.CallExpr) {
		indices, calls := map[string]int{}, map[string]*ast.CallExpr{}
		for i, statement := range body.List {
			if expression, ok := statement.(*ast.ExprStmt); ok {
				if call, ok := expression.X.(*ast.CallExpr); ok {
					name := callName(call)
					indices[name], calls[name] = i, call
				}
			}
		}
		return indices, calls
	}
	_, stopCalls := direct(callbacks[1].Body)
	stop := stopCalls["stopServing"]
	if stop == nil || counts["stopServing"] != 1 || len(stop.Args) != 6 || runVar(stop.Args[1]) != runVar(service) {
		return fmt.Errorf("stopServing must be the sole direct stop callback call for the actual service")
	}
	grpcServer, ok := stop.Args[0].(*ast.SelectorExpr)
	if !ok || grpcServer.Sel.Name != "grpcSrv" || runVar(grpcServer.X) != daemon {
		return fmt.Errorf("stopServing must stop the actual daemon's gRPC server")
	}
	if counts["db.Close"] != 0 {
		return fmt.Errorf("Run must close the database through closeDatabase, never directly")
	}
	indices, _ := direct(callbacks[2].Body)
	for _, name := range []string{"repl.Stop", "closeDatabase", "virt.Close"} {
		if _, ok := indices[name]; !ok || counts[name] != 1 {
			return fmt.Errorf("%s must occur once, directly in the actual cleanup callback", name)
		}
	}
	if !(indices["repl.Stop"] < indices["closeDatabase"] && indices["closeDatabase"] < indices["virt.Close"]) {
		return fmt.Errorf("cleanup must stop replication, close the database, then close libvirt")
	}
	return nil
}

// The signal context must be a child of the coordinator's parent, with its
// actual cancel function deferred and called immediately after awaitServe.
// Parent cancellation and an unexpected Serve return must both initiate cleanup.
func daemonShutdownContextError(run *ast.FuncDecl, shutdown *ast.CallExpr, parent ast.Expr) error {
	var stop, cancel *ast.Object
	var declared token.Pos
	for _, statement := range run.Body.List {
		a, ok := statement.(*ast.AssignStmt)
		if !ok || a.Tok != token.DEFINE || len(a.Lhs) != 2 || len(a.Rhs) != 1 || runVar(a.Lhs[0]) != runVar(shutdown.Args[0]) {
			continue
		}
		call, ok := a.Rhs[0].(*ast.CallExpr)
		if !ok || len(call.Args) != 1 || runVar(call.Args[0]) != runVar(parent) {
			return fmt.Errorf("shutdown context must derive from the coordinator's parent")
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "WithCancel" {
			return fmt.Errorf("shutdown context must use context.WithCancel")
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "context" || pkg.Obj != nil || stop != nil {
			return fmt.Errorf("shutdown context factory is shadowed or repeated")
		}
		stop, cancel, declared = runVar(a.Lhs[0]), runVar(a.Lhs[1]), a.Pos()
	}
	if stop == nil || cancel == nil || declared >= shutdown.Pos() {
		return fmt.Errorf("shutdown needs its proven child context before launch")
	}
	isCancel := func(call *ast.CallExpr) bool { return runVar(call.Fun) == cancel && len(call.Args) == 0 }
	deferred, afterServe, serveCount := 0, 0, 0
	for i, statement := range run.Body.List {
		if d, ok := statement.(*ast.DeferStmt); ok && isCancel(d.Call) && d.Pos() > declared && d.Pos() < shutdown.Pos() {
			deferred++
		}
		a, ok := statement.(*ast.AssignStmt)
		if !ok || len(a.Rhs) != 1 {
			continue
		}
		call, ok := a.Rhs[0].(*ast.CallExpr)
		if !ok || !isFuncCall(call, "awaitServe") {
			continue
		}
		serveCount++
		if a.Pos() <= shutdown.Pos() || i+1 >= len(run.Body.List) {
			continue
		}
		if e, ok := run.Body.List[i+1].(*ast.ExprStmt); ok {
			if c, ok := e.X.(*ast.CallExpr); ok && isCancel(c) {
				afterServe++
			}
		}
	}
	if deferred != 1 || serveCount != 1 || afterServe != 1 {
		return fmt.Errorf("shutdown cancel must be deferred once and called directly after the sole awaitServe")
	}
	// Reject reassignment of either binding: parser identity alone must not
	// let a different context or cancel function replace the proven pair.
	var rebound bool
	ast.Inspect(run.Body, func(n ast.Node) bool {
		if a, ok := n.(*ast.AssignStmt); ok && a.Pos() != declared {
			for _, lhs := range a.Lhs {
				if obj := runVar(lhs); obj == stop || obj == cancel {
					rebound = true
				}
			}
		}
		return true
	})
	if rebound {
		return fmt.Errorf("shutdown context or cancel was reassigned")
	}
	return nil
}

func TestRunShutdownWiringRejectsUnsafeCallbacks(t *testing.T) {
	const stop = "stopServing(d.grpcSrv, svc, 1, 1, stopped, func(){})"
	const cleanup = "repl.Stop(); d.closeDatabase(); d.virt.Close()"
	const fixture = `package daemon
func (d *Daemon) Run(ctx context.Context) error {
 repl := newReplicator()
 svc := d.newServer()
 workers := newDBWorkerCoordinator(ctx, svc)
 workers.startSweep()
 workers.startLB(1)
 stopCtx, cancelStop := context.WithCancel(ctx)
 defer cancelStop()
 go workers.shutdown(stopCtx, svc.ReExecCh, svc.ShutdownCh, func(reason daemonStopReason){},
  func(){ stopServing(d.grpcSrv, svc, 1, 1, stopped, func(){}) },
  func(){ repl.Stop(); d.closeDatabase(); d.virt.Close() })
 serveErr := awaitServe(serveErrs, stopped, bound)
 cancelStop()
 _ = serveErr
 return nil
}`
	for _, tc := range []struct {
		name, old, replacement string
	}{
		{name: "correct"},
		{"wrong_coordinator", "go workers.shutdown", "go other.shutdown"},
		{"wrong_context", "workers.shutdown(stopCtx,", "workers.shutdown(other,"},
		{"wrong_context_parent", "context.WithCancel(ctx)", "context.WithCancel(other)"},
		{"wrong_context_factory", "context.WithCancel(ctx)", "context.WithoutCancel(ctx)"},
		{"missing_deferred_cancel", "defer cancelStop()", "doNothing()"},
		{"missing_serve_cancel", "\n cancelStop()", "\n doNothing()"},
		{"conditional_serve_cancel", "\n cancelStop()", "\n if condition { cancelStop() }"},
		{"cancel_before_serve", "serveErr := awaitServe(serveErrs, stopped, bound)\n cancelStop()", "cancelStop()\n serveErr := awaitServe(serveErrs, stopped, bound)"},
		{"rebound_stop_context", "defer cancelStop()", "defer cancelStop(); stopCtx = other"},
		{"rebound_cancel", "defer cancelStop()", "defer cancelStop(); cancelStop = otherCancel"},
		{"wrong_service_channel", "svc.ReExecCh", "other.ReExecCh"},
		{"missing_stop", stop, "doNothing()"},
		{"conditional_stop", stop, "if condition { " + stop + " }"},
		{"wrong_stop_service", "stopServing(d.grpcSrv, svc,", "stopServing(d.grpcSrv, other,"},
		{"wrong_stop_server", "stopServing(d.grpcSrv, svc,", "stopServing(other.grpcSrv, svc,"},
		{"swapped_callbacks", "func(){ " + stop + " },\n  func(){ " + cleanup + " }", "func(){ " + cleanup + " },\n  func(){ " + stop + " }"},
		{"early_db_in_stop", stop, "d.closeDatabase(); " + stop},
		{"raw_db_in_stop", stop, "d.db.Close(); " + stop},
		{"raw_db_in_prepare", "func(reason daemonStopReason){}", "func(reason daemonStopReason){ d.db.Close() }"},
		{"raw_db_cleanup", "d.closeDatabase()", "d.db.Close()"},
		{"early_db_in_prepare", "func(reason daemonStopReason){}", "func(reason daemonStopReason){ d.closeDatabase() }"},
		{"conditional_db_cleanup", "d.closeDatabase()", "if condition { d.closeDatabase() }"},
		{"db_before_repl", cleanup, "d.closeDatabase(); repl.Stop(); d.virt.Close()"},
		{"virt_before_db", cleanup, "repl.Stop(); d.virt.Close(); d.closeDatabase()"},
		{"wrong_daemon_close", "d.closeDatabase()", "other.closeDatabase()"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := fixture
			if tc.old != "" {
				if strings.Count(source, tc.old) != 1 {
					t.Fatal("mutation does not target exactly one fixture site")
				}
				source = strings.Replace(source, tc.old, tc.replacement, 1)
			}
			file, err := parser.ParseFile(token.NewFileSet(), "shutdown-fixture.go", source, 0)
			if err != nil {
				t.Fatalf("mutation must remain valid Go syntax: %v", err)
			}
			run := file.Decls[0].(*ast.FuncDecl)
			err = daemonShutdownWiringError(run)
			if tc.name == "correct" && err != nil {
				t.Fatalf("valid coordinator/callback wiring refused: %v", err)
			}
			if tc.name != "correct" && err == nil {
				t.Fatal("unsafe coordinator/callback wiring escaped the guard")
			}
		})
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

// executionOwnedRun unwraps only the actual first-return ownership boundary.
// Parser-resolved receiver and parameter objects survive in the shallow copy,
// so the existing coordinator/context/shutdown oracle remains unchanged.
func executionOwnerSelector(e ast.Expr, pkg, name string) bool {
	selector, ok := e.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != name {
		return false
	}
	qualifier, ok := selector.X.(*ast.Ident)
	return ok && qualifier.Name == pkg
}

func executionOwnedRun(run *ast.FuncDecl) (*ast.FuncDecl, error) {
	if run.Recv == nil || len(run.Recv.List) != 1 || len(run.Recv.List[0].Names) != 1 || run.Body == nil || len(run.Body.List) != 1 {
		return nil, fmt.Errorf("Run must consist of its owned startup return")
	}
	receiver := runVar(run.Recv.List[0].Names[0])
	ret, ok := run.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return nil, fmt.Errorf("Run must return its owner continuation")
	}
	call, ok := ret.Results[0].(*ast.CallExpr)
	if !ok || !isFuncCall(call, "withExecutionOwner") || len(call.Args) != 2 {
		return nil, fmt.Errorf("Run must call the actual execution owner")
	}
	path, ok := call.Args[0].(*ast.CallExpr)
	if !ok || len(path.Args) != 2 || !executionOwnerSelector(path.Fun, "filepath", "Join") {
		return nil, fmt.Errorf("owner path must be the daemon journal")
	}
	data, ok := path.Args[0].(*ast.SelectorExpr)
	if !ok || data.Sel.Name != "DataDir" {
		return nil, fmt.Errorf("owner data directory missing")
	}
	config, ok := data.X.(*ast.SelectorExpr)
	if !ok || config.Sel.Name != "cfg" || runVar(config.X) != receiver {
		return nil, fmt.Errorf("owner must use the actual daemon config")
	}
	leaf, ok := path.Args[1].(*ast.BasicLit)
	if !ok || leaf.Kind != token.STRING || leaf.Value != `"opjournal"` {
		return nil, fmt.Errorf("owner journal path differs")
	}
	body, ok := call.Args[1].(*ast.FuncLit)
	if !ok || body.Type.Params == nil || len(body.Type.Params.List) != 2 || body.Type.Results == nil || len(body.Type.Results.List) != 1 || exprString(body.Type.Results.List[0].Type) != "error" || len(body.Body.List) == 0 {
		return nil, fmt.Errorf("owner continuation signature differs")
	}
	wantTypes := []string{"Journal", "ExecutionController"}
	for i, f := range body.Type.Params.List {
		pointer, ok := f.Type.(*ast.StarExpr)
		if len(f.Names) != 1 || !ok || !executionOwnerSelector(pointer.X, "opjournal", wantTypes[i]) {
			return nil, fmt.Errorf("owner continuation parameter differs")
		}
	}
	install, ok := body.Body.List[0].(*ast.AssignStmt)
	if !ok || install.Tok != token.ASSIGN || len(install.Lhs) != 2 || len(install.Rhs) != 2 {
		return nil, fmt.Errorf("owner fields must be installed first")
	}
	for i, name := range []string{"opJournal", "executionController"} {
		field, ok := install.Lhs[i].(*ast.SelectorExpr)
		if !ok || field.Sel.Name != name || runVar(field.X) != receiver || runVar(install.Rhs[i]) != runVar(body.Type.Params.List[i].Names[0]) {
			return nil, fmt.Errorf("owner field is not the actual supplied owner")
		}
	}
	owned := *run
	owned.Body = body.Body
	return &owned, nil
}

func TestRunOwnershipWiringRejectsWrongContinuation(t *testing.T) {
	const fixture = `package daemon
func (d *Daemon) Run(ctx context.Context) error {
 return withExecutionOwner(filepath.Join(d.cfg.DataDir,"opjournal"),func(j *opjournal.Journal,c *opjournal.ExecutionController)error{
 d.opJournal,d.executionController=j,c
 return nil
 })
}`
	for _, tc := range []struct{ name, old, replacement string }{
		{name: "correct"},
		{"wrong-helper", "withExecutionOwner(", "otherOwner("},
		{"wrong-config", "d.cfg.DataDir", "other.cfg.DataDir"},
		{"wrong-path", `"opjournal"`, `"elsewhere"`},
		{"wrong-owner", "d.opJournal,d.executionController=j,c", "d.opJournal,d.executionController=j,other"},
		{"wrong-receiver", "d.opJournal,d.executionController=j,c", "other.opJournal,other.executionController=j,c"},
		{"work-before-owner", "return withExecutionOwner", "work(); return withExecutionOwner"},
		{"wrong-signature", "*opjournal.ExecutionController", "*OtherController"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := fixture
			if tc.old != "" {
				if strings.Count(source, tc.old) != 1 {
					t.Fatal("mutation must match exactly once")
				}
				source = strings.Replace(source, tc.old, tc.replacement, 1)
			}
			file, err := parser.ParseFile(token.NewFileSet(), "owner-fixture.go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, err = executionOwnedRun(file.Decls[0].(*ast.FuncDecl))
			if (err == nil) != (tc.name == "correct") {
				t.Fatalf("owner wiring result: %v", err)
			}
		})
	}
}

// parseRun parses the actual owned startup body of (*Daemon).Run.
func parseRun(t *testing.T) *ast.FuncDecl {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "daemon.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon.go: %v", err)
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil && fn.Name.Name == "Run" {
			owned, err := executionOwnedRun(fn)
			if err != nil {
				t.Fatal(err)
			}
			return owned
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
