package daemon

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/pressure"
)

type pressureSinkRecorder struct {
	src atomic.Pointer[grpcapi.PressureSource]
}

func (r *pressureSinkRecorder) SetPressureSource(src grpcapi.PressureSource) { r.src.Store(&src) }

// startPressure wires a RUNNING sampler into Ready: the source it hands the
// server has sampled the data directory on its own, and the observer
// (metrics) sees every sample. With pressure off it wires nothing.
func TestStartPressure_RunsAndWires(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := &Config{HostName: "n", DataDir: t.TempDir(), Pressure: pressure.DefaultConfig()}
	cfg.Pressure.SampleIntervalSec = 1
	d := &Daemon{cfg: cfg}
	var sink pressureSinkRecorder
	var observed atomic.Int32
	d.startPressure(ctx, &sink, func() func(pressure.Report) {
		return func(pressure.Report) { observed.Add(1) }
	})
	t.Cleanup(d.pressure.Stop)
	p := sink.src.Load()
	if p == nil {
		t.Fatal("no pressure source was wired into the server")
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rep := (*p).Report()
		for _, r := range rep.Resources {
			if r.Name == "data_dir.space" && !rep.SampledAt.IsZero() && observed.Load() > 0 {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the wired sampler never sampled the data directory (observed %d): it was not started", observed.Load())
}

func TestStartPressure_OffWiresNothing(t *testing.T) {
	cfg := &Config{HostName: "n", DataDir: t.TempDir(), Pressure: pressure.DefaultConfig()}
	cfg.Pressure.Enabled = false
	d := &Daemon{cfg: cfg}
	var sink pressureSinkRecorder
	d.startPressure(context.Background(), &sink, func() func(pressure.Report) {
		t.Fatal("metrics registered with pressure off")
		return nil
	})
	if sink.src.Load() != nil {
		t.Fatal("a source was wired with pressure.enabled false")
	}
}

// The daemon's Start makes both calls: the sampler is started and wired, and
// the lease holder's coordinator writes host.pressure. Each is one line whose
// deletion compiles and leaves every behavioural test green.
func TestDaemonWiresPressure(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "daemon.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var started, hooked bool
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "startPressure" {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "d" && len(x.Args) == 3 {
					if svc, ok := x.Args[1].(*ast.Ident); ok && svc.Name == "svc" {
						started = true
					}
				}
			}
		case *ast.AssignStmt:
			if len(x.Lhs) != 1 || len(x.Rhs) != 1 {
				return true
			}
			l, lok := x.Lhs[0].(*ast.SelectorExpr)
			r, rok := x.Rhs[0].(*ast.SelectorExpr)
			if lok && rok && l.Sel.Name == "PressureHealth" && r.Sel.Name == "PressureHealthTick" {
				if lx, ok := l.X.(*ast.Ident); ok && lx.Name == "fc" {
					if rx, ok := r.X.(*ast.Ident); ok && rx.Name == "svc" {
						hooked = true
					}
				}
			}
		}
		return true
	})
	if !started {
		t.Error("daemon.go does not call d.startPressure(ctx, svc, ...): the sampler is never started or wired into Ready")
	}
	if !hooked {
		t.Error("daemon.go does not set fc.PressureHealth = svc.PressureHealthTick: no lease holder ever writes host.pressure")
	}
}

// Shutdown closes the database only once the pressure sampler and its pool
// read, which uses it, are stopped and joined. The daemon's context stays live
// here, as it does on re-exec and uninstall, so cancelling it is not what ends
// the read.
func TestCloseDatabase_JoinsThePressurePoolsRead(t *testing.T) {
	// closeDatabase closes it here; the cleanup's second Close is harmless.
	db := corrosion.NewTestClientT(t)
	cfg := &Config{HostName: "n", DataDir: t.TempDir(), Pressure: pressure.DefaultConfig()}
	d := &Daemon{cfg: cfg, db: db}
	entered, readDone, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var enterOnce, doneOnce sync.Once
	var closed, usedAfterClose atomic.Bool
	d.listHostPools = func(ctx context.Context, c *corrosion.Client, host string) ([]corrosion.StoragePoolRecord, error) {
		defer doneOnce.Do(func() { close(readDone) })
		enterOnce.Do(func() { close(entered) })
		select {
		case <-ctx.Done():
		case <-release:
		case <-time.After(10 * time.Second):
		}
		if closed.Load() {
			usedAfterClose.Store(true)
		}
		return corrosion.ListStoragePoolsForHost(ctx, c, host)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sink pressureSinkRecorder
	d.startPressure(ctx, &sink, func() func(pressure.Report) { return func(pressure.Report) {} })
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the sampler never read the pool list")
	}
	d.closeDatabase()
	closed.Store(true)
	close(release)
	select {
	case <-readDone:
	case <-time.After(15 * time.Second):
		t.Fatal("the pool read never returned")
	}
	if usedAfterClose.Load() {
		t.Fatal("the pressure pool read used the database after closeDatabase closed it")
	}
}

// The shutdown closes the database through closeDatabase, which joins the
// sampler first: a direct d.db.Close() anywhere else in daemon.go would skip
// that join, and no behavioural test drives the shutdown goroutine.
func TestDaemonClosesDatabaseThroughCloseDatabase(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "daemon.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	isDMethod := func(n ast.Node, name string) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != name {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && id.Name == "d"
	}
	var viaHelper bool
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			if isDMethod(n, "closeDatabase") {
				viaHelper = true
			}
			if call, ok := n.(*ast.CallExpr); ok && fn.Name.Name != "closeDatabase" {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Close" {
					if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "db" {
						if id, ok := inner.X.(*ast.Ident); ok && id.Name == "d" {
							t.Errorf("%s calls d.db.Close() directly: the pressure sampler is not joined first (use d.closeDatabase)", fn.Name.Name)
						}
					}
				}
			}
			return true
		})
	}
	if !viaHelper {
		t.Error("daemon.go never calls d.closeDatabase(): the shutdown does not close the database through the join")
	}
}

// A pool-list read whose context has ended (the sampler is stopping, and the
// database may be closing) returns the last list without touching the
// database.
func TestPressurePools_EndedContextDoesNotReadTheDatabase(t *testing.T) {
	cfg := &Config{HostName: "n", DataDir: t.TempDir(), Pressure: pressure.DefaultConfig()}
	d := &Daemon{cfg: cfg, db: corrosion.NewTestClientT(t)}
	var reads atomic.Int32
	d.listHostPools = func(context.Context, *corrosion.Client, string) ([]corrosion.StoragePoolRecord, error) {
		reads.Add(1)
		return nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.pressurePools()(ctx)
	if n := reads.Load(); n != 0 {
		t.Fatalf("a pool-list read with an ended context queried the database %d time(s)", n)
	}
}
