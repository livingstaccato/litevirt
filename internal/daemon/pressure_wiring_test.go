package daemon

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"sync/atomic"
	"testing"
	"time"

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
