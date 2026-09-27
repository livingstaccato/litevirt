package grpcapi

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/lxc"
)

// The container checker and this host's container operations drive the same
// LXC runtime and the same rows. These pin that neither undoes the other: the
// production wiring — one lxc.Runtime behind both the Server
// (LXCRuntimeAdapter) and the checker, and the checker holding
// Server.LockContainer — with a runtime fake whose State can run an operation
// at the moment the sweep probes.

// raceLXC is a goroutine-safe lxc.Runtime covering what create, start, stop and
// the checker's sweep use. Start refuses a container that is already running,
// as `lxc-start` does.
type raceLXC struct {
	lxc.Runtime // unused methods panic
	mu          sync.Mutex
	states      map[string]lxc.State
	starts      int
	// onState, when set, runs once inside the next State call, before the
	// state is read — an operation landing while the sweep probes.
	onState func()
}

func newRaceLXC() *raceLXC { return &raceLXC{states: map[string]lxc.State{}} }

func (f *raceLXC) Create(_ context.Context, opts lxc.CreateOpts) (*lxc.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states[opts.Name] = lxc.StateStopped
	return &lxc.Container{Name: opts.Name, State: lxc.StateStopped}, nil
}

func (f *raceLXC) Start(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.states[name] == lxc.StateRunning {
		return errors.New("lxc-start: " + name + ": container is already running")
	}
	f.starts++
	f.states[name] = lxc.StateRunning
	return nil
}

func (f *raceLXC) Stop(_ context.Context, name string, _ int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states[name] = lxc.StateStopped
	return nil
}

func (f *raceLXC) State(_ context.Context, name string) (lxc.State, error) {
	f.mu.Lock()
	hook := f.onState
	f.onState = nil
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.states[name]; ok {
		return s, nil
	}
	return lxc.StateUnknown, nil
}

func (f *raceLXC) List(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.states))
	for n := range f.states {
		out = append(out, n)
	}
	return out, nil
}

func (f *raceLXC) Limits(context.Context, string) (int, lxc.MemoryLimit, error) {
	return 0, lxc.MemoryLimit{Unlimited: true}, nil
}

func (f *raceLXC) snapshot(name string) (lxc.State, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.states[name], f.starts
}

func raceRig(t *testing.T) (*Server, *raceLXC, *health.ContainerChecker) {
	t.Helper()
	s := testServer(t)
	rt := newRaceLXC()
	s.SetContainerRuntime(NewLXCRuntimeAdapter(rt))
	ck := health.NewContainerChecker(s.hostName, s.db, rt)
	ck.SetContainerLock(s.LockContainer)
	return s, rt, ck
}

var alwaysRestart = &pb.RestartPolicy{Condition: "always"}

// A sweep between a create and its start — compose's create-then-start, or
// `lv ct create` followed by `lv ct start` — must leave the container to the
// start. It read the just-created, never-started container as having stopped
// unexpectedly, recorded an out-of-band stop and started it under the restart
// policy; the operator's start then hit a running container and failed.
func TestContainerChecker_SweepBetweenCreateAndStartLeavesItToTheStart(t *testing.T) {
	s, rt, ck := raceRig(t)
	ctx := adminCtx()

	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "web", Template: "download", Distro: "alpine", Release: "3.21", MemoryMib: 256,
		Restart: alwaysRestart,
	}); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	ck.SweepOnce(context.Background())
	if st, starts := rt.snapshot("web"); st != lxc.StateStopped || starts != 0 {
		t.Fatalf("after a sweep between create and start: runtime %q with %d starts, want stopped and "+
			"untouched — the checker started a container nobody had started yet", st, starts)
	}

	if _, err := s.StartContainer(ctx, &pb.StartContainerRequest{Name: "web"}); err != nil {
		t.Fatalf("StartContainer after the sweep: %v", err)
	}
	rec, err := corrosion.GetContainer(context.Background(), s.db, s.hostName, "web")
	if err != nil || rec == nil || rec.State != "running" || rec.StateDetail != "" {
		t.Fatalf("web after start = %+v err=%v, want running with no restart-policy detail", rec, err)
	}
	if _, starts := rt.snapshot("web"); starts != 1 {
		t.Fatalf("runtime started %d times, want once (the operator's start)", starts)
	}
}

// A stop that completes after the sweep listed the containers but before it
// takes the container's lock must not be undone either: the sweep reconciles
// the row as it is under the lock, not the listed copy that still says running.
func TestContainerChecker_StopBetweenListAndLockIsNotUndone(t *testing.T) {
	s, rt, ck := raceRig(t)
	ctx := adminCtx()
	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "web", Template: "download", Distro: "alpine", Release: "3.21", MemoryMib: 256,
		Restart: alwaysRestart,
	}); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	if _, err := s.StartContainer(ctx, &pb.StartContainerRequest{Name: "web"}); err != nil {
		t.Fatalf("StartContainer: %v", err)
	}

	stoppedOnce := false
	ck.SetContainerLock(func(name string) func() {
		if !stoppedOnce {
			stoppedOnce = true
			if _, err := s.StopContainer(ctx, &pb.StopContainerRequest{Name: name}); err != nil {
				t.Errorf("StopContainer between list and lock: %v", err)
			}
		}
		return s.LockContainer(name)
	})
	ck.SweepOnce(context.Background())

	st, _ := rt.snapshot("web")
	rec, err := corrosion.GetContainer(context.Background(), s.db, s.hostName, "web")
	if st != lxc.StateStopped || err != nil || rec == nil || rec.State != "stopped" || rec.StateDetail != "operator-stop" {
		t.Fatalf("after a stop between the sweep's list and its lock: runtime %q, row %+v err=%v; want runtime "+
			"stopped and the row stopped/operator-stop — the sweep acted on its stale listed row", st, rec, err)
	}
}

// A stop that lands while the sweep is probing must not be undone. The sweep
// had read the row as running; the stop then stopped the runtime and recorded
// operator-stop; the sweep's probe saw the container stopped, judged the stop
// unexpected by its stale row, overwrote operator-stop with an out-of-band
// stop and restarted the container the operator had just stopped.
func TestContainerChecker_StopDuringSweepIsNotUndone(t *testing.T) {
	s, rt, ck := raceRig(t)
	ctx := adminCtx()
	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "web", Template: "download", Distro: "alpine", Release: "3.21", MemoryMib: 256,
		Restart: alwaysRestart,
	}); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	if _, err := s.StartContainer(ctx, &pb.StartContainerRequest{Name: "web"}); err != nil {
		t.Fatalf("StartContainer: %v", err)
	}

	stopped := make(chan error, 1)
	rt.mu.Lock()
	rt.onState = func() {
		go func() {
			_, err := s.StopContainer(ctx, &pb.StopContainerRequest{Name: "web"})
			stopped <- err
		}()
		// Let the stop run to completion if nothing holds it back; if the
		// sweep holds the container's lock, it waits for the sweep instead.
		select {
		case err := <-stopped:
			stopped <- err
		case <-time.After(300 * time.Millisecond):
		}
	}
	rt.mu.Unlock()

	ck.SweepOnce(context.Background())
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("StopContainer during the sweep: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("StopContainer never returned")
	}

	st, _ := rt.snapshot("web")
	rec, err := corrosion.GetContainer(context.Background(), s.db, s.hostName, "web")
	if st != lxc.StateStopped || err != nil || rec == nil || rec.State != "stopped" || rec.StateDetail != "operator-stop" {
		t.Fatalf("after a stop during the sweep: runtime %q, row %+v err=%v; want runtime stopped and the row "+
			"stopped/operator-stop — the sweep undid the operator's stop", st, rec, err)
	}
}
