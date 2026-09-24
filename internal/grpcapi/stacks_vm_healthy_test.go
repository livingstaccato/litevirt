package grpcapi

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// vm_healthy used to be "running and state_detail != 'unhealthy'", and
// nothing wrote 'unhealthy': it was vm_started under another name. With a
// healthcheck it now needs the owner's passing verdict for the VM as it is.

type waitProbe struct {
	mu   sync.Mutex
	pass bool
}

func (p *waitProbe) set(pass bool) { p.mu.Lock(); p.pass = pass; p.mu.Unlock() }
func (p *waitProbe) fn(context.Context, corrosion.VMRecord, *pb.HealthCheckSpec) (bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pass {
		return true, ""
	}
	return false, "tcp 10.0.0.9:80: connection refused"
}

func healthWaitServer(t *testing.T) (*Server, *health.VMChecker, *waitProbe) {
	t.Helper()
	s := coordResizeServer(t)
	ctx := adminCtx()
	if h, _ := corrosion.GetHost(ctx, s.db, "test-host"); h == nil {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
			Name: "test-host", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
			State: "active", CertSerial: "a", MemTotal: 8192,
		}); err != nil {
			t.Fatalf("InsertHost: %v", err)
		}
	}
	seedRunningVM(t, s, "web", &pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256,
		Healthcheck: &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.9:80", Interval: "1ms", Retries: 1}}, 1, 256)
	checker := health.NewVMChecker("test-host", t.TempDir(), s.db, nil)
	p := &waitProbe{}
	checker.SetProbeFunc(p.fn)
	return s, checker, p
}

func TestWaitVMHealthy_RunningIsNotEnoughWithAHealthcheck(t *testing.T) {
	s, checker, p := healthWaitServer(t)
	ctx := adminCtx()

	err := s.waitForConditionWithin(ctx, "web", "vm_healthy", 300*time.Millisecond)
	if err == nil {
		t.Fatal("vm_healthy was met by a running VM whose healthcheck has never passed")
	}
	for _, want := range []string{"web", "no probe verdict"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("timeout error %q does not mention %q", err, want)
		}
	}

	p.set(true)
	checker.SweepOnce(ctx)
	if err := s.waitForConditionWithin(ctx, "web", "vm_healthy", 300*time.Millisecond); err != nil {
		t.Fatalf("vm_healthy not met after a passing probe: %v", err)
	}
}

func TestWaitVMHealthy_TimeoutReportsTheLastProbeResult(t *testing.T) {
	s, checker, p := healthWaitServer(t)
	ctx := adminCtx()
	p.set(false)
	checker.SweepOnce(ctx)

	err := (&serverOps{s: s}).WaitHealthy(ctx, "web", 300*time.Millisecond)
	if err == nil {
		t.Fatal("WaitHealthy passed on a VM whose probe is failing")
	}
	for _, want := range []string{"web", "unhealthy", "connection refused", "health-wait"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("health-wait error %q does not mention %q", err, want)
		}
	}
}

// The wait must look once more at its deadline: a verdict that lands between
// the last poll and the deadline is a pass, not a timeout.
func TestWaitVMHealthy_VerdictArrivingMidWaitIsSeen(t *testing.T) {
	s, checker, p := healthWaitServer(t)
	ctx := adminCtx()
	p.set(true)
	go func() {
		time.Sleep(300 * time.Millisecond)
		checker.SweepOnce(ctx)
	}()
	start := time.Now()
	if err := s.waitForConditionWithin(ctx, "web", "vm_healthy", 800*time.Millisecond); err != nil {
		t.Fatalf("a verdict published mid-wait was missed: %v (after %s)", err, time.Since(start))
	}
}

// A VM without a healthcheck keeps the old meaning: running is healthy.
func TestWaitVMHealthy_NoHealthcheckRunningSuffices(t *testing.T) {
	s := coordResizeServer(t)
	ctx := adminCtx()
	seedRunningVM(t, s, "plain", &pb.VMSpec{Name: "plain", Cpu: 1, MemoryMib: 256}, 1, 256)
	if err := s.waitForConditionWithin(ctx, "plain", "vm_healthy", 300*time.Millisecond); err != nil {
		t.Fatalf("running VM without a healthcheck: %v", err)
	}
	if err := corrosion.UpdateVMState(ctx, s.db, "plain", "stopped", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.waitForConditionWithin(ctx, "plain", "vm_healthy", 300*time.Millisecond); err == nil {
		t.Fatal("stopped VM without a healthcheck met vm_healthy")
	}
}
