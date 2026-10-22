package fleet

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
)

// TestFleet_HandlerPanicIsAnsweredAndTheHostIsNotFenced: a handler on node c
// panics. The caller gets Internal, c keeps serving, its observers count no
// failure against it, and the coordinator does not fence it.
//
// Before the recovery interceptor a handler panic ended the daemon; its peers
// fenced the host about 13 s later and every VM on it died.
//
// Mutations: (1) drop grpcapi.RecoverUnaryInterceptor from the chain (here
// and in the daemon's serverUnaryInterceptors) — the panic ends the process,
// this test binary included; (2) kill c instead of letting the call panic —
// the observers count it down and the coordinator fences it, so the "not
// fenced" assertion is not vacuous.
func TestFleet_HandlerPanicIsAnsweredAndTheHostIsNotFenced(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 4407})
	a, b, target := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	observers := []*Node{a, b}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		splitMembership(t, n)
	}
	settleByAntiEntropy(t, c, true)
	for _, n := range observers {
		go health.NewChecker(n.Name, n.PKIDir, n.DB).Start(ctx)
	}

	var mu sync.Mutex
	var fenced []string
	coord := failover.NewCoordinator(a.Name, a.DB)
	coord.SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
		mu.Lock()
		fenced = append(fenced, h.Name)
		mu.Unlock()
		return fence.Result{Method: "fleet-test", Success: true}
	})
	go func() {
		tk := time.NewTicker(250 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				coord.RunOnce(ctx)
			}
		}
	}()

	// Both observers have probed target successfully before the panic.
	eventually(t, convergeTimeout, "both observers to record target healthy", func() bool {
		for _, n := range observers {
			if f, _, ok := observedFailures(n, target.Name); !ok || f != 0 {
				return false
			}
		}
		return true
	})

	target.HookUnary("ListVMs", func(hctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		var m map[string]int
		m["handler bug"]++ // a runtime panic inside the handler's call
		return h(hctx, req)
	})
	client := c.SelfClient(target)
	if _, err := client.ListVMs(ctx, &pb.ListVMsRequest{}); status.Code(err) != codes.Internal {
		t.Fatalf("ListVMs whose handler panics: err = %v, want Internal", err)
	}
	panicked := time.Now()
	if _, err := client.ListVMs(ctx, &pb.ListVMsRequest{}); err != nil {
		t.Fatalf("ListVMs after the recovered panic: %v", err)
	}

	// Long enough for a dead daemon to be counted down and fenced.
	watch := time.Duration(health.FailuresToFence+2) * health.ProbeInterval
	for deadline := panicked.Add(watch); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		for _, n := range observers {
			if f, _, ok := observedFailures(n, target.Name); ok && f > 0 {
				t.Fatalf("%s counted %d failure(s) against %s after a recovered handler panic", n.Name, f, target.Name)
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(fenced) != 0 {
		t.Fatalf("the coordinator fenced %v after a recovered handler panic", fenced)
	}
	if _, err := client.Ping(ctx, &pb.PingRequest{}); err != nil {
		t.Fatalf("target stopped serving: %v", err)
	}
}
