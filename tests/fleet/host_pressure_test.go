package fleet

// Resource pressure, the observing phase (docs/configuration.md, "Resource
// pressure"). A host whose data directory is filling grades itself, says so on
// the readiness probe its peers already send, and the lease holder raises
// host.pressure for it — while the host stays a healthy, counted member of
// every peer's quorum. Pressure must never become a reason to lose a vote: a
// fill common to every host (a log storm) would then cost the fleet its
// majority.
//
// Mutations (each red here):
//   - Ready answers ready=false at degrade or worse: node-1 drops out of every
//     peer's QuorumProof and the "quorum unchanged" check fails.
//   - PeerReady drops the answer's pressure: node-0 never sees degrade.
//   - PressureHealthTick never resolves: the condition stays open after the
//     level clears.
//   - The old-build case reads a missing field as "ok" (PeerPressureView.Level):
//     the unknown check fails.

import (
	"context"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/pressure"
	"google.golang.org/grpc"
)

// pressureFS is one node's statfs seam: one filesystem, at a settable free
// percentage.
type pressureFS struct {
	mu  sync.Mutex
	pct float64
}

func (f *pressureFS) set(pct float64) {
	f.mu.Lock()
	f.pct = pct
	f.mu.Unlock()
}

func (f *pressureFS) Statfs(string) (pressure.FSStat, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	const total = uint64(1000) << 30
	return pressure.FSStat{TotalBytes: total, AvailBytes: uint64(float64(total) * f.pct / 100), TotalInodes: 1000, FreeInodes: 900}, nil
}

type pressureNode struct {
	n       *Node
	fs      *pressureFS
	sampler *pressure.Sampler
	clk     time.Time
	chk     *health.Checker
}

// sample takes one sample and moves the node's sampler clock one interval.
func (p *pressureNode) sample(ctx context.Context) {
	p.sampler.Sample(ctx)
	p.clk = p.clk.Add(5 * time.Second)
}

func newPressureStack(t *testing.T, c *Cluster) []*pressureNode {
	t.Helper()
	var out []*pressureNode
	for _, n := range c.Nodes {
		p := &pressureNode{n: n, fs: &pressureFS{pct: 50}, clk: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
		p.sampler = pressure.NewSampler(pressure.DefaultConfig(), n.FW.DataDir, pressure.Options{
			FS:  p.fs,
			Now: func() time.Time { return p.clk },
			FDs: func() (uint64, uint64, bool) { return 0, 0, false },
			Mem: func() (uint64, bool) { return 0, false },
		})
		n.Server.SetPressureSource(p.sampler)
		p.chk = health.NewChecker(n.Name, n.PKIDir, n.DB)
		p.chk.SetPeerReadiness(n.Server.PeerReady)
		out = append(out, p)
	}
	return out
}

func probeAll(ctx context.Context, ps []*pressureNode) {
	for _, p := range ps {
		p.chk.CheckAllPeersForTests(ctx)
	}
}

type quorumSnap struct {
	state      health.QuorumState
	live, need int
}

func quorums(ctx context.Context, ps []*pressureNode) map[string]quorumSnap {
	out := map[string]quorumSnap{}
	for _, p := range ps {
		st, live, need := p.chk.QuorumProof(ctx)
		out[p.n.Name] = quorumSnap{st, live, need}
	}
	return out
}

func pressureCondition(t *testing.T, n *Node, host string) (corrosion.HealthCondition, bool) {
	t.Helper()
	c, ok, err := corrosion.GetHealthCondition(context.Background(), n.DB, grpcapi.PressureEvaluator, grpcapi.CondHostPressure, "host", host)
	if err != nil {
		t.Fatal(err)
	}
	return c, ok
}

func TestFleet_HostPressure_RaisedAndClearedWithoutLosingQuorum(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3})
	ps := newPressureStack(t, c)
	holder, target := ps[0], ps[1]
	for _, p := range ps {
		p.sample(ctx)
		p.sample(ctx)
	}
	probeAll(ctx, ps)
	base := quorums(ctx, ps)
	for name, q := range base {
		if q.state != health.QuorumYes || q.live != 3 {
			t.Fatalf("setup: %s quorum %+v, want met with 3 live", name, q)
		}
	}
	if l := holder.n.Server.PeerPressure(target.n.Name).Level(); l != "ok" {
		t.Fatalf("setup: %s sees %s at %q, want ok", holder.n.Name, target.n.Name, l)
	}

	// node-1's data directory falls to 6 % free: degrade, after two samples.
	target.fs.set(6)
	target.sample(ctx)
	target.sample(ctx)
	if l := target.sampler.Report().Level; l != pressure.Degrade {
		t.Fatalf("%s graded itself %v at 6 %% free, want degrade", target.n.Name, l)
	}

	// Its peers learn it within two probe intervals.
	for i := 0; i < 2 && holder.n.Server.PeerPressure(target.n.Name).Level() != "degrade"; i++ {
		probeAll(ctx, ps)
	}
	if l := holder.n.Server.PeerPressure(target.n.Name).Level(); l != "degrade" {
		t.Fatalf("after two probe cycles %s sees %s at %q, want degrade", holder.n.Name, target.n.Name, l)
	}
	// And it stays a healthy, counted member of every quorum.
	if got := quorums(ctx, ps); !equalQuorums(got, base) {
		t.Fatalf("quorum changed under pressure: %+v, want %+v — pressure must never cost a host its vote", got, base)
	}

	// The lease holder raises host.pressure for it.
	holder.n.Server.PressureHealthTick(ctx)
	cond, ok := pressureCondition(t, holder.n, target.n.Name)
	if !ok || cond.Lifecycle == corrosion.ConditionResolved || cond.Severity != corrosion.SeverityWarning || cond.Reporter != holder.n.Name {
		t.Fatalf("host.pressure for %s: %+v (found %v), want open, warning, written by %s", target.n.Name, cond, ok, holder.n.Name)
	}
	for _, p := range ps {
		if p == target {
			continue
		}
		if _, ok := pressureCondition(t, holder.n, p.n.Name); ok {
			t.Errorf("host.pressure raised for %s, which is at 50 %% free", p.n.Name)
		}
	}

	// Space comes back: the level clears only after clear_after_sec (120 s)
	// past the margin, then the condition resolves.
	target.fs.set(50)
	for i := 0; i < 24; i++ {
		target.sample(ctx)
	}
	if l := target.sampler.Report().Level; l != pressure.Degrade {
		t.Fatalf("115 s after space returned: %v, want degrade still", l)
	}
	target.sample(ctx)
	if l := target.sampler.Report().Level; l != pressure.OK {
		t.Fatalf("120 s after space returned: %v, want ok", l)
	}
	probeAll(ctx, ps)
	holder.n.Server.PressureHealthTick(ctx)
	if cond, _ := pressureCondition(t, holder.n, target.n.Name); cond.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("after the level cleared: %s, want resolved", cond.Lifecycle)
	}
	if got := quorums(ctx, ps); !equalQuorums(got, base) {
		t.Fatalf("quorum changed: %+v, want %+v", got, base)
	}
}

// A peer on a build that predates ReadyResponse.pressure answers without it.
// Its peers read that as unknown — not ok — and it keeps its vote; the lease
// holder writes no condition for a host that said nothing.
func TestFleet_HostPressure_OldPeerIsUnknownAndCounted(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3})
	ps := newPressureStack(t, c)
	holder, old := ps[0], ps[1]
	old.fs.set(1) // it IS pressured, but its build cannot say so
	old.sample(ctx)
	old.sample(ctx)
	stripPressure := func(ctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		resp, err := handler(ctx, req)
		if r, ok := resp.(*pb.ReadyResponse); ok && err == nil {
			r.Pressure = nil
		}
		return resp, err
	}
	for i := 0; i < 2; i++ {
		old.n.HookUnary("Ready", stripPressure)
		holder.chk.CheckAllPeersForTests(ctx)
	}
	v := holder.n.Server.PeerPressure(old.n.Name)
	if !v.Answered || v.Level() != "unknown" {
		t.Fatalf("an answer without the field: %+v level %q, want answered and unknown", v, v.Level())
	}
	if st, live, _ := holder.chk.QuorumProof(ctx); st != health.QuorumYes || live != 3 {
		t.Fatalf("quorum %v with %d live, want met with 3: an old peer is a counted member", st, live)
	}
	holder.n.Server.PressureHealthTick(ctx)
	if _, ok := pressureCondition(t, holder.n, old.n.Name); ok {
		t.Fatal("host.pressure written for a host that reported no pressure")
	}
}

func equalQuorums(a, b map[string]quorumSnap) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// The production path: the failover coordinator that holds the lease writes
// host.pressure on its own cycle (Coordinator.PressureHealth, wired as the
// daemon wires it). Mutation: drop the call in Coordinator.run and it is red.
func TestFleet_HostPressure_TheLeaseHoldersCycleWritesTheCondition(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3})
	ps := newPressureStack(t, c)
	holder, target := ps[0], ps[1]
	target.fs.set(6)
	target.sample(ctx)
	target.sample(ctx)
	probeAll(ctx, ps)
	if l := holder.n.Server.PeerPressure(target.n.Name).Level(); l != "degrade" {
		t.Fatalf("setup: %s sees %q, want degrade", target.n.Name, l)
	}
	cs := c.NewCoordinators(NewVirtualClock(time.Now().UTC()))
	cs.Tick(ctx, holder.n)
	if !cs.ByNode[holder.n.Name].HoldsLease() {
		t.Fatalf("setup: %s does not hold the lease after its tick", holder.n.Name)
	}
	cond, ok := pressureCondition(t, holder.n, target.n.Name)
	if !ok || cond.Lifecycle == corrosion.ConditionResolved || cond.Reporter != holder.n.Name {
		t.Fatalf("after the lease holder's cycle: %+v (found %v), want host.pressure raised by %s", cond, ok, holder.n.Name)
	}
}
