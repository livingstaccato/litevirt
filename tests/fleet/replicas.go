package fleet

// Independent replicas and per-link replication faults.
//
// Options.IndependentReplicas gives every node its own database AND starts the
// production corrosion.Replicator push loop on it. The loop discovers its peers
// through Members() — the seeded gossip view, see seedGossipMembership — resolves
// each one through the replicated `hosts` table (so it dials the node's real
// ephemeral gRPC port) and pushes its mutation_log over the real PushMutations
// RPC. Nothing steers delivery: a write on one node reaches the others the way
// it does in production, on the loop's own write-notify wakeups, backoff and
// relay topology (with three or fewer nodes every node is a relay, so the mesh
// is full).
//
// The fault injector sits on the RECEIVING side of each directed link a→b, as a
// gRPC interceptor on b keyed by the caller's mTLS common name, so it models the
// network between two daemons rather than anything inside either one:
//
//   - Block refuses every replication RPC from a to b (the WAL push, digests,
//     dumps, the lease-term quorum read — the same set Partition severs), in one
//     direction only. Partition(a, b) is the two-direction boolean form.
//   - Delay (+ Jitter) holds each PushMutations before it is applied.
//   - Drop refuses a push with codes.Unavailable. The sender sees an error,
//     keeps its watermark and retries under its own backoff (1s doubling to
//     30s), so a high drop rate slows convergence rather than losing entries.
//   - Duplicate applies a push twice; the receiver's mutation_seen dedup is what
//     makes the second a no-op.
//   - Reorder holds a push back, answers the sender with success (its watermark
//     advances past the batch) and applies the held batch only AFTER the next
//     push on the same link. Held batches are also delivered when the link's
//     fault is replaced or cleared, so a reorder never silently loses history.
//
// Every probabilistic decision comes from a per-link PRNG seeded from
// Options.FaultSeed and the link's name, and each push draws the same number of
// values, so a given sequence of pushes on a link always meets the same
// sequence of faults. The loop's timing is real time, so which entries share a
// batch is not fixed; the fault sequence per push is.

import (
	"context"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
)

// LinkFault is what the network does to replication on one directed link. The
// zero value is a healthy link.
type LinkFault struct {
	// Block refuses every replication RPC on the link (see partitionedMethods).
	Block bool
	// Delay is added before each push is applied; Jitter adds a further
	// uniform [0, Jitter) drawn from the link's PRNG.
	Delay  time.Duration
	Jitter time.Duration
	// Drop, Duplicate and Reorder are per-push probabilities in [0, 1].
	Drop      float64
	Duplicate float64
	Reorder   float64
	// BlockClaims refuses the recovery-claim RPCs on the link (claimMethods),
	// independently of replication: a claim RPC is ordinary gRPC, and a
	// scenario needs to reach a voter by one and not the other.
	BlockClaims bool
}

// LinkStats counts what the injector did on one directed link.
type LinkStats struct {
	Pushes     int // PushMutations calls that reached the injector
	Applied    int // batches handed to the real handler, duplicates included
	Dropped    int
	Duplicated int
	Reordered  int // batches held back and delivered later
	Blocked    int // replication RPCs of any kind refused by Block
	HeldFailed int // held batches whose late delivery the handler refused
}

// heldPush is a batch the Reorder fault is sitting on.
type heldPush struct {
	ctx     context.Context
	req     any
	handler grpc.UnaryHandler
}

// linkState is the injector's per-link state on the receiving node.
type linkState struct {
	fault LinkFault
	rng   *rand.Rand
	held  []heldPush
	stats LinkStats
}

// faults is the receiving node's injector: sender name → link state.
type faults struct {
	mu    sync.Mutex
	links map[string]*linkState
}

func linkName(from, to string) string { return from + "->" + to }

func (c *Cluster) linkRNG(from, to string) *rand.Rand {
	h := fnv.New64a()
	_, _ = h.Write([]byte(linkName(from, to)))
	return rand.New(rand.NewPCG(uint64(c.opts.FaultSeed), h.Sum64()))
}

// link returns (creating) the state for pushes from `from` into n. Caller holds
// n.faults.mu.
func (n *Node) link(from string) *linkState {
	if n.faults.links == nil {
		n.faults.links = make(map[string]*linkState)
	}
	ls := n.faults.links[from]
	if ls == nil {
		ls = &linkState{rng: n.cluster.linkRNG(from, n.Name)}
		n.faults.links[from] = ls
	}
	return ls
}

// SetLinkFault sets what the network does to replication from `from` to `to`,
// replacing any earlier fault on that link. Batches a previous Reorder was
// holding are delivered first, in the order they were held.
func (c *Cluster) SetLinkFault(from, to *Node, f LinkFault) {
	to.faults.mu.Lock()
	ls := to.link(from.Name)
	held := ls.held
	ls.held = nil
	ls.fault = f
	to.faults.mu.Unlock()
	to.deliverHeld(from.Name, held)
}

// SetLinkFaultBoth applies f to a→b and b→a.
func (c *Cluster) SetLinkFaultBoth(a, b *Node, f LinkFault) {
	c.SetLinkFault(a, b, f)
	c.SetLinkFault(b, a, f)
}

// Isolate blocks every replication link into and out of n — a host that has
// died, as far as replication can tell.
func (c *Cluster) Isolate(n *Node) {
	for _, o := range c.Nodes {
		if o != n {
			c.SetLinkFaultBoth(n, o, LinkFault{Block: true})
		}
	}
}

// ClearLinkFaults heals every link in the cluster and delivers anything held.
func (c *Cluster) ClearLinkFaults() {
	for _, to := range c.Nodes {
		for _, from := range c.Nodes {
			if from != to {
				c.SetLinkFault(from, to, LinkFault{})
			}
		}
	}
}

// LinkStats reports what the injector has done on from→to so far.
func (c *Cluster) LinkStats(from, to *Node) LinkStats {
	to.faults.mu.Lock()
	defer to.faults.mu.Unlock()
	return to.link(from.Name).stats
}

// claimMethods are the recovery-claim RPCs LinkFault.BlockClaims refuses.
var claimMethods = map[string]bool{
	"PrepareRecoveryClaim": true,
	"AcceptRecoveryClaim":  true,
	"GetRecoveryClaim":     true,
	"ListRecoveryClaims":   true,
}

// claimBlocked reports whether BlockClaims refuses caller's claim RPC into n.
func (n *Node) claimBlocked(fullMethod string, caller string) bool {
	if !claimMethods[methodName(fullMethod)] || caller == "" {
		return false
	}
	n.faults.mu.Lock()
	defer n.faults.mu.Unlock()
	ls := n.faults.links[caller]
	if ls == nil || !ls.fault.BlockClaims {
		return false
	}
	ls.stats.Blocked++
	return true
}

// linkBlocked reports whether the Block fault refuses caller's replication RPCs
// into n, counting the refusal.
func (n *Node) linkBlocked(caller string) bool {
	n.faults.mu.Lock()
	defer n.faults.mu.Unlock()
	ls := n.faults.links[caller]
	if ls == nil || !ls.fault.Block {
		return false
	}
	ls.stats.Blocked++
	return true
}

// deliverHeld applies batches a Reorder fault held back. A held batch's own RPC
// has long returned, so it runs on a context that keeps the caller's identity
// (the handler checks the mTLS common name against the sender) without the
// cancellation.
func (n *Node) deliverHeld(from string, held []heldPush) {
	for _, h := range held {
		_, err := h.handler(h.ctx, h.req)
		n.faults.mu.Lock()
		ls := n.link(from)
		ls.stats.Applied++
		if err != nil {
			ls.stats.HeldFailed++
		}
		n.faults.mu.Unlock()
	}
}

// faultUnaryInterceptor applies the link fault to PushMutations. Block is
// handled by the partition interceptor ahead of it, for every replication RPC.
func (n *Node) faultUnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if methodName(info.FullMethod) != "PushMutations" {
		return handler(ctx, req)
	}
	from := peerCertCN(ctx)
	if from == "" {
		return handler(ctx, req)
	}

	n.faults.mu.Lock()
	ls := n.link(from)
	f := ls.fault
	ls.stats.Pushes++
	// Always draw the same four values, so the fault sequence on a link depends
	// only on how many pushes it has carried.
	jitterDraw, dropDraw, dupDraw, reorderDraw := ls.rng.Float64(), ls.rng.Float64(), ls.rng.Float64(), ls.rng.Float64()
	delay := f.Delay + time.Duration(jitterDraw*float64(f.Jitter))
	drop := dropDraw < f.Drop
	dup := !drop && dupDraw < f.Duplicate
	reorder := !drop && reorderDraw < f.Reorder
	var held []heldPush
	switch {
	case drop:
		ls.stats.Dropped++
	case reorder:
		ls.stats.Reordered++
		ls.held = append(ls.held, heldPush{ctx: context.WithoutCancel(ctx), req: req, handler: handler})
	default:
		held = ls.held
		ls.held = nil
	}
	n.faults.mu.Unlock()

	if delay > 0 {
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, status.FromContextError(ctx.Err()).Err()
		case <-n.cluster.ctx.Done():
			timer.Stop()
			return nil, status.Error(codes.Unavailable, "fleet: cluster stopping")
		}
	}
	if drop {
		return nil, status.Errorf(codes.Unavailable, "fleet fault: push %s->%s dropped", from, n.Name)
	}
	if reorder {
		// AppliedUpTo 0 makes the sender advance its watermark to the batch's
		// last entry, exactly as if it had been applied.
		return &pb.ReplicateResponse{}, nil
	}

	resp, err := handler(ctx, req)
	applied := 1
	if dup && err == nil {
		_, _ = handler(ctx, req)
		applied++
	}
	n.faults.mu.Lock()
	ls = n.link(from)
	ls.stats.Applied += applied
	if applied > 1 {
		ls.stats.Duplicated++
	}
	n.faults.mu.Unlock()
	// The batches held back behind this one land after it: that is the reorder.
	n.deliverHeld(from, held)
	return resp, err
}

// startReplicators starts the production push loop on every node. Called once
// every node is listening, so no loop's first push meets a closed port.
func (c *Cluster) startReplicators() {
	for _, n := range c.Nodes {
		// Every node runs this build, so every peer honours the monotone proof
		// resolver: the daemon's gate answers true for it once
		// split_brain_gate_v1 is advertised. Left nil the gate FAILS CLOSED and
		// drops every proof-bearing entry from the stream.
		n.repl.SetProofReplicaGate(func(context.Context, string) bool { return true })
		n.repl.Start(c.ctx)
		n.replStarted = true
	}
}

// ── convergence ─────────────────────────────────────────────────────────────

// digestOf is a node's replicated-state fingerprint: every public and sensitive
// table digest, which is what anti-entropy compares.
func digestOf(n *Node) (map[string]corrosion.TableDigest, error) {
	ctx := context.Background()
	out := map[string]corrosion.TableDigest{}
	pub, err := n.DB.StateDigest(ctx)
	if err != nil {
		return nil, err
	}
	sens, err := n.DB.SensitiveStateDigest(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range append(pub, sens...) {
		out[d.Name] = d
	}
	return out, nil
}

// divergence names the tables on which the given nodes' digests differ, empty
// when they agree.
func divergence(nodes []*Node) ([]string, error) {
	var base map[string]corrosion.TableDigest
	diff := map[string]bool{}
	for i, n := range nodes {
		d, err := digestOf(n)
		if err != nil {
			return nil, fmt.Errorf("digest %s: %w", n.Name, err)
		}
		if i == 0 {
			base = d
			continue
		}
		for name, bd := range base {
			if od, ok := d[name]; !ok || od.Hash != bd.Hash || od.Count != bd.Count {
				diff[name] = true
			}
		}
		for name := range d {
			if _, ok := base[name]; !ok {
				diff[name] = true
			}
		}
	}
	out := make([]string, 0, len(diff))
	for name := range diff {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// WaitConverged blocks until every given node (all nodes when none are given)
// reports the same state digest, or fails the test after timeout naming the
// tables still apart. It waits on the running push loops; it moves nothing
// itself, so it only makes sense with Options.IndependentReplicas.
func (c *Cluster) WaitConverged(t *testing.T, timeout time.Duration, nodes ...*Node) {
	t.Helper()
	c.WaitConvergedExcept(t, timeout, nil, nodes...)
}

// WaitConvergedExcept is WaitConverged ignoring the named tables — for a table
// whose divergence is by design, like leader_lease_terms after a contested
// claim (its merge keeps both claims; see leader_lease_contest_test.go).
func (c *Cluster) WaitConvergedExcept(t *testing.T, timeout time.Duration, except []string, nodes ...*Node) {
	t.Helper()
	if len(nodes) == 0 {
		nodes = c.Nodes
	}
	deadline := time.Now().Add(timeout)
	for {
		all, err := divergence(nodes)
		if err != nil {
			t.Fatalf("WaitConverged: %v", err)
		}
		var apart []string
		for _, name := range all {
			if !slices.Contains(except, name) {
				apart = append(apart, name)
			}
		}
		if len(apart) == 0 {
			return
		}
		if time.Now().After(deadline) {
			names := make([]string, len(nodes))
			for i, n := range nodes {
				names[i] = n.Name
			}
			t.Fatalf("replicas %s did not converge within %s; tables apart: %s",
				strings.Join(names, ","), timeout, strings.Join(apart, ", "))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ── coordinators and virtual time ───────────────────────────────────────────

// VirtualClock is a settable time source shared by a set of coordinators. It is
// the same mechanism every failover scenario uses — the coordinator's exported
// Now field — held in one place so every node reads the same instant.
type VirtualClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewVirtualClock starts a clock at t0.
func NewVirtualClock(t0 time.Time) *VirtualClock { return &VirtualClock{now: t0} }

// Now reads the clock.
func (v *VirtualClock) Now() time.Time {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.now
}

// Advance moves the clock forward by d.
func (v *VirtualClock) Advance(d time.Duration) {
	v.mu.Lock()
	v.now = v.now.Add(d)
	v.mu.Unlock()
}

// Coordinators is a failover coordinator on every node, each over its node's
// OWN database, all reading one virtual clock, all fencing through a recording
// stub that reports success. Scenarios drive them with Tick instead of the
// production 5s ticker, so "one poll interval" is a step the test takes.
type Coordinators struct {
	Clock  *VirtualClock
	ByNode map[string]*failover.Coordinator

	mu     sync.Mutex
	fences []FenceCall
}

// FenceCall is one fence a coordinator issued.
type FenceCall struct {
	By, Target string
	// IPMIPass is the BMC password the coordinator handed the fencer — what
	// an `ipmi` fence would authenticate with.
	IPMIPass string
}

// NewCoordinators builds a coordinator on every node.
func (c *Cluster) NewCoordinators(clock *VirtualClock) *Coordinators {
	cs := &Coordinators{Clock: clock, ByNode: map[string]*failover.Coordinator{}}
	for _, n := range c.Nodes {
		by := n.Name
		coord := failover.NewCoordinator(n.Name, n.DB)
		coord.Now = clock.Now
		coord.SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
			cs.mu.Lock()
			cs.fences = append(cs.fences, FenceCall{By: by, Target: h.Name, IPMIPass: h.IPMIPass})
			cs.mu.Unlock()
			return fence.Result{Method: "fleet-test", Success: true}
		})
		// Automatic voter genesis runs on the lease holder's tick, as the
		// daemon wires it. Inert until a scenario opens the voter_configs
		// gate (OpenVoterConfigGate).
		coord.VoterGenesis = n.Server.VoterGenesisTick
		cs.ByNode[n.Name] = coord
	}
	return cs
}

// Tick runs one coordinator cycle on each given node, concurrently — the shape
// of every node's poll firing within the same interval.
func (cs *Coordinators) Tick(ctx context.Context, nodes ...*Node) {
	var wg sync.WaitGroup
	for _, n := range nodes {
		coord := cs.ByNode[n.Name]
		wg.Add(1)
		go func() {
			defer wg.Done()
			coord.RunOnce(ctx)
		}()
	}
	wg.Wait()
}

// Fences returns every fence issued so far, in call order.
func (cs *Coordinators) Fences() []FenceCall {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return append([]FenceCall(nil), cs.fences...)
}

// PublishHealth writes node n's own observation of target the way the health
// checker does — the same statement, so it replicates like a real probe result
// (the receiver's statement-shape guard refuses ad-hoc SQL, and health seeded
// through a different shape never leaves the node it was written on). Unlike the
// checker's deferred write it wakes the push loop at once.
func PublishHealth(t *testing.T, n *Node, target string, failures int, at time.Time) {
	t.Helper()
	if err := n.DB.Execute(context.Background(),
		`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
		n.Name, target, "suspect", failures, nil, at.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("publish %s's health of %s: %v", n.Name, target, err)
	}
}
