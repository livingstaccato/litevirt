package fleet

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/grpcapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Gate evidence (F1 Task 5G follow-up B): the gate's imported-voter count
// recovers after a voter change without any user command, counts a voter that
// is always slower than the engine's per-call timeout, and does not drop a
// voter whose last signature has aged past the newest anchors.

// importedElectorate is grownElectorate with d's import done and automation
// enforced on every node: generation 2 = {a,b,c,d}, all holding authority,
// and no automation decision certified at generation 2 yet.
func importedElectorate(t *testing.T) *automationMembershipFixture {
	t.Helper()
	m := grownElectorate(t)
	if err := m.d.Server.ImportAutomationPrefix(m.ctx); err != nil {
		t.Fatal(err)
	}
	for _, n := range m.cluster.Nodes {
		n.Server.SetAutomationEnforce(true)
	}
	return m
}

func (m *automationMembershipFixture) imported(t *testing.T, n *Node) int {
	t.Helper()
	return n.Server.AutomationMembershipStatus(m.ctx).ImportedVoters
}

// slowAccepts makes n answer its next count AcceptRecoveryClaim calls only
// after delay: slower than the engine's 750ms per-call timeout, but alive.
func slowAccepts(n *Node, count int, delay time.Duration) {
	for range count {
		n.HookUnary("AcceptRecoveryClaim", func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
			time.Sleep(delay)
			return h(context.WithoutCancel(ctx), req)
		})
	}
}

// After a voter change nothing is certified at the new generation, so no
// voter but this one has evidence there. The internal generation barrier
// certifies one without any user command, and every voter's count reaches 4.
func TestAutomationGateEvidenceBarrierAfterVoterChange(t *testing.T) {
	m := importedElectorate(t)
	if got := m.imported(t, m.a); got >= 4 {
		t.Fatalf("fixture: a already counts %d imported voters at generation 2", got)
	}
	if err := m.a.Server.AutomationGenerationBarrier(m.ctx); err != nil {
		t.Fatalf("generation barrier: %v", err)
	}
	m.converge(t, 0, 1, 2, 3)
	for _, n := range []*Node{m.a, m.b, m.c, m.d} {
		if got := m.imported(t, n); got != 4 {
			t.Fatalf("%s counts %d imported voters after the generation barrier, want 4", n.Name, got)
		}
	}
	// Complete evidence: b's first pass (no backoff pending there) submits
	// nothing.
	head := m.Head(t, 0)
	if err := m.b.Server.AutomationGenerationBarrier(m.ctx); err != nil {
		t.Fatal(err)
	}
	if h := m.Head(t, 0); h != head {
		t.Fatalf("a barrier was certified with complete evidence: head %+v -> %+v", head, h)
	}
	// Without enforcement the barrier does nothing (fail closed, no writes).
	fresh := importedElectorate(t)
	fresh.a.Server.SetAutomationEnforce(false)
	head = fresh.Head(t, 0)
	_ = fresh.a.Server.AutomationGenerationBarrier(fresh.ctx)
	if h := fresh.Head(t, 0); h != head {
		t.Fatalf("a non-enforcing node certified a barrier: head %+v -> %+v", head, h)
	}
}

// c answers every accept after 1.2s. An ordinary command (750ms per call) is
// certified without it, so c is not counted; the generation barrier waits
// for it, and the count reaches 4.
func TestAutomationGateEvidenceCountsAnAlwaysSlowVoter(t *testing.T) {
	m := importedElectorate(t)
	slowAccepts(m.c, 16, 1200*time.Millisecond)
	if _, err := m.Engine(0).Submit(m.ctx, m.Barrier(0, "ordinary")); err != nil {
		t.Fatal(err)
	}
	if got := m.imported(t, m.a); got != 3 {
		t.Fatalf("after an ordinary command a counts %d imported voters, want 3 (c too slow to sign)", got)
	}
	if err := m.a.Server.AutomationGenerationBarrier(m.ctx); err != nil {
		t.Fatalf("generation barrier: %v", err)
	}
	if got := m.imported(t, m.a); got != 4 {
		t.Fatalf("a counts %d imported voters after the generation barrier, want 4 with the slow voter", got)
	}
}

// d signs at generation 2, then is cut off from claims while a, b and c
// certify more than 64 decisions. d's evidence is older than the newest 64
// anchors, and the count must not drop.
func TestAutomationGateEvidenceDoesNotAgeOut(t *testing.T) {
	m := importedElectorate(t)
	if err := m.a.Server.AutomationGenerationBarrier(m.ctx); err != nil {
		t.Fatal(err)
	}
	if got := m.imported(t, m.a); got != 4 {
		t.Fatalf("fixture: a counts %d, want 4", got)
	}
	for _, n := range []*Node{m.a, m.b, m.c} {
		m.cluster.SetLinkFaultBoth(m.d, n, LinkFault{BlockClaims: true})
	}
	for i := range 70 {
		if _, err := m.Engine(0).Submit(m.ctx, m.Barrier(0, fmt.Sprintf("without-d-%d", i))); err != nil {
			t.Fatalf("decision %d without d: %v", i, err)
		}
	}
	if got := m.imported(t, m.a); got != 4 {
		t.Fatalf("a counts %d imported voters after 70 decisions without d, want 4: d's evidence aged out", got)
	}
}

// While evidence stays incomplete (d is cut off from claims), a second pass
// right after the first waits out the backoff instead of certifying another
// barrier.
func TestAutomationGateEvidenceBarrierBacksOff(t *testing.T) {
	m := importedElectorate(t)
	for _, n := range []*Node{m.a, m.b, m.c} {
		m.cluster.SetLinkFaultBoth(m.d, n, LinkFault{BlockClaims: true})
	}
	if err := m.a.Server.AutomationGenerationBarrier(m.ctx); err != nil {
		t.Fatal(err)
	}
	if got := m.imported(t, m.a); got != 3 {
		t.Fatalf("fixture: a counts %d with d cut off, want 3", got)
	}
	head := m.Head(t, 0)
	if err := m.a.Server.AutomationGenerationBarrier(m.ctx); err != nil {
		t.Fatal(err)
	}
	if h := m.Head(t, 0); h != head {
		t.Fatalf("a second barrier was certified inside the backoff: head %+v -> %+v", head, h)
	}
}

// A voter without automation authority (d before its import) has nothing to
// give evidence for: its pass is a quiet no-op, not an engine refusal.
func TestAutomationGateEvidenceBarrierNeedsAuthority(t *testing.T) {
	m := grownElectorate(t)
	for _, n := range m.cluster.Nodes {
		n.Server.SetAutomationEnforce(true)
	}
	head := m.Head(t, 0)
	if err := m.d.Server.AutomationGenerationBarrier(m.ctx); err != nil {
		t.Fatalf("pass on a voter without authority: %v", err)
	}
	if h := m.Head(t, 0); h != head {
		t.Fatalf("a voter without authority certified a barrier: %+v -> %+v", head, h)
	}
}

// Every voter may certify its own barrier at a generation: the request ids
// never collide.
func TestAutomationGateEvidenceBarriersFromEveryVoter(t *testing.T) {
	m := importedElectorate(t)
	for i := range 4 {
		if err := m.Engine(i).GenerationBarrier(m.ctx, 2, "same-tag", nil); err != nil {
			t.Fatalf("%s's barrier at generation 2: %v", m.cluster.Nodes[i].Name, err)
		}
	}
}

// refuseAccepts makes n refuse its next count AcceptRecoveryClaim calls at
// once: alive (it still answers the import-source probe) but never signing.
func refuseAccepts(n *Node, count int) {
	for range count {
		n.HookUnary("AcceptRecoveryClaim", func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
			return nil, status.Error(codes.Unavailable, "injected refusal")
		})
	}
}

// d is blackholed: every claim RPC to it is held 30s and then refused. A
// pass finds no missing member alive, certifies nothing, returns quickly, and
// holds up no ordinary submit; repeated passes add no record.
func TestAutomationGateEvidenceDeadMemberNoStormNoStall(t *testing.T) {
	m := importedElectorate(t)
	for _, n := range []*Node{m.a, m.b, m.c} {
		m.cluster.SetLinkFaultBoth(m.d, n, LinkFault{ClaimDelay: 30 * time.Second})
	}
	// Evidence for a, b and c; d, the only member missing, is dead.
	if _, err := m.Engine(0).Submit(m.ctx, m.Barrier(0, "evidence-without-d")); err != nil {
		t.Fatal(err)
	}
	if got := m.imported(t, m.a); got != 3 {
		t.Fatalf("fixture: a counts %d, want 3", got)
	}
	head := m.Head(t, 0)
	barrierDone := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		_ = m.a.Server.AutomationGenerationBarrier(m.ctx)
		barrierDone <- time.Since(start)
	}()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	if _, err := m.Engine(0).Submit(m.ctx, m.Barrier(0, "ordinary-beside-a-dead-member")); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 6*time.Second {
		t.Fatalf("an ordinary submit beside the generation barrier took %v", took)
	}
	if took := <-barrierDone; took > 6*time.Second {
		t.Fatalf("a generation barrier pass with a dead member took %v", took)
	}
	for range 5 {
		m.a.Server.ResetGenerationBarrierBackoffForTest()
		_ = m.a.Server.AutomationGenerationBarrier(m.ctx)
	}
	if h := m.Head(t, 0); h.Sequence != head.Sequence+1 {
		t.Fatalf("head moved %d -> %d: barriers were certified for a dead member", head.Sequence, h.Sequence)
	}
}

// d is alive but never signs: each pass would certify a record without it.
// Attempts are capped per generation, membership and live missing set.
func TestAutomationGateEvidenceBarrierAttemptsCapped(t *testing.T) {
	m := importedElectorate(t)
	refuseAccepts(m.d, 64)
	head := m.Head(t, 0)
	for range 8 {
		m.a.Server.ResetGenerationBarrierBackoffForTest()
		_ = m.a.Server.AutomationGenerationBarrier(m.ctx)
	}
	if added := m.Head(t, 0).Sequence - head.Sequence; added == 0 || added > 3 {
		t.Fatalf("%d barrier records for one unchanged missing voter, want 1..3", added)
	}
}

// A restarted voter's next barrier is a fresh request, not a replay of a
// pre-restart one that returns a stored receipt and certifies nothing.
func TestAutomationGateEvidenceBarrierAfterRestart(t *testing.T) {
	m := importedElectorate(t)
	refuseAccepts(m.d, 64)
	head := m.Head(t, 0)
	if err := m.a.Server.AutomationGenerationBarrier(m.ctx); err != nil {
		t.Fatal(err)
	}
	if h := m.Head(t, 0); h.Sequence != head.Sequence+1 {
		t.Fatalf("fixture: first barrier did not certify: %d -> %d", head.Sequence, h.Sequence)
	}
	restarted := grpcapi.NewServerForTests(grpcapi.TestServerOpts{
		HostName: m.a.Name, DataDir: filepath.Join(t.TempDir(), "restarted"), PKIDir: m.a.PKIDir, DB: m.a.DB, Virt: m.a.Virt,
	})
	restarted.SetPeerUnaryInterceptor(m.cluster.networkRPCClient())
	restarted.SetAutomationEnforce(true)
	if err := restarted.AutomationGenerationBarrier(m.ctx); err != nil {
		t.Fatalf("barrier after restart: %v", err)
	}
	if h := m.Head(t, 0); h.Sequence != head.Sequence+2 {
		t.Fatalf("barrier after restart certified nothing: head %d, want %d", h.Sequence, head.Sequence+2)
	}
}

// b and c are missing and alive, d is missing and dead. The barrier certifies
// with b and c without waiting on d, so neither it nor an ordinary submit
// queued behind it is held for d's timeout.
func TestAutomationGateEvidenceBarrierSkipsDeadVoters(t *testing.T) {
	m := importedElectorate(t)
	for _, n := range []*Node{m.a, m.b, m.c} {
		m.cluster.SetLinkFaultBoth(m.d, n, LinkFault{ClaimDelay: 30 * time.Second})
	}
	barrierDone := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		if err := m.a.Server.AutomationGenerationBarrier(m.ctx); err != nil {
			t.Error(err)
		}
		barrierDone <- time.Since(start)
	}()
	time.Sleep(2500 * time.Millisecond) // past the probes: the barrier holds the engine
	start := time.Now()
	if _, err := m.Engine(0).Submit(m.ctx, m.Barrier(0, "ordinary-behind-the-barrier")); err != nil {
		t.Fatal(err)
	}
	// A dead member already costs an ordinary submit a few 750ms timeouts
	// (recover, prepare, distribute); waiting out the barrier's 10s accept
	// timeout on it as well would push this past 12s.
	took := time.Since(start)
	barrierTook := <-barrierDone
	t.Logf("ordinary submit behind the barrier: %v; barrier: %v", took, barrierTook)
	if took > 9*time.Second {
		t.Fatalf("an ordinary submit behind the generation barrier took %v", took)
	}
	if barrierTook > 8*time.Second {
		t.Fatalf("the generation barrier took %v with one dead member", barrierTook)
	}
	if got := m.imported(t, m.a); got != 3 {
		t.Fatalf("a counts %d after the barrier, want 3 (a, b, c)", got)
	}
}

// A pass has its own deadline: started with a context that has none (as the
// daemon's adoption loop does), it returns by that deadline even when every
// peer is blackholed.
func TestAutomationGateEvidencePassHasADeadline(t *testing.T) {
	m := importedElectorate(t)
	for _, n := range []*Node{m.b, m.c, m.d} {
		m.cluster.SetLinkFaultBoth(m.a, n, LinkFault{ClaimDelay: 30 * time.Second})
	}
	defer grpcapi.SetGenerationBarrierDeadlineForTest(500 * time.Millisecond)()
	start := time.Now()
	_ = m.a.Server.AutomationGenerationBarrier(context.Background())
	if took := time.Since(start); took > 1500*time.Millisecond {
		t.Fatalf("a pass with no caller deadline took %v, past its own 500ms deadline", took)
	}
}
