package grpcapi

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Owner-probe latency (docs/design/recovery-claims.md §3.5.1, §10 item 36).
//
// A dead host's dial can take longer than the Accept that asks about it has
// left: an ARP timeout is ~3 s, and an Accept arrives with what phase 1 left
// of claimTimeout. These pin that the probe runs detached from the Accept,
// under its own claimProbeTimeout, one per host; that an Accept which cannot
// wait for it still reads as reached (§10 item 9); and that the finished
// answer is what the next round sees, for no longer than claimProbeMaxAge.

// unreachableAfter is a dial to a host that is gone: it fails with "no route
// to host" after d, or earlier when its own context ends. It counts dials and
// records whether any dial's context was cancelled before it finished.
func unreachableAfter(d time.Duration, dials *atomic.Int32, cancelled *atomic.Bool) func(context.Context, string) (string, error) {
	return func(ctx context.Context, _ string) (string, error) {
		dials.Add(1)
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
			return "", errors.New("dial tcp 10.0.0.1:7443: connect: no route to host")
		case <-ctx.Done():
			if cancelled != nil {
				cancelled.Store(true)
			}
			return "", ctx.Err()
		}
	}
}

// waitProbeIdle waits until no probe of host is in flight: the detached probe
// has finished, stored its result and exited.
func waitProbeIdle(t *testing.T, s *Server, host string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.claims.probe.mu.Lock()
		_, busy := s.claims.probe.inflight[host]
		s.claims.probe.mu.Unlock()
		if !busy {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the probe of %s never finished", host)
}

// acceptWithin is probeOwner under an Accept that has d left.
func acceptWithin(s *Server, host string, d time.Duration) (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return s.probeOwner(ctx, host)
}

// TestProbeOwner_SlowDialDecidesTheNextRound is the kvm003 run: the dead
// owner's dial fails only after longer than an Accept has. Round 1's Accept
// cannot wait and reads as reached — an unfinished probe never certifies an
// eviction — but the probe it started keeps running and finishes; round 2's
// Accept, just as short, finds the finished "not reached" and does not dial
// again.
//
// Mutation: run the probe under the Accept's context (the pre-fix probeOwner)
// — every round's dial is cancelled with its Accept, nothing is ever cached,
// and round 2 reads as reached again.
func TestProbeOwner_SlowDialDecidesTheNextRound(t *testing.T) {
	s := testServer(t)
	var dials atomic.Int32
	s.claims.probe.dial = unreachableAfter(200*time.Millisecond, &dials, nil)

	reached, detail := acceptWithin(s, "victim", 30*time.Millisecond)
	if !reached || !strings.Contains(detail, "in flight") {
		t.Fatalf("round 1, with the probe unfinished, read as %v %q; want reached, in flight", reached, detail)
	}
	waitProbeIdle(t, s, "victim")

	reached, detail = acceptWithin(s, "victim", 30*time.Millisecond)
	if reached || !strings.Contains(detail, "no route to host") {
		t.Fatalf("round 2 read as %v %q; want the finished probe's not reached", reached, detail)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("the source was dialled %d times over two rounds, want once", got)
	}
}

// TestProbeOwner_CallerCancelDoesNotCancelTheSharedProbe: fifty Accepts for
// one dead host share one probe. The first caller giving up must not take the
// probe with it: the dial runs to its own end, and a caller still waiting gets
// its answer from that one dial.
//
// Mutation: derive the probe's context from the first caller's — the dial is
// cancelled with it, and the waiter reads the cancellation (or dials again).
func TestProbeOwner_CallerCancelDoesNotCancelTheSharedProbe(t *testing.T) {
	s := testServer(t)
	var dials atomic.Int32
	var cancelled atomic.Bool
	s.claims.probe.dial = unreachableAfter(150*time.Millisecond, &dials, &cancelled)

	first, cancel := context.WithCancel(context.Background())
	firstDone := make(chan [2]any, 1)
	go func() {
		r, d := s.probeOwner(first, "victim")
		firstDone <- [2]any{r, d}
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	got := <-firstDone
	if reached := got[0].(bool); !reached {
		t.Fatalf("a caller that gave up before the probe finished read as not reached: %q", got[1])
	}

	reached, detail := s.probeOwner(context.Background(), "victim")
	if reached || !strings.Contains(detail, "no route to host") {
		t.Fatalf("the waiter read %v %q; want the shared probe's not reached", reached, detail)
	}
	if cancelled.Load() {
		t.Fatal("cancelling one caller cancelled the shared probe's dial")
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("%d dials for one source, want one shared probe", n)
	}
	waitProbeIdle(t, s, "victim")
}

// TestProbeOwner_NotReachedExpires: a finished "not reached" is reused for
// claimProbeMaxAge and no longer, so a host that comes back is probed again
// and found.
//
// Mutation: drop the max-age comparison in probeOwner — the returned host
// still reads as not reached.
func TestProbeOwner_NotReachedExpires(t *testing.T) {
	s := testServer(t)
	now := time.Unix(1000, 0)
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	s.claims.probe.now = func() time.Time { return time.Unix(0, clock.Load()) }
	var dials atomic.Int32
	var back atomic.Bool
	s.claims.probe.dial = func(context.Context, string) (string, error) {
		dials.Add(1)
		if back.Load() {
			return "victim", nil
		}
		return "", errors.New("no route to host")
	}
	if reached, _ := s.probeOwner(context.Background(), "victim"); reached {
		t.Fatal("the dead source read as reached")
	}
	back.Store(true)
	clock.Store(now.Add(claimProbeMaxAge - time.Millisecond).UnixNano())
	if reached, _ := s.probeOwner(context.Background(), "victim"); reached || dials.Load() != 1 {
		t.Fatalf("a fresh result was not reused (reached=%v dials=%d)", reached, dials.Load())
	}
	clock.Store(now.Add(claimProbeMaxAge).UnixNano())
	if reached, detail := s.probeOwner(context.Background(), "victim"); !reached || dials.Load() != 2 {
		t.Fatalf("a not-reached older than claimProbeMaxAge was reused: %v %q, dials=%d", reached, detail, dials.Load())
	}
}

// TestPrepare_StartsTheOwnerProbe: a Prepare for a workload key starts the
// probe of the host the voter's own row names, so the Accept that follows
// finds it finished — in the same round, not the next — and a result younger
// than claimProbeRefreshAge is not re-probed.
//
// Mutation: drop primeOwnerProbe from localPrepare — nothing is dialled until
// the Accept, which then cannot wait for it.
func TestPrepare_StartsTheOwnerProbe(t *testing.T) {
	s := voterTestServer(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm-1", HostName: "victim", State: "running",
		Spec: `{}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	start := time.Unix(1000, 0)
	clock.Store(start.UnixNano())
	s.claims.probe.now = func() time.Time { return time.Unix(0, clock.Load()) }
	var dials atomic.Int32
	s.claims.probe.dial = unreachableAfter(100*time.Millisecond, &dials, nil)

	key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-1"}
	prepare := func() {
		t.Helper()
		// No voter generation is adopted, so the promise itself is refused;
		// the probe is started regardless — it decides nothing.
		if _, err := s.localPrepare(ctx, key, corrosion.Ballot{Round: 1, Coordinator: "coord"}, 1, nil); err != nil {
			t.Fatalf("Prepare: %v", err)
		}
	}
	prepare()
	waitProbeIdle(t, s, "victim")
	if dials.Load() != 1 {
		t.Fatalf("Prepare dialled the row's owner %d times, want once", dials.Load())
	}
	if reached, detail := acceptWithin(s, "victim", 10*time.Millisecond); reached {
		t.Fatalf("the Accept after a Prepare-time probe read as reached: %q", detail)
	}

	clock.Store(start.Add(claimProbeRefreshAge - time.Millisecond).UnixNano())
	prepare()
	waitProbeIdle(t, s, "victim")
	if dials.Load() != 1 {
		t.Fatalf("a result younger than claimProbeRefreshAge was re-probed (%d dials)", dials.Load())
	}
	clock.Store(start.Add(claimProbeRefreshAge).UnixNano())
	prepare()
	waitProbeIdle(t, s, "victim")
	if dials.Load() != 2 {
		t.Fatalf("a result at claimProbeRefreshAge was not refreshed at Prepare (%d dials)", dials.Load())
	}
}

// TestPrepare_StartsTheProbeOfTheLastAcceptedSource: with no row naming an
// owner at the key's epoch, the Prepare falls back to the source the last
// Accept at the key named, so a retried round still finds its probe finished.
//
// Mutation: drop the remembered source — the second Prepare dials nothing.
func TestPrepare_StartsTheProbeOfTheLastAcceptedSource(t *testing.T) {
	s := voterTestServer(t)
	var dials atomic.Int32
	s.claims.probe.dial = unreachableAfter(time.Millisecond, &dials, nil)
	key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-gone"}
	ctx := context.Background()
	b := corrosion.Ballot{Round: 1, Coordinator: "coord"}
	if _, err := s.localPrepare(ctx, key, b, 1, nil); err != nil {
		t.Fatal(err)
	}
	if dials.Load() != 0 {
		t.Fatal("a Prepare with no row and no remembered source dialled something")
	}
	s.rememberClaimSource(key, "victim")
	if _, err := s.localPrepare(ctx, key, b, 1, nil); err != nil {
		t.Fatal(err)
	}
	waitProbeIdle(t, s, "victim")
	if dials.Load() != 1 {
		t.Fatalf("the remembered source was dialled %d times, want once", dials.Load())
	}
}

// TestClaimProbeBudget states the timing the constants must keep (§10 item
// 36). A dead source's claim decides in its first round when:
//
//   - a probe finishes before the proposer gives up on the Accept that waits
//     for it: claimProbeTimeout < claims.DefaultCallTimeout;
//   - a result a Prepare did not refresh is still fresh when that round's
//     Accept arrives, at most one call timeout later:
//     claimProbeRefreshAge + claims.DefaultCallTimeout <= claimProbeMaxAge;
//   - and refreshing is not constant churn: a probe finishes before its
//     result is old enough to refresh, claimProbeTimeout <= claimProbeRefreshAge.
//
// Mutation: raise claimProbeRefreshAge to claimProbeMaxAge — the second
// inequality fails.
func TestClaimProbeBudget(t *testing.T) {
	if claimProbeTimeout >= claims.DefaultCallTimeout {
		t.Errorf("claimProbeTimeout %s is not below the proposer's call timeout %s", claimProbeTimeout, claims.DefaultCallTimeout)
	}
	if claimProbeRefreshAge+claims.DefaultCallTimeout > claimProbeMaxAge {
		t.Errorf("a result unrefreshed at Prepare (%s) can expire before its Accept (+%s > %s)",
			claimProbeRefreshAge, claims.DefaultCallTimeout, claimProbeMaxAge)
	}
	if claimProbeTimeout > claimProbeRefreshAge {
		t.Errorf("claimProbeTimeout %s exceeds claimProbeRefreshAge %s", claimProbeTimeout, claimProbeRefreshAge)
	}
}

// TestForcedProbe_InterruptedByTheOperatorReadsAsReached: a forced
// reconfiguration's fresh check runs under the operator's context. When that
// context ends before the dial does, nothing learned the host is gone, so the
// check must not read as "not reached" — a lost voter is named only on a
// probe that finished.
//
// Mutation: drop the ctx.Err() check in forcedProbe — the cancelled dial's
// error reads as not reached.
func TestForcedProbe_InterruptedByTheOperatorReadsAsReached(t *testing.T) {
	s := testServer(t)
	var dials atomic.Int32
	s.claims.probe.dial = unreachableAfter(200*time.Millisecond, &dials, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	reached, detail := s.forcedProbe(ctx, "victim")
	if !reached || !strings.Contains(detail, "interrupted") {
		t.Fatalf("an interrupted forced probe read as %v %q; want reached, interrupted", reached, detail)
	}
}
