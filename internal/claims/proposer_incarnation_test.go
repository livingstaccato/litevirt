package claims

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The bridge from a legacy claim key to its incarnation-scoped form
// (docs/design/recovery-claims.md §10 item 37). Coordinators claim the legacy
// key until claim_incarnation_v1 latches and the scoped key after, so one
// recovery can be claimed at both across the latch. A voter's promise at the
// scoped key reports what it accepted at the legacy key and seals that key
// against every later legacy step; the proposer re-proposes the legacy value
// when the scoped key holds none. Together they keep one decision.

func scopedSpec(key corrosion.ClaimKey, voters []string, dest string, adopt func(corrosion.ClaimValue) bool) Spec {
	s := workloadSpec(key, voters, dest)
	s.AdoptLegacy = adopt
	return s
}

func adoptAll(corrosion.ClaimValue) bool { return true }

// TestProposer_BridgeCompletesALegacyDecision: a value decided at the legacy
// key, before the latch, is what the first scoped claim decides — the same
// proof, not a second recovery.
//
// Mutation: drop the AdoptLegacy block in try — the scoped claim decides its
// own value, and the recovery has two decisions.
func TestProposer_BridgeCompletesALegacyDecision(t *testing.T) {
	ctx := context.Background()
	tr, voters := newMemCluster(t, "a", "b", "c")
	all := names(voters)
	legacy := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-bridge", OwnerEpoch: 2}
	decided, err := NewProposer("a", tr).Decide(ctx, workloadSpec(legacy, all, "dest-legacy"))
	if err != nil {
		t.Fatal(err)
	}
	scoped := legacy.WithIncarnation("inc-1")
	out, err := NewProposer("b", tr).Decide(ctx, scopedSpec(scoped, all, "dest-scoped", adoptAll))
	if err != nil {
		t.Fatal(err)
	}
	if out.Digest != decided.Digest || out.Ours {
		t.Fatalf("the scoped claim decided %s (ours=%v); the legacy key had decided %s",
			out.Value.Proof.DestHost, out.Ours, decided.Value.Proof.DestHost)
	}
	if out.Certificate.Key != scoped {
		t.Fatalf("the certificate decides %s, want %s", out.Certificate.Key, scoped)
	}
	// And the legacy key is now sealed on every voter that promised.
	if _, err := NewProposer("c", tr).Decide(ctx, workloadSpec(legacy, all, "dest-late")); err == nil {
		t.Fatal("a legacy claim decided after the scoped claim sealed the legacy key")
	}
}

// TestProposer_BridgeLeavesARefusedLegacyValue: a legacy value AdoptLegacy
// refuses (its proof is spent, or it names another incarnation's owner) is not
// re-proposed; the scoped claim decides afresh.
func TestProposer_BridgeLeavesARefusedLegacyValue(t *testing.T) {
	ctx := context.Background()
	tr, voters := newMemCluster(t, "a", "b", "c")
	all := names(voters)
	legacy := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-old", OwnerEpoch: 1}
	decided, err := NewProposer("a", tr).Decide(ctx, workloadSpec(legacy, all, "dest-legacy"))
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	refuse := func(v corrosion.ClaimValue) bool {
		if v.MustDigest() == decided.Digest {
			seen++
		}
		return false
	}
	out, err := NewProposer("b", tr).Decide(ctx, scopedSpec(legacy.WithIncarnation("inc-2"), all, "dest-fresh", refuse))
	if err != nil {
		t.Fatal(err)
	}
	if seen == 0 {
		t.Fatal("the legacy value was never offered to AdoptLegacy; the rest is vacuous")
	}
	if !out.Ours || out.Value.Proof.DestHost != "dest-fresh" {
		t.Fatalf("the scoped claim did not decide afresh: ours=%v dest=%s", out.Ours, out.Value.Proof.DestHost)
	}
}

// TestProposer_AnAcceptForAnotherKeyIsNotCounted: an accept counts only for
// the key it signs. A voter on an older build drops the incarnation and signs
// the legacy key.
//
// Mutation: drop the res.Accept.Key == spec.Key condition in acceptAll — the
// legacy-signed accepts certify the scoped key.
func TestProposer_AnAcceptForAnotherKeyIsNotCounted(t *testing.T) {
	ctx := context.Background()
	tr, voters := newMemCluster(t, "a", "b", "c")
	all := names(voters)
	old := &legacyVoterTransport{memTransport: tr}
	scoped := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-mixed", OwnerEpoch: 1, Incarnation: "inc-1"}
	if _, err := NewProposer("a", old).Decide(ctx, scopedSpec(scoped, all, "dest", adoptAll)); err == nil {
		t.Fatal("accepts signed at the legacy key certified an incarnation-scoped claim")
	}
}

// legacyVoterTransport is every voter on a build that does not know the key's
// incarnation: it answers the legacy key.
type legacyVoterTransport struct{ *memTransport }

func (l *legacyVoterTransport) Prepare(ctx context.Context, voter string, key corrosion.ClaimKey, b corrosion.Ballot, gen int64, ev *corrosion.SupersedeEvidence) (corrosion.PrepareResult, error) {
	return l.memTransport.Prepare(ctx, voter, key.Legacy(), b, gen, ev)
}

func (l *legacyVoterTransport) Accept(ctx context.Context, voter string, key corrosion.ClaimKey, b corrosion.Ballot, v corrosion.ClaimValue, gen int64) (corrosion.AcceptResult, error) {
	return l.memTransport.Accept(ctx, voter, key.Legacy(), b, v, gen)
}

// TestProposer_OneDecisionAcrossTheLatch is the property test for the bridge:
// over random schedules with message loss and delay, two proposers on the
// legacy key and two on its incarnation-scoped form — coordinators either side
// of the latch, claiming one recovery — never choose two different values
// between them.
//
// Mutations: drop the legacy-key seal in the voter (legacyKeySealedTx) — a
// legacy proposer chooses after the scoped key decided something else; drop
// the AdoptLegacy block in try — the scoped key decides its own value over a
// chosen legacy one.
func TestProposer_OneDecisionAcrossTheLatch(t *testing.T) {
	for _, n := range []int{3, 5} {
		t.Run(fmt.Sprintf("%d voters", n), func(t *testing.T) {
			var vnames []string
			for i := 0; i < n; i++ {
				vnames = append(vnames, fmt.Sprintf("v%d", i))
			}
			tr, voters := newMemCluster(t, vnames...)
			tr.drop, tr.delay = 0.2, 3*time.Millisecond
			all := names(voters)
			for sched := 0; sched < 25; sched++ {
				legacy := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: fmt.Sprintf("vm-%d", sched), OwnerEpoch: 1}
				scoped := legacy.WithIncarnation("inc")
				tr.mu.Lock()
				tr.rng = rand.New(rand.NewPCG(uint64(n)+100, uint64(sched)))
				tr.accepts = nil
				tr.mu.Unlock()
				var wg sync.WaitGroup
				var mu sync.Mutex
				certs := map[string]bool{}
				for pi := 0; pi < 4; pi++ {
					wg.Add(1)
					go func(pi int) {
						defer wg.Done()
						p := NewProposer(all[pi%n], tr)
						p.CallTimeout = time.Second
						p.Backoff = func(int) time.Duration { return time.Duration(rand.Int64N(int64(2 * time.Millisecond))) }
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						spec := workloadSpec(legacy, all, fmt.Sprintf("dest-%d", pi))
						if pi%2 == 1 {
							spec = scopedSpec(scoped, all, fmt.Sprintf("dest-%d", pi), adoptAll)
						}
						if out, err := p.Decide(ctx, spec); err == nil {
							mu.Lock()
							certs[out.Digest] = true
							mu.Unlock()
						}
					}(pi)
				}
				wg.Wait()
				chosen := map[string]bool{}
				for d := range tr.chosen(legacy, n) {
					chosen[d] = true
				}
				for d := range tr.chosen(scoped, n) {
					chosen[d] = true
				}
				if len(chosen) > 1 {
					t.Fatalf("schedule %d: the legacy and scoped keys chose %d different values between them: %v",
						sched, len(chosen), chosen)
				}
				if len(certs) > 1 {
					t.Fatalf("schedule %d: proposers returned certificates for %d different values", sched, len(certs))
				}
			}
		})
	}
}
