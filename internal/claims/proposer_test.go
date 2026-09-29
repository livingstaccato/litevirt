package claims

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// ── an in-memory cluster of real voters ────────────────────────────────────

type memVoter struct {
	name   string
	db     *corrosion.Client
	signer *corrosion.ClaimSigner
	inc    string
}

type acceptEvent struct {
	voter  string
	ballot corrosion.Ballot
	digest string
}

// memTransport delivers to real corrosion voters, with optional message loss
// and delay, and records every successful accept so a test can check the
// Paxos safety property over the whole history.
type memTransport struct {
	voters map[string]*memVoter
	drop   float64
	delay  time.Duration

	mu      sync.Mutex
	rng     *rand.Rand
	accepts []acceptEvent
	down    map[string]bool
	// probe is every voter's owner probe; nil reaches nothing.
	probe corrosion.OwnerProbe
	// beforeAccept, when set, runs before every Accept is delivered.
	beforeAccept func(voter string, b corrosion.Ballot)
}

var dbSeq atomic.Int64

func newMemCluster(t *testing.T, names ...string) (*memTransport, []*memVoter) {
	t.Helper()
	ctx := context.Background()
	caDir := t.TempDir()
	caCert, caKey := filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key")
	if err := pki.GenerateCA(caCert, caKey); err != nil {
		t.Fatal(err)
	}
	tr := &memTransport{voters: map[string]*memVoter{}, rng: rand.New(rand.NewPCG(1, 2)), down: map[string]bool{}}
	var out []*memVoter
	for _, n := range names {
		db, err := corrosion.NewSharedTestClient(fmt.Sprintf("claims-%s-%d", n, dbSeq.Add(1)), n)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if err := corrosion.InitSchema(ctx, db); err != nil {
			t.Fatal(err)
		}
		db.SetVoterConfigGate(func() bool { return true })
		dir := t.TempDir()
		b, _ := os.ReadFile(caCert)
		if err := os.WriteFile(filepath.Join(dir, "ca.crt"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := pki.GenerateHostCert(caCert, caKey, filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), n, net.ParseIP("127.0.0.1")); err != nil {
			t.Fatal(err)
		}
		s, err := corrosion.LoadClaimSigner(dir, n)
		if err != nil {
			t.Fatal(err)
		}
		inc, err := db.VoterIncarnation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		v := &memVoter{name: n, db: db, signer: s, inc: inc}
		tr.voters[n] = v
		out = append(out, v)
	}
	var members []corrosion.VoterMember
	for _, v := range out {
		members = append(members, corrosion.VoterMember{Name: v.name, Incarnation: v.inc})
	}
	members = corrosion.SortMembers(members)
	for _, v := range out {
		val := corrosion.VoterConfigValue{Generation: 1, Members: members, Change: corrosion.VoterChangeGenesis, CreatedBy: "t", CreatedAt: "t"}
		if err := corrosion.WriteVoterConfig(ctx, v.db, val, corrosion.ClaimCertificate{}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.RecordVoterAdoption(ctx, v.db, 1); err != nil {
			t.Fatal(err)
		}
	}
	return tr, out
}

var errDropped = errors.New("dropped")

func (m *memTransport) fault(voter string) error {
	m.mu.Lock()
	down := m.down[voter]
	lost := m.drop > 0 && m.rng.Float64() < m.drop
	var d time.Duration
	if m.delay > 0 {
		d = time.Duration(m.rng.Int64N(int64(m.delay)))
	}
	m.mu.Unlock()
	if d > 0 {
		time.Sleep(d)
	}
	if down || lost {
		return errDropped
	}
	return nil
}

func unreachable(context.Context, string) (bool, string) { return false, "" }

func (m *memTransport) Prepare(ctx context.Context, voter string, key corrosion.ClaimKey, b corrosion.Ballot, gen int64, _ *corrosion.SupersedeEvidence) (corrosion.PrepareResult, error) {
	if err := m.fault(voter); err != nil {
		return corrosion.PrepareResult{}, err
	}
	res, err := m.voters[voter].db.ClaimPrepare(ctx, key, b, gen)
	if err == nil {
		// A lost reply: the voter acted, the proposer never hears.
		if ferr := m.fault(voter); ferr != nil {
			return corrosion.PrepareResult{}, ferr
		}
	}
	return res, err
}

func (m *memTransport) Accept(ctx context.Context, voter string, key corrosion.ClaimKey, b corrosion.Ballot, v corrosion.ClaimValue, gen int64) (corrosion.AcceptResult, error) {
	if err := m.fault(voter); err != nil {
		return corrosion.AcceptResult{}, err
	}
	mv := m.voters[voter]
	probe := corrosion.OwnerProbe(unreachable)
	m.mu.Lock()
	if m.probe != nil {
		probe = m.probe
	}
	hook := m.beforeAccept
	m.mu.Unlock()
	if hook != nil {
		hook(voter, b)
	}
	res, err := mv.db.ClaimAccept(ctx, key, b, v, gen, mv.signer, probe)
	if err == nil && res.Accepted {
		m.mu.Lock()
		m.accepts = append(m.accepts, acceptEvent{voter: voter, ballot: b, digest: res.Accept.ValueDigest})
		m.mu.Unlock()
		if ferr := m.fault(voter); ferr != nil {
			return corrosion.AcceptResult{}, ferr
		}
	}
	return res, err
}

func names(vs []*memVoter) []string {
	var out []string
	for _, v := range vs {
		out = append(out, v.name)
	}
	return out
}

func valueFor(key corrosion.ClaimKey, dest string) corrosion.ClaimValue {
	return corrosion.ClaimValue{
		Proof: &corrosion.ActionProof{ID: "proof-" + dest + "-" + key.TargetName, Action: "reschedule",
			TargetKind: key.TargetKind, TargetName: key.TargetName, DestHost: dest, Coordinator: dest,
			OwnerEpoch: fmt.Sprint(key.OwnerEpoch)},
		SourceHost: "victim",
	}
}

func workloadSpec(key corrosion.ClaimKey, voters []string, dest string) Spec {
	q := corrosion.MajorityOf(len(voters))
	return Spec{
		Key: key, Generation: 1, Voters: voters, PrepareQuorum: q,
		Electorate: func(corrosion.ClaimValue) ([]string, int) { return voters, q },
		Propose: func(map[string]corrosion.PrepareResult) (corrosion.ClaimValue, error) {
			return valueFor(key, dest), nil
		},
		MaxRounds: 20,
	}
}

// chosen is every digest a majority of distinct voters accepted at one ballot.
func (m *memTransport) chosen(key corrosion.ClaimKey, n int) map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	byBallot := map[string]map[string]map[string]bool{} // ballot → digest → voters
	for _, a := range m.accepts {
		bk := a.ballot.String()
		if byBallot[bk] == nil {
			byBallot[bk] = map[string]map[string]bool{}
		}
		if byBallot[bk][a.digest] == nil {
			byBallot[bk][a.digest] = map[string]bool{}
		}
		byBallot[bk][a.digest][a.voter] = true
	}
	out := map[string]bool{}
	for _, byDigest := range byBallot {
		for d, vs := range byDigest {
			if len(vs) >= corrosion.MajorityOf(n) {
				out[d] = true
			}
		}
	}
	return out
}

// TestProposer_SafetyUnderRandomSchedules is the property test (§7.2): over
// random schedules with message loss and delay, three concurrent proposers
// each pushing their own destination, at most one value_digest ever gathers a
// majority of accepts at one key, and every certificate any proposer returns
// names that value.
//
// Mutations: make the voter accept a ballot below its promise; make the
// proposer ignore accepted values in promises. Either one produces a second
// chosen value within the schedules below.
func TestProposer_SafetyUnderRandomSchedules(t *testing.T) {
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
				key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: fmt.Sprintf("vm-%d", sched), OwnerEpoch: 1}
				tr.mu.Lock()
				tr.rng = rand.New(rand.NewPCG(uint64(n), uint64(sched)))
				tr.accepts = nil
				tr.mu.Unlock()
				var wg sync.WaitGroup
				var mu sync.Mutex
				certs := map[string]bool{}
				for pi := 0; pi < 3; pi++ {
					wg.Add(1)
					go func(pi int) {
						defer wg.Done()
						p := NewProposer(all[pi%n], tr)
						p.CallTimeout = time.Second
						p.Backoff = func(int) time.Duration { return time.Duration(rand.Int64N(int64(2 * time.Millisecond))) }
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						out, err := p.Decide(ctx, workloadSpec(key, all, fmt.Sprintf("dest-%d", pi)))
						if err == nil {
							mu.Lock()
							certs[out.Digest] = true
							mu.Unlock()
						}
					}(pi)
				}
				wg.Wait()
				chosen := tr.chosen(key, n)
				if len(chosen) > 1 {
					t.Fatalf("schedule %d: %d different values were each accepted by a majority at one key: %v",
						sched, len(chosen), chosen)
				}
				if len(certs) > 1 {
					t.Fatalf("schedule %d: proposers returned certificates for %d different values", sched, len(certs))
				}
				for d := range certs {
					if !chosen[d] {
						t.Fatalf("schedule %d: a certificate names a value no majority accepted", sched)
					}
				}
			}
		})
	}
}

// TestProposer_DuellingProposersConverge: both proposers of a duel return the
// same decided value — the loser completes the winner's decision rather than
// failing or deciding its own (§3.16 step 4).
func TestProposer_DuellingProposersConverge(t *testing.T) {
	tr, voters := newMemCluster(t, "a", "b", "c")
	all := names(voters)
	key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-duel", OwnerEpoch: 1}
	var wg sync.WaitGroup
	outs := make([]Outcome, 2)
	errs := make([]error, 2)
	for i, self := range []string{"a", "b"} {
		wg.Add(1)
		go func(i int, self string) {
			defer wg.Done()
			p := NewProposer(self, tr)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			outs[i], errs[i] = p.Decide(ctx, workloadSpec(key, all, self))
		}(i, self)
	}
	wg.Wait()
	for i := range outs {
		if errs[i] != nil {
			t.Fatalf("proposer %d: %v", i, errs[i])
		}
	}
	if outs[0].Digest != outs[1].Digest {
		t.Fatalf("duelling proposers decided different values: %s vs %s", outs[0].Value.Proof.DestHost, outs[1].Value.Proof.DestHost)
	}
	if outs[0].Ours == outs[1].Ours {
		t.Fatalf("exactly one proposer's own value should win (ours=%v/%v)", outs[0].Ours, outs[1].Ours)
	}
}

// TestProposer_RelearningItsOwnValueIsOurs: a proposer whose phase 2 reached
// one voter before another proposer's Prepare outranked it retries higher,
// finds its OWN value accepted in a promise and re-proposes it. The decided
// value is the one it built, so the outcome is Ours — a caller that reads
// !Ours as "another coordinator won" would otherwise count its own recovery
// lost, and in a duel neither side would report the win.
//
// Mutation: report Ours only for a value built in the deciding round (the
// old rule) — Ours is false.
func TestProposer_RelearningItsOwnValueIsOurs(t *testing.T) {
	tr, voters := newMemCluster(t, "a", "b", "c")
	all := names(voters)
	key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-relearn", OwnerEpoch: 1}
	var once sync.Once
	tr.beforeAccept = func(_ string, b corrosion.Ballot) {
		if b.Round != 1 {
			return
		}
		// Before any round-1 Accept lands, another proposer promises round 2
		// on b and c: only a accepts round 1.
		once.Do(func() {
			rival := corrosion.Ballot{Round: 2, Coordinator: "rival", Nonce: []byte{7}}
			for _, v := range []string{"b", "c"} {
				if _, err := tr.voters[v].db.ClaimPrepare(context.Background(), key, rival, 1); err != nil {
					t.Errorf("rival prepare on %s: %v", v, err)
				}
			}
		})
	}
	p := NewProposer("a", tr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := p.Decide(ctx, workloadSpec(key, all, "a"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Value.Proof.DestHost != "a" {
		t.Fatalf("decided %s, want the proposer's own value", out.Value.Proof.DestHost)
	}
	if out.Certificate.Ballot.Round < 3 {
		t.Fatalf("decided at round %d; the scenario needs a retry above the rival", out.Certificate.Ballot.Round)
	}
	if !out.Ours {
		t.Fatal("the proposer re-learned and decided its own value, and reported it as another's")
	}
}

// TestProposer_SplitVoteWithDeadVoterResolves is the harness scenario (§3.16):
// config {a, b, victim}, the victim dead, and each coordinator's own voter has
// already promised a ballot far above the proposer's lease-term seed (a
// crashed earlier proposer, or the other side of a duel). The claim still
// resolves within a few rounds because a refused proposer retries ABOVE the
// promise it was refused with, and the second proposer completes the same
// decision.
//
// Mutation: drop the round bump on refusal (retry at the next round of its
// own) — three rounds never climb past round 40, and the test goes red.
func TestProposer_SplitVoteWithDeadVoterResolves(t *testing.T) {
	tr, _ := newMemCluster(t, "a", "b", "victim")
	tr.mu.Lock()
	tr.down["victim"] = true
	tr.mu.Unlock()
	all := []string{"a", "b", "victim"}
	key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-victim", OwnerEpoch: 1}
	ctx := context.Background()
	for _, self := range []string{"a", "b"} {
		stale := corrosion.Ballot{Round: 40, Coordinator: "z", Nonce: []byte{9}}
		if res, err := tr.voters[self].db.ClaimPrepare(ctx, key, stale, 1); err != nil || !res.Promised {
			t.Fatalf("stale promise on %s: %+v %v", self, res, err)
		}
	}
	pa, pb := NewProposer("a", tr), NewProposer("b", tr)
	specA, specB := workloadSpec(key, all, "a"), workloadSpec(key, all, "b")
	specA.MaxRounds, specB.MaxRounds = 3, 3
	out, err := pb.Decide(ctx, specB)
	if err != nil {
		t.Fatalf("the split vote did not resolve: %v", err)
	}
	out2, err := pa.Decide(ctx, specA)
	if err != nil {
		t.Fatalf("the second proposer did not complete the decision: %v", err)
	}
	if out.Digest != out2.Digest || out2.Ours {
		t.Fatalf("the second proposer decided its own value instead of completing the first (ours=%v)", out2.Ours)
	}
}

// TestProposer_OwnerRefusalRetriesAtTheSameRound: a claim the voters refused
// because the owner was still reachable is retried at the SAME round with the
// same value — nothing was contending, so nothing should have to outrank it —
// and a different value at that round is never sent: the round is bound to
// the value it carried (§3.2, §3.13 step 6).
//
// Mutations: drop the reuse arm in ballot — the retry moves up a round; drop
// the bind check in try — the second value is sent at the bound round.
func TestProposer_OwnerRefusalRetriesAtTheSameRound(t *testing.T) {
	ctx := context.Background()
	tr, vs := newMemCluster(t, "a", "b", "c")
	var reached atomic.Bool
	reached.Store(true)
	tr.probe = func(context.Context, string) (bool, string) { return reached.Load(), "answered" }
	p := NewProposer("a", tr)

	key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "same", OwnerEpoch: 1}
	spec := workloadSpec(key, names(vs), "a")
	spec.StartRound, spec.ReuseRound, spec.MaxRounds = 5, true, 1
	var nm *NoMajorityError
	if _, err := p.Decide(ctx, spec); !errors.As(err, &nm) {
		t.Fatalf("with the owner reachable the claim must form no certificate: %v", err)
	}
	reached.Store(false)
	out, err := p.Decide(ctx, spec)
	if err != nil {
		t.Fatalf("the retry once the owner is gone: %v", err)
	}
	if out.Certificate.Ballot.Round != 5 {
		t.Fatalf("the retry decided at round %d, want the same round 5", out.Certificate.Ballot.Round)
	}

	// Another value at a bound round moves up rather than reuse it.
	key2 := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "other", OwnerEpoch: 1}
	first := workloadSpec(key2, names(vs), "a")
	first.StartRound, first.ReuseRound, first.MaxRounds = 5, true, 1
	reached.Store(true)
	if _, err := p.Decide(ctx, first); !errors.As(err, &nm) {
		t.Fatalf("with the owner reachable the claim must form no certificate: %v", err)
	}
	reached.Store(false)
	second := workloadSpec(key2, names(vs), "b")
	second.StartRound, second.ReuseRound, second.MaxRounds = 5, true, 3
	out, err = p.Decide(ctx, second)
	if err != nil {
		t.Fatalf("a new value after a refusal: %v", err)
	}
	if out.Certificate.Ballot.Round <= 5 {
		t.Fatalf("a second value was decided at bound round %d", out.Certificate.Ballot.Round)
	}
}

// TestProposer_BallotNeverReusedInProcess: two concurrent Decide calls on one
// key in one process never share a ballot (§3.2).
func TestProposer_BallotNeverReusedInProcess(t *testing.T) {
	p := NewProposer("a", nil)
	key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "x", OwnerEpoch: 1}
	seen := map[uint64]bool{}
	for i := 0; i < 10; i++ {
		b := p.ballot(key, 3, false)
		if seen[b.Round] {
			t.Fatalf("round %d handed out twice", b.Round)
		}
		seen[b.Round] = true
	}
}
