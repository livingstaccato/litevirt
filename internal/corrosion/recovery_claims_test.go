package corrosion

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

// ── fixtures ────────────────────────────────────────────────────────────────

type claimTestCA struct {
	dir, cert, key string
}

func newClaimTestCA(t *testing.T) claimTestCA {
	t.Helper()
	dir := t.TempDir()
	ca := claimTestCA{dir: dir, cert: filepath.Join(dir, "ca.crt"), key: filepath.Join(dir, "ca.key")}
	if err := pki.GenerateCA(ca.cert, ca.key); err != nil {
		t.Fatal(err)
	}
	return ca
}

// pkiDir mints a host identity for name under this CA.
func (ca claimTestCA) pkiDir(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	if err := copyTestFile(ca.cert, filepath.Join(dir, "ca.crt")); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateHostCert(ca.cert, ca.key, filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"),
		name, net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	return dir
}

type claimTestVoter struct {
	name   string
	c      *Client
	signer *ClaimSigner
	pki    string
	inc    string
}

var claimTestDB atomic.Int64

func newClaimTestVoter(t *testing.T, ca claimTestCA, name string) *claimTestVoter {
	t.Helper()
	ctx := context.Background()
	c, err := NewSharedTestClient(fmt.Sprintf("claimtest-%s-%d", name, claimTestDB.Add(1)), name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.SetVoterConfigGate(func() bool { return true })
	dir := ca.pkiDir(t, name)
	s, err := LoadClaimSigner(dir, name)
	if err != nil {
		t.Fatal(err)
	}
	inc, err := c.VoterIncarnation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return &claimTestVoter{name: name, c: c, signer: s, pki: dir, inc: inc}
}

func membersOf(vs ...*claimTestVoter) []VoterMember {
	var out []VoterMember
	for _, v := range vs {
		out = append(out, VoterMember{Name: v.name, Incarnation: v.inc})
	}
	return SortMembers(out)
}

// adoptHandBuilt writes generation gen with members on every voter and adopts
// it there. The certificate is not what these tests are about.
func adoptHandBuilt(t *testing.T, gen int64, members []VoterMember, voters ...*claimTestVoter) {
	t.Helper()
	ctx := context.Background()
	for _, v := range voters {
		// Adoption is per generation; fill the history below gen.
		for g := int64(1); g <= gen; g++ {
			val := VoterConfigValue{Generation: g, Members: members, Change: VoterChangeGenesis, CreatedBy: "t", CreatedAt: "t"}
			if err := WriteVoterConfig(ctx, v.c, val, ClaimCertificate{}); err != nil {
				t.Fatal(err)
			}
			if err := RecordVoterAdoption(ctx, v.c, g); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func testBallot(round uint64, coord string) Ballot {
	return Ballot{Round: round, Coordinator: coord, Nonce: []byte{1}}
}

func workloadKey() ClaimKey {
	return ClaimKey{TargetKind: ClaimKindVM, TargetName: "vm-1", OwnerEpoch: 3}
}

func workloadValue(id, dest, source string) ClaimValue {
	return ClaimValue{
		Proof: &ActionProof{ID: id, Action: "reschedule", TargetKind: ClaimKindVM, TargetName: "vm-1",
			DestHost: dest, Coordinator: dest, OwnerEpoch: "3", LeaseTerm: 4, LeaseKey: "failover"},
		SourceHost: source,
	}
}

func unreachable(context.Context, string) (bool, string) { return false, "" }

// ── ballot order ────────────────────────────────────────────────────────────

func TestCompareBallots(t *testing.T) {
	for _, tc := range []struct {
		a, b Ballot
		want int
	}{
		{testBallot(2, "b"), testBallot(1, "a"), 1},               // higher round wins
		{testBallot(1, "a"), testBallot(1, "b"), 1},               // equal round: lower name ranks higher
		{testBallot(1, "b"), testBallot(1, "a"), -1},              //
		{Ballot{1, "a", []byte{2}}, Ballot{1, "a", []byte{1}}, 1}, // nonce breaks the tie
		{testBallot(1, "a"), testBallot(1, "a"), 0},
		{Ballot{}, testBallot(1, "z"), -1}, // the zero ballot is below every real one
	} {
		if got := CompareBallots(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareBallots(%v, %v) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// ── voter rules (§3.5) ──────────────────────────────────────────────────────

func threeVoters(t *testing.T) (claimTestCA, *claimTestVoter, *claimTestVoter, *claimTestVoter) {
	ca := newClaimTestCA(t)
	a, b, c := newClaimTestVoter(t, ca, "a"), newClaimTestVoter(t, ca, "b"), newClaimTestVoter(t, ca, "c")
	adoptHandBuilt(t, 1, membersOf(a, b, c), a, b, c)
	return ca, a, b, c
}

// TestClaimVoter_PromiseOrdering: a voter promises only a ballot above its
// promise, answers an identical Prepare as the promise it already made, and
// reports what it has promised when it refuses.
func TestClaimVoter_PromiseOrdering(t *testing.T) {
	ctx := context.Background()
	_, a, _, _ := threeVoters(t)
	k := workloadKey()
	res, err := a.c.ClaimPrepare(ctx, k, testBallot(5, "x"), 1)
	if err != nil || !res.Promised {
		t.Fatalf("first prepare: %+v %v", res, err)
	}
	res, _ = a.c.ClaimPrepare(ctx, k, testBallot(4, "x"), 1)
	if res.Promised || res.Refusal != RefusalBallotStale || !res.PromisedBallot.Equal(testBallot(5, "x")) {
		t.Fatalf("a lower ballot was not refused with the promise named: %+v", res)
	}
	res, _ = a.c.ClaimPrepare(ctx, k, testBallot(5, "x"), 1)
	if !res.Promised {
		t.Fatalf("an identical prepare was refused: %+v", res)
	}
	res, _ = a.c.ClaimPrepare(ctx, k, testBallot(5, "w"), 1) // same round, lower name ranks higher
	if !res.Promised {
		t.Fatalf("(5,w) ranks above (5,x) and must be promised: %+v", res)
	}
}

// TestClaimVoter_AcceptBelowPromiseRefused is the rule the intersection
// argument (§3.16) rests on.
//
// Mutation: make the Accept check `> 0` into `> 1` (never refuse) — the stale
// accept is taken and the test goes red.
func TestClaimVoter_AcceptBelowPromiseRefused(t *testing.T) {
	ctx := context.Background()
	_, a, _, _ := threeVoters(t)
	k := workloadKey()
	if res, _ := a.c.ClaimPrepare(ctx, k, testBallot(7, "x"), 1); !res.Promised {
		t.Fatal(res)
	}
	res, err := a.c.ClaimAccept(ctx, k, testBallot(6, "x"), workloadValue("p1", "b", "ghost"), 1, a.signer, unreachable)
	if err != nil {
		t.Fatal(err)
	}
	if res.Accepted || res.Refusal != RefusalBallotStale {
		t.Fatalf("an accept below the promise was taken: %+v", res)
	}
	st, found, _ := a.c.ClaimState(ctx, k)
	if !found || !st.Accepted.IsZero() {
		t.Fatalf("a refused accept wrote state: %+v", st)
	}
}

// TestClaimVoter_PromiseReportsAcceptedValue: phase 1 is how a later proposer
// learns a value that might have been chosen.
func TestClaimVoter_PromiseReportsAcceptedValue(t *testing.T) {
	ctx := context.Background()
	_, a, _, _ := threeVoters(t)
	k := workloadKey()
	v := workloadValue("p1", "b", "ghost")
	if res, err := a.c.ClaimAccept(ctx, k, testBallot(1, "x"), v, 1, a.signer, unreachable); err != nil || !res.Accepted {
		t.Fatalf("accept: %+v %v", res, err)
	}
	res, _ := a.c.ClaimPrepare(ctx, k, testBallot(2, "y"), 1)
	if !res.Promised || !res.State.Accepted.Equal(testBallot(1, "x")) || res.State.ValueDigest != v.MustDigest() {
		t.Fatalf("the promise did not report the accepted value: %+v", res)
	}
}

// TestClaimVoter_OneValuePerBallot and the idempotent repeat.
func TestClaimVoter_OneValuePerBallot(t *testing.T) {
	ctx := context.Background()
	_, a, _, _ := threeVoters(t)
	k := workloadKey()
	b1 := testBallot(1, "x")
	first, err := a.c.ClaimAccept(ctx, k, b1, workloadValue("p1", "b", "ghost"), 1, a.signer, unreachable)
	if err != nil || !first.Accepted {
		t.Fatal(first, err)
	}
	again, _ := a.c.ClaimAccept(ctx, k, b1, workloadValue("p1", "b", "ghost"), 1, a.signer, unreachable)
	if !again.Accepted || string(again.Accept.Signature) != string(first.Accept.Signature) {
		t.Fatalf("a repeated accept must return the stored signed accept: %+v", again)
	}
	other, _ := a.c.ClaimAccept(ctx, k, b1, workloadValue("p2", "c", "ghost"), 1, a.signer, unreachable)
	if other.Accepted || other.Refusal != RefusalValueConflict {
		t.Fatalf("a second value at one ballot was accepted: %+v", other)
	}
}

// TestClaimVoter_MembershipRefusals: the voter answers only for the generation
// it has adopted, only as a member, and only as the incarnation it was
// admitted with (§3.11).
//
// Mutation: skip the incarnation comparison in memberCheck — the amnesiac voter
// promises and the test goes red.
func TestClaimVoter_MembershipRefusals(t *testing.T) {
	ctx := context.Background()
	ca := newClaimTestCA(t)
	a, b, c := newClaimTestVoter(t, ca, "a"), newClaimTestVoter(t, ca, "b"), newClaimTestVoter(t, ca, "c")
	outsider := newClaimTestVoter(t, ca, "d")
	stale := membersOf(a, b, c)
	for i := range stale {
		if stale[i].Name == "c" {
			stale[i].Incarnation = "before-the-reimage"
		}
	}
	adoptHandBuilt(t, 1, stale, a, b, c, outsider)
	k := workloadKey()

	if res, _ := a.c.ClaimPrepare(ctx, k, testBallot(1, "x"), 2); res.Refusal != RefusalWrongGeneration {
		t.Errorf("a prepare under an unadopted generation: %+v", res)
	}
	if res, _ := outsider.c.ClaimPrepare(ctx, k, testBallot(1, "x"), 1); res.Refusal != RefusalNotMember {
		t.Errorf("a non-member promised: %+v", res)
	}
	res, _ := c.c.ClaimPrepare(ctx, k, testBallot(1, "x"), 1)
	if res.Promised || res.Refusal != RefusalIncarnationMismatch {
		t.Errorf("a voter whose incarnation changed did not abstain from Prepare: %+v", res)
	}
	acc, _ := c.c.ClaimAccept(ctx, k, testBallot(1, "x"), workloadValue("p", "a", "ghost"), 1, c.signer, unreachable)
	if acc.Accepted || acc.Refusal != RefusalIncarnationMismatch {
		t.Errorf("a voter whose incarnation changed did not abstain from Accept: %+v", acc)
	}
	if !strings.Contains(acc.Detail, "lv cluster voter rm c") {
		t.Errorf("the abstention does not name the heal: %q", acc.Detail)
	}
	if res, _ := a.c.ClaimPrepare(ctx, k, testBallot(1, "x"), 1); !res.Promised {
		t.Errorf("a current member refused: %+v", res)
	}
}

// TestClaimVoter_SealRefusesWorkloadKeys: accepting a change of generation g
// stops this voter answering workload keys under g (§4.4 rule 1).
//
// Mutation: drop the sealed check in admit — the workload prepare is promised.
func TestClaimVoter_SealRefusesWorkloadKeys(t *testing.T) {
	ctx := context.Background()
	_, a, b, c := threeVoters(t)
	next := VoterConfigValue{Generation: 2, Members: membersOf(a, b), Change: VoterChangeRm("c"), CreatedBy: "a", CreatedAt: "t"}
	cfgKey := ClaimKey{TargetKind: ClaimKindVoterConfig, OwnerEpoch: 1}
	if res, err := a.c.ClaimAccept(ctx, cfgKey, testBallot(1, "a"), ClaimValue{Config: &next}, 1, a.signer, nil); err != nil || !res.Accepted {
		t.Fatalf("config accept: %+v %v", res, err)
	}
	res, _ := a.c.ClaimPrepare(ctx, workloadKey(), testBallot(9, "x"), 1)
	if res.Promised || res.Refusal != RefusalSealed {
		t.Fatalf("a sealed voter answered a workload key: %+v", res)
	}
	// It still answers the config key, so the decision can finish.
	if res, _ := a.c.ClaimPrepare(ctx, cfgKey, testBallot(2, "b"), 1); !res.Promised {
		t.Fatalf("a sealed voter refused the config key it sealed on: %+v", res)
	}
	_ = c
}

// TestClaimVoter_ConfigChangeValidated: voters accept exactly one member
// changed per generation.
func TestClaimVoter_ConfigChangeValidated(t *testing.T) {
	ctx := context.Background()
	ca, a, b, _ := threeVoters(t)
	d := newClaimTestVoter(t, ca, "d")
	cfgKey := ClaimKey{TargetKind: ClaimKindVoterConfig, OwnerEpoch: 1}
	two := VoterConfigValue{Generation: 2, Members: membersOf(a), Change: VoterChangeRm("b"), CreatedBy: "a", CreatedAt: "t"}
	if res, _ := a.c.ClaimAccept(ctx, cfgKey, testBallot(1, "a"), ClaimValue{Config: &two}, 1, a.signer, nil); res.Accepted {
		t.Fatalf("a two-member removal was accepted: %+v", res)
	}
	swap := VoterConfigValue{Generation: 2, Members: membersOf(a, b, d), Change: VoterChangeAdd("d"), CreatedBy: "a", CreatedAt: "t"}
	if res, _ := a.c.ClaimAccept(ctx, cfgKey, testBallot(1, "a"), ClaimValue{Config: &swap}, 1, a.signer, nil); res.Accepted {
		t.Fatalf("an add that also drops c was accepted: %+v", res)
	}
}

// TestClaimVoter_GenesisNeedsOwnEntry: with no member generation, a voter
// accepts a genesis only if it is listed with the incarnation it has.
func TestClaimVoter_GenesisNeedsOwnEntry(t *testing.T) {
	ctx := context.Background()
	ca := newClaimTestCA(t)
	a, b := newClaimTestVoter(t, ca, "a"), newClaimTestVoter(t, ca, "b")
	key := ClaimKey{TargetKind: ClaimKindVoterConfig, OwnerEpoch: 0}
	wrong := membersOf(a, b)
	wrong[0].Incarnation = "not-a's"
	g := VoterConfigValue{Generation: 1, Members: wrong, Change: VoterChangeGenesis, CreatedBy: "a", CreatedAt: "t"}
	if res, _ := a.c.ClaimAccept(ctx, key, testBallot(1, "a"), ClaimValue{Config: &g}, 0, a.signer, nil); res.Accepted {
		t.Fatalf("a genesis listing the wrong incarnation for a was accepted: %+v", res)
	}
	g.Members = membersOf(a, b)
	if res, err := a.c.ClaimAccept(ctx, key, testBallot(1, "a"), ClaimValue{Config: &g}, 0, a.signer, nil); err != nil || !res.Accepted {
		t.Fatalf("a correct genesis was refused: %+v %v", res, err)
	}
	// And no workload key is answered before a member generation exists.
	if res, _ := a.c.ClaimPrepare(ctx, workloadKey(), testBallot(1, "x"), 0); res.Refusal != RefusalNoVoterConfig {
		t.Fatalf("a workload key was answered without a voter config: %+v", res)
	}
}

// ── the owner probe (§3.5.1) ────────────────────────────────────────────────

// TestClaimVoter_OwnerProbe covers every branch of the owner check.
//
// Mutations, each red on its own subtest: drop the `source == me` check;
// drop the settled-row cross-check; ignore the probe's answer; re-probe an
// already-accepted value.
func TestClaimVoter_OwnerProbe(t *testing.T) {
	ctx := context.Background()
	k := workloadKey()

	t.Run("the old owner refuses outright", func(t *testing.T) {
		_, a, _, _ := threeVoters(t)
		res, _ := a.c.ClaimAccept(ctx, k, testBallot(1, "x"), workloadValue("p", "b", "a"), 1, a.signer, unreachable)
		if res.Accepted || res.Refusal != RefusalOwnerReachable || !strings.Contains(res.Detail, "a is the owner") {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("a settled row naming another owner refuses", func(t *testing.T) {
		_, a, _, _ := threeVoters(t)
		if err := a.c.Execute(ctx, `INSERT INTO vms (name, host_name, spec, state, vm_owner_epoch, created_at, updated_at)
			VALUES ('vm-1', 'live-host', '{}', 'running', 3, 't', 't')`); err != nil {
			t.Fatal(err)
		}
		res, _ := a.c.ClaimAccept(ctx, k, testBallot(1, "x"), workloadValue("p", "b", "dead-host"), 1, a.signer, unreachable)
		if res.Accepted || res.Refusal != RefusalSourceMismatch {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("a reachable source refuses, naming what answered", func(t *testing.T) {
		_, a, _, _ := threeVoters(t)
		reach := func(_ context.Context, h string) (bool, string) { return h == "ghost", "Ping answered in 4ms" }
		res, _ := a.c.ClaimAccept(ctx, k, testBallot(1, "x"), workloadValue("p", "b", "ghost"), 1, a.signer, reach)
		if res.Accepted || res.Refusal != RefusalOwnerReachable || !strings.Contains(res.Detail, "a still reaches ghost") {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("an already-accepted value is not re-probed", func(t *testing.T) {
		_, a, _, _ := threeVoters(t)
		var probes atomic.Int32
		counting := func(context.Context, string) (bool, string) { probes.Add(1); return false, "" }
		v := workloadValue("p", "b", "ghost")
		if res, _ := a.c.ClaimAccept(ctx, k, testBallot(1, "x"), v, 1, a.signer, counting); !res.Accepted {
			t.Fatal(res)
		}
		// The owner came back after the value was accepted (§3.15, last row).
		// Re-accepting it at a higher ballot must not probe again.
		back := func(context.Context, string) (bool, string) { probes.Add(1); return true, "back" }
		if res, _ := a.c.ClaimAccept(ctx, k, testBallot(2, "y"), v, 1, a.signer, back); !res.Accepted {
			t.Fatalf("an already-accepted value was re-probed and refused: %+v", res)
		}
		if n := probes.Load(); n != 1 {
			t.Fatalf("probed %d times, want 1", n)
		}
	})
	t.Run("no probe wired fails closed", func(t *testing.T) {
		_, a, _, _ := threeVoters(t)
		res, _ := a.c.ClaimAccept(ctx, k, testBallot(1, "x"), workloadValue("p", "b", "ghost"), 1, a.signer, nil)
		if res.Accepted || res.Refusal != RefusalProbeUnavailable {
			t.Fatalf("%+v", res)
		}
	})
}

// ── seal and transfer (§4.4) ────────────────────────────────────────────────

// TestImportClaimsAndAdopt_CarriesHighestValueAndRaisesPromise: import takes
// the highest-ballot accepted value, never downgrades, keeps the accepted
// ballot at or below the promise, and adopts in the same transaction.
func TestImportClaimsAndAdopt_CarriesHighestValueAndRaisesPromise(t *testing.T) {
	ctx := context.Background()
	_, a, b, c := threeVoters(t)
	k := workloadKey()
	low, high := workloadValue("p-low", "b", "ghost"), workloadValue("p-high", "c", "ghost")
	if res, _ := a.c.ClaimAccept(ctx, k, testBallot(1, "x"), low, 1, a.signer, unreachable); !res.Accepted {
		t.Fatal(res)
	}
	if res, _ := b.c.ClaimAccept(ctx, k, testBallot(3, "x"), high, 1, b.signer, unreachable); !res.Accepted {
		t.Fatal(res)
	}
	var states []ClaimVoterState
	for _, v := range []*claimTestVoter{a, b} {
		src, err := v.c.ClaimStatesForImport(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		states = append(states, src.States...)
	}
	// c becomes a member of generation 2 and imports.
	next := VoterConfigValue{Generation: 2, Members: membersOf(b, c), Change: VoterChangeRm("a"), CreatedBy: "b", CreatedAt: "t"}
	if err := WriteVoterConfig(ctx, c.c, next, ClaimCertificate{}); err != nil {
		t.Fatal(err)
	}
	if n, err := c.c.ImportClaimsAndAdopt(ctx, 2, []string{"a", "b"}, states); err != nil || n != 1 {
		t.Fatalf("import: n=%d err=%v", n, err)
	}
	st, _, _ := c.c.ClaimState(ctx, k)
	if st.ValueDigest != high.MustDigest() || !st.Accepted.Equal(testBallot(3, "x")) {
		t.Fatalf("import did not take the highest-ballot value: %+v", st)
	}
	if CompareBallots(st.Promised, st.Accepted) < 0 {
		t.Fatalf("import left the accepted ballot above the promise: %+v", st)
	}
	if g, _ := AdoptedVoterGeneration(ctx, c.c); g != 2 {
		t.Fatalf("import did not adopt: generation %d", g)
	}
	// A voter under generation 2 now reports the imported value in phase 1.
	res, _ := c.c.ClaimPrepare(ctx, k, testBallot(4, "z"), 2)
	if !res.Promised || res.State.ValueDigest != high.MustDigest() {
		t.Fatalf("the imported value is not reported: %+v", res)
	}
}

// ── certificates (§3.9–§3.10) ───────────────────────────────────────────────

type certFixture struct {
	ca       claimTestCA
	voters   []*claimTestVoter
	verifier *ClaimVerifier
	key      ClaimKey
	value    ClaimValue
	cert     ClaimCertificate
	want     CertExpectation
}

func newCertFixture(t *testing.T) *certFixture {
	t.Helper()
	ctx := context.Background()
	f := &certFixture{ca: newClaimTestCA(t), key: workloadKey(), value: workloadValue("p1", "b", "ghost")}
	for _, n := range []string{"a", "b", "c"} {
		f.voters = append(f.voters, newClaimTestVoter(t, f.ca, n))
	}
	adoptHandBuilt(t, 1, membersOf(f.voters...), f.voters...)
	b := testBallot(2, "b")
	f.cert = ClaimCertificate{Key: f.key, ConfigGeneration: 1, Ballot: b, ValueDigest: f.value.MustDigest(), SourceHost: "ghost"}
	for _, v := range f.voters[:2] {
		res, err := v.c.ClaimAccept(ctx, f.key, b, f.value, 1, v.signer, unreachable)
		if err != nil || !res.Accepted {
			t.Fatalf("%s accept: %+v %v", v.name, res, err)
		}
		f.cert.Accepts = append(f.cert.Accepts, *res.Accept)
	}
	var err error
	if f.verifier, err = LoadClaimVerifier(f.ca.pkiDir(t, "verifier")); err != nil {
		t.Fatal(err)
	}
	f.want = CertExpectation{Key: f.key, ValueDigest: f.value.MustDigest(), ConfigGeneration: 1,
		Electorate: membersOf(f.voters...), Quorum: 2}
	return f
}

// TestVerifyClaimCertificate: a genuine majority certificate verifies, and each
// forgery below is refused.
//
// Mutations, each named where it is exercised: skip the signature check; skip
// the CN check; skip the CA chain check; skip the revocation check; count
// accepts without de-duplicating voters; skip the generation check; skip the
// digest check; skip the incarnation check.
func TestVerifyClaimCertificate(t *testing.T) {
	f := newCertFixture(t)
	if err := f.verifier.Verify(f.cert, f.want); err != nil {
		t.Fatalf("a genuine certificate was refused: %v", err)
	}

	clone := func() ClaimCertificate {
		c := f.cert
		c.Accepts = append([]ClaimAccept(nil), f.cert.Accepts...)
		return c
	}
	refused := func(t *testing.T, cert ClaimCertificate, want CertExpectation, contains string) {
		t.Helper()
		err := f.verifier.Verify(cert, want)
		if err == nil {
			t.Fatalf("verified; want a refusal mentioning %q", contains)
		}
		if contains != "" && !strings.Contains(err.Error(), contains) {
			t.Fatalf("refused for the wrong reason: %v (want %q)", err, contains)
		}
	}

	t.Run("forged signature", func(t *testing.T) { // mutation: skip ecdsa.VerifyASN1
		c := clone()
		sig := append([]byte(nil), c.Accepts[0].Signature...)
		sig[len(sig)-1] ^= 0xff
		c.Accepts[0].Signature = sig
		refused(t, c, f.want, "signature")
	})
	t.Run("wrong CN", func(t *testing.T) { // mutation: skip the CN comparison
		c := clone()
		// b signs an accept claiming to be a, with b's own certificate.
		forged := c.Accepts[1]
		forged.Voter = "a"
		forged.VoterIncarnation = f.voters[0].inc
		sig, err := signRaw(f.voters[1].signer, acceptPayload(forged.Key, forged.ConfigGeneration, forged.Ballot,
			forged.ValueDigest, forged.Voter, forged.VoterIncarnation))
		if err != nil {
			t.Fatal(err)
		}
		forged.Signature = sig
		c.Accepts = []ClaimAccept{forged, c.Accepts[1]}
		refused(t, c, f.want, "certificate")
	})
	t.Run("self-minted certificate", func(t *testing.T) { // mutation: skip the CA chain check
		rogueCA := newClaimTestCA(t)
		rogue := newClaimTestVoter(t, rogueCA, "c")
		c := clone()
		sig, err := signRaw(rogue.signer, acceptPayload(f.key, 1, c.Ballot, c.ValueDigest, "c", f.voters[2].inc))
		if err != nil {
			t.Fatal(err)
		}
		c.Accepts = []ClaimAccept{c.Accepts[0], {Voter: "c", VoterIncarnation: f.voters[2].inc, ConfigGeneration: 1,
			Key: f.key, Ballot: c.Ballot, ValueDigest: c.ValueDigest, CertPEM: rogue.signer.certPEM, Signature: sig}}
		refused(t, c, f.want, "cluster CA")
	})
	t.Run("revoked certificate", func(t *testing.T) { // mutation: skip pki.IsCertRevoked
		dir := f.ca.pkiDir(t, "verifier-crl")
		serial, err := pki.CertSerial(filepath.Join(f.voters[0].pki, "host.crt"))
		if err != nil {
			t.Fatal(err)
		}
		if err := pki.AppendToCRL(f.ca.cert, f.ca.key, filepath.Join(dir, "crl.pem"), serial); err != nil {
			t.Fatal(err)
		}
		v, err := LoadClaimVerifier(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Verify(f.cert, f.want); err == nil || !strings.Contains(err.Error(), "revoked") {
			t.Fatalf("a certificate relying on a revoked voter verified: %v", err)
		}
	})
	t.Run("one voter counted twice", func(t *testing.T) { // mutation: count accepts, not distinct voters
		c := clone()
		c.Accepts = []ClaimAccept{c.Accepts[0], c.Accepts[0]}
		refused(t, c, f.want, "distinct")
	})
	t.Run("wrong generation", func(t *testing.T) { // mutation: skip the generation comparison
		want := f.want
		want.ConfigGeneration = 2
		refused(t, f.cert, want, "generation")
	})
	t.Run("digest mismatch", func(t *testing.T) { // mutation: skip the digest comparison
		other := workloadValue("p1", "c", "ghost")
		want := f.want
		want.ValueDigest = other.MustDigest()
		refused(t, f.cert, want, "certifies value")
	})
	t.Run("changed source host", func(t *testing.T) { // the source is inside the digest
		moved := workloadValue("p1", "b", "some-other-host")
		want := f.want
		want.ValueDigest = moved.MustDigest()
		refused(t, f.cert, want, "certifies value")
	})
	t.Run("stale incarnation", func(t *testing.T) { // mutation: skip the incarnation comparison
		want := f.want
		want.Electorate = append([]VoterMember(nil), f.want.Electorate...)
		for i := range want.Electorate {
			if want.Electorate[i].Name == "a" {
				want.Electorate[i].Incarnation = "re-admitted"
			}
		}
		refused(t, f.cert, want, "incarnation")
	})
	t.Run("not a member", func(t *testing.T) {
		want := f.want
		want.Electorate = want.Electorate[1:] // a is not in this generation
		refused(t, f.cert, want, "not a member")
	})
}

// TestClaimVerifier_HistoricalRelaxesOnlyRevocation: the verifier a node uses
// for a voter generation below its anchor (§4.1 "History and revocation")
// still counts an accept whose certificate has been revoked since, and
// refuses everything else Verify refuses. The node's own verifier is not
// changed by deriving it.
//
// Mutations: make revoked() ignore historical (the revoked accept is refused
// by the historical verifier too); make Historical skip the CA chain check as
// well (the self-minted accept counts); make Historical mutate its receiver
// (the plain verifier stops refusing the revoked accept).
func TestClaimVerifier_HistoricalRelaxesOnlyRevocation(t *testing.T) {
	f := newCertFixture(t)
	dir := f.ca.pkiDir(t, "verifier-history")
	serial, err := pki.CertSerial(filepath.Join(f.voters[0].pki, "host.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.AppendToCRL(f.ca.cert, f.ca.key, filepath.Join(dir, "crl.pem"), serial); err != nil {
		t.Fatal(err)
	}
	now, err := LoadClaimVerifier(dir)
	if err != nil {
		t.Fatal(err)
	}
	hist := now.Historical()
	if err := hist.Verify(f.cert, f.want); err != nil {
		t.Fatalf("history signed by a voter revoked since was refused: %v", err)
	}
	if err := now.Verify(f.cert, f.want); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("deriving the historical verifier relaxed the node's own: %v", err)
	}

	rogue := newClaimTestVoter(t, newClaimTestCA(t), "c")
	c := f.cert
	sig, err := signRaw(rogue.signer, acceptPayload(f.key, 1, c.Ballot, c.ValueDigest, "c", f.voters[2].inc))
	if err != nil {
		t.Fatal(err)
	}
	c.Accepts = []ClaimAccept{c.Accepts[1], {Voter: "c", VoterIncarnation: f.voters[2].inc, ConfigGeneration: 1,
		Key: f.key, Ballot: c.Ballot, ValueDigest: c.ValueDigest, CertPEM: rogue.signer.certPEM, Signature: sig}}
	if err := hist.Verify(c, f.want); err == nil || !strings.Contains(err.Error(), "cluster CA") {
		t.Fatalf("the historical verifier counted a certificate the cluster CA never issued: %v", err)
	}
	forged := f.cert
	forged.Accepts = append([]ClaimAccept(nil), f.cert.Accepts...)
	bad := append([]byte(nil), forged.Accepts[0].Signature...)
	bad[len(bad)-1] ^= 0xff
	forged.Accepts[0].Signature = bad
	if err := hist.Verify(forged, f.want); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("the historical verifier counted a forged signature: %v", err)
	}
}

// ── voter-config values ─────────────────────────────────────────────────────

func TestValidateVoterChange(t *testing.T) {
	m := func(names ...string) []VoterMember {
		var out []VoterMember
		for _, n := range names {
			out = append(out, VoterMember{Name: n, Incarnation: "i-" + n})
		}
		return out
	}
	prev := &VoterConfig{VoterConfigValue: VoterConfigValue{Generation: 3, Members: m("a", "b", "c")}}
	for _, tc := range []struct {
		name string
		prev *VoterConfig
		next VoterConfigValue
		ok   bool
	}{
		{"genesis", nil, VoterConfigValue{Generation: 1, Members: m("a"), Change: VoterChangeGenesis}, true},
		{"empty genesis", nil, VoterConfigValue{Generation: 1, Change: VoterChangeGenesis}, false},
		{"add", prev, VoterConfigValue{Generation: 4, Members: m("a", "b", "c", "d"), Change: VoterChangeAdd("d")}, true},
		{"rm", prev, VoterConfigValue{Generation: 4, Members: m("a", "b"), Change: VoterChangeRm("c")}, true},
		{"rm mislabelled", prev, VoterConfigValue{Generation: 4, Members: m("a", "b"), Change: VoterChangeRm("b")}, false},
		{"two at once", prev, VoterConfigValue{Generation: 4, Members: m("a"), Change: VoterChangeRm("b")}, false},
		{"skips a generation", prev, VoterConfigValue{Generation: 5, Members: m("a", "b"), Change: VoterChangeRm("c")}, false},
		{"reset", prev, VoterConfigValue{Generation: 4, Change: VoterChangeReset}, true},
		{"reset with members", prev, VoterConfigValue{Generation: 4, Members: m("a"), Change: VoterChangeReset}, false},
		{"genesis over members", prev, VoterConfigValue{Generation: 4, Members: m("a", "b", "c"), Change: VoterChangeGenesis}, false},
	} {
		err := ValidateVoterChange(tc.prev, tc.next)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

// TestVoterSet_ReadsAdoptedConfig: once a member generation is adopted, the
// voter set is its members whatever host state says, and a reset derives it
// again (§4.5).
//
// Mutation: make VoterSet ignore the adopted config — the fenced member drops
// out and the test goes red.
func TestVoterSet_ReadsAdoptedConfig(t *testing.T) {
	ctx := context.Background()
	ca := newClaimTestCA(t)
	a := newClaimTestVoter(t, ca, "a")
	for _, h := range []string{"a", "b", "c"} {
		if err := InsertHost(ctx, a.c, HostRecord{Name: h, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := UpdateHostState(ctx, a.c, "c", "fenced"); err != nil {
		t.Fatal(err)
	}
	vs, _ := VoterSet(ctx, a.c)
	if len(vs) != 2 || vs["c"] {
		t.Fatalf("before any generation the set is derived: %v", vs)
	}
	members := []VoterMember{{Name: "a", Incarnation: a.inc}, {Name: "b", Incarnation: "x"}, {Name: "c", Incarnation: "y"}}
	adoptHandBuilt(t, 1, members, a)
	vs, _ = VoterSet(ctx, a.c)
	if len(vs) != 3 || !vs["c"] {
		t.Fatalf("a fenced member must still count once a generation is adopted: %v", vs)
	}
	reset := VoterConfigValue{Generation: 2, Change: VoterChangeReset, CreatedBy: "a", CreatedAt: "t"}
	if err := WriteVoterConfig(ctx, a.c, reset, ClaimCertificate{}); err != nil {
		t.Fatal(err)
	}
	if err := RecordVoterAdoption(ctx, a.c, 2); err != nil {
		t.Fatal(err)
	}
	vs, _ = VoterSet(ctx, a.c)
	if len(vs) != 2 || vs["c"] {
		t.Fatalf("after a reset the set is derived again: %v", vs)
	}
}

func copyTestFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600)
}

// signRaw signs a digest with s's key, for forging accepts in tests.
func signRaw(s *ClaimSigner, digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.key, digest)
}
