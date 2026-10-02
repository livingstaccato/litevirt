package failover

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// fakeClaimer decides every claim the way decide says, recording each call.
type fakeClaimer struct {
	mu           sync.Mutex
	calls        []corrosion.ClaimKey
	evidence     []*corrosion.SupersedeEvidence
	abandonAsked []string
	decide       func(key corrosion.ClaimKey, proposal corrosion.ClaimValue) (claims.Outcome, error)
	abandon      func(host string, key corrosion.ClaimKey, proofID string) (string, error)
	// foreign answers RequestForeignAbandonment; nil refuses.
	foreign func(host string, key corrosion.ClaimKey, proofID string) (string, error)
	// noted records each NoteLegacyHeld, as key/proof.
	noted []string
}

func (f *fakeClaimer) NoteLegacyHeld(_ context.Context, key corrosion.ClaimKey, v corrosion.ClaimValue, _ string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := ""
	if v.Proof != nil {
		id = v.Proof.ID
	}
	f.noted = append(f.noted, key.String()+"/"+id)
}

var errNoAbandonment = errors.New("the destination refused to abandon")

func (f *fakeClaimer) DecideRecoveryClaim(_ context.Context, key corrosion.ClaimKey, proposal corrosion.ClaimValue, _ uint64, ev *corrosion.SupersedeEvidence) (claims.Outcome, error) {
	f.mu.Lock()
	f.calls = append(f.calls, key)
	f.evidence = append(f.evidence, ev)
	f.mu.Unlock()
	return f.decide(key, proposal)
}

func (f *fakeClaimer) RequestAbandonment(_ context.Context, host string, key corrosion.ClaimKey, proofID, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.abandonAsked = append(f.abandonAsked, host+"/"+proofID)
	if f.abandon != nil {
		return f.abandon(host, key, proofID)
	}
	return "", errNoAbandonment
}

func (f *fakeClaimer) RequestForeignAbandonment(_ context.Context, host string, key corrosion.ClaimKey, proofID, _ string) (string, error) {
	if f.foreign != nil {
		return f.foreign(host, key, proofID)
	}
	return "", errNoAbandonment
}

// ClaimKeyFor scopes every key to the incarnation, as a node on which
// claim_incarnation_v1 has latched does.
func (f *fakeClaimer) ClaimKeyFor(_ context.Context, kind, name string, epoch int64, incarnation string) corrosion.ClaimKey {
	return corrosion.ClaimKey{TargetKind: kind, TargetName: name, OwnerEpoch: epoch, Incarnation: incarnation}
}

// decideOurs certifies whatever is proposed.
func decideOurs(key corrosion.ClaimKey, v corrosion.ClaimValue) (claims.Outcome, error) {
	d := v.MustDigest()
	return claims.Outcome{Value: v, Digest: d, Ours: true, Certificate: corrosion.ClaimCertificate{
		Key: key, ConfigGeneration: 1, Ballot: corrosion.Ballot{Round: 1, Coordinator: "coord"},
		ValueDigest: d, SourceHost: v.SourceHost}}, nil
}

// decideTheirs certifies another coordinator's reschedule of the VM to dest.
func decideTheirs(action, dest string) func(corrosion.ClaimKey, corrosion.ClaimValue) (claims.Outcome, error) {
	return func(key corrosion.ClaimKey, v corrosion.ClaimValue) (claims.Outcome, error) {
		p := *v.Proof
		p.ID, p.Action, p.DestHost, p.Coordinator = "their-proof", action, dest, "other-coord"
		p.LeaseHolder, p.LeaseExpiresAt, p.QuorumLive, p.QuorumNeeded = "", "", 0, 0
		theirs := corrosion.ClaimValue{Proof: &p, SourceHost: v.SourceHost}
		out, err := decideOurs(key, theirs)
		out.Ours = false
		return out, err
	}
}

// claimFixture is a fenced host "dead" holding vm1 and ct1, a survivor "live"
// both coordinators could place on, and a coordinator with claims enforced.
func claimFixture(t *testing.T, cl *fakeClaimer) (*corrosion.Client, *Coordinator) {
	t.Helper()
	ctx := context.Background()
	db := newTestDB(t)
	db.SetRecoveryClaimGate(func() bool { return true })
	for _, h := range []string{"dead", "live", "other"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "dead", State: "running", Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 4 WHERE name = 'vm1'`); err != nil {
		t.Fatal(err)
	}
	fenceQuorum(t, ctx, db, []string{"coord", "live", "other"}, "dead")
	c := newTestCoordinator("coord", db)
	c.Gate = fakeFailoverGate{
		supports: map[string]bool{"live": true, "other": true},
		enforced: map[string]bool{capabilities.SplitBrainGateV1: true},
	}
	c.Claimer = cl
	c.RecoveryClaimEnforced = func(context.Context) bool { return true }
	return db, c
}

func vmProofs(t *testing.T, db *corrosion.Client) []corrosion.ProofRecord {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT id FROM runtime_action_proofs WHERE target_name = 'vm1'`)
	if err != nil {
		t.Fatal(err)
	}
	var out []corrosion.ProofRecord
	for _, r := range rows {
		pr, _, err := corrosion.GetActionProof(context.Background(), db, r.String("id"))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, pr)
	}
	return out
}

// TestReschedule_ClaimsBeforeItMints: under recovery_claim_v1 the reschedule
// proof is written only once a claim for it is decided, and it carries the
// certificate that decided it (docs/design/recovery-claims.md §3.13).
//
// Mutation: skip claimRecovery in the reschedule branch — the proof is
// written with no certificate and no claim was made.
func TestReschedule_ClaimsBeforeItMints(t *testing.T) {
	cl := &fakeClaimer{decide: decideOurs}
	db, c := claimFixture(t, cl)
	c.run(context.Background())

	vm, err := corrosion.GetVM(context.Background(), db, "vm1")
	if err != nil || vm == nil || vm.CreatedAt == "" {
		t.Fatalf("read vm1: %v %+v", err, vm)
	}
	// Scoped to the row's incarnation (docs/design/recovery-claims.md §10
	// item 37): the fake claimer stands in for a node where
	// claim_incarnation_v1 has latched.
	want := corrosion.ClaimKey{TargetKind: "vm", TargetName: "vm1", OwnerEpoch: 4, Incarnation: vm.CreatedAt}
	if len(cl.calls) == 0 || cl.calls[0] != want {
		t.Fatalf("the reschedule was not claimed at %s: %v", want, cl.calls)
	}
	ps := vmProofs(t, db)
	if len(ps) != 1 || ps[0].ClaimCertificate == "" {
		t.Fatalf("want one certified reschedule proof, got %+v", ps)
	}
	if _, err := corrosion.CertificateAuthorizesProof(ps[0].ClaimCertificate, ps[0].ActionProof); err != nil {
		t.Fatalf("the stored certificate does not certify the stored proof: %v", err)
	}
}

// TestReschedule_RefusedClaimMintsNothing: a claim that forms no certificate
// writes no proof and no pending row, and marks the host for a retry on the
// next tick — never an uncertified fallback (§3.13 step 6).
//
// Mutation: on a refused claim, fall through to WriteVMRescheduleProof — an
// uncertified proof and a pending row appear.
func TestReschedule_RefusedClaimMintsNothing(t *testing.T) {
	cl := &fakeClaimer{decide: func(corrosion.ClaimKey, corrosion.ClaimValue) (claims.Outcome, error) {
		return claims.Outcome{}, &claims.NoMajorityError{Phase: "accept", Got: 1, Need: 2,
			Refusals: []claims.Refusal{{Voter: "live", Reason: corrosion.RefusalOwnerReachable, Detail: "live still reaches dead"}}}
	}}
	db, c := claimFixture(t, cl)
	var refused []string
	c.SetGateRefusedObserver(func(_, reason string) { refused = append(refused, reason) })
	c.run(context.Background())

	if ps := vmProofs(t, db); len(ps) != 0 {
		t.Fatalf("a refused claim minted %d proof(s): %+v", len(ps), ps)
	}
	if vm := mustVM(t, db, "vm1"); vm.HostName != "dead" || vm.PendingActionID != "" {
		t.Fatalf("a refused claim moved the VM: host=%s pending=%q", vm.HostName, vm.PendingActionID)
	}
	if !c.claimRetry["dead"] {
		t.Fatal("the refused recovery is not marked for a retry; a fenced host is processed once")
	}
	found := false
	for _, r := range refused {
		found = found || r == "recovery_claim_owner_reachable"
	}
	if !found {
		t.Fatalf("the owner-probe refusal was not counted under its reason: %v", refused)
	}
}

// TestReschedule_LoserWritesTheWinnersProof: when another coordinator's value
// was decided, this one writes THAT proof — its ID and destination — and
// nothing naming its own choice (§3.13 step 5).
//
// Mutation: write our own proposal after a lost claim — the proof names our
// destination.
func TestReschedule_LoserWritesTheWinnersProof(t *testing.T) {
	cl := &fakeClaimer{decide: decideTheirs(corrosion.ActionReschedule, "other")}
	db, c := claimFixture(t, cl)
	c.run(context.Background())

	ps := vmProofs(t, db)
	if len(ps) != 1 || ps[0].ID != "their-proof" || ps[0].DestHost != "other" || ps[0].Coordinator != "other-coord" {
		t.Fatalf("the loser did not re-materialize the decided proof: %+v", ps)
	}
	if vm := mustVM(t, db, "vm1"); vm.HostName != "other" || vm.PendingActionID != "their-proof" {
		t.Fatalf("the VM is not pending on the decided destination: host=%s pending=%q", vm.HostName, vm.PendingActionID)
	}
}

// TestReschedule_AdoptedSpentDecisionReassertsLegacyHeld: a decided value at
// an incarnation-scoped key whose proof has already run is refused — never
// written — and every refusal re-asserts ha.claim.legacy_held
// (RecoveryClaimer.NoteLegacyHeld). The bridge that first raised it never
// runs again for the key once the key has decided, so a raise whose write
// failed is retried only from here; without it the refusal loop runs
// silently.
//
// Mutation: drop the NoteLegacyHeld call from claimRecovery's refusal — no
// tick re-asserts the condition.
func TestReschedule_AdoptedSpentDecisionReassertsLegacyHeld(t *testing.T) {
	ctx := context.Background()
	cl := &fakeClaimer{decide: decideTheirs(corrosion.ActionReschedule, "other")}
	db, c := claimFixture(t, cl)
	spent := corrosion.ActionProof{ID: "their-proof", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "other", Coordinator: "other-coord", OwnerEpoch: "4"}
	if err := corrosion.WriteActionProof(ctx, db, spent); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.ClaimActionProof(ctx, db, spent.ID, "other"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.CompleteActionProof(ctx, db, spent.ID, "other"); err != nil {
		t.Fatal(err)
	}
	c.run(ctx)
	c.run(ctx)
	if vm := mustVM(t, db, "vm1"); vm.PendingActionID != "" || vm.HostName != "dead" {
		t.Fatalf("the VM was pointed at a spent decision: host=%s pending=%q", vm.HostName, vm.PendingActionID)
	}
	cl.mu.Lock()
	defer cl.mu.Unlock()
	n := 0
	for _, s := range cl.noted {
		if strings.HasSuffix(s, "/their-proof") {
			n++
		}
	}
	if n < 2 {
		t.Fatalf("ha.claim.legacy_held was re-asserted %d time(s) over two refusing ticks, want one per tick: %v", n, cl.noted)
	}
}

// TestReschedule_DecidedPromoteIsNotRescheduled: a decided value that is
// another coordinator's PROMOTE is not written as a reschedule; nothing is
// minted and the recovery is retried.
//
// Mutation: drop the action check after the claim — a promote proof is
// linked to the VM as a pending reschedule.
func TestReschedule_DecidedPromoteIsNotRescheduled(t *testing.T) {
	cl := &fakeClaimer{decide: decideTheirs(corrosion.ActionPromote, "other")}
	db, c := claimFixture(t, cl)
	c.run(context.Background())
	if vm := mustVM(t, db, "vm1"); vm.PendingActionID != "" || vm.HostName != "dead" {
		t.Fatalf("a decided promote was acted on as a reschedule: host=%s pending=%q", vm.HostName, vm.PendingActionID)
	}
	if !c.claimRetry["dead"] {
		t.Fatal("the deferred recovery is not retried")
	}
}

// TestImageRecreate_ClaimsBeforeItMints: a failover container relocation is
// claimed, and the re-keyed row carries the DECIDED token and destination.
//
// Mutation: skip claimContainerRelocation in imageRecreateOrSkip — the proof
// has no certificate.
func TestImageRecreate_ClaimsBeforeItMints(t *testing.T) {
	ctx := context.Background()
	cl := &fakeClaimer{decide: decideTheirs(corrosion.ActionRelocate, "other")}
	db, c := claimFixture(t, cl)
	if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
		HostName: "dead", Name: "ct1", State: "running", Image: "alpine:3.19", OnHostFailure: "image-recreate",
	}); err != nil {
		t.Fatal(err)
	}
	ct, _ := corrosion.GetContainer(ctx, db, "dead", "ct1")
	// First sight of another coordinator's decision: write it, act on nothing.
	c.imageRecreateOrSkip(ctx, &corrosion.HostRecord{Name: "dead"}, *ct, "live", nil)
	if moved, _ := corrosion.GetContainer(ctx, db, "other", "ct1"); moved != nil {
		t.Fatal("the loser carried out another coordinator's fresh decision instead of deferring to it")
	}
	pr, ok, err := corrosion.GetActionProof(ctx, db, "their-proof")
	if err != nil || !ok || pr.ClaimCertificate == "" {
		t.Fatalf("the decided relocation proof was not written with its certificate: ok=%v err=%v", ok, err)
	}

	// Ours: the re-keyed row carries our decided token.
	cl.decide = decideOurs
	c.imageRecreateOrSkip(ctx, &corrosion.HostRecord{Name: "dead"}, *ct, "live", nil)
	moved, _ := corrosion.GetContainer(ctx, db, "live", "ct1")
	if moved == nil || moved.RelocateToken == "" {
		t.Fatalf("the claimed relocation did not re-key the row: %+v", moved)
	}
	own, ok, _ := corrosion.GetActionProofByToken(ctx, db, moved.RelocateToken)
	if !ok || own.ClaimCertificate == "" || own.DestHost != "live" {
		t.Fatalf("the re-keyed row's token names no certified proof to live: %+v", own)
	}
}

// TestClaimMetrics_PhaseClaimResults: every claim outcome is counted on the
// existing attempt triple under PhaseClaim (§5.4) — ok, lost, owner_reachable,
// no_majority and superseded — so a stuck recovery is visible on
// litevirt_failover_attempts_total with no new series.
//
// Mutation: drop the mAttempt call in claimAttempt — no PhaseClaim sample is
// recorded.
func TestClaimMetrics_PhaseClaimResults(t *testing.T) {
	for _, tc := range []struct {
		name   string
		decide func(corrosion.ClaimKey, corrosion.ClaimValue) (claims.Outcome, error)
		want   string
	}{
		{"ok", decideOurs, ResultOK},
		{"lost", decideTheirs(corrosion.ActionReschedule, "other"), ResultLost},
		{"owner reachable", func(corrosion.ClaimKey, corrosion.ClaimValue) (claims.Outcome, error) {
			return claims.Outcome{}, &claims.NoMajorityError{Phase: "accept", Refusals: []claims.Refusal{
				{Voter: "live", Reason: corrosion.RefusalOwnerReachable, Detail: "live still reaches dead"}}}
		}, ResultOwnerReachable},
		{"no majority", func(corrosion.ClaimKey, corrosion.ClaimValue) (claims.Outcome, error) {
			return claims.Outcome{}, &claims.NoMajorityError{Phase: "prepare", Refusals: []claims.Refusal{
				{Voter: "live", Reason: claims.ReasonUnreachable}}}
		}, ResultNoMajority},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, c := claimFixture(t, &fakeClaimer{decide: tc.decide})
			m := newFakeMetrics()
			c.Metrics = m
			c.run(context.Background())
			if m.attempts[foKey(PhaseClaim, tc.want, "")] == 0 {
				t.Fatalf("no %s/%s sample; attempts=%v", PhaseClaim, tc.want, m.attempts)
			}
		})
	}
}

// TestClaimMetrics_Superseded: a decided promote of this coordinator's own,
// abandoned by its destination, moves the claim to attempt 1 and is counted
// as superseded; the reschedule is then minted at attempt 1.
//
// Mutation: drop the superseded sample in claimRecovery.
func TestClaimMetrics_Superseded(t *testing.T) {
	cl := &fakeClaimer{}
	cl.decide = func(key corrosion.ClaimKey, v corrosion.ClaimValue) (claims.Outcome, error) {
		if key.Attempt == 0 {
			p := *v.Proof
			p.ID, p.Action, p.DestHost = "own-promote", corrosion.ActionPromote, "other"
			out, err := decideOurs(key, corrosion.ClaimValue{Proof: &p, SourceHost: v.SourceHost})
			out.Ours = false
			return out, err
		}
		return decideOurs(key, v)
	}
	cl.abandon = func(string, corrosion.ClaimKey, string) (string, error) { return `{"host":"other"}`, nil }
	db, c := claimFixture(t, cl)
	m := newFakeMetrics()
	c.Metrics = m
	c.run(context.Background())
	if m.attempts[foKey(PhaseClaim, ResultSuperseded, "")] == 0 {
		t.Fatalf("no superseded sample; attempts=%v", m.attempts)
	}
	if len(cl.abandonAsked) != 1 || cl.abandonAsked[0] != "other/own-promote" {
		t.Fatalf("the abandonment was not asked of the promote's destination: %v", cl.abandonAsked)
	}
	ps := vmProofs(t, db)
	if len(ps) != 1 {
		t.Fatalf("want one reschedule proof after the supersede, got %+v", ps)
	}
	cert, err := corrosion.DecodeClaimCertificate(ps[0].ClaimCertificate)
	if err != nil || cert.Key.Attempt != 1 {
		t.Fatalf("the reschedule was not decided at attempt 1: %+v %v", cert.Key, err)
	}
}

// uncertifiedReschedule writes, as a coordinator did before recovery claims
// were enforced, a reschedule of vm1 (owner epoch 4) to live with no
// certificate; fenceEpoch is its fence binding.
func uncertifiedReschedule(t *testing.T, db *corrosion.Client, fenceEpoch string) corrosion.ActionProof {
	t.Helper()
	p := corrosion.ActionProof{ID: "pre-latch", Action: corrosion.ActionReschedule, TargetKind: "vm", TargetName: "vm1",
		DestHost: "live", Coordinator: "coord", OwnerEpoch: "4", FenceEpoch: fenceEpoch}
	if err := corrosion.WriteVMRescheduleProof(context.Background(), db, p, "vm1", "live"); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCertifyUncertified_LostKeepsTheDecidedValue: a proof minted before
// recovery claims were enforced is claimed for its own value; when another
// value was already decided for the key, that value is written in its place
// (recovery_claim_lost) and the uncertified proof never gains a certificate.
//
// Mutation: drop the WriteVMRescheduleProof in certifyUncertified's lost
// branch — vm1 still points at the proof nothing will ever execute.
func TestCertifyUncertified_LostKeepsTheDecidedValue(t *testing.T) {
	ctx := context.Background()
	cl := &fakeClaimer{decide: decideTheirs(corrosion.ActionReschedule, "other")}
	db, c := claimFixture(t, cl)
	p := uncertifiedReschedule(t, db, "host=dead;fence_id=f1;ts=2026-01-01T00:00:00Z")
	c.certifyUncertified(ctx)
	if len(cl.calls) != 1 || cl.calls[0].Attempt != 0 || cl.calls[0].OwnerEpoch != 4 {
		t.Fatalf("want one claim at attempt 0 for owner epoch 4, got %v", cl.calls)
	}
	if vm := mustVM(t, db, "vm1"); vm.PendingActionID != "their-proof" || vm.HostName != "other" {
		t.Fatalf("the decided value was not written in place of the uncertified one: %+v", vm)
	}
	if got, _, _ := corrosion.GetActionProof(ctx, db, p.ID); got.ClaimCertificate != "" {
		t.Fatal("the losing uncertified proof gained a certificate")
	}
}

// TestCertifyUncertified_NoFenceBindingNoClaim: a proof that binds no
// proof-grade fence names no old owner for the voters to probe, so no claim
// is made for it — its source is never guessed — and it stays uncertified
// (ha.claim.uncertified reports it).
//
// Mutation: claim with an empty source when the proof binds no fence — the
// claimer is called.
func TestCertifyUncertified_NoFenceBindingNoClaim(t *testing.T) {
	ctx := context.Background()
	cl := &fakeClaimer{decide: decideOurs}
	db, c := claimFixture(t, cl)
	p := uncertifiedReschedule(t, db, "")
	c.certifyUncertified(ctx)
	if len(cl.calls) != 0 {
		t.Fatalf("a claim was made for a proof with no fenced old owner: %v", cl.calls)
	}
	if got, _, _ := corrosion.GetActionProof(ctx, db, p.ID); got.ClaimCertificate != "" {
		t.Fatal("a proof with no source gained a certificate")
	}
}

func mustVM(t *testing.T, db *corrosion.Client, name string) *corrosion.VMRecord {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), db, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM %s: %v", name, err)
	}
	return vm
}
