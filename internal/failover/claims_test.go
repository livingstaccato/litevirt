package failover

import (
	"context"
	"sync"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// fakeClaimer decides every claim the way decide says, recording each call.
type fakeClaimer struct {
	mu     sync.Mutex
	calls  []corrosion.ClaimKey
	decide func(key corrosion.ClaimKey, proposal corrosion.ClaimValue) (claims.Outcome, error)
}

func (f *fakeClaimer) DecideRecoveryClaim(_ context.Context, key corrosion.ClaimKey, proposal corrosion.ClaimValue, _ uint64) (claims.Outcome, error) {
	f.mu.Lock()
	f.calls = append(f.calls, key)
	f.mu.Unlock()
	return f.decide(key, proposal)
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

	if len(cl.calls) == 0 || cl.calls[0] != (corrosion.ClaimKey{TargetKind: "vm", TargetName: "vm1", OwnerEpoch: 4}) {
		t.Fatalf("the reschedule was not claimed at (vm, vm1, 4, 0): %v", cl.calls)
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

func mustVM(t *testing.T, db *corrosion.Client, name string) *corrosion.VMRecord {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), db, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM %s: %v", name, err)
	}
	return vm
}
