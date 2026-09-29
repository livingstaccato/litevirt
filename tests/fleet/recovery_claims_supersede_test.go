// Fleet scenarios: attempt progression and supersede
// (docs/design/recovery-claims.md §3.12, §7.1 "Promote→reschedule fallback",
// "Dead destinations and dead voters").
//
// A claim key's attempt moves on only past a decided value whose destination
// provably will never execute it: the destination's signed abandonment of a
// proof it never started, or its permanent removal — fenced proof-grade, no
// longer a member, revoked — which `lv host rm --dead` produces in one command.
// Every voter checks the evidence in its own replica before it promises.
package fleet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// decidePromote decides a claim at (vm, 0, 0) for a promote of vm to dest, by
// coordinator by, the way Server.claimPromote does before relaying.
func decidePromote(t *testing.T, by *Node, vm, dest, source string) corrosion.ActionProof {
	t.Helper()
	p := corrosion.ActionProof{ID: "promote-" + vm, Action: corrosion.ActionPromote, TargetKind: "vm", TargetName: vm,
		DestHost: dest, Coordinator: by.Name, OwnerEpoch: "0"}
	key := corrosion.ClaimKey{TargetKind: "vm", TargetName: vm}
	out, err := by.Server.DecideRecoveryClaim(context.Background(), key, corrosion.ClaimValue{Proof: &p, SourceHost: source}, 1, nil)
	if err != nil || !out.Ours {
		t.Fatalf("decide the promote: ours=%v err=%v", out.Ours, err)
	}
	return p
}

func pendingCert(t *testing.T, n *Node, vm string) (corrosion.ProofRecord, corrosion.ClaimCertificate) {
	t.Helper()
	row := vmOn(t, n, vm)
	if row.PendingActionID == "" {
		t.Fatalf("%s: %s is not pending anywhere: %+v", n.Name, vm, row)
	}
	pr, ok, err := corrosion.GetActionProof(context.Background(), n.DB, row.PendingActionID)
	if err != nil || !ok {
		t.Fatalf("%s: read proof %s: ok=%v err=%v", n.Name, row.PendingActionID, ok, err)
	}
	cert, err := corrosion.DecodeClaimCertificate(pr.ClaimCertificate)
	if err != nil {
		t.Fatalf("%s: the pending proof's certificate: %v", n.Name, err)
	}
	return pr, cert
}

// TestFleet_RecoveryClaim_PromoteFallbackAbandonsAndMovesOn: this coordinator's
// promote was decided and failed before StartDomain; it falls back to a
// reschedule, whose claim finds the key decided — for the promote. The promote's
// destination signs that it never started it, the claim moves to attempt 1 on
// that evidence, and the reschedule recovers the VM with one owner. The
// destination refuses the abandoned promote forever.
func TestFleet_RecoveryClaim_PromoteFallbackAbandonsAndMovesOn(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, victim := claimFleet(t, clock, 2521, "vm-p")
	promote := decidePromote(t, a, "vm-p", b.Name, victim.Name)

	cs := c.NewCoordinators(clock)
	cs.ByNode[a.Name].Gate = quorateGate{}
	cs.Tick(ctx, a)

	pr, cert := pendingCert(t, a, "vm-p")
	if cert.Key.Attempt != 1 || pr.Action != corrosion.ActionReschedule {
		t.Fatalf("the fallback reschedule was decided at attempt %d (%s), want a reschedule at attempt 1",
			cert.Key.Attempt, pr.Action)
	}
	if abandoned, err := b.DB.ProofAbandoned(ctx, promote.ID); err != nil || !abandoned {
		t.Fatalf("%s did not record its abandonment of the promote: %v %v", b.Name, abandoned, err)
	}
	if err := corrosion.WriteActionProof(ctx, b.DB, promote); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.ClaimActionProof(ctx, b.DB, promote.ID, b.Name); !errors.Is(err, corrosion.ErrProofAbandoned) {
		t.Fatalf("%s claimed the promote it abandoned: %v", b.Name, err)
	}
	dest := c.Node(pr.DestHost)
	c.WaitConverged(t, convergeTimeout, a, b)
	claimReconciler(t, dest).ReconcileOnce(ctx)
	owners := 0
	for _, n := range []*Node{a, b} {
		if st, _ := n.Virt.DomainState("vm-p"); st == string(libvirtfake.StateRunning) {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("%d owners after the superseded promote, want 1", owners)
	}
}

// TestFleet_RecoveryClaim_AStartedPromoteIsNeverAbandoned: when the decided
// promote's destination has recorded its start checkpoint it may be running
// the VM, so it refuses to abandon it, and the fallback reschedule stays
// behind the decided promote — a second owner is exactly what the refusal
// prevents.
//
// Mutation: let AbandonProof ignore the start checkpoint (return the
// abandonment after StartDomain) — the destination abandons, the claim moves
// on, and the VM is rescheduled while the promote may be running.
func TestFleet_RecoveryClaim_AStartedPromoteIsNeverAbandoned(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, victim := claimFleet(t, clock, 2522, "vm-s")
	promote := decidePromote(t, a, "vm-s", b.Name, victim.Name)
	// b took the promote and reached StartDomain before the coordinator lost
	// track of it.
	if err := corrosion.WriteActionProof(ctx, b.DB, promote); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.ClaimActionProof(ctx, b.DB, promote.ID, b.Name); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.AppendProofStepUnlessAbandoned(ctx, b.DB, promote.ID, "start_attempted"); err != nil {
		t.Fatal(err)
	}

	cs := c.NewCoordinators(clock)
	cs.ByNode[a.Name].Gate = quorateGate{}
	cs.Tick(ctx, a)

	if vm := vmOn(t, a, "vm-s"); vm.PendingActionID != "" || vm.HostName != victim.Name {
		t.Fatalf("the VM was rescheduled past a promote that may be running: %+v", vm)
	}
	if abandoned, _ := b.DB.ProofAbandoned(ctx, promote.ID); abandoned {
		t.Fatalf("%s abandoned a promote it had started", b.Name)
	}
}

// deadFleet is five hosts: a, b, e survive, v owned vm-dead and has failed, and
// d is where the recovery was decided — then d died before its reconciler ran.
// Generation 1 is all five. Returns once a's coordinator has fenced d and found
// the recovery stranded on it.
func deadFleet(t *testing.T, seed int64) (c *Cluster, a, b, e, v, d *Node, cs *Coordinators, clock *VirtualClock) {
	t.Helper()
	ctx := context.Background()
	c = New(t, Options{Nodes: 5, IndependentReplicas: true, FaultSeed: seed})
	a, b, e, v, d = c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3], c.Nodes[4]
	insertVM(t, a, "vm-dead", v.Name)
	c.WaitConverged(t, convergeTimeout)
	genesisByTick(t, c, a)
	enableRecoveryClaims(t, c)

	// v fails; its recovery is decided for d and written.
	c.Kill(v)
	key := corrosion.ClaimKey{TargetKind: "vm", TargetName: "vm-dead"}
	p := corrosion.ActionProof{ID: "resched-to-d", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm-dead", DestHost: d.Name, Coordinator: a.Name, OwnerEpoch: "0"}
	out, err := a.Server.DecideRecoveryClaim(ctx, key, corrosion.ClaimValue{Proof: &p, SourceHost: v.Name}, 1, nil)
	if err != nil {
		t.Fatalf("decide the recovery for %s: %v", d.Name, err)
	}
	p.ClaimCertificate, _ = out.Certificate.Encode()
	if err := corrosion.WriteVMRescheduleProof(ctx, a.DB, p, "vm-dead", d.Name); err != nil {
		t.Fatalf("write the decided proof: %v", err)
	}
	c.WaitConverged(t, convergeTimeout, a, b, e, d)
	// ...and d dies before it acts.
	c.Kill(d)
	clock = NewVirtualClock(time.Now().UTC())
	for _, n := range []*Node{a, b, e} {
		PublishHealth(t, n, d.Name, 5, clock.Now())
	}
	c.WaitConverged(t, convergeTimeout, a, b, e)
	cs = c.NewCoordinators(clock)
	cs.ByNode[a.Name].Gate = quorateGate{}
	cs.Tick(ctx, a) // fences d; the recovery is decided for d: stranded
	clock.Advance(contentionPoll)
	cs.Tick(ctx, a) // the stranded condition sees d fenced
	return
}

// withOperatorPKI points the CLI at a CA-holding PKI directory, as `lv` on the
// machine that ran `lv host init` has.
func withOperatorPKI(t *testing.T, n *Node) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Symlink(n.PKIDir, filepath.Join(dir, "pki")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LV_CONFIG_DIR", dir)
}

// syncCRL installs the published CRL on each node, as its 30 s loop does.
func syncCRL(t *testing.T, nodes ...*Node) {
	t.Helper()
	for _, n := range nodes {
		if _, err := corrosion.SyncClusterCRL(context.Background(), n.DB, n.PKIDir); err != nil {
			t.Fatalf("%s: SyncClusterCRL: %v", n.Name, err)
		}
	}
}

// TestFleet_RecoveryClaim_HostRmDeadSupersedesAStrandedRecovery: a recovery
// decided for d, and d destroyed before it acted. ha.claim.stranded names the
// workload and the command. `lv host rm --dead d` refuses while d has no
// proof-grade fence; --dry-run then reports one stranded recovery and changes
// nothing; the real run removes d from the voter set, removes the host and
// publishes the CRL. The voters refuse the supersede until the revocation has
// reached them, and then the next tick recovers the VM at attempt 1 with one
// owner.
//
// Mutation: skip the revocation check in the voters' supersede verification
// (RemovedHostEvidence) — the supersede succeeds before the CRL lands.
func TestFleet_RecoveryClaim_HostRmDeadSupersedesAStrandedRecovery(t *testing.T) {
	ctx := context.Background()
	c, a, b, e, _, d, cs, clock := deadFleet(t, 2523)

	cond, found, err := corrosion.GetHealthCondition(ctx, a.DB, "recovery_claim", "ha.claim.stranded", "cluster", "claims")
	if err != nil || !found || cond.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("ha.claim.stranded is not raised: %+v found=%v err=%v", cond, found, err)
	}
	if !strings.Contains(cond.Evidence, "vm/vm-dead") || !strings.Contains(cond.Evidence, "lv host rm --dead "+d.Name) {
		t.Fatalf("the stranded condition does not name the workload and the command: %s", cond.Evidence)
	}
	if vm := vmOn(t, a, "vm-dead"); vm.HostName != d.Name {
		t.Fatalf("the stranded VM moved before d was removed: %+v", vm)
	}
	withOperatorPKI(t, a)
	lv := c.SelfClient(a)
	if err := cli.HostRemoveDead(ctx, lv, d.Name, false); err == nil || !strings.Contains(err.Error(), "lv host fence-confirm "+d.Name) {
		t.Fatalf("--dead without a proof-grade fence was not refused with the fence command: %v", err)
	}
	if err := corrosion.InsertFenceLog(ctx, a.DB, corrosion.FenceLogRecord{ID: "confirm-" + d.Name, HostName: d.Name,
		Method: "manual", Result: "manual-confirmed", Detail: "operator powered it off"}); err != nil {
		t.Fatal(err)
	}
	plan, err := lv.PlanDeadHostRemoval(ctx, &pb.PlanDeadHostRemovalRequest{Name: d.Name})
	if err != nil || !plan.GetFenced() || !plan.GetVoter() {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	retry := 0
	for _, s := range plan.GetStranded() {
		if s.GetNextAttempt() == 1 && s.GetName() == "vm-dead" {
			retry++
		}
	}
	if retry != 1 {
		t.Fatalf("--dry-run's plan does not report the one stranded recovery: %+v", plan.GetStranded())
	}
	if err := cli.HostRemoveDead(ctx, lv, d.Name, true); err != nil {
		t.Fatalf("--dry-run: %v", err)
	}
	if h, _ := corrosion.GetHost(ctx, a.DB, d.Name); h == nil {
		t.Fatal("--dry-run removed the host")
	}
	if adoptedGen(t, a) != 1 {
		t.Fatal("--dry-run changed the voter set")
	}

	if err := cli.HostRemoveDead(ctx, lv, d.Name, false); err != nil {
		t.Fatalf("lv host rm --dead %s: %v", d.Name, err)
	}
	adoptAll(t, c, 2, a, b, e)
	c.WaitConverged(t, convergeTimeout, a, b, e)

	// The CRL has replicated but no voter has installed it yet: the supersede
	// must wait for the revocation, not merely for the removal.
	clock.Advance(contentionPoll)
	cs.Tick(ctx, a)
	if vm := vmOn(t, a, "vm-dead"); vm.HostName == d.Name && vm.PendingActionID != "resched-to-d" {
		t.Fatalf("unexpected row: %+v", vm)
	} else if vm.HostName != d.Name {
		t.Fatalf("the recovery was superseded before the voters held %s's revocation: %+v", d.Name, vm)
	}

	syncCRL(t, a, b, e)
	clock.Advance(contentionPoll)
	cs.Tick(ctx, a)
	pr, cert := pendingCert(t, a, "vm-dead")
	if cert.Key.Attempt != 1 || pr.DestHost == d.Name {
		t.Fatalf("the stranded recovery did not supersede to attempt 1 on a live host: attempt %d dest %s",
			cert.Key.Attempt, pr.DestHost)
	}
	dest := c.Node(pr.DestHost)
	c.WaitConverged(t, convergeTimeout, a, b, e)
	claimReconciler(t, dest).ReconcileOnce(ctx)
	owners := 0
	for _, n := range []*Node{a, b, e} {
		if st, _ := n.Virt.DomainState("vm-dead"); st == string(libvirtfake.StateRunning) {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("%d owners after the supersede, want 1", owners)
	}
}
