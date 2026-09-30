// Fleet scenarios: forced reconfiguration of the voter set
// (docs/design/recovery-claims.md §4.6, §7.1 "lv cluster voter
// force-reconfigure" and "A forged forced row").
//
// Once a majority of a voter generation is gone for good, neither `voter rm`
// nor any recovery claim can succeed under it again. force-reconfigure is the
// audited break-glass: the survivors seal the generation, sign the next one
// unanimously, and import everything any of them accepted and every
// certificate a reachable host holds. Every node adopts the forced generation
// only after checking it for itself, including probing the hosts it names
// lost.
package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// initVoters starts generation 1 with exactly members, by hand: parked is
// held in maintenance so automatic genesis cannot run and init is allowed
// (§4.2), then returned to active. Returns once every node adopted it.
func initVoters(t *testing.T, c *Cluster, parked *Node, members ...*Node) {
	t.Helper()
	ctx := context.Background()
	openVoterConfigGates(c)
	setHostState(t, c, parked, "maintenance")
	if _, err := c.SelfClient(members[0]).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "init", Members: nodeNames(members...)}); err != nil {
		t.Fatalf("voter init: %v", err)
	}
	adoptAll(t, c, 1)
	setHostState(t, c, parked, "active")
}

// fenceConfirm is an operator's `lv host fence-confirm <host>` run on n: a
// manual-confirmed fencing_log row, and the host marked fenced.
func fenceConfirm(t *testing.T, c *Cluster, n *Node, host *Node) {
	t.Helper()
	if _, err := c.SelfClient(n).FenceHost(context.Background(),
		&pb.FenceHostRequest{Name: host.Name, Confirmed: true, ConfirmManualOnly: true}); err != nil {
		t.Fatalf("fence-confirm %s: %v", host.Name, err)
	}
}

func forceErr(t *testing.T, c *Cluster, via *Node, dry bool, lost ...*Node) (*pb.ForceReconfigureVotersResponse, error) {
	t.Helper()
	return c.SelfClient(via).ForceReconfigureVoters(context.Background(),
		&pb.ForceReconfigureVotersRequest{Lost: nodeNames(lost...), DryRun: dry})
}

// TestFleet_VoterForceReconfigure: five voters, three destroyed. It refuses
// while a named host lacks a proof-grade fence, when only two are named (a
// majority survives — `voter rm` is the change), and while a non-voter host is
// neither reachable nor fenced. With all three fenced it writes generation 2
// from the two survivors, emits the audit event and raises ha.voter.forced. A
// value accepted at generation 1 by one survivor ALONE is imported and
// re-certified at generation 2 with the same proof ID; a generation-1
// certificate held on a destination does not execute until it too is
// re-certified.
//
// Mutation: skip the forced-seal check at the destination
// (ReplacedByForcedGeneration in VerifyClaimCertificate) — the generation-1
// certificate on n1 executes straight after the force, which must fail.
func TestFleet_VoterForceReconfigure(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 6, IndependentReplicas: true, FaultSeed: 2531})
	n0, n1, n2, n3, n4, n5 := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3], c.Nodes[4], c.Nodes[5]
	insertVM(t, n0, "vm-f", n2.Name)
	insertVM(t, n0, "vm-g", n3.Name)
	c.WaitConverged(t, convergeTimeout)
	initVoters(t, c, n5, n0, n1, n2, n3, n4)
	enableRecoveryClaims(t, c, n0, n1, n2, n3, n4, n5)

	// While all five vote, a recovery of vm-g is decided at generation 1 for
	// n1 and written; its owner n3 is out of every voter's probe reach.
	for _, n := range []*Node{n0, n1, n2, n4} {
		c.SetLinkFault(n, n3, LinkFault{BlockProbe: true})
	}
	gKey := corrosion.ClaimKey{TargetKind: "vm", TargetName: "vm-g"}
	gProof := corrosion.ActionProof{ID: "g1-vm-g", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm-g", DestHost: n1.Name, Coordinator: n0.Name, OwnerEpoch: "0"}
	out, err := n0.Server.DecideRecoveryClaim(ctx, gKey, corrosion.ClaimValue{Proof: &gProof, SourceHost: n3.Name}, 1, nil)
	if err != nil {
		t.Fatalf("decide vm-g at generation 1: %v", err)
	}
	gProof.ClaimCertificate, _ = out.Certificate.Encode()
	if err := corrosion.WriteVMRescheduleProof(ctx, n0.DB, gProof, "vm-g", n1.Name); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)

	// n2, n3, n4 are destroyed. Before n2 went, one survivor (n0) alone
	// accepted a value for vm-f — no certificate anywhere.
	for _, n := range []*Node{n2, n3, n4} {
		c.Kill(n)
	}
	fKey := corrosion.ClaimKey{TargetKind: "vm", TargetName: "vm-f"}
	if resp := rogueAcceptAt(t, c, n1, n0, fKey, n2.Name, n1.Name, 1); !resp.GetAccepted() {
		t.Fatalf("n0 did not accept the lone value: %+v", resp)
	}

	// Refused: the named hosts are not fenced proof-grade.
	if _, err := forceErr(t, c, n0, false, n2, n3, n4); err == nil || !strings.Contains(err.Error(), "fence-confirm") {
		t.Fatalf("force without proof-grade fences was not refused naming the fence: %v", err)
	}
	fenceConfirm(t, c, n0, n2)
	fenceConfirm(t, c, n0, n3)
	c.WaitConverged(t, convergeTimeout, n0, n1, n5)
	// Refused: naming only two leaves three of five, a majority.
	if _, err := forceErr(t, c, n0, false, n2, n3); err == nil || !strings.Contains(err.Error(), "lv cluster voter rm") {
		t.Fatalf("force with a surviving majority was not refused naming voter rm: %v", err)
	}
	fenceConfirm(t, c, n0, n4)
	c.Kill(n5)
	c.WaitConverged(t, convergeTimeout, n0, n1)
	// Refused: n5, not a voter, is neither reachable nor fenced.
	if _, err := forceErr(t, c, n0, false, n2, n3, n4); err == nil || !strings.Contains(err.Error(), n5.Name) {
		t.Fatalf("force with a live-or-unknown host out of sight was not refused naming it: %v", err)
	}
	fenceConfirm(t, c, n0, n5)
	c.WaitConverged(t, convergeTimeout, n0, n1)

	plan, err := forceErr(t, c, n0, true, n2, n3, n4)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if plan.GetApplied() || plan.GetImportKeys() < 2 || strings.Join(plan.GetSurvivors(), ",") != n0.Name+","+n1.Name {
		t.Fatalf("dry-run plan: %+v", plan)
	}
	if row := voterRow(t, n0, 2); row != nil {
		t.Fatal("the dry run wrote a generation")
	}

	resp, err := forceErr(t, c, n0, false, n2, n3, n4)
	if err != nil {
		t.Fatalf("force-reconfigure: %v", err)
	}
	if resp.GetGeneration() != 2 || !resp.GetApplied() {
		t.Fatalf("force-reconfigure: %+v", resp)
	}
	adoptAll(t, c, 2, n0, n1)
	for _, n := range []*Node{n0, n1} {
		if got := voterNames(t, n); strings.Join(got, ",") != n0.Name+","+n1.Name {
			t.Fatalf("%s counts voters %v after the force", n.Name, got)
		}
	}
	rows, err := n0.DB.Query(ctx, `SELECT COUNT(*) AS n FROM audit_log WHERE action = 'voter.force_reconfigured'`)
	if err != nil || rows[0].Int("n") != 1 {
		t.Fatalf("the forced reconfiguration wrote no audit event: %v", err)
	}

	// A generation-1 certificate certifies nothing any more: the destination
	// refuses it until it is re-certified at generation 2.
	c.WaitConverged(t, convergeTimeout, n0, n1)
	claimReconciler(t, n1).ReconcileOnce(ctx)
	if st, _ := n1.Virt.DomainState("vm-g"); st == string(libvirtfake.StateRunning) {
		t.Fatal("a certificate from the generation the force replaced executed")
	}

	// The next step the force names: remove each lost host for good. With n2
	// removed, the lease holder's tick recovers what it held — the lost value's
	// recovery, completed with its own proof ID — re-certifies vm-g, and keeps
	// ha.voter.forced raised for the lost hosts still to remove.
	withOperatorPKI(t, n0)
	if err := cli.HostRemoveDead(ctx, c.SelfClient(n0), n2.Name, false); err != nil {
		t.Fatalf("lv host rm --dead %s: %v", n2.Name, err)
	}
	c.WaitConverged(t, convergeTimeout, n0, n1)
	cs := c.NewCoordinators(NewVirtualClock(time.Now().UTC()))
	cs.ByNode[n0.Name].Gate = quorateGate{}
	cs.Tick(ctx, n0)

	cond, found, err := corrosion.GetHealthCondition(ctx, n0.DB, "voter_config", "ha.voter.forced", "cluster", "voters")
	if err != nil || !found || cond.Lifecycle == corrosion.ConditionResolved || !strings.Contains(cond.Evidence, "lv host rm --dead") {
		t.Fatalf("ha.voter.forced is not raised naming the next step: %+v found=%v err=%v", cond, found, err)
	}
	fvm := vmOn(t, n0, "vm-f")
	if fvm.PendingActionID != "rogue-"+n2.Name {
		t.Fatalf("the value one survivor alone accepted was not the one completed: %+v", fvm)
	}
	pr, fcert := pendingCert(t, n0, "vm-f")
	if fcert.ConfigGeneration != 2 || pr.DestHost != n1.Name {
		t.Fatalf("vm-f's recovery certificate is at generation %d for %s, want 2 for %s", fcert.ConfigGeneration, pr.DestHost, n1.Name)
	}
	gpr, _, _ := corrosion.GetActionProof(ctx, n0.DB, "g1-vm-g")
	gcert, err := corrosion.DecodeClaimCertificate(gpr.ClaimCertificate)
	if err != nil || gcert.ConfigGeneration != 2 {
		t.Fatalf("vm-g's proof was not re-certified at generation 2: %+v %v", gcert, err)
	}
	c.WaitConverged(t, convergeTimeout, n0, n1)
	claimReconciler(t, n1).ReconcileOnce(ctx)
	if st, _ := n1.Virt.DomainState("vm-g"); st != string(libvirtfake.StateRunning) {
		t.Fatalf("the re-certified recovery did not start (libvirt %q)", st)
	}
}

// TestFleet_VoterForcedRowForged: a node holding one voter's key writes a
// force: row naming LIVE voters as lost, with forged fence rows. Valid
// signatures do not make a false claim of loss true: every node that reaches
// a named host refuses the row, and a named host that receives it — running,
// so not lost — refuses too.
//
// Mutation: skip the receiver-side probe in verifyForcedRow — the non-voter
// adopts the forged generation.
func TestFleet_VoterForcedRowForged(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 2532})
	n0, n1, n2, n3 := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	c.WaitConverged(t, convergeTimeout)
	initVoters(t, c, n3, n0, n1, n2)

	gen1 := voterRow(t, n0, 1)
	fenceConfirm(t, c, n0, n1)
	fenceConfirm(t, c, n0, n2)
	signer, err := corrosion.LoadClaimSigner(n0.PKIDir, n0.Name)
	if err != nil {
		t.Fatal(err)
	}
	me, _ := gen1.Member(n0.Name)
	forged := corrosion.VoterConfigValue{Generation: 2, Members: []corrosion.VoterMember{me},
		Change: corrosion.VoterChangeForce([]string{n1.Name, n2.Name}), CreatedBy: "mallory", CreatedAt: "now"}
	sig, err := signer.SignForced(1, forged, me.Incarnation)
	if err != nil {
		t.Fatal(err)
	}
	var fences []corrosion.ForcedFence
	for _, l := range []*Node{n1, n2} {
		fences = append(fences, corrosion.ForcedFence{Host: l.Name, FenceID: "confirm-" + l.Name, Method: "manual", Result: "manual-confirmed"})
	}
	if err := corrosion.WriteForcedVoterConfig(ctx, n0.DB, forged, corrosion.ForcedVoterEvidence{FromGeneration: 1,
		Lost: []string{n1.Name, n2.Name}, Fences: fences, Signatures: []corrosion.ForcedSignature{sig}}); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		_, _ = n.Server.AdoptVoterConfigs(ctx)
		if g := adoptedGen(t, n); g != 1 {
			t.Errorf("%s adopted the forged forced generation (adopted %d)", n.Name, g)
		}
	}
}
