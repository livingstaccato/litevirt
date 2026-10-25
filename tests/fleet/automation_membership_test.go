package fleet

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/automation"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// automationMembershipFixture is four nodes: voters a, b and c at generation 1
// with automation authority installed exactly as NewAutomationFixture installs
// it, and d, a host outside the voter set that has none. The cluster is
// initialized through a's engine and converged on the three voters.
type automationMembershipFixture struct {
	*AutomationFixture
	a, b, c, d *Node
}

func newAutomationMembershipFixture(t *testing.T) *automationMembershipFixture {
	t.Helper()
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 5102026})
	c.WaitConverged(t, convergeTimeout)
	a, b, cn, d := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	initVoters(t, c, d, a, b, cn)
	enableRecoveryClaims(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)
	f := &AutomationFixture{ctx: ctx, cluster: c}
	for i, n := range c.Nodes {
		if i < 3 {
			cfg, err := corrosion.AdoptedVoterConfig(ctx, n.DB)
			if err != nil {
				t.Fatal(err)
			}
			incarnation, err := n.DB.VoterIncarnation(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := localExec(ctx, n.DB, `INSERT INTO local_automation_authority (id,generation,members_hash,incarnation,bootstrap_principal,bootstrap_request,provenance) VALUES (1,?,?,?,?,?,?)`, cfg.Generation, corrosion.MembersHash(cfg.Members), incarnation, "fixture-bootstrap", "same-request", "test-only:authenticated-fleet-membership:5102026"); err != nil {
				t.Fatal(err)
			}
		}
		e, err := n.Server.AutomationEngine()
		if err != nil {
			t.Fatal(err)
		}
		f.engines = append(f.engines, e)
	}
	if _, err := f.Engine(0).Submit(ctx, f.Initialize("same-request")); err != nil {
		t.Fatal(err)
	}
	m := &automationMembershipFixture{AutomationFixture: f, a: a, b: b, c: cn, d: d}
	m.converge(t, 0, 1, 2)
	return m
}

// converge recovers the listed engines and requires equal heads on them.
func (m *automationMembershipFixture) converge(t *testing.T, nodes ...int) {
	t.Helper()
	for _, i := range nodes {
		if err := m.Engine(i).Recover(m.ctx); err != nil {
			t.Fatalf("recover %s: %v", m.cluster.Nodes[i].Name, err)
		}
	}
	want := m.Head(t, nodes[0])
	for _, i := range nodes[1:] {
		if h := m.Head(t, i); h != want {
			t.Fatalf("%s head %+v, want %+v", m.cluster.Nodes[i].Name, h, want)
		}
	}
}

// replaceC replaces voter c with d by two ordinary certified changes (add d,
// then rm c), driven through b. Generations: 2 = {a,b,c,d}, 3 = {a,b,d}.
// Every node in adopters runs its adoption pass to each generation.
func (m *automationMembershipFixture) replaceC(t *testing.T, adopters ...*Node) {
	t.Helper()
	ctx := context.Background()
	if _, err := m.cluster.SelfClient(m.b).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "add", Host: m.d.Name}); err != nil {
		t.Fatalf("voter add %s: %v", m.d.Name, err)
	}
	adoptAll(t, m.cluster, 2, adopters...)
	if _, err := m.cluster.SelfClient(m.b).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "rm", Host: m.c.Name}); err != nil {
		t.Fatalf("voter rm %s: %v", m.c.Name, err)
	}
	adoptAll(t, m.cluster, 3, adopters...)
}

// partialAccept makes a's barrier "partial" accepted at slot 2 by a and c
// only, with no certificate published: the Accept to b never arrives and c's
// reply is lost. It returns the accepted envelope as c holds it.
func (m *automationMembershipFixture) partialAccept(t *testing.T) []byte {
	t.Helper()
	m.cluster.SetClaimScript(func(msg ClaimMsg) ClaimFate {
		if msg.From != m.a.Name || msg.Method != "AcceptRecoveryClaim" {
			return ClaimDefault
		}
		switch msg.To {
		case m.b.Name:
			return ClaimDropRequest
		case m.c.Name:
			return ClaimDropReply
		}
		return ClaimDefault
	})
	_, err := m.Engine(0).Submit(m.ctx, m.Barrier(0, "partial"))
	m.cluster.SetClaimScript(nil)
	if automation.Code(err) != automation.CodeUnavailable {
		t.Fatalf("partially accepted command unexpectedly completed: %v", err)
	}
	key, _ := corrosion.AutomationClaimKey(2)
	st, ok, err := m.c.DB.ClaimState(m.ctx, key)
	if err != nil || !ok || st.Value == nil || st.Value.Automation == nil {
		t.Fatalf("c holds no accepted slot-2 value: %v", err)
	}
	if st, ok, _ := m.b.DB.ClaimState(m.ctx, key); ok && st.Value != nil {
		t.Fatal("b accepted the value: the command is not partially accepted")
	}
	return append([]byte(nil), st.Value.Automation.Envelope...)
}

func (m *automationMembershipFixture) record(t *testing.T, n *Node, seq uint64) corrosion.AutomationRecord {
	t.Helper()
	rec, ok, err := n.DB.AutomationRecord(m.ctx, seq)
	if err != nil || !ok {
		t.Fatalf("%s has no automation record %d: %v", n.Name, seq, err)
	}
	return rec
}

// A command accepted by a and c (a quorum of generation 1, never certified)
// must survive c's replacement by d: a new proposer in generation 3 recovers
// exactly that command with its full payload, and the old proposer's retry of
// the same request returns the same chosen slot instead of a second command.
func TestAutomationMembershipPartialAcceptSurvivesVoterReplacement(t *testing.T) {
	m := newAutomationMembershipFixture(t)
	envelope := m.partialAccept(t)
	m.replaceC(t)

	// The membership import carried the accepted envelope: b never accepted
	// it, and now holds it in full from the sealed old majority.
	key, _ := corrosion.AutomationClaimKey(2)
	if st, ok, err := m.b.DB.ClaimState(m.ctx, key); err != nil || !ok || st.Value == nil || st.Value.Automation == nil ||
		!bytes.Equal(st.Value.Automation.Envelope, envelope) {
		t.Fatalf("b did not import the partially accepted envelope across the change: %v", err)
	}

	// New proposer: b, in generation 3, appends its own barrier after
	// recovering slot 2.
	r, err := m.Engine(1).Submit(m.ctx, m.Barrier(1, "successor"))
	if err != nil {
		t.Fatalf("new proposer could not progress after the voter replacement: %v", err)
	}
	if r.Sequence != 3 {
		t.Fatalf("new proposer's command chose slot %d, want 3 after the recovered slot 2", r.Sequence)
	}
	got := m.record(t, m.b, 2)
	if !bytes.Equal(got.Value.Automation.Envelope, envelope) {
		t.Fatal("slot 2 was not recovered with the partially accepted command's complete payload")
	}

	// Old proposer resumes: the same request resolves to the chosen slot.
	again, err := m.Engine(0).Submit(m.ctx, m.Barrier(0, "partial"))
	if err != nil {
		t.Fatalf("old proposer could not resume after the voter replacement: %v", err)
	}
	if again.Sequence != 2 {
		t.Fatalf("old proposer's retry chose slot %d: a second command was chosen for one request", again.Sequence)
	}
	m.converge(t, 0, 1)
	for _, n := range []*Node{m.a, m.b} {
		if rec := m.record(t, n, 2); !bytes.Equal(rec.Value.Automation.Envelope, envelope) {
			t.Fatalf("%s holds a different slot-2 command", n.Name)
		}
	}
	if h := m.Head(t, 0); h.Sequence != 3 {
		t.Fatalf("head %+v, want exactly the two chosen commands after genesis", h)
	}
}

// Once generation 3 is active on a, b and d, c — removed while isolated and
// still holding generation-1 authority — cannot certify a continuation: every
// member of the old electorate it could reach has moved past generation 1.
func TestAutomationMembershipOldGenerationCannotCertify(t *testing.T) {
	m := newAutomationMembershipFixture(t)
	envelope := m.partialAccept(t)
	m.Isolate(2)
	m.replaceC(t, m.a, m.b, m.d)
	if _, err := m.Engine(1).Submit(m.ctx, m.Barrier(1, "successor")); err != nil {
		t.Fatalf("new generation could not progress: %v", err)
	}
	headA, headB := m.Head(t, 0), m.Head(t, 1)
	if adoptedGen(t, m.c) != 1 {
		t.Fatal("c adopted a later generation; the scenario needs it at generation 1")
	}
	// c can reach every voter again for claim RPCs, but replication stays
	// blocked so its replica never sees generations 2 and 3.
	m.Heal(2)
	for _, n := range m.cluster.Nodes {
		if n != m.c {
			m.cluster.SetLinkFaultBoth(m.c, n, LinkFault{Block: true})
		}
	}
	_, err := m.Engine(2).Submit(m.ctx, m.Barrier(2, "old-continuation"))
	if err == nil {
		t.Fatal("a generation-1 proposer certified a continuation after generation 3 became active")
	}
	t.Logf("old proposer refused: %v", err)
	if h := m.Head(t, 0); h != headA {
		t.Fatalf("a's head moved from %+v to %+v after the old proposer's attempt", headA, h)
	}
	if h := m.Head(t, 1); h != headB {
		t.Fatalf("b's head moved from %+v to %+v after the old proposer's attempt", headB, h)
	}
	key, _ := corrosion.AutomationClaimKey(4)
	for _, n := range []*Node{m.a, m.b, m.d} {
		if st, ok, err := n.DB.ClaimState(m.ctx, key); err != nil || (ok && st.Value != nil) {
			t.Fatalf("%s accepted an old-generation continuation at slot 4: %v", n.Name, err)
		}
	}
	if rec := m.record(t, m.b, 2); !bytes.Equal(rec.Value.Automation.Envelope, envelope) {
		t.Fatal("slot 2 changed after the old proposer's attempt")
	}
}

// d joined the electorate without any automation import: its replica holds no
// certified prefix and no authority. It must report that and refuse to take
// part, while a and b, which carried their complete state across the change,
// are ready.
func TestAutomationVoterImportGuardRefusesAbsentData(t *testing.T) {
	m := newAutomationMembershipFixture(t)
	m.replaceC(t)
	st := m.d.Server.AutomationMembershipStatus(m.ctx)
	if st.Imported || st.Code != "automation_import_absent" {
		t.Fatalf("d reports %+v, want not imported (automation_import_absent)", st)
	}
	for _, n := range []*Node{m.a, m.b} {
		if st := n.Server.AutomationMembershipStatus(m.ctx); !st.Imported || st.Generation != 3 || st.Voters != 3 {
			t.Fatalf("%s reports %+v, want imported at generation 3 with three voters", n.Name, st)
		}
	}
	if _, err := m.d.DB.AutomationMembership(m.ctx); err == nil {
		t.Fatal("d holds automation authority without an import")
	}
	if _, err := m.Engine(3).Submit(m.ctx, m.Barrier(3, "fresh-voter")); automation.Code(err) != automation.CodeUnavailable {
		t.Fatalf("d submitted without imported data: %v", err)
	}
}

// A forced reconfiguration has no old quorum to import from, so nothing proves
// the survivors hold every chosen automation command. While automation history
// exists it is refused at the planner (before any signature is collected) and
// at every survivor asked to sign.
func TestAutomationVoterForceGuardNeedsRecoveryProof(t *testing.T) {
	m := newAutomationMembershipFixture(t)
	_, err := forceErr(t, m.cluster, m.a, true, m.b, m.c)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "automation") {
		t.Fatalf("forced reconfiguration with automation history = %v, want an automation refusal", err)
	}
	_, err = m.cluster.PeerClient(m.a, m.b).SignForcedVoterConfig(context.Background(), &pb.SignForcedVoterConfigRequest{FromGeneration: 1, Lost: []string{m.c.Name}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "automation") {
		t.Fatalf("survivor asked to sign a forced generation = %v, want an automation refusal", err)
	}
}

// `lv cluster voter reset` re-derives the voter set at one generation without
// an import from the old majority: refused while automation history exists.
func TestAutomationVoterResetGuardNeedsRecoveryProof(t *testing.T) {
	m := newAutomationMembershipFixture(t)
	for _, dry := range []bool{true, false} {
		_, err := m.cluster.SelfClient(m.a).ChangeVoterConfig(context.Background(), &pb.ChangeVoterConfigRequest{Op: corrosion.VoterChangeReset, DryRun: dry})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "automation") {
			t.Fatalf("voter reset (dry run %v) with automation history = %v, want an automation refusal", dry, err)
		}
	}
	if g := adoptedGen(t, m.a); g != 1 {
		t.Fatalf("a adopted generation %d after a refused reset", g)
	}
}
