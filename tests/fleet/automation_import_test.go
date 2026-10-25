package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// F1 Task 5G: a voter new to the automation electorate imports the certified
// prefix of the old majority and only then gains automation authority.

// grownElectorate is the membership fixture with a certified prefix of
// initialize + two barriers on a, b and c, the real release-feature gate wired
// on every node, and d added as a fourth voter: generation 2 = {a,b,c,d},
// adopted everywhere. d holds no authority yet.
func grownElectorate(t *testing.T) *automationMembershipFixture {
	t.Helper()
	m := newAutomationMembershipFixture(t)
	gates := gateAll(t, m.cluster)
	wireReleaseFeatures(t, m.cluster, gates)
	// failover_scope_v1 opens cluster_policies, where release-feature use is
	// recorded (wireReleaseFeatures); automation_v1 is the feature's token.
	for _, tok := range []string{capabilities.FailoverScopeV1, capabilities.AutomationV1} {
		for _, n := range m.cluster.Nodes {
			if !gates[n.Name].Enforced(m.ctx, tok) {
				t.Fatalf("%s: %s did not latch", n.Name, tok)
			}
		}
	}
	for _, req := range []string{"before-1", "before-2"} {
		if _, err := m.Engine(0).Submit(m.ctx, m.Barrier(0, req)); err != nil {
			t.Fatal(err)
		}
	}
	m.converge(t, 0, 1, 2)
	if _, err := m.cluster.SelfClient(m.b).ChangeVoterConfig(context.Background(), &pb.ChangeVoterConfigRequest{Op: "add", Host: m.d.Name}); err != nil {
		t.Fatalf("voter add %s: %v", m.d.Name, err)
	}
	adoptAll(t, m.cluster, 2)
	if st := m.d.Server.AutomationMembershipStatus(m.ctx); st.Imported || st.Code != "automation_import_absent" || st.Generation != 2 {
		t.Fatalf("fixture: d reports %+v, want generation 2 without authority", st)
	}
	return m
}

// attestations asks every old voter for its import attestation over the real
// peer RPC, as d.
func (m *automationMembershipFixture) attestations(t *testing.T, gen int64) []corrosion.AutomationImportSource {
	t.Helper()
	var out []corrosion.AutomationImportSource
	for _, n := range []*Node{m.a, m.b, m.c} {
		r, err := m.cluster.PeerClient(m.d, n).GetAutomationImportSource(m.ctx, &pb.GetAutomationImportSourceRequest{Generation: gen})
		if err != nil {
			t.Fatalf("%s: %v", n.Name, err)
		}
		out = append(out, corrosion.AutomationImportSource{Voter: r.Voter, Incarnation: r.Incarnation, Adopted: r.AdoptedGeneration,
			Authority: r.Authority, Head: corrosion.AutomationPrefix{ClusterUID: r.ClusterUid, Sequence: r.HeadSequence, Digest: r.HeadDigest}})
	}
	return out
}

func (m *automationMembershipFixture) requireNoImport(t *testing.T, why string) {
	t.Helper()
	if st := m.d.Server.AutomationMembershipStatus(m.ctx); st.Imported {
		t.Fatalf("%s: d gained automation authority: %+v", why, st)
	}
	if _, err := m.d.DB.AutomationMembership(m.ctx); err == nil {
		t.Fatalf("%s: d holds automation authority", why)
	}
}

// requireNothingImported: d staged and applied no certified history. (d does
// hold automation claim rows: every member's ordinary adoption merges them
// from the sealed old majority, which is what makes the import safe.)
func (m *automationMembershipFixture) requireNothingImported(t *testing.T, why string) {
	t.Helper()
	m.requireNoImport(t, why)
	if h := m.Head(t, 3); h.Sequence != 0 {
		t.Fatalf("%s: d applied certified history up to %+v", why, h)
	}
	if pending, err := m.d.DB.AutomationRecoveryPending(m.ctx); err != nil || pending {
		t.Fatalf("%s: d opened an import job: %v %v", why, pending, err)
	}
}

// d, added at generation 2, imports the old majority's certified prefix,
// gains authority there and takes part: its own proposal certifies, and once
// every voter has signed a decision at generation 2 the gate's evidence count
// of imported voters is 4.
func TestAutomationVoterImportGrowsElectorate(t *testing.T) {
	m := grownElectorate(t)
	if err := m.d.Server.ImportAutomationPrefix(m.ctx); err != nil {
		t.Fatalf("d's import: %v", err)
	}
	st := m.d.Server.AutomationMembershipStatus(m.ctx)
	if !st.Imported || st.Generation != 2 || st.Code != "" {
		t.Fatalf("d reports %+v after its import, want imported at generation 2", st)
	}
	if h, want := m.Head(t, 3), m.Head(t, 0); h != want {
		t.Fatalf("d's certified head %+v, want the old majority's %+v", h, want)
	}
	if !featureUsedOn(t, m.d, capabilities.AutomationV1, string(capabilities.FeatureAutomationState)) {
		t.Fatal("d wrote automation state without recording the automation_state use")
	}
	// Every voter proposes once at generation 2; each proposal carries its
	// proposer's own accept.
	for i, req := range []string{"after-a", "after-b", "after-c", "after-d"} {
		if _, err := m.Engine(i).Submit(m.ctx, m.Barrier(i, req)); err != nil {
			t.Fatalf("%s's proposal at generation 2: %v", m.cluster.Nodes[i].Name, err)
		}
	}
	m.converge(t, 3, 0, 1, 2)
	if h := m.Head(t, 3); h.Sequence != 7 {
		t.Fatalf("head %+v, want initialize + 2 + 4 barriers", h)
	}
	for _, n := range []*Node{m.d, m.a} {
		if st := n.Server.AutomationMembershipStatus(m.ctx); st.ImportedVoters != 4 {
			t.Fatalf("%s reports %+v, want 4 evidenced imported voters at generation 2", n.Name, st)
		}
	}
	// Nothing to do the second time.
	if err := m.d.Server.ImportAutomationPrefix(m.ctx); err != nil {
		t.Fatalf("second import: %v", err)
	}
}

// An import interrupted after staging its tip leaves a pending job and no
// authority; the next pass resumes it. An import that applied the whole
// prefix but never committed its grant (the authority row is the only thing
// the grant writes) completes on the next pass without restaging.
func TestAutomationVoterImportResumesAfterInterruption(t *testing.T) {
	m := grownElectorate(t)
	fail := func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		return nil, status.Error(codes.Unavailable, "injected")
	}
	pass := func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) { return h(ctx, req) }
	// The tip comes from a (sources are tried in name order); every
	// predecessor fetch then fails.
	m.a.HookUnary("GetAutomationDecision", pass)
	m.a.HookUnary("GetAutomationDecision", fail)
	m.b.HookUnary("GetAutomationDecision", fail)
	m.c.HookUnary("GetAutomationDecision", fail)
	if err := m.d.Server.ImportAutomationPrefix(m.ctx); err == nil {
		t.Fatal("import completed with every predecessor fetch failing")
	}
	m.requireNoImport(t, "interrupted import")
	if pending, err := m.d.DB.AutomationRecoveryPending(m.ctx); err != nil || !pending {
		t.Fatalf("interrupted import left no pending job: %v %v", pending, err)
	}
	if err := m.d.Server.ImportAutomationPrefix(m.ctx); err != nil {
		t.Fatalf("resumed import: %v", err)
	}
	if st := m.d.Server.AutomationMembershipStatus(m.ctx); !st.Imported {
		t.Fatalf("resumed import: d reports %+v", st)
	}

	// Applied but not granted.
	if err := localExec(m.ctx, m.d.DB, `DELETE FROM local_automation_authority WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	m.requireNoImport(t, "fixture")
	before := m.Head(t, 3)
	if err := m.d.Server.ImportAutomationPrefix(m.ctx); err != nil {
		t.Fatalf("grant after a complete prefix: %v", err)
	}
	if st := m.d.Server.AutomationMembershipStatus(m.ctx); !st.Imported || m.Head(t, 3) != before {
		t.Fatalf("grant after a complete prefix: d reports %+v, head %+v (was %+v)", st, m.Head(t, 3), before)
	}
}

// forgeDecision makes the next GetAutomationDecision served by n return the
// real record with its certificate replaced by another record's: the value,
// and so the digest an importer checks first, is unchanged.
func forgeDecision(t *testing.T, n *Node, cert corrosion.ClaimCertificate) {
	n.HookUnary("GetAutomationDecision", func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		resp, err := h(ctx, req)
		if err != nil {
			return resp, err
		}
		r := resp.(*pb.GetAutomationDecisionResponse)
		var rec corrosion.AutomationRecord
		if err := json.Unmarshal(r.RecordJson, &rec); err != nil {
			t.Error(err)
			return resp, nil
		}
		rec.Certificate = cert
		b, _ := json.Marshal(rec)
		return &pb.GetAutomationDecisionResponse{Found: true, RecordJson: b}, nil
	})
}

// A tip whose certificate does not certify it, a predecessor that does not
// match its successor's parent digest, an attested digest that differs from
// the certified history, and fewer than a majority of old voters attesting:
// each is refused, and d gains no authority.
func TestAutomationVoterImportRefusesForgedOrStaleCut(t *testing.T) {
	m := grownElectorate(t)
	head := m.Head(t, 0)
	other := m.record(t, m.a, head.Sequence-1)

	// Forged tip. Sources are tried in name order and the first record with
	// the attested digest is taken, so a serves it.
	forgeDecision(t, m.a, other.Certificate)
	if err := m.d.Server.ImportAutomationPrefix(m.ctx); err == nil {
		t.Fatal("import accepted a tip whose certificate certifies another record")
	}
	m.requireNoImport(t, "forged tip")
	if pending, _ := m.d.DB.AutomationRecoveryPending(m.ctx); pending {
		t.Fatal("a forged tip opened an import job")
	}

	// Wrong predecessor: the tip is genuine, the record served for its
	// parent slot is a different (genuine) record.
	wrong := m.record(t, m.a, 1)
	m.a.HookUnary("GetAutomationDecision", func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) { return h(ctx, req) })
	for _, n := range []*Node{m.a, m.b, m.c} {
		n.HookUnary("GetAutomationDecision", func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
			b, _ := json.Marshal(wrong)
			return &pb.GetAutomationDecisionResponse{Found: true, RecordJson: b}, nil
		})
	}
	if err := m.d.Server.ImportAutomationPrefix(m.ctx); err == nil {
		t.Fatal("import accepted a predecessor outside the tip's digest chain")
	}
	m.requireNoImport(t, "wrong predecessor")

	// Fewer than a majority of generation 1 attest authority: nothing is
	// written and no automation_state use is recorded.
	denied := func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		resp, err := h(ctx, req)
		if err == nil {
			resp.(*pb.GetAutomationImportSourceResponse).Authority = false
		}
		return resp, err
	}
	fresh := grownElectorate(t)
	fresh.b.HookUnary("GetAutomationImportSource", denied)
	fresh.c.HookUnary("GetAutomationImportSource", denied)
	if err := fresh.d.Server.ImportAutomationPrefix(fresh.ctx); err == nil {
		t.Fatal("import proceeded with one of three old voters attesting authority")
	}
	fresh.requireNoImport(t, "minority of sources")
	fresh.requireNothingImported(t, "minority of sources")
	if featureUsedOn(t, fresh.d, capabilities.AutomationV1, string(capabilities.FeatureAutomationState)) {
		t.Fatal("a refused import recorded the automation_state use")
	}

	// Finish m's import from genuine sources, then show the grant itself
	// refuses an attested digest that differs from the local certified
	// history, and a minority of attestations.
	if err := m.d.Server.ImportAutomationPrefix(m.ctx); err != nil {
		t.Fatalf("genuine import after the refusals: %v", err)
	}
	if err := localExec(m.ctx, m.d.DB, `DELETE FROM local_automation_authority WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	grant := capabilities.GrantForTest(t, capabilities.FeatureAutomationState)
	att := m.attestations(t, 2)
	bad := append([]corrosion.AutomationImportSource(nil), att...)
	for i := range bad {
		bad[i].Head.Digest = strings.Repeat("0", len(bad[i].Head.Digest))
	}
	if err := m.d.DB.AutomationGrantImportedAuthority(m.ctx, grant, 2, bad); err == nil {
		t.Fatal("grant accepted an attested head digest that differs from the certified history")
	}
	if err := m.d.DB.AutomationGrantImportedAuthority(m.ctx, grant, 2, att[:1]); err == nil {
		t.Fatal("grant accepted one attestation of three")
	}
	m.requireNoImport(t, "grant refusals")
	if err := m.d.DB.AutomationGrantImportedAuthority(m.ctx, grant, 2, att); err != nil {
		t.Fatalf("grant with genuine attestations: %v", err)
	}
}

// Without the automation_state release feature (no gate: the fixture's
// default), the import writes nothing at all.
func TestAutomationVoterImportNeedsTheReleaseFeature(t *testing.T) {
	m := newAutomationMembershipFixture(t)
	if _, err := m.cluster.SelfClient(m.b).ChangeVoterConfig(context.Background(), &pb.ChangeVoterConfigRequest{Op: "add", Host: m.d.Name}); err != nil {
		t.Fatal(err)
	}
	adoptAll(t, m.cluster, 2)
	if err := m.d.Server.ImportAutomationPrefix(m.ctx); err == nil {
		t.Fatal("import ran without the automation_state release feature")
	}
	m.requireNoImport(t, "no release feature")
	m.requireNothingImported(t, "no release feature")
}

// The source RPC answers only a direct peer that is a member of the requested
// generation: not a voter outside it, not an on-node caller.
func TestAutomationVoterImportSourceAuthorization(t *testing.T) {
	m := newAutomationMembershipFixture(t)
	if _, err := m.cluster.PeerClient(m.d, m.a).GetAutomationImportSource(m.ctx, &pb.GetAutomationImportSourceRequest{Generation: 1}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-member peer: %v, want PermissionDenied", err)
	}
	if _, err := m.cluster.SelfClient(m.a).GetAutomationImportSource(m.ctx, &pb.GetAutomationImportSourceRequest{Generation: 1}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("on-node caller: %v, want PermissionDenied", err)
	}
	r, err := m.cluster.PeerClient(m.b, m.a).GetAutomationImportSource(m.ctx, &pb.GetAutomationImportSourceRequest{Generation: 1})
	if err != nil || !r.Authority || r.HeadSequence != m.Head(t, 0).Sequence || r.AdoptedGeneration != 1 {
		t.Fatalf("member peer: %+v, %v", r, err)
	}
}

// After d has imported, a reset is still refused (d now holds automation
// state too), and a forced generation still never carries: d's plan at a
// forced generation is ineligible.
func TestAutomationVoterImportKeepsResetAndForceRefused(t *testing.T) {
	m := grownElectorate(t)
	if err := m.d.Server.ImportAutomationPrefix(m.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := m.cluster.SelfClient(m.d).ChangeVoterConfig(context.Background(), &pb.ChangeVoterConfigRequest{Op: corrosion.VoterChangeReset}); err == nil || !strings.Contains(err.Error(), "automation") {
		t.Fatalf("reset coordinated by the imported voter: %v, want an automation refusal", err)
	}
	if _, err := forceErr(t, m.cluster, m.d, true, m.a, m.b); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "automation") {
		t.Fatalf("forced reconfiguration planned by the imported voter: %v, want an automation refusal", err)
	}
	if _, err := m.d.DB.AutomationImportPlan(m.ctx); !errors.Is(err, corrosion.ErrAutomationAlreadyImported) {
		t.Fatalf("plan after import: %v", err)
	}
}
