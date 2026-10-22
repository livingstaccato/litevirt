package fleet

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	automationv1 "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	nativeOwnerProject      = "native-owner-project"
	nativeOwnerProjectUID   = "native-owner-project-uid"
	nativeOwnerUsername     = "native-owner-user"
	nativeOwnerPrincipalUID = "native-owner-principal-uid"
)

// The only signed fixture history below enrolls prerequisite identities. Every
// owner/session decision must originate at the real authenticated public RPC,
// acquire actual durable voter signatures, and pass the existing FULL reducer.
type nativeOwnerClient struct {
	f      *AutomationFixture
	ctx    context.Context
	public automationv1.AutomationClient
	owner  *automationv1.OwnerRef
}

func newNativeOwnerClient(t *testing.T, deniedBinding bool) nativeOwnerClient {
	t.Helper()
	f := NewAutomationFixture(t, 3)
	return newNativeOwnerClientWithFixture(t, f, deniedBinding)
}
func newNativeOwnerClientWithFixture(t *testing.T, f *AutomationFixture, deniedBinding bool) nativeOwnerClient {
	t.Helper()
	entry := f.cluster.Nodes[0]
	legacy := f.cluster.SelfClient(entry)
	if _, err := legacy.CreateProject(f.Context(), &pb.CreateProjectRequest{Name: nativeOwnerProject}); err != nil {
		t.Fatalf("real project birth: %v", err)
	}
	if _, err := legacy.CreateUser(f.Context(), &pb.CreateUserRequest{Username: nativeOwnerUsername, Password: "native-owner-password-0123456789", Role: "operator"}); err != nil {
		t.Fatalf("real account birth: %v", err)
	}
	nativeOwnerPrerequisiteHistory(t, f)
	// Use the daemon's actual policy engine. The positive case exercises its
	// no-bindings operator fallback; an explicit Viewer binding must override it.
	if err := auth.SeedBuiltinRoles(f.Context(), entry.DB); err != nil {
		t.Fatal(err)
	}
	entry.Server.SetAuthEngine(auth.NewEngine(entry.DB))
	if deniedBinding {
		if _, err := legacy.GrantRole(f.Context(), &pb.GrantRoleRequest{Path: "/projects/" + nativeOwnerProject, Role: "Viewer", Principal: "user:" + nativeOwnerUsername + "@local", Propagate: true}); err != nil {
			t.Fatalf("real explicit policy binding: %v", err)
		}
	}
	login, err := legacy.Login(f.Context(), &pb.LoginRequest{Username: nativeOwnerUsername, Password: "native-owner-password-0123456789", Realm: "local"})
	if err != nil || !strings.HasPrefix(login.GetToken(), grpcapi.SessionTokenPrefix) {
		t.Fatalf("real local Login: %v", err)
	}
	principal, err := corrosion.AutomationSessionPrincipal(f.Context(), entry.DB, strings.TrimPrefix(login.GetToken(), grpcapi.SessionTokenPrefix))
	if err != nil || principal == nil || principal.UID != nativeOwnerPrincipalUID || principal.ClusterUID != f.Head(t, 0).ClusterUID {
		t.Fatalf("Login must commit genuine certified-principal provenance: %+v %v", principal, err)
	}
	ctx := metadata.AppendToOutgoingContext(f.Context(), "authorization", "Bearer "+login.GetToken())
	who, err := legacy.Whoami(ctx, &emptypb.Empty{})
	if err != nil || who.GetUsername() != nativeOwnerUsername || who.GetRealm() != "local" || who.GetRole() != "operator" {
		t.Fatalf("actual TLS bearer identity: %+v %v", who, err)
	}
	return nativeOwnerClient{f: f, ctx: ctx, public: automationv1.NewAutomationClient(entry.selfConn), owner: &automationv1.OwnerRef{ProjectUid: nativeOwnerProjectUID, OwnerId: "native-owner"}}
}

// Adapt only the retained assign_identity prerequisite pattern from Observe.
// Real birth witnesses bind the historical principal/project aliases to their
// current lifetimes. This helper cannot sign an owner/session success record.
func nativeOwnerPrerequisiteHistory(t *testing.T, f *AutomationFixture) {
	t.Helper()
	for _, identity := range []struct{ kind, alias, uid string }{
		{"project", nativeOwnerProject, nativeOwnerProjectUID},
		{"principal", nativeOwnerUsername, nativeOwnerPrincipalUID},
	} {
		head := f.Head(t, 0)
		lifetime, err := corrosion.AutomationLifetime(f.Context(), f.cluster.Nodes[0].DB, identity.kind, identity.alias)
		if err != nil || lifetime.Witness == "" {
			t.Fatalf("real %s birth witness: %+v %v", identity.kind, lifetime, err)
		}
		body, err := json.Marshal(contract.IdentityEnrollment{Version: 1, Kind: identity.kind, Alias: identity.alias, Witness: lifetime.Witness, EvidenceID: "native-owner-prerequisite-cutover"})
		if err != nil {
			t.Fatal(err)
		}
		assignment, err := json.Marshal(contract.Assignment{Version: 1, ClusterUID: head.ClusterUID, OperationID: identity.kind + "-prerequisite-op", RecordedAt: "2026-10-19T00:00:00Z", Identity: &contract.IdentityAssignment{UID: identity.uid, Generation: 1, Enrollment: &contract.IdentityEnrollmentFacts{Version: 1, EvidenceID: "native-owner-prerequisite-cutover", ClusterUID: head.ClusterUID, Kind: identity.kind, Alias: identity.alias, Witness: lifetime.Witness, CoverageDigest: strings.Repeat("b", 64), FenceSequence: 1}}})
		if err != nil {
			t.Fatal(err)
		}
		d := contract.Decision{Sequence: head.Sequence + 1, ParentDigest: head.Digest, Command: contract.Command{Kind: "assign_identity", ClusterUID: head.ClusterUID, PrincipalID: "host", RequestID: identity.kind + "-prerequisite-request", Body: body}, Assignment: assignment}
		envelope, err := contract.EncodeDecision(d)
		if err != nil {
			t.Fatal(err)
		}
		value := corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: envelope}}
		key, err := corrosion.AutomationClaimKey(d.Sequence)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := corrosion.AdoptedVoterConfig(f.Context(), f.cluster.Nodes[0].DB)
		if err != nil {
			t.Fatal(err)
		}
		ballot := corrosion.Ballot{Round: 2, Coordinator: f.cluster.Nodes[0].Name, Nonce: []byte("native-owner-prerequisite-history")}
		record := corrosion.AutomationRecord{Value: value, Certificate: corrosion.ClaimCertificate{Key: key, Ballot: ballot, ConfigGeneration: cfg.Generation, ValueDigest: value.MustDigest()}}
		for _, n := range f.cluster.Nodes {
			signer, err := corrosion.LoadClaimSigner(n.PKIDir, n.Name)
			if err != nil {
				t.Fatal(err)
			}
			incarnation, err := n.DB.VoterIncarnation(f.Context())
			if err != nil {
				t.Fatal(err)
			}
			accept, err := signer.Sign(key, cfg.Generation, ballot, value.MustDigest(), incarnation)
			if err != nil {
				t.Fatal(err)
			}
			record.Certificate.Accepts = append(record.Certificate.Accepts, accept)
		}
		for _, n := range f.cluster.Nodes {
			verifier, err := corrosion.LoadClaimVerifier(n.PKIDir)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifier.Verify(record.Certificate, corrosion.CertExpectation{Key: key, ValueDigest: value.MustDigest(), ConfigGeneration: cfg.Generation, Electorate: cfg.Members, Quorum: corrosion.MajorityOf(len(cfg.Members))}); err != nil {
				t.Fatal(err)
			}
			if receipt, err := n.DB.AutomationApply(f.Context(), record, verifier, contract.Reduce); err != nil || receipt.Code != "" || receipt.Sequence != d.Sequence {
				t.Fatalf("certified identity prerequisite: %+v %v", receipt, err)
			}
		}
	}
}

func TestAutomationOwnerSessionNativePublicLifecycle(t *testing.T) {
	c := newNativeOwnerClient(t, false)
	ensure := &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: "native-ensure"}
	created, err := c.public.EnsureOwner(c.ctx, ensure)
	if err != nil {
		t.Fatalf("RED_NATIVE_OWNER_ADMISSION: enrolled real Login EnsureOwner requires native fresh quorum admission: %v", err)
	}
	if !proto.Equal(created.GetOwner().GetRef(), c.owner) || created.GetOwner().GetActivationGeneration() != 0 {
		t.Fatalf("initial owner identity/activation: %+v", created)
	}
	c.assertDecision(t, created.GetCursor(), "ensure_owner", ensure.RequestId, "", 0)
	c.assertOwner(t, "", 0)
	acquire := &automationv1.AcquireOwnerSessionRequest{Owner: c.owner, SessionId: "caller-selected-first-session", RequestId: "native-acquire"}
	acquired, err := c.public.AcquireOwnerSession(c.ctx, acquire)
	if err != nil {
		t.Fatalf("real AcquireOwnerSession: %v", err)
	}
	c.assertSession(t, acquired.GetSession(), acquire.SessionId, 1)
	c.assertDecision(t, acquired.GetCursor(), "acquire_session", acquire.RequestId, acquire.SessionId, 1)
	c.assertOwner(t, acquire.SessionId, 1)
	handoff := &automationv1.HandoffOwnerSessionRequest{Current: acquired.GetSession(), SuccessorSessionId: "caller-selected-successor-session", RequestId: "native-handoff"}
	handed, err := c.public.HandoffOwnerSession(c.ctx, handoff)
	if err != nil {
		t.Fatalf("real HandoffOwnerSession: %v", err)
	}
	c.assertSession(t, handed.GetSession(), handoff.SuccessorSessionId, 2)
	c.assertDecision(t, handed.GetCursor(), "handoff_session", handoff.RequestId, handoff.SuccessorSessionId, 2)
	c.assertOwner(t, handoff.SuccessorSessionId, 2)
	// Receipt lookup must precede fresh stale-session checks and reconstruct
	// the original response, even though the live owner now holds generation 2.
	replayedEnsure, err := c.public.EnsureOwner(c.ctx, ensure)
	if err != nil || !proto.Equal(replayedEnsure, created) {
		t.Fatalf("Ensure original receipt replay: %+v %v", replayedEnsure, err)
	}
	replayedAcquire, err := c.public.AcquireOwnerSession(c.ctx, acquire)
	if err != nil || !proto.Equal(replayedAcquire, acquired) {
		t.Fatalf("Acquire original target/cursor replay: %+v %v", replayedAcquire, err)
	}
	replayedHandoff, err := c.public.HandoffOwnerSession(c.ctx, handoff)
	if err != nil || !proto.Equal(replayedHandoff, handed) {
		t.Fatalf("Handoff original target/cursor replay: %+v %v", replayedHandoff, err)
	}
	changedAcquire := proto.Clone(acquire).(*automationv1.AcquireOwnerSessionRequest)
	changedAcquire.SessionId = "different-first-target"
	_, err = c.public.AcquireOwnerSession(c.ctx, changedAcquire)
	nativeOwnerError(t, err, automationv1.ErrorCode_ERROR_CODE_IDEMPOTENCY_CONFLICT)
	changedHandoff := proto.Clone(handoff).(*automationv1.HandoffOwnerSessionRequest)
	changedHandoff.SuccessorSessionId = "different-successor-target"
	_, err = c.public.HandoffOwnerSession(c.ctx, changedHandoff)
	nativeOwnerError(t, err, automationv1.ErrorCode_ERROR_CODE_IDEMPOTENCY_CONFLICT)
	_, err = c.public.EnsureOwner(c.ctx, &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: acquire.RequestId})
	nativeOwnerError(t, err, automationv1.ErrorCode_ERROR_CODE_IDEMPOTENCY_CONFLICT)
	_, err = c.public.AcquireOwnerSession(c.ctx, &automationv1.AcquireOwnerSessionRequest{Owner: c.owner, ExpectedActivationGeneration: 2, SessionId: "invalid-acquisition", RequestId: "native-invalid-acquire"})
	nativeOwnerError(t, err, automationv1.ErrorCode_ERROR_CODE_VALIDATION)
	c.assertOwner(t, handoff.SuccessorSessionId, 2)
}

func (c nativeOwnerClient) assertSession(t *testing.T, session *automationv1.OwnerSession, target string, activation uint64) {
	t.Helper()
	if !proto.Equal(session.GetOwner(), c.owner) || session.GetSessionId() != target || session.GetActivationGeneration() != activation {
		t.Fatalf("caller-selected session = %+v, want %q activation %d", session, target, activation)
	}
}

func (c nativeOwnerClient) assertOwner(t *testing.T, target string, activation uint64) {
	t.Helper()
	for _, n := range c.f.cluster.Nodes {
		rows, err := n.DB.Query(c.f.Context(), `SELECT founder_principal_uid,session_principal_uid,session_id,activation FROM local_automation_owners WHERE stage='' AND cluster_uid=? AND project_uid=? AND owner_id=?`, c.f.Head(t, 0).ClusterUID, c.owner.ProjectUid, c.owner.OwnerId)
		if err != nil || len(rows) != 1 {
			t.Fatalf("%s owner projection: %+v %v", n.Name, rows, err)
		}
		wantSessionPrincipal := ""
		if activation > 0 {
			wantSessionPrincipal = nativeOwnerPrincipalUID
		}
		if rows[0].String("founder_principal_uid") != nativeOwnerPrincipalUID || rows[0].String("session_principal_uid") != wantSessionPrincipal || rows[0].String("session_id") != target || rows[0].Int64("activation") != int64(activation) {
			t.Fatalf("%s original stable principal/owner result: %+v", n.Name, rows[0])
		}
	}
}

func (c nativeOwnerClient) assertDecision(t *testing.T, cursor *automationv1.ReadCursor, kind, request, target string, activation uint64) {
	t.Helper()
	sequence := cursor.GetAppliedSequence()
	if sequence == 0 {
		t.Fatal("public success omitted certified cursor")
	}
	key, err := corrosion.AutomationClaimKey(sequence)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range c.f.cluster.Nodes {
		record, found, err := n.DB.AutomationRecord(c.f.Context(), sequence)
		if err != nil || !found || record.Value.Automation == nil {
			t.Fatalf("%s success without certified decision: %v", n.Name, err)
		}
		d, err := contract.DecodeDecision(record.Value.Automation.Envelope)
		if err != nil || d.Command.Kind != kind || d.Command.RequestID != request || d.Command.PrincipalID != nativeOwnerPrincipalUID || d.Command.ProjectUID != c.owner.ProjectUid || d.Command.OwnerID != c.owner.OwnerId {
			t.Fatalf("%s original decision: %+v %v", n.Name, d, err)
		}
		var assigned contract.Assignment
		if err := json.Unmarshal(d.Assignment, &assigned); err != nil {
			t.Fatal(err)
		}
		if target == "" {
			if assigned.Owner != nil {
				t.Fatal("Ensure assigned a session")
			}
		} else if assigned.Owner == nil || assigned.Owner.SessionID != target {
			t.Fatalf("certified caller target missing: %+v", assigned.Owner)
		}
		receipt, err := n.DB.AutomationRequest(c.f.Context(), corrosion.AutomationScope(d), request)
		if err != nil || receipt == nil || receipt.Receipt.Code != "" || receipt.Receipt.Sequence != sequence || receipt.Receipt.Generation != activation {
			t.Fatalf("%s cursor/original receipt: %+v %v", n.Name, receipt, err)
		}
		state, found, err := n.DB.ClaimState(c.f.Context(), key)
		if err != nil || !found || state.Accept == nil || state.Value == nil || state.ValueDigest != record.Value.MustDigest() || state.Value.MustDigest() != record.Value.MustDigest() || state.Accept.Voter != n.Name {
			t.Fatalf("%s success without actual durable local valued vote: %+v %v", n.Name, state, err)
		}
		cfg, err := corrosion.AdoptedVoterConfig(c.f.Context(), n.DB)
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := corrosion.LoadClaimVerifier(n.PKIDir)
		if err != nil {
			t.Fatal(err)
		}
		want := corrosion.CertExpectation{Key: key, ValueDigest: record.Value.MustDigest(), ConfigGeneration: cfg.Generation, Electorate: cfg.Members, Quorum: corrosion.MajorityOf(len(cfg.Members))}
		if err := verifier.Verify(record.Certificate, want); err != nil {
			t.Fatalf("%s public result lacks real quorum: %v", n.Name, err)
		}
		want.Quorum = 1 // Verify this actual stored vote, not a one-vote success certificate.
		if err := verifier.Verify(corrosion.ClaimCertificate{Key: key, ConfigGeneration: state.ConfigGeneration, Ballot: state.Accepted, ValueDigest: state.ValueDigest, Accepts: []corrosion.ClaimAccept{*state.Accept}}, want); err != nil {
			t.Fatalf("%s stored vote is not authentic: %v", n.Name, err)
		}
	}
}

func TestAutomationOwnerSessionNativeNoQuorum(t *testing.T) {
	c := newNativeOwnerClient(t, false)
	before := c.f.Head(t, 0)
	for _, n := range c.f.cluster.Nodes[1:] {
		t.Cleanup(n.DoNotImplement("AcceptRecoveryClaim"))
	}
	response, err := c.public.EnsureOwner(c.ctx, &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: "native-no-quorum"})
	if response != nil || status.Code(err) != codes.Unavailable {
		t.Fatalf("one-voter admission returned success: %+v %v", response, err)
	}
	c.assertNoOwnerEffects(t, before, "native-no-quorum")
	key, err := corrosion.AutomationClaimKey(before.Sequence + 1)
	if err != nil {
		t.Fatal(err)
	}
	for i, n := range c.f.cluster.Nodes {
		state, found, err := n.DB.ClaimState(c.f.Context(), key)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if !found || state.Accept == nil || state.Value == nil || state.Value.Automation == nil {
				t.Fatalf("RED_NATIVE_LOCAL_VOTE: authorized entry must durably accept before remote quorum refusal; state=%+v", state)
			}
			d, err := contract.DecodeDecision(state.Value.Automation.Envelope)
			if err != nil || d.Command.Kind != "ensure_owner" || d.Command.RequestID != "native-no-quorum" || d.Command.PrincipalID != nativeOwnerPrincipalUID {
				t.Fatalf("one-vote exact authenticated value: %+v %v", d, err)
			}
		} else if state.Accept != nil || state.Value != nil {
			t.Fatalf("%s accepted despite actual Accept RPC refusal: %+v", n.Name, state)
		}
	}
}

func TestAutomationOwnerSessionNativeRejectsRawPeer(t *testing.T) {
	c := newNativeOwnerClient(t, false)
	before := c.f.Head(t, 0)
	assignment, err := json.Marshal(contract.Assignment{Version: 1, ClusterUID: before.ClusterUID, OperationID: "raw-peer-owner-op", RecordedAt: "2026-10-19T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	d := contract.Decision{Sequence: before.Sequence + 1, ParentDigest: before.Digest, Command: contract.Command{Kind: "ensure_owner", ClusterUID: before.ClusterUID, ProjectUID: c.owner.ProjectUid, OwnerID: c.owner.OwnerId, PrincipalID: nativeOwnerPrincipalUID, RequestID: "raw-peer-owner", Body: []byte(`{"version":1}`)}, Assignment: assignment}
	envelope, err := contract.EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	key, err := corrosion.AutomationClaimKey(d.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := corrosion.AdoptedVoterConfig(c.f.Context(), c.f.cluster.Nodes[0].DB)
	if err != nil {
		t.Fatal(err)
	}
	for i, voter := range c.f.cluster.Nodes {
		source := c.f.cluster.Nodes[(i+1)%len(c.f.cluster.Nodes)]
		response, err := c.f.cluster.PeerClient(source, voter).AcceptRecoveryClaim(c.f.Context(), &pb.AcceptRecoveryClaimRequest{Key: claimKeyPB(key), Ballot: &pb.ClaimBallot{Round: 50, Coordinator: source.Name, BootNonce: []byte("unissued-raw-peer")}, ConfigGeneration: cfg.Generation, Value: &pb.RecoveryClaimValue{Automation: &pb.AutomationClaimValue{Envelope: envelope}}})
		if err != nil || response.GetAccepted() || response.GetAccept() != nil || response.GetRefusalReason() != corrosion.RefusalAutomationUnavailable {
			t.Fatalf("%s raw peer bootstrapped owner authority: %+v %v", voter.Name, response, err)
		}
		state, _, err := voter.DB.ClaimState(c.f.Context(), key)
		if err != nil || state.Accept != nil || state.Value != nil {
			t.Fatalf("%s refused peer left accepted bytes: %+v %v", voter.Name, state, err)
		}
	}
	c.assertNoOwnerEffects(t, before, "raw-peer-owner")
}

func TestAutomationOwnerSessionNativeRequiresScopedPermission(t *testing.T) {
	c := newNativeOwnerClient(t, true)
	before := c.f.Head(t, 0)
	response, err := c.public.EnsureOwner(c.ctx, &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: "native-denied"})
	if response != nil || status.Code(err) != codes.PermissionDenied {
		t.Errorf("explicit Viewer binding must deny owner.manage despite legacy operator role: %+v %v", response, err)
	}
	nativeOwnerError(t, err, automationv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED)
	c.assertNoOwnerEffects(t, before, "native-denied")
}

func nativeOwnerError(t *testing.T, err error, want automationv1.ErrorCode) {
	t.Helper()
	for _, detail := range status.Convert(err).Details() {
		if typed, ok := detail.(*automationv1.ErrorDetail); ok && typed.GetCode() == want {
			return
		}
	}
	t.Fatalf("public structured error = %v, want %s", err, want)
}

func (c nativeOwnerClient) assertNoOwnerEffects(t *testing.T, before corrosion.AutomationPrefix, request string) {
	t.Helper()
	for i, n := range c.f.cluster.Nodes {
		if after := c.f.Head(t, i); after != before {
			t.Errorf("%s no-quorum/refused request advanced certified history: %+v -> %+v", n.Name, before, after)
		}
		if _, found, err := n.DB.AutomationRecord(c.f.Context(), before.Sequence+1); err != nil || found {
			t.Errorf("%s refused request published a next-slot certificate: found=%v %v", n.Name, found, err)
		}
		rows, err := n.DB.Query(c.f.Context(), `SELECT count(*) AS n FROM local_automation_owners WHERE stage='' AND project_uid=? AND owner_id=?`, c.owner.ProjectUid, c.owner.OwnerId)
		if err != nil || len(rows) != 1 || rows[0].Int64("n") != 0 {
			t.Errorf("%s refused request created an owner: %+v %v", n.Name, rows, err)
		}
		d := contract.Decision{Command: contract.Command{ClusterUID: before.ClusterUID, ProjectUID: c.owner.ProjectUid, OwnerID: c.owner.OwnerId}}
		receipt, err := n.DB.AutomationRequest(c.f.Context(), corrosion.AutomationScope(d), request)
		if err != nil || receipt != nil {
			t.Errorf("%s refused request created a receipt: %+v %v", n.Name, receipt, err)
		}
	}
}
