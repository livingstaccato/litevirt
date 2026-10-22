package fleet

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	automationv1 "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	"google.golang.org/grpc/metadata"
)

func TestAutomationOwnerSessionNativeDuplicateFULLTarget(t *testing.T) {
	c := newNativeOwnerClient(t, false)
	n := c.f.cluster.Nodes[0]
	if _, e := c.public.EnsureOwner(c.ctx, &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: "duplicate-full-owner"}); e != nil {
		t.Fatal(e)
	}
	md, ok := metadata.FromOutgoingContext(c.ctx)
	if !ok || len(md.Get("authorization")) != 1 {
		t.Fatal("fixture did not retain its actual Login bearer")
	}
	bearer := strings.TrimPrefix(md.Get("authorization")[0], "Bearer ")
	if !strings.HasPrefix(bearer, grpcapi.SessionTokenPrefix) {
		t.Fatal("fixture bearer is not an actual Login session")
	}
	// Invoke the same provenance bridge the actual interceptor uses, on the
	// exact real Login session. The returned stable identity determines the
	// command principal; a username or supplied role never supplies its UID.
	p, handle, e := corrosion.AuthenticateAutomationOwnerSession(c.f.Context(), n.DB, strings.TrimPrefix(bearer, grpcapi.SessionTokenPrefix), time.Hour)
	if e != nil || p == nil || handle == nil {
		t.Fatalf("actual Login provenance bridge: %v", e)
	}
	command := contract.Command{Kind: "acquire_session", ClusterUID: p.ClusterUID, PrincipalID: p.UID, ProjectUID: c.owner.ProjectUid, OwnerID: c.owner.OwnerId, RequestID: "duplicate-full-acquire", Body: []byte(`{"version":1}`)}
	// Both immutable intents pass the real current preflight BEFORE either
	// acquisition wins. They are references to real credentials, not permits.
	changed, e := corrosion.NewAutomationOwnerSubmission(c.f.Context(), handle, command, "losing-target")
	if e != nil {
		t.Fatal(e)
	}
	exact, e := corrosion.NewAutomationOwnerSubmission(c.f.Context(), handle, command, "winning-target")
	if e != nil {
		t.Fatal(e)
	}
	winner, e := c.public.AcquireOwnerSession(c.ctx, &automationv1.AcquireOwnerSessionRequest{Owner: c.owner, RequestId: command.RequestID, SessionId: "winning-target"})
	if e != nil {
		t.Fatal(e)
	}
	c.assertDecision(t, winner.GetCursor(), "acquire_session", command.RequestID, "winning-target", 1)
	before := c.f.Head(t, 0)
	key, e := corrosion.AutomationClaimKey(before.Sequence + 1)
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := corrosion.AdoptedVoterConfig(c.f.Context(), n.DB)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := corrosion.LoadClaimSigner(n.PKIDir, n.Name)
	if e != nil {
		t.Fatal(e)
	}
	value := func(target string) corrosion.ClaimValue {
		a, e := json.Marshal(contract.Assignment{Version: 1, ClusterUID: p.ClusterUID, OperationID: "duplicate-full-operation", RecordedAt: time.Now().UTC().Format(time.RFC3339Nano), Owner: &contract.OwnerAssignment{SessionID: target}})
		if e != nil {
			t.Fatal(e)
		}
		envelope, e := contract.EncodeDecision(contract.Decision{Sequence: before.Sequence + 1, ParentDigest: before.Digest, Command: command, Assignment: a})
		if e != nil {
			t.Fatal(e)
		}
		return corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: envelope}}
	}
	ballot := corrosion.Ballot{Round: 100, Coordinator: n.Name, Nonce: []byte("duplicate-full-boundary")}
	// Correct current parent/key/electorate and real credential reference:
	// refusal must occur at the original target's FULL duplicate boundary.
	refused, e := n.DB.ClaimAcceptOwnerNative(c.f.Context(), key, ballot, value("losing-target"), cfg.Generation, signer, changed)
	if e != nil || refused.Accepted || refused.Accept != nil || refused.Refusal != corrosion.RefusalAutomationUnavailable {
		t.Fatalf("changed duplicate target bypassed FULL admission: %+v %v", refused, e)
	}
	stored, _, e := n.DB.ClaimState(c.f.Context(), key)
	if e != nil || stored.Accept != nil || stored.Value != nil {
		t.Fatalf("changed target persisted fresh authority: %+v %v", stored, e)
	}
	// Same key/current prerequisites/actual credentials, original exact target:
	// this control demonstrates that a generic unavailable gate did not make
	// the changed-target negative pass. Production signs under FULL itself.
	ballot.Round++
	accepted, e := n.DB.ClaimAcceptOwnerNative(c.f.Context(), key, ballot, value("winning-target"), cfg.Generation, signer, exact)
	if e != nil || !accepted.Accepted || accepted.Accept == nil {
		t.Fatalf("original target control cannot reach actual FULL signer: %+v %v", accepted, e)
	}
	for i := range c.f.cluster.Nodes {
		if c.f.Head(t, i) != before {
			t.Fatal("one-vote duplicate test changed applied history")
		}
		if _, found, e := c.f.cluster.Nodes[i].DB.AutomationRecord(c.f.Context(), before.Sequence+1); e != nil || found {
			t.Fatalf("one-vote duplicate published certificate: %v", e)
		}
	}
	c.assertOwner(t, "winning-target", 1)
}
