package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth/policy"
	"github.com/litevirt/litevirt/internal/automation"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

func continuityDaemonRequest(t *testing.T, n *continuityNode, kind, uid, request string) *corrosion.AutomationIdentityContinuity {
	t.Helper()
	ctx := context.Background()
	login, err := n.s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "correct-password", Realm: "local"})
	if err != nil {
		t.Fatal(err)
	}
	_, session, err := corrosion.AuthenticateAutomationOwnerSession(ctx, n.d.db, strings.TrimPrefix(login.GetToken(), "lvs_"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p, err := corrosion.PrepareAutomationIdentityContinuity(ctx, n.d.db, session, kind, uid, request)
	if err != nil {
		t.Fatalf("real continuity preparation: %v", err)
	}
	return p
}

// Removing the selected-other handle drop makes the real proposer try to lend
// the losing request's native authorization to different accepted bytes.
func TestContinuityDaemonHigherBallotSelectedOtherKeepsOriginalRequestsDistinct(t *testing.T) {
	nodes := continuityDaemonCluster(t)
	a, b, c := nodes[0], nodes[1], nodes[2]
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	winner, value := continuityDaemonPreparation(t, a)
	loser := continuityDaemonRequest(t, a, "principal", "principal-uid", "different-retained-request")
	if winner.Command().RequestID == loser.Command().RequestID {
		t.Fatal("fixture requests are identical")
	}
	key, _ := corrosion.AutomationClaimKey(3)
	accepted, err := a.d.db.ClaimAcceptContinuityNative(ctx, key, corrosion.Ballot{Round: 7, Coordinator: "a", Nonce: []byte{7}}, value, 1, a.signer, winner)
	if err != nil || !accepted.Accepted || accepted.Accept == nil {
		t.Fatalf("genuine earlier accepted value: %+v %v", accepted, err)
	}
	c.stop() // A/B prepare quorum must observe A's actual higher accepted ballot.
	var selected atomic.Bool
	a.s.SetClaimVoteObserverForTest(func(v grpcapi.ClaimVote) {
		if v.Phase == "prepare" && v.Key == key && v.AcceptedBallot.Round == 7 && v.AcceptedDigest == value.MustDigest() {
			selected.Store(true)
		}
	})
	engine, err := a.s.AutomationEngine()
	if err != nil {
		t.Fatal(err)
	}
	losingReceipt, err := engine.CertifyIdentityContinuity(ctx, loser)
	if err != nil {
		t.Fatalf("selected-other proposer recovery: %+v %v", losingReceipt, err)
	}
	if !selected.Load() {
		t.Fatal("actual proposer never observed higher accepted other value")
	}
	record, found, err := a.d.db.AutomationRecord(ctx, 3)
	if err != nil || !found || !bytes.Equal(record.Value.Automation.Envelope, value.Automation.Envelope) {
		t.Fatalf("selected exact bytes were replaced: found=%v err=%v", found, err)
	}
	winningReceipt, err := engine.CertifyIdentityContinuity(ctx, winner)
	if err != nil {
		t.Fatalf("retained winning original unavailable: %+v %v", winningReceipt, err)
	}
	if winningReceipt.Sequence != 3 || losingReceipt.Sequence != 4 || winningReceipt.OperationID == losingReceipt.OperationID {
		t.Fatalf("retained originals conflated: winner=%+v loser=%+v", winningReceipt, losingReceipt)
	}
	for _, p := range []*corrosion.AutomationIdentityContinuity{winner, loser} {
		r, e := a.d.db.AutomationRequest(ctx, contract.Scope(contract.Decision{Command: p.Command()}), p.Command().RequestID)
		want := winningReceipt
		if p == loser {
			want = losingReceipt
		}
		identity, _ := contract.CanonicalCommand(p.Command())
		if e != nil || r == nil || r.Receipt != want || !bytes.Equal(r.Identity, identity) {
			t.Fatalf("original request lost: %+v %v", r, e)
		}
	}
	peer, found, err := b.d.db.AutomationRecord(ctx, 3)
	if err != nil || !found || !bytes.Equal(peer.Value.Automation.Envelope, value.Automation.Envelope) {
		t.Fatalf("actual peer did not recover selected bytes: %v %v", found, err)
	}
}

func continuityDaemonProject(t *testing.T, nodes []*continuityNode) *corrosion.AutomationIdentityContinuity {
	t.Helper()
	ctx := context.Background()
	a := nodes[0]
	a.d.db.SetProjectIncarnationGate(func() bool { return true })
	if err := corrosion.InsertProject(ctx, a.d.db, corrosion.ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	origin, err := corrosion.AutomationLifetime(ctx, a.d.db, "project", "/acme")
	if err != nil {
		t.Fatal(err)
	}
	h, err := a.d.db.AutomationHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(contract.IdentityEnrollment{Version: 1, Kind: "project", Alias: "/acme", Witness: origin.Witness, EvidenceID: "closed-project-cutover"})
	assignment, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: h.ClusterUID, OperationID: "project-op", RecordedAt: time.Now().UTC().Format(time.RFC3339Nano), Identity: &contract.IdentityAssignment{UID: "project-uid", Generation: 1, Enrollment: &contract.IdentityEnrollmentFacts{Version: 1, EvidenceID: "closed-project-cutover", ClusterUID: h.ClusterUID, Kind: "project", Alias: "/acme", Witness: origin.Witness, CoverageDigest: strings.Repeat("b", 64), FenceSequence: 1}}})
	raw, err := contract.EncodeDecision(contract.Decision{Sequence: 3, ParentDigest: h.Digest, Command: contract.Command{Kind: "assign_identity", ClusterUID: h.ClusterUID, PrincipalID: "host", RequestID: "project-identity-request", Body: body}, Assignment: assignment})
	if err != nil {
		t.Fatal(err)
	}
	value := corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: raw}}
	key, _ := corrosion.AutomationClaimKey(3)
	ballot := corrosion.Ballot{Round: 2, Coordinator: "a", Nonce: []byte{1}}
	record := corrosion.AutomationRecord{Value: value, Certificate: corrosion.ClaimCertificate{Key: key, ConfigGeneration: 1, Ballot: ballot, ValueDigest: value.MustDigest()}}
	for _, n := range nodes[:2] {
		vote, e := n.signer.Sign(key, 1, ballot, value.MustDigest(), n.inc)
		if e != nil {
			t.Fatal(e)
		}
		record.Certificate.Accepts = append(record.Certificate.Accepts, vote)
	}
	for _, n := range nodes {
		if receipt, e := n.d.db.AutomationApply(ctx, record, n.verifier, contract.Reduce); e != nil || receipt.Code != "" {
			t.Fatalf("certified project prerequisite: %+v %v", receipt, e)
		}
	}
	if err = corrosion.InsertRole(ctx, a.d.db, corrosion.RoleRecord{Name: "ProjectOwner", Verbs: []string{policy.OwnerManage}}); err != nil {
		t.Fatal(err)
	}
	id, err := corrosion.ProjectBindingID(ctx, a.d.db, "/projects/acme", "project-owner")
	if err != nil {
		t.Fatal(err)
	}
	if err = corrosion.InsertRoleBinding(ctx, a.d.db, corrosion.RoleBindingRecord{ID: id, Path: "/projects/acme", Role: "ProjectOwner", Principal: "user:alice@local", Propagate: true}); err != nil {
		t.Fatal(err)
	}
	return continuityDaemonRequest(t, a, "project", "project-uid", "project-retained-request")
}

// Each engine call has bounded voter RPCs and can return unavailable after
// committing. Positive fixtures retain the exact original preparation and retry
// only that documented code; current-authorization denials stay single calls.
func continuityDaemonCertifyRetained(t *testing.T, ctx context.Context, engine *automation.Engine, p *corrosion.AutomationIdentityContinuity) (contract.Receipt, error) {
	t.Helper()
	var receipt contract.Receipt
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		receipt, err = engine.CertifyIdentityContinuity(ctx, p)
		if automation.Code(err) != automation.CodeUnavailable || ctx.Err() != nil {
			return receipt, err
		}
		t.Logf("same retained request unavailable on bounded call %d of 3: %v", attempt, err)
	}
	return receipt, err
}

func TestContinuityDaemonProjectCertificationAndFinalAuthorization(t *testing.T) {
	for _, mode := range []string{"current-scope", "scope-changed-during-quorum", "session-revoked-during-quorum", "project-reborn-during-quorum"} {
		t.Run(mode, func(t *testing.T) {
			nodes := continuityDaemonCluster(t)
			a, b, c := nodes[0], nodes[1], nodes[2]
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			p := continuityDaemonProject(t, nodes)
			engine, err := a.s.AutomationEngine()
			if err != nil {
				t.Fatal(err)
			}
			original, err := continuityDaemonCertifyRetained(t, ctx, engine, p)
			if err != nil || original.Sequence != 4 || original.ResourceUID != "project-uid" {
				t.Fatalf("real project certification: %+v %v", original, err)
			}
			c.stop()
			var changed atomic.Bool
			if mode != "current-scope" {
				b.s.SetClaimVoteObserverForTest(func(v grpcapi.ClaimVote) {
					if v.Phase == "accept" && v.Key.OwnerEpoch == 4 && changed.CompareAndSwap(false, true) {
						var e error
						switch mode {
						case "scope-changed-during-quorum":
							e = corrosion.InsertRole(context.Background(), a.d.db, corrosion.RoleRecord{Name: "ProjectOwner", Verbs: []string{"vm.read"}})
						case "session-revoked-during-quorum":
							e = a.d.db.Execute(context.Background(), `UPDATE sessions SET revoked_at = ? WHERE username = ?`, a.d.db.NowTS(), "alice")
						case "project-reborn-during-quorum":
							e = corrosion.DeleteProject(context.Background(), a.d.db, "/acme")
							if e == nil {
								e = corrosion.InsertProject(context.Background(), a.d.db, corrosion.ProjectRecord{Name: "/acme"})
							}
						}
						if e != nil {
							t.Error(e)
						}
					}
				})
			}
			var retry contract.Receipt
			var e error
			if mode == "current-scope" {
				retry, e = continuityDaemonCertifyRetained(t, ctx, engine, p)
			} else {
				retry, e = engine.CertifyIdentityContinuity(ctx, p)
			}
			if mode == "current-scope" {
				if e != nil || retry != original {
					t.Fatalf("current scope lost original: %+v %v", retry, e)
				}
			} else if !changed.Load() || e == nil || retry.OperationID != "" {
				t.Fatalf("current project authorization not repeated after real exchange: changed=%v receipt=%+v err=%v", changed.Load(), retry, e)
			}
			stored, e := a.d.db.AutomationRequest(context.Background(), contract.Scope(contract.Decision{Command: p.Command()}), p.Command().RequestID)
			if e != nil || stored == nil || stored.Receipt != original {
				t.Fatalf("denied disclosure changed original: %+v %v", stored, e)
			}
			head, e := a.d.db.AutomationHead(context.Background())
			if e != nil || head.Sequence != 4 {
				t.Fatalf("original lookup reexecuted: %+v %v", head, e)
			}
		})
	}
}

// A successful first write is followed by a separate fresh confirmation quorum.
// Withhold both remote replies at precisely that quorum, after their promises
// are durable. This exercises the documented per-call timeout with real RPCs.
func TestContinuityDaemonProjectRetainsOriginalAfterConfirmationTimeout(t *testing.T) {
	nodes := continuityDaemonCluster(t)
	a, b, c := nodes[0], nodes[1], nodes[2]
	p := continuityDaemonProject(t, nodes)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	release := make(chan struct{})
	arrived := make(chan string, 2)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	for _, n := range []*continuityNode{b, c} {
		var blocked atomic.Bool
		n.s.SetClaimVoteObserverForTest(func(v grpcapi.ClaimVote) {
			if v.Phase == "prepare" && v.Key.OwnerEpoch == 4 && v.AcceptedDigest != "" && blocked.CompareAndSwap(false, true) {
				arrived <- v.Voter
				<-release
			}
		})
	}
	engine, err := a.s.AutomationEngine()
	if err != nil {
		t.Fatal(err)
	}
	first, err := engine.CertifyIdentityContinuity(ctx, p)
	if automation.Code(err) != automation.CodeUnavailable || first.OperationID != "" {
		t.Fatalf("withheld confirmation must be retryable unavailable: receipt=%+v err=%v", first, err)
	}
	if len(arrived) != 2 {
		t.Fatalf("did not reach both controlled confirmation replies: %d", len(arrived))
	}
	stored, err := a.d.db.AutomationRequest(ctx, contract.Scope(contract.Decision{Command: p.Command()}), p.Command().RequestID)
	if err != nil || stored == nil || stored.Receipt.Sequence != 4 || stored.Receipt.ResourceUID != "project-uid" {
		t.Fatalf("first call did not preserve its committed original: %+v %v", stored, err)
	}
	identity, _ := contract.CanonicalCommand(p.Command())
	if !bytes.Equal(stored.Identity, identity) {
		t.Fatal("retained request identity changed")
	}
	before, err := a.d.db.AutomationHead(ctx)
	if err != nil || before.Sequence != 4 {
		t.Fatalf("unexpected committed head: %+v %v", before, err)
	}
	unblock()
	retry, err := continuityDaemonCertifyRetained(t, ctx, engine, p)
	if err != nil || retry != stored.Receipt {
		t.Fatalf("same retained request did not return exact original: %+v %v", retry, err)
	}
	after, err := a.d.db.AutomationHead(ctx)
	if err != nil || after != before {
		t.Fatalf("same request duplicated an effect: before=%+v after=%+v err=%v", before, after, err)
	}
	again, err := a.d.db.AutomationRequest(ctx, contract.Scope(contract.Decision{Command: p.Command()}), p.Command().RequestID)
	if err != nil || again == nil || again.Receipt != stored.Receipt || !bytes.Equal(again.Identity, stored.Identity) {
		t.Fatalf("same original was replaced: %+v %v", again, err)
	}
}
