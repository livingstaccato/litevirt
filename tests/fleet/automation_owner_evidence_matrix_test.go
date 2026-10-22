package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
	automationv1 "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// The base is a genuinely authorized, stored, signed native vote. Refusing two
// actual peer Accept methods with the existing harness prevents publication.
// No signer or manually constructed owner certificate participates here.
func nativeOwnerUnpublished(t *testing.T, c nativeOwnerClient) (corrosion.AutomationPrefix, corrosion.ClaimVoterState) {
	t.Helper()
	before := c.f.Head(t, 0)
	restore1 := c.f.cluster.Nodes[1].DoNotImplement("AcceptRecoveryClaim")
	restore2 := c.f.cluster.Nodes[2].DoNotImplement("AcceptRecoveryClaim")
	defer restore1()
	defer restore2()
	r, e := c.public.EnsureOwner(c.ctx, &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: "unpublished-native-owner"})
	if r != nil || status.Code(e) != codes.Unavailable {
		t.Fatalf("one vote returned success: %+v %v", r, e)
	}
	c.assertNoOwnerEffects(t, before, "unpublished-native-owner")
	key, err := corrosion.AutomationClaimKey(before.Sequence + 1)
	if err != nil {
		t.Fatal(err)
	}
	s, found, err := c.f.cluster.Nodes[0].DB.ClaimState(c.f.Context(), key)
	if err != nil || !found || s.Accept == nil || s.Value == nil || s.Accept.Voter != c.f.cluster.Nodes[0].Name {
		t.Fatalf("actual native vote missing: %+v %v", s, err)
	}
	return before, s
}

func nativeOwnerPeerAccept(t *testing.T, c nativeOwnerClient, target int, s corrosion.ClaimVoterState, round uint64, value *pb.RecoveryClaimValue) *pb.AcceptRecoveryClaimResponse {
	t.Helper()
	if value == nil {
		value = &pb.RecoveryClaimValue{Automation: &pb.AutomationClaimValue{Envelope: append([]byte(nil), s.Value.Automation.Envelope...)}}
	}
	source := c.f.cluster.Nodes[(target+1)%len(c.f.cluster.Nodes)]
	r, e := c.f.cluster.PeerClient(source, c.f.cluster.Nodes[target]).AcceptRecoveryClaim(c.f.Context(), &pb.AcceptRecoveryClaimRequest{
		Key: claimKeyPB(s.Key), Ballot: &pb.ClaimBallot{Round: round, Coordinator: source.Name, BootNonce: []byte("native-owner-evidence-matrix")}, ConfigGeneration: s.ConfigGeneration, Value: value,
	})
	if e != nil {
		t.Fatalf("actual peer Accept transport: %v", e)
	}
	return r
}

func TestAutomationOwnerSessionNativeStoredEvidenceBinding(t *testing.T) {
	for _, variant := range []string{"matching-control", "different-value", "different-parent", "different-request", "wrong-source-state", "wrong-source-signature", "wrong-incarnation", "wrong-adopted-generation", "wrong-signature-generation", "wrong-ballot", "wrong-key", "bad-signature", "unsigned-state"} {
		t.Run(variant, func(t *testing.T) {
			c := newNativeOwnerClient(t, false)
			before, s := nativeOwnerUnpublished(t, c)
			value := &pb.RecoveryClaimValue{Automation: &pb.AutomationClaimValue{Envelope: append([]byte(nil), s.Value.Automation.Envelope...)}}
			if variant == "different-value" || variant == "different-parent" || variant == "different-request" {
				d, e := contract.DecodeDecision(value.Automation.Envelope)
				if e != nil {
					t.Fatal(e)
				}
				switch variant {
				case "different-value":
					a, e := contract.DecodeAssignment(d)
					if e != nil {
						t.Fatal(e)
					}
					a.OperationID = "altered-unissued-operation"
					d.Assignment, e = json.Marshal(a)
					if e != nil {
						t.Fatal(e)
					}
				case "different-parent":
					d.ParentDigest = strings.Repeat("a", 64)
				case "different-request":
					d.Command.RequestID = "unissued-request"
				}
				value.Automation.Envelope, e = contract.EncodeDecision(d)
				if e != nil {
					t.Fatal(e)
				}
			}
			// Node 2 has no accepted value; make that absence explicit, so the
			// consumer cannot accidentally succeed using a second evidence source.
			t.Cleanup(c.f.cluster.Nodes[2].DoNotImplement("GetRecoveryClaim"))
			c.f.cluster.Nodes[0].HookUnary("GetRecoveryClaim", func(ctx context.Context, req any, next grpc.UnaryHandler) (any, error) {
				x, e := next(ctx, req)
				if e != nil {
					return nil, e
				}
				r := proto.Clone(x.(*pb.GetRecoveryClaimResponse)).(*pb.GetRecoveryClaimResponse)
				switch variant {
				case "wrong-source-state":
					r.State.Voter = c.f.cluster.Nodes[2].Name
				case "wrong-source-signature":
					r.Accept.Voter = c.f.cluster.Nodes[2].Name
				case "wrong-incarnation":
					r.State.VoterIncarnation = "different-incarnation"
					r.Accept.VoterIncarnation = "different-incarnation"
				case "wrong-adopted-generation":
					r.AdoptedGeneration++
				case "wrong-signature-generation":
					r.Accept.ConfigGeneration++
				case "wrong-ballot":
					r.State.AcceptedBallot.Round++
				case "wrong-key":
					r.Accept.Key.TargetName = "wrong-slot"
				case "bad-signature":
					r.Accept.Signature[0] ^= 0x80
				case "unsigned-state":
					r.Accept = nil
				}
				return r, nil
			})
			r := nativeOwnerPeerAccept(t, c, 1, s, s.Accepted.Round+10, value)
			stored, _, e := c.f.cluster.Nodes[1].DB.ClaimState(c.f.Context(), s.Key)
			if e != nil {
				t.Fatal(e)
			}
			if variant == "matching-control" {
				if !r.GetAccepted() || r.GetAccept() == nil || stored.Accept == nil || stored.ValueDigest != s.ValueDigest {
					t.Fatalf("actual exact stored evidence failed to admit: %+v %+v", r, stored)
				}
				cfg, e := corrosion.AdoptedVoterConfig(c.f.Context(), c.f.cluster.Nodes[1].DB)
				if e != nil {
					t.Fatal(e)
				}
				v, e := corrosion.LoadClaimVerifier(c.f.cluster.Nodes[1].PKIDir)
				if e != nil {
					t.Fatal(e)
				}
				if e := v.Verify(corrosion.ClaimCertificate{Key: s.Key, ConfigGeneration: stored.ConfigGeneration, Ballot: stored.Accepted, ValueDigest: stored.ValueDigest, Accepts: []corrosion.ClaimAccept{*stored.Accept}}, corrosion.CertExpectation{Key: s.Key, ConfigGeneration: cfg.Generation, ValueDigest: s.ValueDigest, Electorate: cfg.Members, Quorum: 1}); e != nil {
					t.Fatal(e)
				}
			} else if r.GetAccepted() || r.GetAccept() != nil || stored.Accept != nil || stored.Value != nil {
				t.Fatalf("altered or unsigned evidence authorized owner: response=%+v stored=%+v", r, stored)
			}
			c.assertNoOwnerEffects(t, before, "unpublished-native-owner")
		})
	}
}

func TestAutomationOwnerSessionNativeUnpublishedRecovery(t *testing.T) {
	for _, survivingHolder := range []bool{false, true} {
		name := "only-holder-unreachable"
		if survivingHolder {
			name = "chosen-unpublished-surviving-holder"
		}
		t.Run(name, func(t *testing.T) {
			c := newNativeOwnerClient(t, false)
			before, s := nativeOwnerUnpublished(t, c)
			if survivingHolder {
				// Chosen requires a majority at ONE ballot. Use the native
				// origin's actual tuple, not merely another higher-ballot vote.
				origin, holder := c.f.cluster.Nodes[0], c.f.cluster.Nodes[1]
				r, e := c.f.cluster.PeerClient(origin, holder).AcceptRecoveryClaim(c.f.Context(), &pb.AcceptRecoveryClaimRequest{
					Key: claimKeyPB(s.Key), ConfigGeneration: s.ConfigGeneration,
					Ballot: &pb.ClaimBallot{Round: s.Accepted.Round, Coordinator: s.Accepted.Coordinator, BootNonce: append([]byte(nil), s.Accepted.Nonce...)},
					Value:  &pb.RecoveryClaimValue{Automation: &pb.AutomationClaimValue{Envelope: append([]byte(nil), s.Value.Automation.Envelope...)}},
				})
				if e != nil {
					t.Fatal(e)
				}
				if !r.GetAccepted() || r.GetAccept() == nil {
					t.Fatalf("real second acceptance missing: %+v", r)
				}
				second, found, e := holder.DB.ClaimState(c.f.Context(), s.Key)
				if e != nil || !found || second.Accept == nil || !second.Accepted.Equal(s.Accepted) || second.ValueDigest != s.ValueDigest {
					t.Fatalf("second stored vote is not same-ballot chosen evidence: %+v %v", second, e)
				}
				cfg, e := corrosion.AdoptedVoterConfig(c.f.Context(), holder.DB)
				if e != nil {
					t.Fatal(e)
				}
				v, e := corrosion.LoadClaimVerifier(holder.PKIDir)
				if e != nil {
					t.Fatal(e)
				}
				chosen := corrosion.ClaimCertificate{Key: s.Key, ConfigGeneration: s.ConfigGeneration, Ballot: s.Accepted, ValueDigest: s.ValueDigest, Accepts: []corrosion.ClaimAccept{*s.Accept, *second.Accept}}
				if e := v.Verify(chosen, corrosion.CertExpectation{Key: s.Key, ConfigGeneration: cfg.Generation, ValueDigest: s.ValueDigest, Electorate: cfg.Members, Quorum: corrosion.MajorityOf(len(cfg.Members))}); e != nil {
					t.Fatalf("unpublished owner was not actually chosen: %v", e)
				}
				c.assertNoOwnerEffects(t, before, "unpublished-native-owner")
			}
			// The bearer is genuinely revoked before the origin becomes
			// unreachable. Recovery is performed by the surviving ordinary
			// engine and must use accepted bytes, never that bearer.
			if _, e := c.f.cluster.SelfClient(c.f.cluster.Nodes[0]).Logout(c.ctx, &emptypb.Empty{}); e != nil {
				t.Fatal(e)
			}
			c.f.Isolate(0)
			t.Cleanup(func() { c.f.Heal(0) })
			r, e := c.f.Engine(1).Submit(c.f.Context(), c.f.Barrier(1, "recover-after-origin-loss"))
			if !survivingHolder {
				// A majority that cannot see any accepted value may choose its
				// barrier: the lost minority vote never made the owner chosen.
				if e != nil {
					t.Fatalf("available majority barrier: %v", e)
				}
				for _, n := range c.f.cluster.Nodes[1:] {
					rows, e := n.DB.Query(c.f.Context(), `SELECT count(*) AS n FROM local_automation_owners WHERE stage='' AND project_uid=? AND owner_id=?`, c.owner.ProjectUid, c.owner.OwnerId)
					if e != nil || len(rows) != 1 || rows[0].Int64("n") != 0 {
						t.Fatalf("lost minority supplied false owner authority: %+v %v", rows, e)
					}
				}
				return
			}
			if e != nil || r.Sequence != before.Sequence+2 {
				t.Fatalf("highest chosen bytes not recovered before new command: %+v %v", r, e)
			}
			for _, n := range c.f.cluster.Nodes[1:] {
				record, found, e := n.DB.AutomationRecord(c.f.Context(), before.Sequence+1)
				if e != nil || !found || record.Value.Automation == nil || !bytes.Equal(record.Value.Automation.Envelope, s.Value.Automation.Envelope) {
					t.Fatalf("%s recovery changed original accepted bytes: %+v %v", n.Name, record, e)
				}
			}
			c.f.Heal(0)
			c.f.Converge(t)
			c.assertDecision(t, &automationv1.ReadCursor{AppliedSequence: before.Sequence + 1}, "ensure_owner", "unpublished-native-owner", "", 0)
			c.assertOwner(t, "", 0)
		})
	}
}

func TestAutomationOwnerSessionNativeOwnHolderRenewal(t *testing.T) {
	c := newNativeOwnerClient(t, false)
	before, s := nativeOwnerUnpublished(t, c)
	n := c.f.cluster.Nodes[0]
	oldCert := s.Accept.CertPEM
	if _, e := c.f.cluster.SelfClient(n).Logout(c.ctx, &emptypb.Empty{}); e != nil {
		t.Fatal(e)
	}
	installRenewal(t, c.f.cluster, n) // existing CA-authenticated native host renewal
	// No public replay can authorize this new ballot. The actual own durable
	// signed row must be the base for renewal with the current served key.
	r := nativeOwnerPeerAccept(t, c, 0, s, s.Accepted.Round+20, nil)
	if !r.GetAccepted() || r.GetAccept() == nil || r.GetAccept().GetCertPem() == oldCert {
		t.Fatalf("holder did not renew actual durable vote with current leaf: %+v", r)
	}
	stored, found, e := n.DB.ClaimState(c.f.Context(), s.Key)
	if e != nil || !found || stored.Accept == nil || stored.Value == nil || !bytes.Equal(stored.Value.Automation.Envelope, s.Value.Automation.Envelope) {
		t.Fatalf("renewal changed accepted owner bytes: %+v %v", stored, e)
	}
	c.assertNoOwnerEffects(t, before, "unpublished-native-owner")
}

func TestAutomationOwnerSessionNativeAcceptedTargetIsExact(t *testing.T) {
	c := newNativeOwnerClient(t, false)
	if _, e := c.public.EnsureOwner(c.ctx, &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: "target-binding-owner"}); e != nil {
		t.Fatal(e)
	}
	before := c.f.Head(t, 0)
	undo1 := c.f.cluster.Nodes[1].DoNotImplement("AcceptRecoveryClaim")
	undo2 := c.f.cluster.Nodes[2].DoNotImplement("AcceptRecoveryClaim")
	r, e := c.public.AcquireOwnerSession(c.ctx, &automationv1.AcquireOwnerSessionRequest{Owner: c.owner, RequestId: "target-binding-acquire", SessionId: "actual-issued-target"})
	undo1()
	undo2()
	if r != nil || status.Code(e) != codes.Unavailable {
		t.Fatalf("expected actual unpublished native acquisition: %+v %v", r, e)
	}
	key, e := corrosion.AutomationClaimKey(before.Sequence + 1)
	if e != nil {
		t.Fatal(e)
	}
	s, found, e := c.f.cluster.Nodes[0].DB.ClaimState(c.f.Context(), key)
	if e != nil || !found || s.Accept == nil || s.Value == nil {
		t.Fatalf("actual acquisition vote absent: %+v %v", s, e)
	}
	d, e := contract.DecodeDecision(s.Value.Automation.Envelope)
	if e != nil {
		t.Fatal(e)
	}
	a, e := contract.DecodeAssignment(d)
	if e != nil || a.Owner == nil || a.Owner.SessionID != "actual-issued-target" {
		t.Fatalf("native acquisition lost caller target: %+v %v", a, e)
	}
	a.Owner.SessionID = "unissued-altered-target"
	d.Assignment, e = json.Marshal(a)
	if e != nil {
		t.Fatal(e)
	}
	envelope, e := contract.EncodeDecision(d)
	if e != nil {
		t.Fatal(e)
	}
	altered := nativeOwnerPeerAccept(t, c, 1, s, s.Accepted.Round+10, &pb.RecoveryClaimValue{Automation: &pb.AutomationClaimValue{Envelope: envelope}})
	if altered.GetAccepted() || altered.GetAccept() != nil {
		t.Fatalf("stored vote laundered a changed session target: %+v", altered)
	}
	state, _, e := c.f.cluster.Nodes[1].DB.ClaimState(c.f.Context(), key)
	if e != nil || state.Accept != nil || state.Value != nil {
		t.Fatalf("altered target left a valued vote: %+v %v", state, e)
	}
	matching := nativeOwnerPeerAccept(t, c, 1, s, s.Accepted.Round+20, nil)
	if !matching.GetAccepted() || matching.GetAccept() == nil {
		t.Fatalf("exact original acquisition evidence unavailable: %+v", matching)
	}
	for i := range c.f.cluster.Nodes {
		if c.f.Head(t, i) != before {
			t.Fatal("unpublished target checks advanced a certified head")
		}
	}
	c.assertOwner(t, "", 0)
}
