package grpcapi

import (
	"context"
	"encoding/json"
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestStructuredClaimEmptyProofCannotNormalize(t *testing.T) {
	for _, kind := range []string{"lease", "automation"} {
		t.Run(kind, func(t *testing.T) {
			v := wireAutomationValue(t)
			if kind == "lease" {
				v = &corrosion.ClaimValue{LeaseTerm: &corrosion.LeaseTermValue{Key: "failover", Term: 17, Holder: "host"}}
			}
			v.Proof = &corrosion.ActionProof{}
			if _, err := v.Digest(); err == nil {
				t.Fatal("fixture is not a mixed value")
			}
			if out, err := valueToPB(v); err == nil || out != nil {
				t.Error("outbound structured conversion did not explicitly refuse empty Proof corruption")
			}
			for _, result := range []corrosion.PrepareResult{{State: corrosion.ClaimVoterState{Value: v}}, {Legacy: &corrosion.ClaimVoterState{Value: v}}} {
				if out, err := prepareToPB(result); err == nil || out != nil {
					t.Error("prepare conversion normalized mixed evidence")
				}
			}
			if out, err := supersedeToPB(&corrosion.SupersedeEvidence{PriorValue: v}); err == nil || out != nil {
				t.Error("supersede conversion normalized mixed evidence")
			}

		})
	}
	pure := &corrosion.ClaimValue{Proof: &corrosion.ActionProof{}}
	before, err := pure.Digest()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := proto.Marshal(mustValueToPB(t, pure))
	if err != nil {
		t.Fatal(err)
	}
	wire := new(pb.RecoveryClaimValue)
	if err := proto.Unmarshal(raw, wire); err != nil {
		t.Fatal(err)
	}
	got, err := checkedValueFromPB(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Proof == nil || got.MustDigest() != before {
		t.Fatal("pure empty Proof domain changed")
	}
}

func TestPersistedLeaseEmptyProofRefusedAtActualBoundaries(t *testing.T) {
	for _, boundary := range []string{"get", "prepare", "list", "import-source"} {
		t.Run(boundary, func(t *testing.T) {
			s := namedVoterServer(t)
			ctx := context.Background()
			insertTestHost(t, ctx, s.db, "peer-1", "active")
			inc, err := s.db.VoterIncarnation(ctx)
			if err != nil {
				t.Fatal(err)
			}
			adoptTestGeneration(t, s, []corrosion.VoterMember{{Name: s.hostName, Incarnation: inc}})
			key := corrosion.LeaseTermClaimKey("failover", 17)
			value := corrosion.ClaimValue{LeaseTerm: &corrosion.LeaseTermValue{Key: "failover", Term: 17, Holder: s.hostName}}
			signer, _, err := s.claimIdentity()
			if err != nil {
				t.Fatal(err)
			}
			accepted, err := s.db.ClaimAccept(ctx, key, corrosion.Ballot{Round: 2, Coordinator: s.hostName}, value, 1, signer, nil)
			if err != nil || !accepted.Accepted {
				t.Fatal("real signed seed", accepted, err)
			}
			p := &wireClaimPeer{name: "peer-1", caps: []string{capabilities.LeaseTermClaimV1}}
			s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return p, func() {}, nil }
			peer := mtlsCtx("peer-1")
			call := func(round uint64) error {
				switch boundary {
				case "get":
					_, err := s.GetRecoveryClaim(peer, &pb.GetRecoveryClaimRequest{Key: keyToPB(key)})
					return err
				case "prepare":
					_, err := s.PrepareRecoveryClaim(peer, &pb.PrepareRecoveryClaimRequest{Key: keyToPB(key), Ballot: ballotToPB(corrosion.Ballot{Round: round, Coordinator: "peer-1"}), ConfigGeneration: 1})
					return err
				case "list":
					return s.ListRecoveryClaims(&pb.ListRecoveryClaimsRequest{ConfigGeneration: 1}, &leaseStateStream{ctx: peer})
				default:
					_, err := s.fetchImportSource(ctx, s.hostName, 1)
					return err
				}
			}
			if err := call(3); err != nil {
				t.Fatal("valid signed lease positive", err)
			}
			var valid string
			if err := s.db.DB().QueryRow(`SELECT value_json FROM local_recovery_claims WHERE target_kind='lease_term'`).Scan(&valid); err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(valid), &fields); err != nil {
				t.Fatal(err)
			}
			fields["proof"] = json.RawMessage(`{}`)
			corrupt, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.DB().Exec(`UPDATE local_recovery_claims SET value_json=? WHERE target_kind='lease_term'`, string(corrupt)); err != nil {
				t.Fatal(err)
			}
			snapshot := func() string {
				t.Helper()
				rows, err := s.db.Query(ctx, `SELECT * FROM local_recovery_claims ORDER BY target_kind,target_name,owner_epoch,attempt`)
				if err != nil {
					t.Fatal(err)
				}
				b, err := json.Marshal(rows)
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			}
			before := snapshot()
			if err := call(4); err == nil {
				t.Error("persisted mixed lease reached actual boundary without refusal")
			}
			if after := snapshot(); after != before {
				t.Error("corrupt-read refusal changed durable claim evidence")
			}
		})
	}
}

func TestStructuredClaimEmptyProofNeverReachesRemoteRPC(t *testing.T) {
	for _, kind := range []string{"lease", "automation"} {
		t.Run(kind, func(t *testing.T) {
			s := newPeerAuthServer(t)
			peer := &wireClaimPeer{name: "peer-1", caps: []string{capabilities.LeaseTermClaimV1}}
			s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return peer, func() {}, nil }
			v := wireAutomationValue(t)
			key := corrosion.ClaimKey{TargetKind: "automation", TargetName: "cluster", OwnerEpoch: 1}
			if kind == "lease" {
				v = &corrosion.ClaimValue{LeaseTerm: &corrosion.LeaseTermValue{Key: "failover", Term: 17, Holder: "self"}}
				key = corrosion.LeaseTermClaimKey("failover", 17)
			}
			v.Proof = &corrosion.ActionProof{}
			transport := serverClaimTransport{s: s}
			if _, err := transport.Accept(context.Background(), "peer-1", key, corrosion.Ballot{Round: 2, Coordinator: "self"}, *v, 1); err == nil {
				t.Error("remote Accept did not refuse mixed value")
			}
			if _, err := transport.Prepare(context.Background(), "peer-1", key, corrosion.Ballot{Round: 2, Coordinator: "self"}, 1, &corrosion.SupersedeEvidence{PriorValue: v}); err == nil {
				t.Error("remote Prepare did not refuse mixed supersede value")
			}
			if peer.accepts.Load() != 0 || peer.prepares.Load() != 0 {
				t.Error("mixed value reached actual remote RPC", peer.accepts.Load(), peer.prepares.Load())
			}
		})
	}
}
