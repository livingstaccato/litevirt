package grpcapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/health"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// A mixed union must survive conversion so validation can reject it.
func TestLeaseAutomationMixedWireRefused(t *testing.T) {
	a := wireAutomationValue(t)
	for _, name := range []string{"automation", "lun", "config", "proof", "source"} {
		t.Run(name, func(t *testing.T) {
			v := &corrosion.ClaimValue{LeaseTerm: &corrosion.LeaseTermValue{Key: "failover", Term: 7, Holder: "a"}}
			switch name {
			case "automation":
				v.Automation = a.Automation
			case "lun":
				v.LUN = &corrosion.LUNAllocation{}
			case "config":
				v.Config = &corrosion.VoterConfigValue{}
			case "proof":
				v.Proof = &corrosion.ActionProof{ID: "proof"}
			case "source":
				v.SourceHost = "source"
			}
			if _, err := v.Digest(); err == nil {
				t.Error("mixed durable union accepted")
			}
			raw, err := proto.Marshal(valueToPB(v))
			if err != nil {
				t.Fatal(err)
			}
			var p pb.RecoveryClaimValue
			if err = proto.Unmarshal(raw, &p); err != nil {
				t.Fatal(err)
			}
			got := valueFromPB(&p)
			if (v.Automation != nil) != (got.Automation != nil) || (v.LUN != nil) != (got.LUN != nil) || (v.Config != nil) != (got.Config != nil) || (v.Proof != nil) != (got.Proof != nil) || v.SourceHost != got.SourceHost || !reflect.DeepEqual(v.LeaseTerm, got.LeaseTerm) {
				t.Errorf("conversion dropped alternatives: want %+v got %+v", v, got)
			}
			if _, err = checkedValueFromPB(&p); err == nil {
				t.Error("mixed binary union accepted")
			}
			key := corrosion.ClaimKey{TargetKind: "lease_term", TargetName: "failover", OwnerEpoch: 7, Incarnation: "legacy-fixture"}
			for _, wrap := range []proto.Message{&pb.AcceptRecoveryClaimRequest{Value: &p}, &pb.PrepareRecoveryClaimResponse{AcceptedValue: &p}, &pb.PrepareRecoveryClaimResponse{LegacyAcceptedValue: &p, LegacyAcceptedBallot: &pb.ClaimBallot{Round: 1}}, &pb.GetRecoveryClaimResponse{State: &pb.PrepareRecoveryClaimResponse{AcceptedValue: &p}}, &pb.RecoveryClaimState{Value: &p}} {
				raw, err := proto.Marshal(wrap)
				if err != nil {
					t.Fatal(err)
				}
				copy := wrap.ProtoReflect().New().Interface()
				if err = proto.Unmarshal(raw, copy); err != nil {
					t.Fatal(err)
				}
				switch m := copy.(type) {
				case *pb.AcceptRecoveryClaimRequest:
					_, err = checkedValueFromPB(m.Value)
				case *pb.PrepareRecoveryClaimResponse:
					_, err = prepareFromPB(m, key)
				case *pb.GetRecoveryClaimResponse:
					_, err = prepareFromPB(m.State, key)
				case *pb.RecoveryClaimState:
					_, err = checkedValueFromPB(m.Value)
				}
				if err == nil {
					t.Errorf("%T accepted malformed alternatives", wrap)
				}
			}

		})
	}
}

func TestLeaseAutomationWireEnvelopes(t *testing.T) {
	for _, v := range []*corrosion.ClaimValue{wireAutomationValue(t), {LeaseTerm: &corrosion.LeaseTermValue{Key: "future_lease", Term: 17, Holder: "holder"}}} {
		p := valueToPB(v)
		key := &pb.RecoveryClaimKey{TargetKind: "lease_term", TargetName: "future_lease", OwnerEpoch: 17}
		if v.Automation != nil {
			key = &pb.RecoveryClaimKey{TargetKind: "automation", TargetName: "cluster", OwnerEpoch: 1}
		}
		ballot := &pb.ClaimBallot{Round: 2, Coordinator: "holder", BootNonce: []byte{0, 255}}
		accept := &pb.ClaimAccept{Key: key, Ballot: ballot, ConfigGeneration: 1, ValueDigest: v.MustDigest(), Signature: []byte{0, 255, 7}, CertPem: "retained", Voter: "voter", VoterIncarnation: "inc"}
		prepare := &pb.PrepareRecoveryClaimResponse{AcceptedValue: p, LegacyAcceptedValue: p, AcceptedBallot: ballot, LegacyAcceptedBallot: ballot, PromisedBallot: ballot}
		for _, m := range []proto.Message{p, &pb.AcceptRecoveryClaimRequest{Key: key, Ballot: ballot, Value: p, ConfigGeneration: 1}, prepare, &pb.GetRecoveryClaimResponse{State: prepare, Accept: accept, Reattested: accept}, &pb.RecoveryClaimState{Key: key, Value: p, ValueDigest: v.MustDigest(), Accepted: ballot, Promised: ballot}, &pb.AcceptRecoveryClaimResponse{Accept: accept}} {
			raw, err := proto.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			copy := m.ProtoReflect().New().Interface()
			if err = proto.Unmarshal(raw, copy); err != nil || !proto.Equal(m, copy) {
				t.Fatalf("%T binary loss: %v", m, err)
			}
		}
		got, err := checkedValueFromPB(p)
		if err != nil || !reflect.DeepEqual(v, got) || v.MustDigest() != got.MustDigest() {
			t.Fatal("value/digest changed", err)
		}
	}
	d := (&pb.RecoveryClaimValue{}).ProtoReflect().Descriptor().Fields()
	if d.ByName("automation").Number() != 16 || d.ByName("lease_term_claim").Number() != 15 {
		t.Fatal("wrong numeric union")
	}
	// Shipped field15 lease bytes retain their meaning for existing readers.
	nested, _ := proto.Marshal(&pb.LeaseTermClaimValue{Key: "failover", Term: 17, Holder: "a"})
	raw := protowire.AppendTag(nil, 15, protowire.BytesType)
	raw = protowire.AppendBytes(raw, nested)
	var old pb.RecoveryClaimValue
	if err := proto.Unmarshal(raw, &old); err != nil {
		t.Fatal(err)
	}
	if got, err := checkedValueFromPB(&old); err != nil || got.LeaseTerm == nil || got.Automation != nil || got.LeaseTerm.Key != "failover" || got.LeaseTerm.Term != 17 || got.LeaseTerm.Holder != "a" {
		t.Fatal("shipped lease15 changed meaning", got, err)
	}
}

type wireClaimPeer struct {
	pb.LiteVirtClient
	caps                     []string
	pingErr                  error
	name                     string
	refusal                  string
	payload, legacyPayload   *pb.RecoveryClaimValue
	prepares, accepts, pings atomic.Int32
}

func (p *wireClaimPeer) Ping(context.Context, *pb.PingRequest, ...grpc.CallOption) (*pb.PingResponse, error) {
	p.pings.Add(1)
	return &pb.PingResponse{Capabilities: p.caps, VoterGeneration: 1}, p.pingErr
}
func (p *wireClaimPeer) PrepareRecoveryClaim(context.Context, *pb.PrepareRecoveryClaimRequest, ...grpc.CallOption) (*pb.PrepareRecoveryClaimResponse, error) {
	p.prepares.Add(1)
	r := &pb.PrepareRecoveryClaimResponse{Promised: p.refusal == "", Voter: p.name, AcceptedValue: p.payload, LegacyAcceptedValue: p.legacyPayload}
	if p.refusal != "" {
		r.RefusalReason = corrosion.RefusalInvalidValue
		r.RefusalDetail = p.refusal
	}
	return r, nil
}
func (p *wireClaimPeer) AcceptRecoveryClaim(context.Context, *pb.AcceptRecoveryClaimRequest, ...grpc.CallOption) (*pb.AcceptRecoveryClaimResponse, error) {
	p.accepts.Add(1)
	return &pb.AcceptRecoveryClaimResponse{Accepted: true, Voter: p.name}, nil
}
func TestLeaseWirePeerSupport(t *testing.T) {
	for _, tc := range []struct {
		name string
		caps []string
		err  error
		ok   bool
	}{{"v1", []string{capabilities.LeaseTermClaimV1}, nil, true}, {"empty", nil, nil, false}, {"unknown", []string{"future_unknown"}, nil, false}, {"failed", []string{capabilities.LeaseTermClaimV1}, errors.New("unreachable"), false}} {
		t.Run(tc.name, func(t *testing.T) {
			s := namedVoterServer(t)
			p := &wireClaimPeer{caps: tc.caps, pingErr: tc.err, name: "peer"}
			s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return p, func() {}, nil }
			tr := serverClaimTransport{s}
			k := corrosion.LeaseTermClaimKey("failover", 1)
			b := corrosion.Ballot{Round: 1, Coordinator: s.hostName}
			r, err := tr.Prepare(context.Background(), "peer", k, b, 1, nil)
			if (err == nil && r.Promised) != tc.ok {
				t.Errorf("Prepare support gate: result=%+v err=%v", r, err)
			}
			ar, err := tr.Accept(context.Background(), "peer", k, b, corrosion.ClaimValue{LeaseTerm: &corrosion.LeaseTermValue{Key: "failover", Term: 1, Holder: s.hostName}}, 1)
			if (err == nil && ar.Accepted) != tc.ok {
				t.Errorf("Accept support gate: result=%+v err=%v", ar, err)
			}
			if p.pings.Load() < 2 {
				t.Error("no fresh authenticated capability observations")
			}
			if !tc.ok && p.accepts.Load() != 0 {
				t.Error("sent lease payload to incompatible peer")
			}
			// Unaffected workload traffic is not made dependent on lease capability.
			_, err = tr.Prepare(context.Background(), "peer", corrosion.ClaimKey{TargetKind: "vm", TargetName: "vm", OwnerEpoch: 1}, b, 1, nil)
			if err != nil {
				t.Fatal("nonlease traffic gated", err)
			}
		})
	}
}

// Hold the real serving round and connection, not a simulated worker exit.
func TestRunLBReconciler_CancelJoinsActualVRRPChild(t *testing.T) {
	s := vrrpServer(t, true, false, false)
	s.lbKick = make(chan struct{}, 1)
	s.vrrpAskKick = make(chan struct{}, 1)
	s.vrrpRefusedLBs = map[string]string{"held": "reason"}
	s.vrrpRefusedEpoch = map[string]uint64{"held": 1}
	s.vrrpRefusedHosts = map[string][]string{"held": {"peer-1"}}
	entered, release, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	p := &heldServingPeer{entered: entered, release: release}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return p, func() { close(closed) }, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.RunLBReconciler(ctx, time.Hour); close(done) }()
	s.vrrpAskKick <- struct{}{}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		cancel()
		close(release)
		t.Fatal("real child did not enter peer call")
	}
	cancel()
	early := false
	select {
	case <-done:
		early = true
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("peer connection not closed")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("parent not joined")
	}
	if early {
		t.Fatal("parent returned while actual VRRP child and connection were held")
	}
}

type heldServingPeer struct {
	pb.LiteVirtClient
	entered chan struct{}
	release chan struct{}
}

func (p *heldServingPeer) CheckLBPresent(context.Context, *pb.CheckLBPresentRequest, ...grpc.CallOption) (*pb.CheckLBPresentResponse, error) {
	close(p.entered)
	<-p.release
	return &pb.CheckLBPresentResponse{}, nil
}

func TestLeaseWireExistingCapabilityRegistered(t *testing.T) {
	if !slices.Contains(capabilities.Supported(), capabilities.LeaseTermClaimV1) || !slices.Contains(capabilities.All(), capabilities.LeaseTermClaimV1) || !capabilities.Mandatory(capabilities.LeaseTermClaimV1) || !capabilities.ReplicationGated(capabilities.LeaseTermClaimV1) {
		t.Fatal("wire support registry incomplete")
	}
	for _, f := range capabilities.Features() {
		info, _ := capabilities.LookupFeature(f)
		if info.Token == capabilities.LeaseTermClaimV1 {
			t.Fatal("wire support added to release features")
		}
	}
}

type importWirePeer struct {
	*wireClaimPeer
	messages []*pb.RecoveryClaimState
}
type importWireStream struct {
	grpc.ClientStream
	messages []*pb.RecoveryClaimState
}

func (p *importWirePeer) ListRecoveryClaims(context.Context, *pb.ListRecoveryClaimsRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.RecoveryClaimState], error) {
	return &importWireStream{messages: p.messages}, nil
}
func (p *importWireStream) Recv() (*pb.RecoveryClaimState, error) {
	if len(p.messages) == 0 {
		return nil, io.EOF
	}
	m := p.messages[0]
	p.messages = p.messages[1:]
	raw, err := proto.Marshal(m)
	if err != nil {
		return nil, err
	}
	out := new(pb.RecoveryClaimState)
	err = proto.Unmarshal(raw, out)
	return out, err
}
func TestLeaseWireImportRefusesWholeSource(t *testing.T) {
	for _, support := range []string{"v1", "pre_kind", "failed", "empty"} {
		t.Run(support, func(t *testing.T) {
			s := namedVoterServer(t)
			p := &importWirePeer{wireClaimPeer: &wireClaimPeer{name: "peer"}}
			switch support {
			case "v1":
				p.caps = []string{capabilities.LeaseTermClaimV1}
			case "pre_kind":
				p.caps = []string{capabilities.RecoveryClaimV1}
			case "failed":
				p.pingErr = errors.New("offline")
			}
			value := &corrosion.ClaimValue{LeaseTerm: &corrosion.LeaseTermValue{Key: "future_lease", Term: 7, Holder: "a"}}
			p.messages = []*pb.RecoveryClaimState{{Header: true, Voter: "peer", Frozen: true, AdoptedGeneration: 1}, {Key: &pb.RecoveryClaimKey{TargetKind: "vm", TargetName: "ordinary", OwnerEpoch: 1}, Promised: &pb.ClaimBallot{Round: 1, Coordinator: "peer"}}, {Key: keyToPB(corrosion.LeaseTermClaimKey("future_lease", 7)), Value: valueToPB(value), ValueDigest: value.MustDigest(), Accepted: &pb.ClaimBallot{Round: 2, Coordinator: "a"}, Promised: &pb.ClaimBallot{Round: 9, Coordinator: "a"}}}
			s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return p, func() {}, nil }
			out, err := s.fetchImportSource(context.Background(), "peer", 1)
			if support == "v1" {
				if err != nil || len(out.States) != 2 || !reflect.DeepEqual(out.States[1].Value, value) || out.States[1].ValueDigest != value.MustDigest() {
					t.Fatal("full import lost union/digest", out, err)
				}
			} else if err == nil || len(out.States) != 0 {
				t.Fatal("incompatible source returned a partial import", out, err)
			}
		})
	}
}

type leaseStateStream struct {
	grpc.ServerStreamingServer[pb.RecoveryClaimState]
	ctx  context.Context
	sent int
}

func (s *leaseStateStream) Context() context.Context          { return s.ctx }
func (s *leaseStateStream) Send(*pb.RecoveryClaimState) error { s.sent++; return nil }
func TestLeaseWireInboundRefusesBeforeState(t *testing.T) {
	s := namedVoterServer(t)
	ctx := context.Background()
	insertTestHost(t, ctx, s.db, "peer-1", "active")
	inc, err := s.db.VoterIncarnation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	adoptTestGeneration(t, s, []corrosion.VoterMember{{Name: s.hostName, Incarnation: inc}})
	k := corrosion.LeaseTermClaimKey("failover", 7)
	v := corrosion.ClaimValue{LeaseTerm: &corrosion.LeaseTermValue{Key: "failover", Term: 7, Holder: s.hostName}}
	signer, _, err := s.claimIdentity()
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.db.ClaimAccept(ctx, k, corrosion.Ballot{Round: 2, Coordinator: s.hostName}, v, 1, signer, nil)
	if err != nil || !a.Accepted {
		t.Fatal("seed real state", err, a)
	}
	p := &wireClaimPeer{name: "peer-1", caps: []string{capabilities.RecoveryClaimV1}}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return p, func() {}, nil }
	peer := mtlsCtx("peer-1")
	b := &pb.ClaimBallot{Round: 9, Coordinator: "peer-1"}
	if _, err = s.PrepareRecoveryClaim(peer, &pb.PrepareRecoveryClaimRequest{Key: keyToPB(k), Ballot: b, ConfigGeneration: 1}); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("inbound prepare wire refusal", err)
	}
	if _, err = s.AcceptRecoveryClaim(peer, &pb.AcceptRecoveryClaimRequest{Key: keyToPB(k), Ballot: b, Value: valueToPB(&v), ConfigGeneration: 1}); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("inbound accept wire refusal", err)
	}
	nested, _ := proto.Marshal(&pb.LeaseTermClaimValue{Key: "failover", Term: 7, Holder: s.hostName})
	raw := protowire.AppendTag(nil, 15, protowire.BytesType)
	raw = protowire.AppendBytes(raw, nested)
	var old pb.RecoveryClaimValue
	if err = proto.Unmarshal(raw, &old); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AcceptRecoveryClaim(peer, &pb.AcceptRecoveryClaimRequest{Key: keyToPB(k), Ballot: b, Value: &old, ConfigGeneration: 1}); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("lease15 sent state to a peer without lease support", err)
	}
	if _, err = s.GetRecoveryClaim(peer, &pb.GetRecoveryClaimRequest{Key: keyToPB(k)}); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("inbound get wire refusal", err)
	}
	stream := &leaseStateStream{ctx: peer}
	if err = s.ListRecoveryClaims(&pb.ListRecoveryClaimsRequest{ConfigGeneration: 1}, stream); status.Code(err) != codes.FailedPrecondition || stream.sent != 0 {
		t.Fatal("inbound list sent partial source", err, stream.sent)
	}
	st, _, err := s.db.ClaimState(ctx, k)
	if err != nil || st.Promised.Round != 2 {
		t.Fatal("wire refusal wrote state", err, st)
	}
}
func TestLeaseWireWholeElectorateAndExactFallback(t *testing.T) {
	names := []string{"a", "b", "c", "d", "e"}
	key := corrosion.LeaseTermClaimKey("failover", 1)
	spec := leaseTermClaimSpec(key, 1, names, corrosion.LeaseMintRequest{Key: "failover", Term: 1, Holder: "a"}, "a")
	voters, q := spec.Electorate(corrosion.ClaimValue{})
	if spec.PrepareQuorum != 3 || q != 3 || !reflect.DeepEqual(names, voters) {
		t.Fatal("denominator filtered")
	}
	for _, detail := range []string{olderBuildRefusal, "prefix " + olderBuildRefusal, olderBuildRefusal + " suffix"} {
		nm := &claims.NoMajorityError{Phase: "prepare", Need: 3, Refusals: []claims.Refusal{{Voter: "b", Reason: corrosion.RefusalInvalidValue, Detail: detail}, {Voter: "c", Reason: corrosion.RefusalInvalidValue, Detail: detail}, {Voter: "d", Reason: corrosion.RefusalInvalidValue, Detail: detail}}}
		if got := olderBuildsBlockAMajority(nm, names, 3); got != (detail == olderBuildRefusal) {
			t.Errorf("nonexact old-kind evidence %q fallback=%v", detail, got)
		}
	}
}

func TestLeaseWireWholeElectorateActualFallback(t *testing.T) {
	for _, mode := range []string{"unknown_support", "pre_kind", "pre_kind_enforcement_off", "latched_pre_kind"} {
		t.Run(mode, func(t *testing.T) {
			s := namedVoterServer(t)
			ctx := context.Background()
			inc, err := s.db.VoterIncarnation(ctx)
			if err != nil {
				t.Fatal(err)
			}
			adoptTestGeneration(t, s, []corrosion.VoterMember{{Name: s.hostName, Incarnation: inc}, {Name: "b", Incarnation: "b"}, {Name: "c", Incarnation: "c"}, {Name: "d", Incarnation: "d"}})
			s.SetGate(fakeServerGate{quorum: health.QuorumYes, durablyLatchedTok: map[string]bool{capabilities.LeaseTermClaimV1: mode == "latched_pre_kind"}})
			s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
				if host == "d" {
					return nil, nil, errors.New("unreachable")
				}
				caps := []string{capabilities.RecoveryClaimV1}
				if mode == "pre_kind_enforcement_off" {
					caps = []string{capabilities.LeaseTermLedgerV1}
				}
				if mode == "unknown_support" {
					caps = []string{"unknown_future_token"}
				}
				return &wireClaimPeer{name: host, caps: caps, refusal: olderBuildRefusal}, func() {}, nil
			}
			cfg, err := corrosion.AdoptedVoterConfig(ctx, s.db)
			if err != nil {
				t.Fatal(err)
			}
			call, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			ok, why := s.claimLeaseTerm(call, cfg, corrosion.LeaseMintRequest{Key: "failover", Term: 1, Holder: s.hostName, TTL: 30 * time.Second}, time.Now())
			if ok != (mode == "pre_kind" || mode == "pre_kind_enforcement_off") {
				t.Fatal("whole electorate/fallback boundary", mode, ok, why)
			}
			st, _, err := s.db.ClaimState(ctx, corrosion.LeaseTermClaimKey("failover", 1))
			if err != nil || st.Value != nil {
				t.Fatal("partial electorate created local-only lease", err, st)
			}
		})
	}
}

func TestLeaseWirePreKindRequiresExactPayloadFreeRefusal(t *testing.T) {
	for _, mode := range []string{"known_exact", "unknown_only", "known_no_refusal", "known_nonexact", "known_accepted_payload", "known_legacy_payload"} {
		t.Run(mode, func(t *testing.T) {
			s := namedVoterServer(t)
			p := &wireClaimPeer{name: "peer", caps: []string{capabilities.LeaseTermLedgerV1}, refusal: olderBuildRefusal}
			switch mode {
			case "unknown_only":
				p.caps = []string{"unknown_future_token"}
			case "known_no_refusal":
				p.refusal = ""
			case "known_nonexact":
				p.refusal += " suffix"
			case "known_accepted_payload":
				p.payload = &pb.RecoveryClaimValue{}
			case "known_legacy_payload":
				p.legacyPayload = &pb.RecoveryClaimValue{}
			}
			s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return p, func() {}, nil }
			got, err := (serverClaimTransport{s}).Prepare(context.Background(), "peer", corrosion.LeaseTermClaimKey("failover", 1), corrosion.Ballot{Round: 1, Coordinator: s.hostName}, 1, nil)
			if mode == "known_exact" {
				if err != nil || got.Promised || got.Refusal != corrosion.RefusalInvalidValue || got.Detail != olderBuildRefusal {
					t.Fatal("known enforcement-off exact probe refused", got, err)
				}
			} else if err == nil {
				t.Fatal("non-proof accepted as pre-kind refusal", mode, got)
			}
			if mode == "unknown_only" && p.prepares.Load() != 0 {
				t.Fatal("unknown observation sent probe")
			}
		})
	}
}

func TestShippedLeaseField15Bytes(t *testing.T) {
	// Field 15 and the nested lease layout are the shipped integration encoding.
	raw, err := hex.DecodeString("7a0f0a086661696c6f76657210111a0161")
	if err != nil {
		t.Fatal(err)
	}
	var p pb.RecoveryClaimValue
	if err := proto.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	got, err := checkedValueFromPB(&p)
	if err != nil || got.LeaseTerm == nil || got.Automation != nil || got.LeaseTerm.Key != "failover" || got.LeaseTerm.Term != 17 || got.LeaseTerm.Holder != "a" {
		t.Fatalf("shipped lease15 decoded incorrectly: %+v %v", got, err)
	}
	again, err := proto.Marshal(valueToPB(got))
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatalf("lease15 bytes changed: %x %v", again, err)
	}
	automation := valueToPB(wireAutomationValue(t))
	encoded, err := proto.Marshal(automation)
	if err != nil {
		t.Fatal(err)
	}
	number, kind, n := protowire.ConsumeTag(encoded)
	if number != 16 || kind != protowire.BytesType || n != 2 {
		t.Fatalf("automation must use distinct two-byte field16 tag: %x", encoded[:min(8, len(encoded))])
	}
}

func TestLeaseWireV1InboundReadsShippedState(t *testing.T) {
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
		t.Fatal("real seed", accepted, err)
	}
	p := &wireClaimPeer{name: "peer-1", caps: []string{capabilities.LeaseTermClaimV1}}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return p, func() {}, nil }
	peer := mtlsCtx("peer-1")
	got, err := s.GetRecoveryClaim(peer, &pb.GetRecoveryClaimRequest{Key: keyToPB(key)})
	if err != nil || got.GetState().GetAcceptedValue().GetLeaseTermClaim().GetTerm() != 17 {
		t.Fatal("shipped V1 reader refused", got, err)
	}
	stream := &leaseStateStream{ctx: peer}
	if err := s.ListRecoveryClaims(&pb.ListRecoveryClaimsRequest{ConfigGeneration: 1}, stream); err != nil || stream.sent < 2 {
		t.Fatal("shipped V1 list refused", err, stream.sent)
	}
}
