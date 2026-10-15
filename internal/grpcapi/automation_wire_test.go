package grpcapi

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/protobuf/proto"
)

// Mutation: drop any of the four formerly omitted LUN fields.
func TestAutomationLUNBinaryRoundtrip(t *testing.T) {
	for _, kept := range []bool{false, true} {
		v := &corrosion.ClaimValue{LUN: &corrosion.LUNAllocation{LUN: "lun", Generation: 1, ClaimID: "claim", VMID: "vmid", VMName: "vm", Disk: "disk", Host: "host"}}
		if kept {
			v.LUN.RunHost = "run"
			v.LUN.Kept = true
			v.LUN.Project = "project"
			v.LUN.ReplacedCreatedAt = "created"
		}
		b, err := proto.Marshal(valueToPB(v))
		if err != nil {
			t.Fatal(err)
		}
		if !kept && hex.EncodeToString(b) != "72240a036c756e10011a05636c61696d2204766d69642a02766d32046469736b3a04686f7374" {
			t.Fatal("legacy LUN wire bytes changed")
		}
		var p pb.RecoveryClaimValue
		if err = proto.Unmarshal(b, &p); err != nil {
			t.Fatal(err)
		}
		got := valueFromPB(&p)
		if !reflect.DeepEqual(v, got) || v.MustDigest() != got.MustDigest() {
			t.Fatal("LUN lost decision fields over binary transport")
		}
		// Membership export/import carries the same complete value and digest.
		state := &pb.RecoveryClaimState{Value: &p, ValueDigest: v.MustDigest(), Accepted: &pb.ClaimBallot{Round: 1, Coordinator: "host"}, Promised: &pb.ClaimBallot{Round: 2, Coordinator: "host"}}
		raw, err := proto.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		var decoded pb.RecoveryClaimState
		if err := proto.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		imported, err := checkedValueFromPB(decoded.Value)
		if err != nil || !reflect.DeepEqual(v, imported) || imported.MustDigest() != decoded.ValueDigest {
			t.Fatal("membership state lost full LUN", err)
		}

	}
}

func wireAutomationValue(t *testing.T) *corrosion.ClaimValue {
	t.Helper()
	b, err := contract.EncodeDecision(contract.Decision{Sequence: 1, Command: contract.Command{Kind: "initialize_cluster", ClusterUID: "", RequestID: "request", Session: 4, Ciphertext: []byte{0, 255, 5}, Body: []byte(`{"version":1}`)}})
	if err != nil {
		t.Fatal(err)
	}
	return &corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: b}}
}

// Mutation: drop complete bytes, silently select a legacy alternative, or swallow decode errors.
func TestAutomationBinaryTransport(t *testing.T) {
	v := wireAutomationValue(t)
	b, err := proto.Marshal(valueToPB(v))
	if err != nil {
		t.Fatal(err)
	}
	var p pb.RecoveryClaimValue
	if err = proto.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	got, err := checkedValueFromPB(&p)
	if err != nil || !reflect.DeepEqual(v, got) || v.MustDigest() != got.MustDigest() {
		t.Fatal("automation wire loss", err)
	}
	key := corrosion.ClaimKey{TargetKind: "automation", TargetName: "cluster", OwnerEpoch: 1}
	ballot := &pb.ClaimBallot{Round: 1, Coordinator: "node"}
	response := &pb.PrepareRecoveryClaimResponse{Promised: true, PromisedBallot: ballot, AcceptedBallot: ballot, AcceptedValue: &p}
	raw, _ := proto.Marshal(response)
	var decoded pb.PrepareRecoveryClaimResponse
	_ = proto.Unmarshal(raw, &decoded)
	if _, err := prepareFromPB(&decoded, key); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*pb.RecoveryClaimValue){
		func(v *pb.RecoveryClaimValue) { v.Id = "proof" },
		func(v *pb.RecoveryClaimValue) { v.SourceHost = "source" },
		func(v *pb.RecoveryClaimValue) { v.Lun = &pb.LUNAllocationValue{} },
		func(v *pb.RecoveryClaimValue) { v.VoterConfig = &pb.VoterConfigValue{} },
	} {
		mixed := proto.Clone(&p).(*pb.RecoveryClaimValue)
		mutate(mixed)
		if _, err := checkedValueFromPB(mixed); err == nil {
			t.Fatal("mixed alternatives hidden")
		}
		response.AcceptedValue = mixed
		if _, err := prepareFromPB(response, key); err == nil {
			t.Fatal("prepare swallowed malformed acceptance")
		}
	}
	response.AcceptedValue = nil
	if _, err := prepareFromPB(response, key); err == nil {
		t.Fatal("missing value treated as empty slot")
	}
}

// Mutation: increase the admitted complete envelope beyond recovery capacity,
// or duplicate it inside one of the real protobuf recovery wrappers.
func TestAutomationLargestRecoveryMessages(t *testing.T) {
	// Find the last admitted ciphertext byte; JSON contains base64 twice across
	// the command and the enclosing local value, so raw payload size is unsafe.
	d := contract.Decision{Sequence: 1, Command: contract.Command{Kind: "initialize_cluster", RequestID: "request"}}
	lo, hi := 0, 2<<20
	var envelope []byte
	for lo < hi {
		mid := (lo + hi + 1) / 2
		d.Command.Ciphertext = make([]byte, mid)
		b, err := contract.EncodeDecision(d)
		if err != nil {
			hi = mid - 1
		} else {
			lo = mid
			envelope = b
		}
	}
	d.Command.Ciphertext = make([]byte, lo)
	envelope, err := contract.EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	v := &corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: envelope}}
	if _, err := v.Digest(); err != nil {
		t.Fatal("largest decision not storable", err)
	}
	encoded, err := json.Marshal(v)
	if err != nil || len(encoded) > 2<<20 || len(encoded) < 1900<<10 {
		t.Fatal("complete storage bound", len(encoded), err)
	}
	key := &pb.RecoveryClaimKey{TargetKind: "automation", TargetName: "cluster", OwnerEpoch: math.MaxInt64}
	ballot := &pb.ClaimBallot{Round: math.MaxInt64, Coordinator: strings.Repeat("n", 4096), BootNonce: make([]byte, 256)}
	accept := &pb.ClaimAccept{Voter: strings.Repeat("n", 4096), VoterIncarnation: strings.Repeat("i", 4096), ConfigGeneration: math.MaxInt64, Key: key, Ballot: ballot, ValueDigest: strings.Repeat("d", 64), CertPem: strings.Repeat("c", 64<<10), Signature: make([]byte, 256)}
	prepare := &pb.PrepareRecoveryClaimResponse{Promised: true, PromisedBallot: ballot, AcceptedBallot: ballot, AcceptedValue: valueToPB(v), Voter: accept.Voter, VoterIncarnation: accept.VoterIncarnation}
	for _, m := range []proto.Message{
		&pb.AcceptRecoveryClaimRequest{Key: key, Ballot: ballot, Value: valueToPB(v), ConfigGeneration: math.MaxInt64},
		prepare,
		&pb.GetRecoveryClaimResponse{State: prepare, Accept: accept, Reattested: accept, AdoptedGeneration: math.MaxInt64},
		&pb.RecoveryClaimState{Key: key, Promised: ballot, Accepted: ballot, Value: valueToPB(v), ValueDigest: accept.ValueDigest, Voter: accept.Voter, AdoptedGeneration: math.MaxInt64},
	} {
		b, err := proto.Marshal(m)
		t.Logf("%T: %d bytes (storage JSON %d bytes)", m, len(b), len(encoded))
		if err != nil || len(b) >= 4<<20 {
			t.Fatalf("unrecoverable %T: %d bytes: %v", m, len(b), err)
		}
		copy := m.ProtoReflect().New().Interface()
		if err := proto.Unmarshal(b, copy); err != nil || !proto.Equal(m, copy) {
			t.Fatalf("binary recovery wrapper %T lost bytes: %v", m, err)
		}
	}
}
