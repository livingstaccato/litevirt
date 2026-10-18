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
		b, err := proto.Marshal(mustValueToPB(t, v))
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
	b, err := proto.Marshal(mustValueToPB(t, v))
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
	prepare := &pb.PrepareRecoveryClaimResponse{Promised: true, PromisedBallot: ballot, AcceptedBallot: ballot, AcceptedValue: mustValueToPB(t, v), Voter: accept.Voter, VoterIncarnation: accept.VoterIncarnation}
	for _, m := range []proto.Message{
		&pb.AcceptRecoveryClaimRequest{Key: key, Ballot: ballot, Value: mustValueToPB(t, v), ConfigGeneration: math.MaxInt64},
		prepare,
		&pb.GetRecoveryClaimResponse{State: prepare, Accept: accept, Reattested: accept, AdoptedGeneration: math.MaxInt64},
		&pb.RecoveryClaimState{Key: key, Promised: ballot, Accepted: ballot, Value: mustValueToPB(t, v), ValueDigest: accept.ValueDigest, Voter: accept.Voter, AdoptedGeneration: math.MaxInt64},
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

// This is generic codec/wire capacity evidence, NOT semantic admission or
// certificate validity evidence. Task5 must budget electorate/certificate size
// before activation; future real seed handlers must repeat actual admission at
// their advertised combined limits. Prefix frames include a QUORUM certificate.
func TestAutomationPrefixCombinedMessageBounds(t *testing.T) {
	d := contract.Decision{Sequence: 1, Command: contract.Command{Kind: "initialize_cluster", RequestID: "wire-capacity"}}
	lo, hi := 0, 2<<20
	for lo < hi {
		mid := (lo + hi + 1) / 2
		d.Command.Ciphertext = make([]byte, mid)
		if _, err := contract.EncodeDecision(d); err == nil {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	d.Command.Ciphertext = make([]byte, lo)
	envelope, err := contract.EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	value := corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: envelope}}
	key, _ := corrosion.AutomationClaimKey(1)
	ballot := corrosion.Ballot{Round: math.MaxInt64, Coordinator: strings.Repeat("n", 4096), Nonce: make([]byte, 256)}
	record := corrosion.AutomationRecord{Value: value, Certificate: corrosion.ClaimCertificate{Key: key, Ballot: ballot, ConfigGeneration: math.MaxInt64, ValueDigest: value.MustDigest()}}
	accept := corrosion.ClaimAccept{Key: key, Ballot: ballot, ConfigGeneration: math.MaxInt64, ValueDigest: record.Certificate.ValueDigest, Voter: strings.Repeat("v", 4096), VoterIncarnation: strings.Repeat("i", 4096), Signature: make([]byte, 256), CertPEM: strings.Repeat("c", 64<<10)}
	for {
		record.Certificate.Accepts = append(record.Certificate.Accepts, accept)
		if _, err := encodeAutomationRecord(record); err != nil {
			break
		}
	}
	// Fill the final bounded certificate field to the exact complete-record cap.
	last := len(record.Certificate.Accepts) - 1
	// If the final accept metadata alone crosses the cap, make room in the
	// preceding bounded field before filling the last one. Keep the fixture
	// valid when a cap mutation changes where the final accept lands.
	record.Certificate.Accepts[last].CertPEM = ""
	base, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if excess := len(base) - maxAutomationRecordBytes; excess > 0 {
		previous := &record.Certificate.Accepts[last-1].CertPEM
		if excess > len(*previous) {
			t.Fatal("final accept metadata exceeds bounded fixture field")
		}
		*previous = (*previous)[:len(*previous)-excess]
	}
	lo, hi = 0, 64<<10
	for lo < hi {
		mid := (lo + hi + 1) / 2
		record.Certificate.Accepts[last].CertPEM = strings.Repeat("c", mid)
		if _, err := encodeAutomationRecord(record); err == nil {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	record.Certificate.Accepts[last].CertPEM = strings.Repeat("c", lo)
	encoded, err := encodeAutomationRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != maxAutomationRecordBytes {
		t.Fatalf("fixture did not reach combined record cap: %d", len(encoded))
	}
	decoded, err := decodeAutomationRecord(encoded)
	if err != nil || !reflect.DeepEqual(decoded, record) {
		t.Fatalf("combined prefix lost record: %v", err)
	}
	for _, message := range []proto.Message{&pb.GetAutomationDecisionResponse{Found: true, RecordJson: encoded}, &pb.InstallAutomationDecisionRequest{RecordJson: encoded}} {
		b, err := proto.Marshal(message)
		t.Logf("%T: %d bytes, complete record %d bytes, accepts %d", message, len(b), len(encoded), len(record.Certificate.Accepts))
		if err != nil || len(b) >= 4<<20 {
			t.Fatalf("prefix frame cannot use default peer receive bound: %d %v", len(b), err)
		}
		copy := message.ProtoReflect().New().Interface()
		if err := proto.Unmarshal(b, copy); err != nil || !proto.Equal(message, copy) {
			t.Fatalf("prefix binary wrapper lost bytes: %v", err)
		}
	}
	record.Certificate.Accepts[last].CertPEM += "c"
	if _, err := encodeAutomationRecord(record); err == nil {
		t.Fatal("oversize combined record encoded")
	}
	tooLarge, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeAutomationRecord(tooLarge); err == nil {
		t.Fatal("oversize combined record decoded")
	}
}

// Valid-fixture adapter; production conversion errors must never be ignored.
func mustValueToPB(t *testing.T, v *corrosion.ClaimValue) *pb.RecoveryClaimValue {
	t.Helper()
	out, err := valueToPB(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
