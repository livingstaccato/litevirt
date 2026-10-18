package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// A real signed near-native value must retain its exact old digest and original
// certificate through validation. No performance observer or mocked codec.
func TestAutomationStateNearNativeSignedValue(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	d := contract.Decision{Sequence: 2, ParentDigest: strings.Repeat("a", 64), Command: contract.Command{Kind: "read_barrier", ClusterUID: "established-cluster", PrincipalID: "fixture", RequestID: "state", Body: []byte(`{"version":1}`), Ciphertext: bytes.Repeat([]byte{0x67}, 1<<20)}, Assignment: []byte(`{"version":1,"cluster_uid":"established-cluster","operation_id":"op","recorded_at":"2026-10-15T00:00:00Z"}`)}
	envelope, e := contract.EncodeDecision(d)
	if e != nil {
		t.Fatal(e)
	}
	value := ClaimValue{Automation: &AutomationClaimValue{Envelope: envelope}}
	key, _ := AutomationClaimKey(2)
	ballot := testBallot(3, "b")
	digest := value.MustDigest()
	accept, e := a.signer.Sign(key, 1, ballot, digest, a.inc)
	if e != nil {
		t.Fatal(e)
	}
	state := ClaimVoterState{Key: key, Promised: ballot, Accepted: ballot, Value: &value, ValueDigest: digest, ConfigGeneration: 1, Accept: &accept}
	before, e := json.Marshal(state)
	if e != nil {
		t.Fatal(e)
	}
	if e = ValidateAutomationState(state); e != nil {
		t.Fatal("actual signed native state refused", e)
	}
	after, e := json.Marshal(state)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before, after) || state.Value.MustDigest() != digest {
		t.Fatal("validation changed exact signed value")
	}
	// A previous validation cannot authorise a later mutated value's save.
	state.Value.Automation.Envelope = append(state.Value.Automation.Envelope, ' ')
	if e = a.c.ExecuteLocal(context.Background(), func(tx *LocalTx) error { return saveClaimRowTx(context.Background(), tx, state) }); e == nil {
		t.Fatal("save trusted stale validation after value mutation")
	}
	if _, found, e := a.c.ClaimState(context.Background(), key); e != nil || found {
		t.Fatal("invalid later save wrote state", e)
	}
}

func TestAutomationStateSummaryRefusals(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	key, value := automationFixture(t, 2, strings.Repeat("a", 64))
	ballot := testBallot(3, "b")
	digest := value.MustDigest()
	accept, e := a.signer.Sign(key, 1, ballot, digest, a.inc)
	if e != nil {
		t.Fatal(e)
	}
	base := ClaimVoterState{Key: key, Promised: ballot, Accepted: ballot, Value: &value, ValueDigest: digest, ConfigGeneration: 1, Accept: &accept}
	for _, name := range []string{"valid", "unsigned", "empty-proof", "config", "lun", "lease", "source", "other-kind", "sequence", "digest", "negative-generation", "promise-order", "accepted-zero", "accept-key", "accept-ballot", "accept-generation", "accept-digest", "accept-voter", "accept-incarnation", "accept-certificate", "accept-signature", "inner-unknown", "inner-duplicate", "inner-trailing", "native-bound"} {
		t.Run(name, func(t *testing.T) {
			in := base
			v := value
			av := *value.Automation
			v.Automation = &av
			in.Value = &v
			signed := accept
			in.Accept = &signed
			switch name {
			case "unsigned":
				in.Accept = nil
			case "empty-proof":
				in.Value.Proof = &ActionProof{}
			case "config":
				in.Value.Config = &VoterConfigValue{}
			case "lun":
				in.Value.LUN = &LUNAllocation{}
			case "lease":
				in.Value.LeaseTerm = &LeaseTermValue{}
			case "source":
				in.Value.SourceHost = "host"
			case "other-kind":
				in.Key = workloadKey()
			case "sequence":
				in.Key.OwnerEpoch = 3
			case "digest":
				in.ValueDigest = strings.Repeat("b", 64)
			case "negative-generation":
				in.ConfigGeneration = -1
			case "promise-order":
				in.Promised = testBallot(2, "a")
			case "accepted-zero":
				in.Accepted = Ballot{}
			case "accept-key":
				in.Accept.Key.OwnerEpoch = 3
			case "accept-ballot":
				in.Accept.Ballot = testBallot(2, "a")
			case "accept-generation":
				in.Accept.ConfigGeneration = 2
			case "accept-digest":
				in.Accept.ValueDigest = strings.Repeat("b", 64)
			case "accept-voter":
				in.Accept.Voter = "other"
			case "accept-incarnation":
				in.Accept.VoterIncarnation = "other"
			case "accept-certificate":
				in.Accept.CertPEM = "invalid"
			case "accept-signature":
				in.Accept.Signature = []byte{1}
			case "inner-unknown":
				in.Value.Automation.Envelope = append([]byte(`{"unknown":1,`), value.Automation.Envelope[1:]...)
			case "inner-duplicate":
				in.Value.Automation.Envelope = append([]byte(`{"Version":1,`), value.Automation.Envelope[1:]...)
			case "inner-trailing":
				in.Value.Automation.Envelope = append(append([]byte(nil), value.Automation.Envelope...), ' ')
			case "native-bound":
				in.Value.Automation.Envelope = bytes.Repeat([]byte{' '}, contract.MaxDecisionBytes+1)
			}
			e := ValidateAutomationState(in)
			if name == "valid" || name == "unsigned" {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("invalid actual state accepted", name)
			}
		})
	}
	// Structured union corruption must win even when the key is also invalid.
	bad := base
	v := value
	v.Proof = &ActionProof{}
	bad.Value = &v
	bad.Key.OwnerEpoch = 0
	if e := ValidateAutomationState(bad); e == nil || !strings.HasPrefix(e.Error(), "corrupt structured claim state:") {
		t.Fatal("leading union error lost", e)
	}
	// These legacy paths deliberately do not acquire automation's state rules.
	for _, v := range []ClaimValue{{Proof: &ActionProof{}}, {LeaseTerm: &LeaseTermValue{Key: "lease", Term: 1, Holder: "host"}}} {
		if e := ValidateAutomationState(ClaimVoterState{Key: workloadKey(), Value: &v}); e != nil {
			t.Fatal("legacy nonautomation behavior tightened", e)
		}
	}
	mixed := ClaimValue{LeaseTerm: &LeaseTermValue{Key: "lease", Term: 1, Holder: "host"}, Proof: &ActionProof{}}
	if e := ValidateAutomationState(ClaimVoterState{Key: workloadKey(), Value: &mixed}); e == nil {
		t.Fatal("legacy structured union weakened")
	}
}
