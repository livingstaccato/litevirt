package corrosion

import (
	"context"
	"encoding/json"
	"testing"
)

func TestLeaseAutomationMixedDurableRefused(t *testing.T) {
	k, a := automationFixture(t, 1, "")
	a.LeaseTerm = &LeaseTermValue{Key: "failover", Term: 1, Holder: "a"}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var v ClaimValue
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if _, err = v.Digest(); err == nil {
		t.Error("mixed automation/lease digest accepted")
	}
	for _, key := range []ClaimKey{k, LeaseTermClaimKey("failover", 1)} {
		if r, _ := validateGenerationClaimValue(key, &v); r == "" {
			t.Errorf("mixed value admitted at %v", key)
		}
	}
}

func TestLeaseAutomationMixedLiveAdmissionIsInert(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	ctx := context.Background()
	key, value := automationFixture(t, 1, "")
	installAutomationEvidence(t, a.c, key, "", 1)
	value.LeaseTerm = &LeaseTermValue{Key: "failover", Term: 1, Holder: "a"}
	before := localTestMutationLogCount(t, a.c)
	for _, k := range []ClaimKey{key, LeaseTermClaimKey("failover", 1)} {
		res, err := a.c.ClaimAccept(ctx, k, testBallot(2, "a"), value, 1, a.signer, nil)
		if err != nil || res.Accepted || res.Accept != nil || res.Refusal != RefusalInvalidValue {
			t.Fatal("mixed structured value admitted", k, res, err)
		}
		if _, found, err := a.c.ClaimState(ctx, k); err != nil || found {
			t.Fatal("refused union wrote state", k, err)
		}
	}
	if localTestMutationLogCount(t, a.c) != before {
		t.Fatal("refused union changed mutation log")
	}
}
