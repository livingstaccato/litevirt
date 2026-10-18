package corrosion

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

func TestReceiverCurrentUnsupportedSecretEqualityRefuses(t *testing.T) {
	ctx := context.Background()
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Continuing: true, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
		verifier, err := LoadClaimVerifier(local.pki)
		if err != nil {
			t.Fatal(err)
		}
		// Keep the genuine certified encrypted admission and required equality
		// coverage. No provider, synthetic completion or empty-coverage substitution.
		automationTypedHistoryFixtureWithDecision(t, local, voters[0], voters[1], verifier, func(*contract.Decision) {})
		key, _ := AutomationClaimKey(1)
		installAutomationEvidence(t, local.c, key, "", 1)
		if _, err = local.c.db.Exec(`UPDATE local_automation_authority SET bootstrap_request='initialize' WHERE id=1`); err != nil {
			t.Fatal(err)
		}
	}})
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	active, spool, typed := receiverActive(t, f.local.c), receiverStored(t, f.local.c), automationTypedSnapshot(t, f.local.c)
	proof, err := f.receiver.VerifyCurrent(ctx, f.attempt)
	if proof != nil {
		proof.Discard()
	}
	if proof != nil || err == nil || !strings.Contains(err.Error(), "required secret/equality coverage unavailable") {
		t.Fatal("current proof silently accepted unsupported custody/equality", proof != nil, err)
	}
	if active != receiverActive(t, f.local.c) || spool != receiverStored(t, f.local.c) || !reflect.DeepEqual(typed, automationTypedSnapshot(t, f.local.c)) {
		t.Fatal("coverage refusal changed active/spool/typed state")
	}
}
