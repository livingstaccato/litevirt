package corrosion

import (
	"bytes"
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// KeyEngineFixture is test-only access to real voters and already-certified
// historical storage. It supplies no production class or custody provider.
type KeyEngineFixture struct {
	Clients  map[string]*Client
	Signers  map[string]*ClaimSigner
	Verifier *ClaimVerifier
}

func NewKeyEngineFixture(t *testing.T) KeyEngineFixture {
	t.Helper()
	_, a, b, c := threeVoters(t)
	appendKeyPayloadHistoryWithBytes(t, a, []*claimTestVoter{a, b, c}, bytes.Repeat([]byte{0x67}, 1<<20))
	ctx := context.Background()
	// Explicit premise: b and c already retain certified 14. Actual FULL typed
	// reduction reconstructs their prefix; this is not fresh transition issuance.
	for _, voter := range []*claimTestVoter{b, c} {
		for seq := uint64(1); seq <= 14; seq++ {
			record, found, err := a.c.AutomationRecord(ctx, seq)
			if err != nil || !found {
				t.Fatal("fixture original", seq, err)
			}
			if _, err = applySharedAutomation(t, voter.c, record, contract.Reduce, automationFreshAnchor); err != nil {
				t.Fatal("fixture retained", seq, err)
			}
		}
		key, _ := AutomationClaimKey(1)
		installAutomationEvidence(t, voter.c, key, "", 1)
	}
	TruncateKeyEnginePrefix(t, a.c, 13)
	for _, voter := range []*claimTestVoter{b, c} {
		record, found, err := voter.c.AutomationRecord(ctx, 14)
		if err != nil || !found {
			t.Fatal(err)
		}
		key, _ := AutomationClaimKey(14)
		result, err := voter.c.ClaimAccept(ctx, key, testBallot(3, "b"), record.Value, 1, voter.signer, nil)
		if err != nil || !result.Accepted {
			t.Fatal("real historical accept", err, result.Refusal, result.Detail)
		}
	}
	return KeyEngineFixture{Clients: map[string]*Client{"a": a.c, "b": b.c, "c": c.c}, Signers: map[string]*ClaimSigner{"a": a.signer, "b": b.signer, "c": c.signer}, Verifier: keyHistoricalVerifier(t, a)}
}

func TruncateKeyEnginePrefix(t *testing.T, c *Client, seq uint64) {
	t.Helper()
	ctx := context.Background()
	previous, found, err := c.AutomationRecord(ctx, seq)
	if err != nil || !found {
		t.Fatal(err)
	}
	digest := previous.Value.MustDigest()
	err = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if _, e := tx.Exec(ctx, `DELETE FROM local_automation_history WHERE sequence>?`, seq); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `DELETE FROM local_automation_anchors WHERE sequence>?`, seq); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `DELETE FROM local_automation_requests WHERE operation_id IN ('rewrap-op','rotate-op')`); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `UPDATE local_automation_prefix SET sequence=?,digest=? WHERE id=1`, seq, digest); e != nil {
			return e
		}
		return automationResetSemanticProjectionTx(ctx, tx, "")
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.AutomationReplay(ctx, contract.Reduce, 14); err != nil {
		t.Fatal(err)
	}
	key, _ := AutomationClaimKey(1)
	installAutomationEvidence(t, c, key, "", 1)
}

// Per-context diagnostic only: no global observer, authority, or success result.
func WithKeyEngineBodyObserver(ctx context.Context, observe func(uint64, []byte)) context.Context {
	return context.WithValue(ctx, automationKeyBodyObserverKey{}, observe)
}
