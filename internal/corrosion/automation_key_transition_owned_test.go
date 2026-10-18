package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/pki"
)

func keyHistoricalVerifier(t *testing.T, a *claimTestVoter) *ClaimVerifier {
	t.Helper()
	view, e := pki.CaptureHostTrust(context.Background(), a.pki, "a")
	if e != nil {
		t.Fatal(e)
	}
	return &ClaimVerifier{sourceTrust: view, pinned: true}
}
func keyPendingNearNative(t *testing.T) (*claimTestVoter, AutomationRecord) {
	t.Helper()
	_, a, b, c := threeVoters(t)
	appendKeyPayloadHistoryWithBytes(t, a, []*claimTestVoter{a, b, c}, bytes.Repeat([]byte{0x67}, 1<<20))
	ctx := context.Background()
	current, found, e := a.c.AutomationRecord(ctx, 14)
	if e != nil || !found {
		t.Fatal(e)
	}
	d, e := automationDecision(current.Value)
	if e != nil {
		t.Fatal(e)
	}
	// Retain the actual certified prefix through 13. The fixture's later two
	// transitions are removed before reset/replay; no fabricated successful
	// reduction supplies the predecessor state for the owned live operation.
	e = a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if _, e := tx.Exec(ctx, `DELETE FROM local_automation_history WHERE sequence>=14`); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `DELETE FROM local_automation_anchors WHERE sequence>=14`); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `DELETE FROM local_automation_requests WHERE operation_id IN ('rewrap-op','rotate-op')`); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `UPDATE local_automation_prefix SET sequence=13,digest=? WHERE id=1`, d.ParentDigest); e != nil {
			return e
		}
		return automationResetSemanticProjectionTx(ctx, tx, "")
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = a.c.AutomationReplay(ctx, contract.Reduce, 14); e != nil {
		t.Fatal(e)
	}
	key, _ := AutomationClaimKey(14)
	installAutomationEvidence(t, a.c, key, d.ParentDigest, 1)
	return a, current
}
func TestAutomationKeyTransitionOwnedWholeStack(t *testing.T) {
	a, current := keyPendingNearNative(t)
	verifier := keyHistoricalVerifier(t, a)
	ctx, checks := keyWholeStackObserver(t)
	receipt, e := a.c.AutomationApplyOwned(ctx, &current, verifier, contract.Reduce)
	if e != nil || receipt.Code != "" {
		t.Fatal("owned historical application", receipt, e)
	}
	if *checks == 0 {
		t.Fatal("owned whole-stack lifetime assertion did not run")
	}
	if current.Value.Automation == nil {
		t.Fatal("successful forwarding record missing")
	}
	if pending, e := a.c.AutomationRecoveryPending(context.Background()); e != nil || pending {
		t.Fatal("completed job remains", pending, e)
	}
}
func TestAutomationKeyTransitionDurableRetry(t *testing.T) {
	a, genesis, current := keyActivationHistory(t)
	ctx := context.Background()
	key, _ := AutomationClaimKey(2)
	installAutomationEvidence(t, a.c, key, genesis.Value.MustDigest(), 1)
	// A real ext4 state.db survives closing every handle. The certified fixture
	// is copied before handoff; this does not manufacture authority/provider work.
	dir := t.TempDir()
	if _, e := a.c.db.Exec(`VACUUM INTO ?`, filepath.Join(dir, "state.db")); e != nil {
		t.Fatal(e)
	}
	file, e := NewLocalClient(dir, "a")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = file.Close() })
	file.SetVoterConfigGate(func() bool { return true })
	expectedValue, _ := json.Marshal(current.Value)
	expectedCert, _ := current.Certificate.Encode()
	verifier := keyHistoricalVerifier(t, a)
	before := sharedActiveRows(t, file)
	beforeKeys := keyTransitionSnapshot(t, file)
	// Error before handoff retains both caller bytes and all durable state.
	invalid := current
	invalid.Certificate.ValueDigest = "bad"
	if _, e = file.AutomationApplyOwned(ctx, &invalid, verifier, contract.Reduce); e == nil {
		t.Fatal("invalid certificate accepted")
	}
	if invalid.Value.Automation == nil || !reflect.DeepEqual(before, sharedActiveRows(t, file)) || !reflect.DeepEqual(beforeKeys, keyTransitionSnapshot(t, file)) {
		t.Fatal("pre-handoff failure changed ownership or state")
	}
	injected := func(AutomationProjection, contract.Decision) (AutomationReduction, error) {
		return AutomationReduction{}, fmt.Errorf("injected semantic refusal")
	}
	if _, e = file.AutomationApplyOwned(ctx, &current, verifier, injected); e == nil {
		t.Fatal("injected failure was ignored")
	}
	if current.Value.Automation != nil {
		t.Fatal("post-handoff caller still owns full record")
	}
	if !reflect.DeepEqual(before, sharedActiveRows(t, file)) || !reflect.DeepEqual(beforeKeys, keyTransitionSnapshot(t, file)) {
		t.Fatal("failed semantic application changed ACTIVE state")
	}
	pending, e := file.AutomationRecoveryPending(ctx)
	if e != nil || !pending {
		t.Fatal("authenticated retry job lost", e)
	}
	retained, e := file.Query(ctx, `SELECT value_json,certificate FROM local_automation_staging WHERE sequence=2`)
	if e != nil || len(retained) != 1 || retained[0].String("value_json") != string(expectedValue) || retained[0].String("certificate") != expectedCert {
		t.Fatal("handoff changed certified bytes", e)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if e = file.AutomationFinishRecovery(canceled, contract.Reduce, 2); e == nil {
		t.Fatal("canceled retry succeeded")
	}
	if e = file.Close(); e != nil {
		t.Fatal(e)
	}
	if e = file.AutomationFinishRecovery(ctx, contract.Reduce, 2); e == nil {
		t.Fatal("closed DB retry succeeded")
	}
	file, e = NewLocalClient(dir, "a")
	if e != nil {
		t.Fatal(e)
	}
	file.SetVoterConfigGate(func() bool { return true })
	retained, e = file.Query(ctx, `SELECT value_json,certificate FROM local_automation_staging WHERE sequence=2`)
	if e != nil || len(retained) != 1 || retained[0].String("value_json") != string(expectedValue) || retained[0].String("certificate") != expectedCert {
		t.Fatal("cancel/closed DB lost exact durable bytes", e)
	}
	if e = file.AutomationFinishRecovery(ctx, contract.Reduce, 2); e != nil {
		t.Fatal("reopened authenticated retry", e)
	}
	applied, found, e := file.AutomationRecord(ctx, 2)
	if e != nil || !found {
		t.Fatal(e)
	}
	value, _ := json.Marshal(applied.Value)
	cert, _ := applied.Certificate.Encode()
	if !bytes.Equal(value, expectedValue) || cert != expectedCert {
		t.Fatal("reopened application changed original certificate or value")
	}
	if pending, e = file.AutomationRecoveryPending(ctx); e != nil || pending {
		t.Fatal("completed retry retained job", e)
	}
}
