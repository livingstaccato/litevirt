package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// The existing historical fixture premise, with independent WAL/FULL files as
// in aggregate_fixture. Hand-built membership is explicitly test history; this
// helper never supplies a current custody provider or a fresh class issuer.
func custodyLifetimeHistoricalVoters(t *testing.T, original80 bool) []*claimTestVoter {
	t.Helper()
	ctx := context.Background()
	ca := newClaimTestCA(t)
	var voters []*claimTestVoter
	for _, name := range []string{"a", "b", "c"} {
		v := &claimTestVoter{name: name}
		v.c = custodyLifetimeFileClient(t, t.TempDir(), name)
		t.Cleanup(func() { _ = v.c.Close() })
		if original80 {
			custodyLifetimeBuildOriginal80(t, v.c)
			if err := v.c.mintVoterIncarnation(ctx); err != nil {
				t.Fatal(err)
			}
		} else if err := InitSchema(ctx, v.c); err != nil {
			t.Fatal(err)
		}
		v.c.SetVoterConfigGate(func() bool { return true })
		var err error
		v.inc, err = v.c.VoterIncarnation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		v.pki = ca.pkiDir(t, name)
		v.signer, err = LoadClaimSigner(v.pki, name)
		if err != nil {
			t.Fatal(err)
		}
		voters = append(voters, v)
	}
	adoptHandBuilt(t, 1, membersOf(voters...), voters...)
	return voters
}

func TestAutomationKeyTransitionHostLifetimeReplay(t *testing.T) {
	ctx := context.Background()
	voters := custodyLifetimeHistoricalVoters(t, false)
	a := voters[0]
	genesis := sharedAutomationRecord(t, 1, "", "initialize", "initialize-operation", voters...)
	if _, err := applySharedAutomation(t, a.c, genesis, contract.Reduce, automationFreshAnchor); err != nil {
		t.Fatalf("SETUP historical genesis: %v", err)
	}
	record := keyActivationRecordFor(t, a, genesis, voters)
	d, err := automationDecision(record.Value)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := contract.DecodeAssignment(d)
	if err != nil {
		t.Fatal(err)
	}
	assignment.KeyTransition.Recipients[0].HostIncarnation = 0
	d.Assignment, err = json.Marshal(assignment)
	if err != nil {
		t.Fatal(err)
	}
	record = keyCertifiedDecision(t, d, voters...)
	receipt, err := applySharedAutomation(t, a.c, record, contract.Reduce, automationFreshAnchor)
	if err != nil {
		t.Fatalf("SETUP genuine schema81 N0 history persistence: %v", err)
	}
	stored, err := a.c.Query(ctx, `SELECT host_incarnation,admitted_at,admission_serial FROM local_automation_key_recipients WHERE stage='' AND host='a'`)
	if err != nil || len(stored) != 1 || stored[0].Int64("host_incarnation") != 0 || stored[0].String("admitted_at") != "2026-10-18T00:00:00Z" || stored[0].String("admission_serial") != "a0" {
		t.Fatalf("SETUP genuine persisted N0 binding missing: %v", err)
	}
	before := keyTransitionSnapshot(t, a.c)
	dir := a.c.dataDir
	if err := a.c.Close(); err != nil {
		t.Fatal(err)
	}
	a.c = custodyLifetimeFileClient(t, dir, a.name)
	a.c.SetVoterConfigGate(func() bool { return true })
	if err := InitSchema(ctx, a.c); err != nil {
		t.Fatalf("SETUP schema81 reopen: %v", err)
	}
	err = a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		head, err := automationHeadTx(ctx, tx)
		if err != nil {
			return fmt.Errorf("SETUP persisted head: %w", err)
		}
		request, err := automationLocalKeyLookupTx(ctx, tx, 2)
		if err != nil {
			return fmt.Errorf("SETUP actual historical lookup: %w", err)
		}
		projection := AutomationProjection{Head: head}
		if err := automationResolveKeyProjectionTx(ctx, tx, "", &projection, request, nil); err != nil {
			return fmt.Errorf("N0_HISTORICAL_READER_REFUSED: %w", err)
		}
		for _, recipient := range projection.KeyTransition.Recipients {
			if recipient.Binding.Host == "a" && recipient.Binding == assignment.KeyTransition.Recipients[0] {
				return nil
			}
		}
		return fmt.Errorf("historical N0 reader changed original binding")
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, keyTransitionSnapshot(t, a.c)) {
		t.Fatal("reopen/reader changed original history or bindings")
	}
	// This actual later key transition forces the isolated audit to resolve
	// a nonempty stage already containing the original N0 recipient binding.
	const originalSQL = `SELECT digest,value_json,certificate,receipt_json,anchor_sequence FROM local_automation_history WHERE sequence=2`
	original, err := a.c.Query(ctx, originalSQL)
	if err != nil || len(original) != 1 {
		t.Fatal("original activation history missing", err)
	}
	rotation, rotationReceipt := custodyLifetimeRotate(t, a, record, voters)
	before = keyTransitionSnapshot(t, a.c)
	if err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		_, err := auditAutomationCutTx(ctx, tx, contract.Reduce)
		return err
	}); err != nil {
		t.Fatal("isolated historical N0 reconstruction refused", err)
	}
	if !reflect.DeepEqual(before, keyTransitionSnapshot(t, a.c)) {
		t.Fatal("reopen/reader/staged audit changed original history or bindings")
	}
	got, err := applySharedAutomation(t, a.c, record, contract.Reduce, automationAnchoredReplay)
	if err != nil || got != receipt {
		t.Fatal("historical N0 replay changed immutable receipt", got, err)
	}
	got, err = applySharedAutomation(t, a.c, rotation, contract.Reduce, automationAnchoredReplay)
	if err != nil || got != rotationReceipt {
		t.Fatal("historical N0 rotation replay changed immutable receipt", got, err)
	}
	later, err := a.c.Query(ctx, originalSQL)
	if err != nil || !reflect.DeepEqual(original, later) {
		t.Fatal("rotation/audit/replay changed original envelope/digest/certificate/receipt", err)
	}
}

func TestAutomationCustodyLifetimeArchived80Migration(t *testing.T) {
	ctx := context.Background()
	a := custodyLifetimeHistoricalVoters(t, true)[0]
	if storedVersion(t, a.c) != 80 {
		t.Fatal("not a genuine original80 baseline")
	}
	if corrected, err := automationCustodyRecipientShape(ctx, a.c); err != nil || corrected {
		t.Fatal("original80 fixture already has corrected constraint", corrected, err)
	}
	if err := a.c.SealVoterGeneration(ctx, 1, "archive-before81"); err != nil {
		t.Fatal(err)
	}
	id, err := a.c.FreezeAutomationCut(ctx, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, records := cutFixtureRead(t, a.c, id)
	if before.SourceSchema != 80 || len(before.Inventory) != 9 {
		t.Fatal("original80 descriptor/inventory changed")
	}
	if err := InitSchema(ctx, a.c); err != nil {
		t.Fatal(err)
	}
	again, err := a.c.FreezeAutomationCut(ctx, 1, nil)
	if err != nil || again != id || storedVersion(t, a.c) != 81 {
		t.Fatal("schema81 migration relabeled original80 cut", err)
	}
	after, later := cutFixtureRead(t, a.c, again)
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(records, later) {
		t.Fatal("schema81 migration changed original80 cut bytes/root")
	}
}
