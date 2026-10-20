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
func custodyLifetimeHistoricalVoters(t *testing.T, baselineSchema int) []*claimTestVoter {
	t.Helper()
	ctx := context.Background()
	ca := newClaimTestCA(t)
	var voters []*claimTestVoter
	for _, name := range []string{"a", "b", "c"} {
		v := &claimTestVoter{name: name}
		v.c = custodyLifetimeFileClient(t, t.TempDir(), name)
		t.Cleanup(func() { _ = v.c.Close() })
		if baselineSchema == 80 || baselineSchema == 82 {
			if baselineSchema == 80 {
				custodyLifetimeBuildOriginal80(t, v.c)
			} else {
				custodyLifetimeBuildComposed82(t, v.c)
			}
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
	voters := custodyLifetimeHistoricalVoters(t, 0)
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
		t.Fatalf("SETUP genuine schema83 N0 history persistence: %v", err)
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
		t.Fatalf("SETUP schema83 reopen: %v", err)
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

// This is a fresh clone of the frozen d226 original80 source fixture. Its
// valid archive is created before storage-only rows are added. Later archive
// reuse proves original byte preservation, not a new cut of uncertified rows.
func TestAutomationCustodyLifetimeArchived80CloneUpgradePreservesOriginals(t *testing.T) {
	ctx := context.Background()
	a := custodyLifetimeHistoricalVoters(t, 80)[0]
	if storedVersion(t, a.c) != 80 {
		t.Fatal("not a genuine original80 source fixture")
	}
	if corrected, err := automationCustodyRecipientShape(ctx, a.c); err != nil || corrected {
		t.Fatal("original80 fixture already has corrected constraint", corrected, err)
	}
	if err := a.c.SealVoterGeneration(ctx, 1, "archive-original80-before-composition"); err != nil {
		t.Fatal(err)
	}
	id, err := a.c.FreezeAutomationCut(ctx, 1, nil)
	if err != nil {
		t.Fatal("freeze valid original80 source before storage-only rows", err)
	}
	before, records := cutFixtureRead(t, a.c, id)
	if before.SourceSchema != 80 || len(before.Inventory) != 9 {
		t.Fatal("original80 descriptor/inventory changed")
	}
	// Storage preservation fixtures only. These rows are intentionally added
	// AFTER the valid historical cut; they confer no certified history or
	// fresh authority, and no new live-state cut is claimed below.
	for _, stage := range []string{"", "original80-audit-a", "original80-audit-b"} {
		if err := custodyLifetimeInsertRecipient(t, a.c, stage, "original80-positive", 17); err != nil {
			t.Fatal("original80 positive recipient row", err)
		}
	}
	if exists, err := columnExists(ctx, a.c.db, "security_groups", "project"); err != nil || exists {
		t.Fatal("original80 clone already has published SG70 column", exists, err)
	}
	if err := a.c.execLocal(ctx, `INSERT INTO security_groups(id,name,created_at,updated_at) VALUES('original80-global','original80-global','before70','before70')`); err != nil {
		t.Fatal(err)
	}
	originalRows, err := a.c.Query(ctx, "SELECT "+custodyLifetimeRecipientColumns+" FROM local_automation_key_recipients ORDER BY stage,host")
	if err != nil || len(originalRows) != 3 || len(originalRows[0].Columns) != 16 {
		t.Fatal("original80 all-stage/16-column storage fixture", err)
	}
	originalLedger, err := a.c.Query(ctx, `SELECT id,applied_at,checksum FROM applied_migrations ORDER BY id`)
	if err != nil || len(originalLedger) != 196 {
		t.Fatal("original80 exact196 applied preimages missing", err)
	}
	oldIDs := map[string]bool{}
	for _, row := range originalLedger {
		oldIDs[row.String("id")] = true
	}
	const oldInventoryID = "a091_local_automation_receiver_current_established_inventory"
	if !oldIDs[oldInventoryID] {
		t.Fatal("original80 full inventory migration ID missing")
	}
	if err := InitSchema(ctx, a.c); err != nil {
		t.Fatal("fresh original80 clone upgrade to83", err)
	}
	if storedVersion(t, a.c) != 83 || len(schemaMigrationLedger) != 199 {
		t.Fatal("clone did not reach composed83/current199 known units")
	}
	afterRows, err := a.c.Query(ctx, "SELECT "+custodyLifetimeRecipientColumns+" FROM local_automation_key_recipients ORDER BY stage,host")
	if err != nil || !reflect.DeepEqual(originalRows, afterRows) {
		t.Fatal("clone upgrade changed recipient columns/bytes/stages", err)
	}
	if corrected, err := automationCustodyRecipientShape(ctx, a.c); err != nil || !corrected {
		t.Fatal("clone upgrade omitted recipient constraint rebuild", corrected, err)
	}
	groups, err := a.c.Query(ctx, `SELECT project FROM security_groups WHERE id='original80-global'`)
	if err != nil || len(groups) != 1 || groups[0].String("project") != "" {
		t.Fatal("clone upgrade lost published SG70 global default", err)
	}
	upgradedLedger, err := a.c.Query(ctx, `SELECT id,applied_at,checksum FROM applied_migrations ORDER BY id`)
	if err != nil || len(upgradedLedger) != 200 || len(upgradedLedger) != len(originalLedger)+4 {
		t.Fatal("clone upgrade must retain196 old plus only4 new applied rows", err)
	}
	newIDs := map[string]bool{
		"a092_projects_incarnation":                                    false,
		"a091_security_groups_project":                                 false,
		"a093_local_automation_receiver_current_established_inventory": false,
		"r_automation_key_recipients_host_zero":                        false,
	}
	var preserved []Row
	applied := map[string]Row{}
	for _, row := range upgradedLedger {
		name := row.String("id")
		applied[name] = row
		if oldIDs[name] {
			preserved = append(preserved, row)
		} else if _, ok := newIDs[name]; ok {
			newIDs[name] = true
		} else {
			t.Fatal("clone upgrade recorded an unexpected new migration", name)
		}
	}
	if !reflect.DeepEqual(originalLedger, preserved) {
		t.Fatal("clone upgrade rewrote old IDs/checksums/timestamps")
	}
	for name, found := range newIDs {
		if !found {
			t.Fatal("clone upgrade omitted required new migration", name)
		}
	}
	for _, unit := range schemaMigrationLedger {
		row, ok := applied[unit.ID]
		if !ok || row.String("checksum") != sha256hex(unit.SQL) {
			t.Fatal("clone upgrade omitted or misrecorded known current unit", unit.ID)
		}
	}
	again, err := a.c.FreezeAutomationCut(ctx, 1, nil)
	if err != nil || again != id {
		t.Fatal("clone upgrade did not reuse original80 archive", err)
	}
	after, later := cutFixtureRead(t, a.c, again)
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(records, later) {
		t.Fatal("clone upgrade changed original80 cut metadata/records/root")
	}
	complete := custodyLifetimeSnapshot(t, a.c)
	if err := InitSchema(ctx, a.c); err != nil || appliedCount(t, a.c) != 200 || !reflect.DeepEqual(complete, custodyLifetimeSnapshot(t, a.c)) {
		t.Fatal("clone re-init changed retained old/current ledger or recipient rows", err)
	}
}

// This is a NEW synthetic SQL82 migration predecessor, not the genuine old
// descriptor82 source namespace. Never freeze a SourceSchema82 archive from it.
func TestAutomationCustodyLifetimeComposed82UpgradePublishes83(t *testing.T) {
	ctx := context.Background()
	a := custodyLifetimeHistoricalVoters(t, 82)[0]
	if storedVersion(t, a.c) != 82 {
		t.Fatal("not a fresh composed82 prerequisite fixture")
	}
	if corrected, err := automationCustodyRecipientShape(ctx, a.c); err != nil || corrected {
		t.Fatal("composed82 fixture already has corrected constraint", corrected, err)
	}
	before, err := a.c.Query(ctx, `SELECT id FROM local_automation_cuts`)
	if err != nil || len(before) != 0 {
		t.Fatal("synthetic predecessor must not carry an invented descriptor82 cut", before, err)
	}
	if err := InitSchema(ctx, a.c); err != nil {
		t.Fatal(err)
	}
	if storedVersion(t, a.c) != 83 {
		t.Fatal("fresh composed82 migration did not reach truthful current83")
	}
	if corrected, err := automationCustodyRecipientShape(ctx, a.c); err != nil || !corrected {
		t.Fatal("migration omitted corrected recipient constraint", corrected, err)
	}
	if err := a.c.SealVoterGeneration(ctx, 1, "fresh-current83-after-migration"); err != nil {
		t.Fatal(err)
	}
	id, err := a.c.FreezeAutomationCut(ctx, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	current, records := cutFixtureRead(t, a.c, id)
	if current.SourceSchema != 83 || len(current.Inventory) != 9 {
		t.Fatal("new actual current cut did not declare83", current.SourceSchema)
	}
	again, err := a.c.FreezeAutomationCut(ctx, 1, nil)
	if err != nil || again != id {
		t.Fatal("current83 cut reuse changed identity", err)
	}
	later, laterRecords := cutFixtureRead(t, a.c, again)
	if !reflect.DeepEqual(current, later) || !reflect.DeepEqual(records, laterRecords) {
		t.Fatal("current83 cut reuse changed bytes/root")
	}
}
