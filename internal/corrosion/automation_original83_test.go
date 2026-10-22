package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

const original83DatabaseSHA = "13df3d78f8a6f52775f3f7bd162b4559847395b0fec539c6970a4231da980b73"
const original83EvidenceSHA = "95e2d355550f1317a2be39d06d2c0ce59280e057d4ded5526271a032175fe6eb"
const original83MetadataSHA = "88c5543f395784c4d2c1a67effc4e0aaa6884f203caa7ebe1193563b53eadaaf"
const original83Root = "0f69d3f88b82d7cd31080847b80ea36c09a4ecd1d62a0d6f6f62a53f981503ab"

// Produced by real OLD4b30 schema83 code, not current schemaDDL or a manually
// stamped predecessor. Root accepted producer auditd52269cf/manual3930bdbf.
// The exported database/evidence contain test fixture history, not live keys,
// a production enrollment authority or a fresh business-class issuer permit.
type original83FixtureEvidence struct {
	SourceCommit, SourceTree, SourceSchemaBlob, SourceCodecBlob, StateDBSHA256 string
	Version                                                                    int
	CutID                                                                      string
	DDL                                                                        []string
	Ledger                                                                     []Row
	Metadata                                                                   []byte
	Root                                                                       string
	Records                                                                    [][][]byte
}

func original83Hash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func original83Fixture(t *testing.T) ([]byte, original83FixtureEvidence) {
	t.Helper()
	database, err := os.ReadFile("testdata/original83_4b30_state.db")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("testdata/original83_4b30_evidence.json")
	if err != nil {
		t.Fatal(err)
	}
	if original83Hash(database) != original83DatabaseSHA || original83Hash(raw) != original83EvidenceSHA {
		t.Fatal("genuine original83 fixture bytes changed")
	}
	var e original83FixtureEvidence
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if e.SourceCommit != "4b30caf14d7d80a74049799606bf63638e28f003" || e.SourceTree != "3945737ec5b59510df4d304514b2360b2e5a7074" || e.SourceSchemaBlob != "44c3f18f1c21688fea89f81173073e9191df024a" || e.SourceCodecBlob != "620adb0d8517a512ad9271da0a4ebf683e2ae3be" || e.Version != 83 || e.StateDBSHA256 != original83DatabaseSHA || e.CutID != "7b7c3e5af7b3e9c3154f889f23899d30" || e.Root != original83Root || original83Hash(e.Metadata) != original83MetadataSHA || len(e.DDL) != 186 || len(e.Ledger) != 199 || len(e.Records) != 9 {
		t.Fatal("original83 source/DDL/ledger/cut provenance changed")
	}
	return database, e
}

func original83AssertArchive(t *testing.T, c *Client, e original83FixtureEvidence) {
	t.Helper()
	ctx := context.Background()
	raw, err := c.Query(ctx, `SELECT metadata,root FROM local_automation_cuts WHERE id=?`, e.CutID)
	if err != nil || len(raw) != 1 || !bytes.Equal(raw[0].Bytes("metadata"), e.Metadata) || raw[0].String("root") != e.Root {
		t.Fatal("original83 raw metadata/root changed", err)
	}
	m, records := cutFixtureRead(t, c, e.CutID)
	if m.SourceSchema != 83 || m.Codec != 1 || m.Source != "a" || m.Head.Sequence != 2 || m.Head.Digest != "0838f93a994e69a87b8484f20e27f04fe02c025f708b4c617031a3e77ebdbae8" || len(m.Inventory) != 9 || !reflect.DeepEqual(records, e.Records) {
		t.Fatal("original83 archived descriptor/head/record bytes changed")
	}
	// The actual storage owner must reuse its genuine retained archive before
	// considering current schema; passing current Reduce must not reinterpret it.
	id, err := c.FreezeAutomationCut(ctx, 1, contract.Reduce)
	if err != nil || id != e.CutID {
		t.Fatal("genuine original83 archive could not be reused", id, err)
	}
	again, err := c.Query(ctx, `SELECT metadata,root FROM local_automation_cuts WHERE id=?`, e.CutID)
	if err != nil || !reflect.DeepEqual(raw, again) {
		t.Fatal("archive reuse rewrote original83 bytes/root", err)
	}
}

// This is the immutable schema83 predecessor inventory, not the live helper
// whose current target projections require the migration under test. Preserve
// every old typed/key row before and after upgrade, including isolated stages.
func original83TypedSnapshot(t *testing.T, c *Client) map[string][]Row {
	t.Helper()
	out := map[string][]Row{}
	for _, table := range []string{
		"local_automation_identities", "local_automation_aliases", "local_automation_owners", "local_automation_semantic_heads",
		"local_automation_resources", "local_automation_names", "local_automation_bindings", "local_automation_admissions",
		"local_automation_key_epochs", "local_automation_key_recipients", "local_automation_payload_wrappings",
	} {
		rows, err := c.Query(context.Background(), "SELECT * FROM "+table+" ORDER BY stage,2,3,4")
		if err != nil {
			t.Fatal(err)
		}
		out[table] = rows
	}
	return out
}

// After real InitSchema86 the new derived tables must exist and remain empty: old83
// history must not acquire invented target operations, reservations or execution.
func original83AssertEmptyTargets(t *testing.T, c *Client) {
	t.Helper()
	for _, table := range []string{"local_automation_target_operations", "local_automation_target_reservations", "local_automation_executors", "local_automation_execution_progress", "local_automation_execution_artifacts", "local_automation_execution_terminals"} {
		rows, err := c.Query(context.Background(), "SELECT stage FROM "+table+" LIMIT 1")
		if err != nil || len(rows) != 0 {
			t.Fatal("old83 upgrade omitted target table or invented target projection", table, err)
		}
	}
}

func TestAutomationOriginal83ArchiveAndCurrent85(t *testing.T) {
	t.Run("genuine_old83_upgrade_cold_reopen", func(t *testing.T) {
		ctx := context.Background()
		database, e := original83Fixture(t)
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "state.db"), database, 0600); err != nil {
			t.Fatal(err)
		}
		c := custodyLifetimeFileClient(t, dir, "a")
		t.Cleanup(func() { _ = c.Close() })
		if storedVersion(t, c) != 83 {
			t.Fatal("genuine producer database lost old83 stamp")
		}
		if exists, err := columnExists(ctx, c.db, "projects", "incarnation"); err != nil || !exists {
			t.Fatal("genuine old83 lacks published project71", exists, err)
		}
		if corrected, err := automationCustodyRecipientShape(ctx, c); err != nil || !corrected {
			t.Fatal("genuine old83 lacks corrected recipient shape", corrected, err)
		}
		for _, table := range []string{"local_automation_target_operations", "local_automation_target_reservations"} {
			rows, err := c.Query(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table)
			if err != nil || len(rows) != 0 {
				t.Fatal("genuine83 already has84 target table", table, err)
			}
		}
		original83AssertArchive(t, c, e)
		history, typed := sharedActiveRows(t, c), original83TypedSnapshot(t, c)
		beforeLedger, err := c.Query(ctx, `SELECT id,applied_at,checksum FROM applied_migrations ORDER BY id`)
		if err != nil || !reflect.DeepEqual(beforeLedger, e.Ledger) {
			t.Fatal("genuine original199 ledger rows differ", err)
		}
		if err := InitSchema(ctx, c); err != nil {
			t.Fatal("genuine old83 upgrade to current86 refused", err)
		}
		if CurrentSchemaVersion != 87 || storedVersion(t, c) != 87 {
			t.Fatal("current migration did not reach86")
		}
		if exists, err := columnExists(ctx, c.db, "projects", "incarnation"); err != nil || !exists {
			t.Fatal("published project71 migration absent", exists, err)
		}
		original83AssertArchive(t, c, e)
		original83AssertEmptyTargets(t, c)
		if !reflect.DeepEqual(history, sharedActiveRows(t, c)) || !reflect.DeepEqual(typed, original83TypedSnapshot(t, c)) {
			t.Fatal("old82 migration changed certified history/receipt/prefix/typed state")
		}
		upgraded, err := c.Query(ctx, `SELECT id,applied_at,checksum FROM applied_migrations ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		oldIDs := map[string]bool{}
		for _, r := range beforeLedger {
			oldIDs[r.String("id")] = true
		}
		newIDs := map[string]bool{"t_host_fence_ssh": false, "t_local_automation_executors": false, "t_local_automation_execution_progress": false, "t_local_automation_execution_artifacts": false, "t_local_automation_execution_terminals": false, "a094_tokens_user_created_at": false, "t_local_automation_target_operations": false, "t_local_automation_target_reservations": false}
		var preserved []Row
		for _, r := range upgraded {
			id := r.String("id")
			if oldIDs[id] {
				preserved = append(preserved, r)
				continue
			}
			if _, ok := newIDs[id]; !ok || newIDs[id] {
				t.Fatal("unexpected or duplicate new migration", id)
			}
			newIDs[id] = true
			matched := false
			for _, m := range schemaMigrationLedger {
				if m.ID == id {
					matched = true
					if r.String("checksum") != sha256hex(m.SQL) {
						t.Fatal("new migration checksum differs", id)
					}
				}
			}
			if !matched {
				t.Fatal("new ledger ID missing from actual current migration registry", id)
			}
		}
		if len(upgraded) != 207 || !reflect.DeepEqual(beforeLedger, preserved) {
			t.Fatal("upgrade rewrote original199 ledger rows or added wrong count")
		}
		for id, found := range newIDs {
			if !found {
				t.Fatal("upgrade omitted new migration", id)
			}
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		c = custodyLifetimeFileClient(t, dir, "a")
		if storedVersion(t, c) != 87 {
			t.Fatal("cold reopened current86 stamp changed")
		}
		original83AssertArchive(t, c, e)
		if err := InitSchema(ctx, c); err != nil {
			t.Fatal("current86 cold re-init refused", err)
		}
		original83AssertArchive(t, c, e)
		original83AssertEmptyTargets(t, c)
		laterLedger, err := c.Query(ctx, `SELECT id,applied_at,checksum FROM applied_migrations ORDER BY id`)
		if err != nil || !reflect.DeepEqual(upgraded, laterLedger) || !reflect.DeepEqual(history, sharedActiveRows(t, c)) || !reflect.DeepEqual(typed, original83TypedSnapshot(t, c)) {
			t.Fatal("cold current86 reopen/init changed retained ledger/history/receipt/projections", err)
		}
		// All writes above target the private copy, never the pinned original files.
		original83Fixture(t)
	})
	t.Run("new_current85_cut", func(t *testing.T) {
		ctx := context.Background()
		_, e := original83Fixture(t)
		voters := custodyLifetimeHistoricalVoters(t, 0)
		a := voters[0]
		if CurrentSchemaVersion != 87 || automationCutSourceSchema != 87 || storedVersion(t, a.c) != 87 {
			t.Fatal("new source is not actual current86")
		}
		genesis := sharedAutomationRecord(t, 1, "", "initialize", "current85-initialize", voters...)
		if receipt, err := applySharedAutomation(t, a.c, genesis, contract.Reduce, automationFreshAnchor); err != nil || receipt.Code != "" || receipt.Sequence != 1 {
			t.Fatal("actual current86 certified genesis failed", receipt, err)
		}
		if err := a.c.SealVoterGeneration(ctx, 1, "genuine-current85-new-source"); err != nil {
			t.Fatal(err)
		}
		id, err := a.c.FreezeAutomationCut(ctx, 1, contract.Reduce)
		if err != nil {
			t.Fatal("new current86 cut refused", err)
		}
		m, _ := cutFixtureRead(t, a.c, id)
		if m.SourceSchema != 87 || m.Codec != 1 || m.Head.Sequence != 1 || m.Head.Digest != genesis.Value.MustDigest() || len(m.Inventory) != 9 {
			t.Fatal("new current cut did not declare truthful86")
		}
		if id == e.CutID {
			t.Fatal("fresh source reused unrelated original83 cut identity")
		}
	})
}
