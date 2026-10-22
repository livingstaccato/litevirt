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

const original82DatabaseSHA = "fb40602cb2c1e82bf1cbce2d8f79f46aa67a73be0a3777e726f4819d78806eea"
const original82EvidenceSHA = "10f1b755160a06a7bc058ac37af8540cb5b3dce5881a41816f6d5b81868f0e8c"
const original82MetadataSHA = "e77dd8d5907f617c1491218801e0dc5889602f00f1eae9ab759aa5c7d0869bf1"
const original82Root = "af46b09ea3e46fa3693073597e7a5cb10ecbf49a6fefa17d813a8584d7cf8060"

// Produced by real OLD170fc schema82 code, not current schemaDDL or a manually
// stamped predecessor. Root accepted producer audit71bd2d69/manualfec25949.
// The exported database/evidence contain test fixture history, not live keys,
// a production enrollment authority or a fresh business-class issuer permit.
type original82FixtureEvidence struct {
	SourceCommit, SourceSchemaBlob, SourceCodecBlob, StateDBSHA256 string
	Version                                                        int
	CutID                                                          string
	DDL                                                            []string
	Ledger                                                         []Row
	Metadata                                                       []byte
	Root                                                           string
	Records                                                        [][][]byte
}

func original82Hash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func original82Fixture(t *testing.T) ([]byte, original82FixtureEvidence) {
	t.Helper()
	database, err := os.ReadFile("testdata/original82_170fc_state.db")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("testdata/original82_170fc_evidence.json")
	if err != nil {
		t.Fatal(err)
	}
	if original82Hash(database) != original82DatabaseSHA || original82Hash(raw) != original82EvidenceSHA {
		t.Fatal("genuine original82 fixture bytes changed")
	}
	var e original82FixtureEvidence
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if e.SourceCommit != "170fc521b22088086ab327d65af86d0868253731" || e.SourceSchemaBlob != "1bc10986593108f0148cf8eb180d0a8359ccb651" || e.SourceCodecBlob != "4afcbf3e5a678c063744795239691013ccec80fa" || e.Version != 82 || e.StateDBSHA256 != original82DatabaseSHA || e.CutID != "385272a725ac2093a2cc8f2672ed4e26" || e.Root != original82Root || original82Hash(e.Metadata) != original82MetadataSHA || len(e.DDL) != 186 || len(e.Ledger) != 198 || len(e.Records) != 9 {
		t.Fatal("original82 source/DDL/ledger/cut provenance changed")
	}
	return database, e
}

func original82AssertArchive(t *testing.T, c *Client, e original82FixtureEvidence) {
	t.Helper()
	ctx := context.Background()
	raw, err := c.Query(ctx, `SELECT metadata,root FROM local_automation_cuts WHERE id=?`, e.CutID)
	if err != nil || len(raw) != 1 || !bytes.Equal(raw[0].Bytes("metadata"), e.Metadata) || raw[0].String("root") != e.Root {
		t.Fatal("original82 raw metadata/root changed", err)
	}
	m, records := cutFixtureRead(t, c, e.CutID)
	if m.SourceSchema != 82 || m.Codec != 1 || m.Source != "a" || m.Head.Sequence != 2 || m.Head.Digest != "1bfdc67950cebaf9e7f4373eef9316d59c0733114209a94217db42dd6a649e3c" || len(m.Inventory) != 9 || !reflect.DeepEqual(records, e.Records) {
		t.Fatal("original82 archived descriptor/head/record bytes changed")
	}
	// The actual storage owner must reuse its genuine retained archive before
	// considering current schema; passing current Reduce must not reinterpret it.
	id, err := c.FreezeAutomationCut(ctx, 1, contract.Reduce)
	if err != nil || id != e.CutID {
		t.Fatal("genuine original82 archive could not be reused", id, err)
	}
	again, err := c.Query(ctx, `SELECT metadata,root FROM local_automation_cuts WHERE id=?`, e.CutID)
	if err != nil || !reflect.DeepEqual(raw, again) {
		t.Fatal("archive reuse rewrote original82 bytes/root", err)
	}
}

// Frozen82 and83 share these eleven typed tables. Current target tables
// are asserted separately only after real InitSchema86.
func original82TypedSnapshot(t *testing.T, c *Client) map[string][]Row {
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

func TestAutomationOriginal82ArchiveAndCurrent85(t *testing.T) {
	t.Run("genuine_old82_upgrade_cold_reopen", func(t *testing.T) {
		ctx := context.Background()
		database, e := original82Fixture(t)
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "state.db"), database, 0600); err != nil {
			t.Fatal(err)
		}
		c := custodyLifetimeFileClient(t, dir, "a")
		t.Cleanup(func() { _ = c.Close() })
		if storedVersion(t, c) != 82 {
			t.Fatal("genuine producer database lost old82 stamp")
		}
		if exists, err := columnExists(ctx, c.db, "projects", "incarnation"); err != nil || exists {
			t.Fatal("genuine old82 already has published project71", exists, err)
		}
		if corrected, err := automationCustodyRecipientShape(ctx, c); err != nil || !corrected {
			t.Fatal("genuine old82 lacks corrected recipient shape", corrected, err)
		}
		original82AssertArchive(t, c, e)
		history, typed := sharedActiveRows(t, c), original82TypedSnapshot(t, c)
		beforeLedger, err := c.Query(ctx, `SELECT id,applied_at,checksum FROM applied_migrations ORDER BY id`)
		if err != nil || !reflect.DeepEqual(beforeLedger, e.Ledger) {
			t.Fatal("genuine original198 ledger rows differ", err)
		}
		if err := InitSchema(ctx, c); err != nil {
			t.Fatal("genuine old82 upgrade to current86 refused", err)
		}
		if CurrentSchemaVersion != 86 || storedVersion(t, c) != 86 {
			t.Fatal("current migration did not reach86")
		}
		if exists, err := columnExists(ctx, c.db, "projects", "incarnation"); err != nil || !exists {
			t.Fatal("published project71 migration absent", exists, err)
		}
		original82AssertArchive(t, c, e)
		original83AssertEmptyTargets(t, c)
		if !reflect.DeepEqual(history, sharedActiveRows(t, c)) || !reflect.DeepEqual(typed, original82TypedSnapshot(t, c)) {
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
		newIDs := map[string]bool{"t_local_automation_executors": false, "t_local_automation_execution_progress": false, "t_local_automation_execution_artifacts": false, "t_local_automation_execution_terminals": false, "a094_tokens_user_created_at": false, "a092_projects_incarnation": false, "a093_local_automation_receiver_current_established_inventory": false, "t_local_automation_target_operations": false, "t_local_automation_target_reservations": false}
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
			t.Fatal("upgrade rewrote original198 ledger rows or added wrong count")
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
		if storedVersion(t, c) != 86 {
			t.Fatal("cold reopened current86 stamp changed")
		}
		original82AssertArchive(t, c, e)
		if err := InitSchema(ctx, c); err != nil {
			t.Fatal("current86 cold re-init refused", err)
		}
		original82AssertArchive(t, c, e)
		original83AssertEmptyTargets(t, c)
		laterLedger, err := c.Query(ctx, `SELECT id,applied_at,checksum FROM applied_migrations ORDER BY id`)
		if err != nil || !reflect.DeepEqual(upgraded, laterLedger) || !reflect.DeepEqual(history, sharedActiveRows(t, c)) || !reflect.DeepEqual(typed, original82TypedSnapshot(t, c)) {
			t.Fatal("cold current86 reopen/init changed retained ledger/history/receipt/projections", err)
		}
		// All writes above target the private copy, never the pinned original files.
		original82Fixture(t)
	})
	t.Run("new_current85_cut", func(t *testing.T) {
		ctx := context.Background()
		_, e := original82Fixture(t)
		voters := custodyLifetimeHistoricalVoters(t, 0)
		a := voters[0]
		if CurrentSchemaVersion != 86 || automationCutSourceSchema != 86 || storedVersion(t, a.c) != 86 {
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
		if m.SourceSchema != 86 || m.Codec != 1 || m.Head.Sequence != 1 || m.Head.Digest != genesis.Value.MustDigest() || len(m.Inventory) != 9 {
			t.Fatal("new current cut did not declare truthful86")
		}
		if id == e.CutID {
			t.Fatal("fresh source reused unrelated original82 cut identity")
		}
	})
}
