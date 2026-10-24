package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

const update90Private38 = "82aab9aae0d6cd4aada95900cf66bb4564e48a8795486f43e9de7b8e0ac58494"
const update89EvidenceSHA = "d5850cf01c51d2079d761b5260495bb5423bd970bd532cddb090e6dfe532376a"

type update89Evidence struct {
	original83FixtureEvidence
	LocalFramesSHA256 string
	LayoutDigest      string
}

type update89LocalFrame struct {
	Section int
	Ordinal int64
	Raw     []byte
}

func update89ReadBounded(t *testing.T, name string, limit int64) []byte {
	t.Helper()
	dir := os.Getenv("LITEVIRT_UPDATE89_FIXTURES")
	if !filepath.IsAbs(dir) {
		t.Fatal("genuine immutable f8eb89 fixture directory required")
	}
	path := filepath.Join(dir, name)
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		t.Fatal("bounded immutable89 artifact required", name, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAutomationUpdate90DescriptorAndObservation(t *testing.T) {
	if CurrentSchemaVersion != 90 || automationCutSourceSchema != 90 || automationCutCodec != 1 || len(automationCutSections) != 9 || len(aggregateLocalTables()) != 38 || retainedLocalLayoutDigest() != update90Private38 {
		t.Fatal("current90 provenance must retain codec1/nine sections/private38")
	}
	for version := 69; version <= 90; version++ {
		if !supportedAutomationCutDescriptor(version, 1) || supportedAutomationCutDescriptor(version, 2) {
			t.Fatal("archived/current descriptor changed", version)
		}
	}
	if supportedAutomationCutDescriptor(91, 1) {
		t.Fatal("unknown future provenance admitted")
	}
	for _, retained := range []bool{false, true} {
		for _, version := range []int64{88, 89, 90, 91} {
			for _, digest := range []string{update90Private38, login88Layout, strings.Repeat("a", 64)} {
				o := aggregateLocalObservation{retained: retained, layoutDigest: digest}
				err := o.observe(&aggregateLocalAudit{}, 15, 1, Row{Columns: []string{"id", "version"}, Values: []any{int64(1), version}})
				want := digest == update90Private38 && (version == 90 || retained && version == 89) || retained && digest == login88Layout && version == 88
				if (err == nil) != want {
					t.Fatalf("schema/layout meaning retained=%v version=%d digest=%s: %v", retained, version, digest, err)
				}
			}
		}
	}
}

func TestAutomationUpdate90Genuine89UpgradeArchiveAndFrames(t *testing.T) {
	ctx := context.Background()
	raw := update89ReadBounded(t, "source89-evidence.json", 8<<20)
	if original83Hash(raw) != update89EvidenceSHA {
		t.Fatal("genuine immutable f8eb89 evidence changed")
	}
	var e update89Evidence
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if e.SourceCommit != "f8ebae3b38c38442e39851505c812f42c30554e4" || e.SourceTree != "fb0babb5f73d6975269d3e154bfa3261c7400618" || e.SourceSchemaBlob != "be0ad1f7bbf6bfd5b214f49d97813211a468c80f" || e.SourceCodecBlob != "ad0cc98a177187008e9519474cea3f4652cd3bbc" || e.Version != 89 || e.LayoutDigest != update90Private38 || len(e.Records) != 9 {
		t.Fatal("old source89 provenance changed")
	}
	database := update89ReadBounded(t, "source89-state.db", 16<<20)
	local := update89ReadBounded(t, "source89-local.json", 8<<20)
	if original83Hash(database) != e.StateDBSHA256 || original83Hash(local) != e.LocalFramesSHA256 {
		t.Fatal("old source89 DB/private frames changed")
	}
	var frames []update89LocalFrame
	if err := json.Unmarshal(local, &frames); err != nil || len(frames) == 0 {
		t.Fatal("original private frames", err)
	}
	var observation aggregateLocalObservation
	observation.retained, observation.layoutDigest = true, e.LayoutDigest
	var observed aggregateLocalAudit
	for _, f := range frames {
		if f.Section < 0 || f.Section >= len(aggregateLocalTables()) {
			t.Fatal("source89 private section outside unchanged38")
		}
		row, err := decodeAutomationFramedRow(aggregateLocalTables()[f.Section].descriptor(), f.Ordinal, f.Raw, maxAggregateLocalRecordBytes)
		if err != nil || observation.observe(&observed, f.Section, f.Ordinal, row) != nil {
			t.Fatal("current reader refused genuinely emitted private89 frame", f.Section, f.Ordinal, err)
		}
	}
	if len(observation.counts) != 38 || observation.counts[15] != 1 || observation.prefix != observed.head || observed.head.Sequence < 14 {
		t.Fatal("genuine private89 inventory/certified prefix lost")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.db"), database, 0600); err != nil {
		t.Fatal(err)
	}
	var meta automationCutMetadata
	if err := json.Unmarshal(e.Metadata, &meta); err != nil {
		t.Fatal(err)
	}
	c, err := NewLocalClient(dir, meta.Source)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if storedVersion(t, c) != 89 {
		t.Fatal("original89 DB restamped before migration")
	}
	before, beforeRecords := cutFixtureRead(t, c, e.CutID)
	if before.SourceSchema != 89 || !reflect.DeepEqual(beforeRecords, e.Records) || !reflect.DeepEqual(update90Ledger(t, c), e.Ledger) {
		t.Fatal("original89 stored evidence mismatch")
	}
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal("real89 to90 migration", err)
	}
	if storedVersion(t, c) != 90 || derivedSchemaVersion(ctx, c) != 90 || !reflect.DeepEqual(schemaDDL, e.DDL) {
		t.Fatal("index-only90 changed DDL or failed actual migration")
	}
	ledger := update90Ledger(t, c)
	if len(ledger) != len(e.Ledger)+1 {
		t.Fatal("90 must add exactly one ledger unit")
	}
	for _, old := range e.Ledger {
		rows, err := c.Query(ctx, `SELECT id,checksum,applied_at FROM applied_migrations WHERE id=?`, old.String("id"))
		if err != nil || len(rows) != 1 || !reflect.DeepEqual(rows[0], old) {
			t.Fatal("original migration receipt/checksum changed", old.String("id"), err)
		}
	}
	check := func() {
		t.Helper()
		after, records := cutFixtureRead(t, c, e.CutID)
		rows, err := c.Query(ctx, `SELECT metadata,root FROM local_automation_cuts WHERE id=?`, e.CutID)
		if err != nil || len(rows) != 1 || !bytes.Equal(rows[0].Bytes("metadata"), e.Metadata) || rows[0].String("root") != e.Root || !reflect.DeepEqual(after, before) || !reflect.DeepEqual(records, e.Records) {
			t.Fatal("upgrade/reopen rewrote genuine archived89 bytes/root", err)
		}
		id, err := c.FreezeAutomationCut(ctx, before.Generation, contract.Reduce)
		if err != nil || id != e.CutID {
			t.Fatal("archived89 reuse failed", id, err)
		}
	}
	check()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	c, err = NewLocalClient(dir, meta.Source)
	if err != nil {
		t.Fatal(err)
	}
	if err := InitSchema(ctx, c); err != nil || storedVersion(t, c) != 90 || !reflect.DeepEqual(ledger, update90Ledger(t, c)) {
		t.Fatal("cold90 reopened receipt drift", err)
	}
	check()
}

func TestAutomationUpdate90NonemptyCutAndColdReplay(t *testing.T) {
	ctx := context.Background()
	f, _, _ := updateFirst(t)
	before := updateSnapshot(t, f.c)
	if storedVersion(t, f.c) != 90 {
		t.Fatal("current90 real initialization required")
	}
	if err := f.c.SealVoterGeneration(ctx, 1, "current90-update-cut"); err != nil {
		t.Fatal(err)
	}
	id, err := f.c.FreezeAutomationCut(ctx, 1, contract.Reduce)
	if err != nil {
		t.Fatal("actual source90 update cut", err)
	}
	meta, records := cutFixtureRead(t, f.c, id)
	if meta.SourceSchema != 90 || meta.Codec != 1 || len(meta.Inventory) != 9 || meta.Head.Sequence <= 14 || !reflect.DeepEqual(before, updateSnapshot(t, f.c)) {
		t.Fatal("source90 cut omitted update or changed active state")
	}
	var observation aggregateLocalObservation
	var observed aggregateLocalAudit
	if err := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		attempt := &AutomationReceiverAttempt{id: "current90-update-private38", binding: []byte("current90-update-private38")}
		_, err := aggregateLocalSnapshot(ctx, tx, attempt, f.c, func(section int, n int64, row Row, _ []byte) error {
			return observation.observe(&observed, section, n, row)
		})
		return err
	}); err != nil || observation.prefix != observed.head || len(observation.counts) != 38 {
		t.Fatal("actual current90 private38 observation", err)
	}
	if err := f.c.Close(); err != nil {
		t.Fatal(err)
	}
	c, err := NewLocalClient(f.dir, f.c.hostName)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := c.AutomationReplay(ctx, contract.Reduce, 128); err != nil || !reflect.DeepEqual(before, updateSnapshot(t, c)) {
		t.Fatal("cold90 original update replay changed state", err)
	}
	after, again := cutFixtureRead(t, c, id)
	if !reflect.DeepEqual(after, meta) || !reflect.DeepEqual(again, records) {
		t.Fatal("cold90 reopened cut changed original bytes")
	}
}
