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
	"github.com/litevirt/litevirt/internal/pki"
)

const login88Layout = "a9aca37bd633b6f064e26d681953cfeaa240010dae8dde69e45d8ae0574c5301"

func login88Fixture(t *testing.T, name, digest string) []byte {
	t.Helper()
	root := os.Getenv("LITEVIRT_LOGIN88_FIXTURES")
	if root == "" {
		t.Skip("genuine signed88 offline artifact not supplied")
	}
	raw, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	if original83Hash(raw) != digest {
		t.Fatal("genuine88 artifact changed", name)
	}
	return raw
}
func TestAutomationLogin89Frozen88Layout(t *testing.T) {
	if retainedLocalLayout88Digest() != login88Layout || retainedLocalLayoutDigest() != "82aab9aae0d6cd4aada95900cf66bb4564e48a8795486f43e9de7b8e0ac58494" {
		t.Fatal("independent88 descriptor changed")
	}
	old, current := aggregateLocalTables88(), aggregateLocalTables()
	if len(old) != 38 || len(current) != 38 || CurrentSchemaVersion != 89 || automationCutSourceSchema != 89 {
		t.Fatal("current89 boundary")
	}
	for i := range old {
		if old[i].table != "local_automation_credential_issuance" {
			if old[i] != current[i] {
				t.Fatal("unrelated private descriptor changed", i)
			}
		} else {
			if current[i].columns != old[i].columns+",proof_mode,identity_generation,original_witness,parent_kind,parent_alias,parent_realm,parent_birth" || current[i].shape != old[i].shape+"tittttt" {
				t.Fatal("issuance observation shape")
			}
			if bytes.Contains([]byte(current[i].columns), []byte("credential_digest")) {
				t.Fatal("digest exported to observations")
			}
		}
	}
	for _, tc := range []struct {
		digest  string
		version int64
		valid   bool
	}{{login88Layout, 88, true}, {login88Layout, 89, false}, {retainedLocalLayoutDigest(), 89, true}, {retainedLocalLayoutDigest(), 88, false}} {
		o := aggregateLocalObservation{retained: true, layoutDigest: tc.digest}
		err := o.observe(&aggregateLocalAudit{}, 15, 1, Row{Columns: []string{"id", "version"}, Values: []any{int64(1), tc.version}})
		if (err == nil) != tc.valid {
			t.Fatal("schema/layout meaning", tc, err)
		}
	}
	for _, schema := range []int{83, 85, 87, 88, 89} {
		if !supportedAutomationCutDescriptor(schema, 1) || supportedAutomationCutDescriptor(schema, 2) {
			t.Fatal("source admission", schema)
		}
	}
}
func TestAutomationLogin89Genuine88PublicCold(t *testing.T) {
	ctx := context.Background()
	database := login88Fixture(t, "public88-state.db", "7c413f63b9def03c55efcc9386eac1f97aa3d8ad39aeca53b2c10c90b6eaa12f")
	raw := login88Fixture(t, "public88-evidence.json", "69ab4564222d07bd4c597773afb4a5fa7ec0c5b4ad1ab68e524c08d3eb04d8f4")
	var e original83FixtureEvidence
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if e.Version != 88 || e.SourceCommit != "3011d6af1c6cc9293c35a9dca0bd3670c866e4b1" || e.SourceTree != "187640228eec1bfe64dcf3a65b2c17911ff4ef53" || len(e.Ledger) != 208 {
		t.Fatal("actual source88 provenance")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.db"), database, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := NewLocalClient(dir, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if storedVersion(t, c) != 88 {
		t.Fatal("older producer restamped")
	}
	before, records := cutFixtureRead(t, c, e.CutID)
	if before.SourceSchema != 88 || before.Codec != 1 || len(before.Inventory) != 9 || !reflect.DeepEqual(records, e.Records) {
		t.Fatal("archived88 cut")
	}
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	if storedVersion(t, c) != 89 || !reflect.DeepEqual(schemaDDL, e.DDL) {
		t.Fatal("schema89 changed predecessor DDL")
	}
	for _, old := range e.Ledger {
		rows, err := c.Query(ctx, `SELECT checksum,applied_at FROM applied_migrations WHERE id=?`, old.String("id"))
		if err != nil || len(rows) != 1 || rows[0].String("checksum") != old.String("checksum") || rows[0].String("applied_at") != old.String("applied_at") {
			t.Fatal("prior ledger changed", old.String("id"), err)
		}
	}
	rows, err := c.Query(ctx, `SELECT proof_mode,identity_generation,original_witness,parent_kind,parent_alias,parent_realm,parent_birth FROM local_automation_credential_issuance WHERE credential_id='predecessor88'`)
	if err != nil || len(rows) != 1 || rows[0].String("proof_mode") != "origin" || rows[0].Int64("identity_generation") != 0 {
		t.Fatal("old stamp mode changed", rows, err)
	}
	for _, key := range []string{"original_witness", "parent_kind", "parent_alias", "parent_realm", "parent_birth"} {
		if rows[0].String(key) != "" {
			t.Fatal("migration invented attachment")
		}
	}
	i, err := AutomationSessionPrincipal(ctx, c, "predecessor88")
	if err != nil || i == nil || i.UID != "principal-uid" {
		t.Fatal("genuine origin stamp compatibility", i, err)
	}
	after, again := cutFixtureRead(t, c, e.CutID)
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(records, again) {
		t.Fatal("migration reinterpreted original88")
	}
	stored, err := c.Query(ctx, `SELECT metadata,root FROM local_automation_cuts WHERE id=?`, e.CutID)
	if err != nil || !bytes.Equal(stored[0].Bytes("metadata"), e.Metadata) || stored[0].String("root") != e.Root {
		t.Fatal("archive bytes changed", err)
	}
	if id, err := c.FreezeAutomationCut(ctx, 1, contract.Reduce); err != nil || id != e.CutID {
		t.Fatal("genuine88 reuse", id, err)
	}
}

// Historical Current38 means schema88, independently of the current89 shape.
func TestAutomationContinuityCurrent38RetainedWarmCold(t *testing.T) {
	ctx := context.Background()
	database := login88Fixture(t, "private88-state.db", "3fcbf2e2172499e4ab5c284d3b5807ab6db8ffc6d7778997ed1a99ff9aeb274f")
	raw := login88Fixture(t, "private88-evidence.json", "6e5c81d17be9e2f4b30090eb8cf843657950c643705a8ecdfae7d619001e93fc")
	var e continuity87PrivateEvidence
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if e.Version != 88 || e.SourceCommit != "3011d6af1c6cc9293c35a9dca0bd3670c866e4b1" || e.SourceTree != "187640228eec1bfe64dcf3a65b2c17911ff4ef53" {
		t.Fatal("original88 private provenance")
	}
	hostdir := t.TempDir()
	for name, sha := range map[string]string{"ca.crt": "29d8e0f34d1a85208c00b544664a00c1b6b2fdc98c01d1f367181cdeb6f2529f", "host.crt": "9bb528ad59d5d6a82e6f2a988444b0ecbd37bb82728ead13fd7b8ca178bba158", "host.key": "df9b5d7a9ecf59f2274c963749d6ded9a17fa9879ec3cc0b09364db6cb297a2d"} {
		if err := os.WriteFile(filepath.Join(hostdir, name), login88Fixture(t, name, sha), 0600); err != nil {
			t.Fatal(err)
		}
	}
	view, err := pki.CaptureHostTrust(ctx, hostdir, e.Host)
	if err != nil {
		t.Fatal(err)
	}
	public, err := view.PublicEvidence()
	if err != nil || !bytes.Equal(public, e.PublicTrust) {
		t.Fatal("retained trust changed", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.db"), database, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := NewLocalClient(dir, e.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if storedVersion(t, c) != 88 {
		t.Fatal("private producer restamped")
	}
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	h, err := decodeRetainedHeader(e.Header)
	if err != nil || h.LayoutDigest != login88Layout || h.Head.Sequence != 4 {
		t.Fatal("literal88 header meaning", err)
	}
	directory := retainedDirectoryReader{retainedFrameAddress{e.Directory.Namespace, e.Directory.Source, e.Directory.LocalID, retainedStreamKind(e.Directory.Kind)}, e.Directory.Objects}
	active := receiverActive(t, c)
	tx0, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx0.Rollback()
	tx := &LocalTx{tx: tx0}
	frames := retainedCompatibilityFrames(t, ctx, tx, directory)
	rebuilt, err := rebuildRetainedAggregate(ctx, tx, h, e.Binding, directory, view)
	if err != nil || rebuilt.id != e.AggregateID {
		t.Fatal("genuine88 cold rebuild under89", err)
	}
	rows, err := tx.Query(ctx, `SELECT uid,generation,original_witness FROM local_automation_identity_continuity WHERE stage=?`, "receiver-audit:"+rebuilt.local.store.id)
	if err != nil || len(rows) != 1 || rows[0].String("uid") != "principal-uid" || rows[0].Int64("generation") != 1 {
		t.Fatal("old38 lost exact attachment", rows, err)
	}
	if !reflect.DeepEqual(frames, retainedCompatibilityFrames(t, ctx, tx, directory)) {
		t.Fatal("original38 frames mutated")
	}
	retainedCompatibilityClean(t, ctx, tx, rebuilt)
	if err := tx0.Rollback(); err != nil {
		t.Fatal(err)
	}
	if receiverActive(t, c) != active {
		t.Fatal("retained reconstruction changed ACTIVE")
	}
}

func TestAutomationContinuityCurrent38NonemptySnapshot(t *testing.T) {
	ctx := context.Background()
	database := login88Fixture(t, "private88-state.db", "3fcbf2e2172499e4ab5c284d3b5807ab6db8ffc6d7778997ed1a99ff9aeb274f")
	raw := login88Fixture(t, "private88-evidence.json", "6e5c81d17be9e2f4b30090eb8cf843657950c643705a8ecdfae7d619001e93fc")
	var e continuity87PrivateEvidence
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.db"), database, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := NewLocalClient(dir, e.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if storedVersion(t, c) != 88 {
		t.Fatal("source88 snapshot relabeled")
	}
	h, err := decodeRetainedHeader(e.Header)
	if err != nil || h.LayoutDigest != login88Layout {
		t.Fatal(err)
	}
	tx0, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx0.Rollback()
	tx := &LocalTx{tx: tx0}
	directory := retainedDirectoryReader{retainedFrameAddress{e.Directory.Namespace, e.Directory.Source, e.Directory.LocalID, retainedStreamKind(e.Directory.Kind)}, e.Directory.Objects}
	d, a, err := directory.find(ctx, tx, "local", h.LocalID)
	if err != nil || len(d.ComponentInventories) != 38 {
		t.Fatal("genuine38 descriptor", err)
	}
	seen := false
	err = a.walk(ctx, tx, d, func(section int, n int64, raw []byte) error {
		if section != 35 {
			return nil
		}
		row, err := decodeAutomationFramedRow(aggregateLocalTables88()[35].descriptor(), n, raw, maxAggregateLocalRecordBytes)
		if err != nil {
			return err
		}
		if row.String("uid") != "principal-uid" || row.String("original_witness") != "principal-source-lifetime" {
			t.Fatal("original88 snapshot changed")
		}
		seen = true
		return nil
	})
	if err != nil || !seen {
		t.Fatal("nonempty38 continuity frame missing", err)
	}
}

func TestAutomationLogin89LocalColumns(t *testing.T) {
	c := lifecycleDB(t)
	rows, err := c.Query(context.Background(), `SELECT name,type,"notnull" AS required,dflt_value FROM pragma_table_info('local_automation_credential_issuance') ORDER BY cid`)
	if err != nil || len(rows) != 15 {
		t.Fatal("issuance column inventory", len(rows), err)
	}
	names := []string{"proof_mode", "identity_generation", "original_witness", "parent_kind", "parent_alias", "parent_realm", "parent_birth"}
	for i, name := range names {
		r := rows[8+i]
		typ, def := "TEXT", "''"
		if i == 0 {
			def = "'origin'"
		}
		if i == 1 {
			typ, def = "INTEGER", "0"
		}
		if r.String("name") != name || r.String("type") != typ || r.Int64("required") != 1 || r.String("dflt_value") != def {
			t.Fatal("local column shape/default", name, r)
		}
	}
	var seen int
	for _, m := range schemaMigrationLedger {
		if m.Version != 89 {
			continue
		}
		if m.Kind != kindAddColumn || !strings.HasPrefix(m.Target, "local_automation_credential_issuance.") {
			t.Fatal("unrelated89 allocation", m)
		}
		seen++
	}
	if seen != 7 {
		t.Fatal("schema89 allocation", seen)
	}
}
