package corrosion

import (
	"context"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"reflect"
	"testing"
)

func TestAutomationCut86NonemptyExecutionOriginalReplay(t *testing.T) {
	f, _ := executionReplayCompletedFixture(t)
	ctx := context.Background()
	if storedVersion(t, f.c) != 90 {
		t.Fatal("actual InitSchema execution86 required")
	}
	before := executionStorageSnapshot(t, f.c)
	if err := f.c.SealVoterGeneration(ctx, 1, "execution86-original-cut"); err != nil {
		t.Fatal(err)
	}
	id, err := f.c.FreezeAutomationCut(ctx, 1, contract.Reduce)
	if err != nil {
		t.Fatal("actual nonempty execution86 cut", err)
	}
	m, records := cutFixtureRead(t, f.c, id)
	if m.SourceSchema != 90 || m.Codec != 1 || len(m.Inventory) != 9 {
		t.Fatal("execution86 cut changed certified inventory", m)
	}
	after := executionStorageSnapshot(t, f.c)
	for _, table := range executionStorageTables {
		if !reflect.DeepEqual(before[table], after[table]) {
			t.Fatal("cut changed active execution", table)
		}
	}
	again, err := f.c.FreezeAutomationCut(ctx, 1, contract.Reduce)
	if err != nil || again != id {
		t.Fatal("execution86 archive retry", again, err)
	}
	later, laterRecords := cutFixtureRead(t, f.c, id)
	if !reflect.DeepEqual(m, later) || !reflect.DeepEqual(records, laterRecords) {
		t.Fatal("execution86 archive bytes changed")
	}
	for schema := 69; schema <= 86; schema++ {
		if !supportedAutomationCutDescriptor(schema, 1) {
			t.Fatal("archived public descriptor lost", schema)
		}
	}
}

// A forward schema can contain required provenance this binary cannot inventory.
// It must not silently produce a new lower-schema complete cut.
func TestAutomationCutRefusesUnknownSourceSchema(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	ctx := context.Background()
	if err := a.c.SealVoterGeneration(ctx, 1, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.c.db.Exec(`UPDATE schema_state SET version=? WHERE id=1`, CurrentSchemaVersion+1); err != nil {
		t.Fatal(err)
	}
	if _, err := a.c.FreezeAutomationCut(ctx, 1, nil); err == nil {
		t.Fatal("new cut omitted unknown forward-schema provenance")
	}
}

func TestAutomationCutArchiveKeepsSourceSchema(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	ctx := context.Background()
	if err := a.c.SealVoterGeneration(ctx, 1, "test"); err != nil {
		t.Fatal(err)
	}
	// Create the historical fixture with the genuine schema69 descriptor.
	if _, err := a.c.db.Exec(`UPDATE schema_state SET version=69 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	id, err := a.c.FreezeAutomationCut(ctx, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, records := cutFixtureRead(t, a.c, id)
	if before.SourceSchema != 69 {
		t.Fatal("wrong frozen source schema", before.SourceSchema)
	}
	if _, err = a.c.db.Exec(`UPDATE schema_state SET version=? WHERE id=1`, CurrentSchemaVersion+1); err != nil {
		t.Fatal(err)
	}
	again, err := a.c.FreezeAutomationCut(ctx, 1, nil)
	if err != nil || again != id {
		t.Fatal("forward live schema invalidated compatible archive", err)
	}
	after, later := cutFixtureRead(t, a.c, id)
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(records, later) {
		t.Fatal("live schema relabeled or rescanned archive")
	}
	// Even an internally consistent content root cannot make an unsupported
	// artifact schema readable by this codec.
	after.SourceSchema = CurrentSchemaVersion + 1
	metadata, root, err := automationCutRoot(after)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.c.db.Exec(`UPDATE local_automation_cuts SET metadata=?,root=? WHERE id=?`, metadata, root, id); err != nil {
		t.Fatal(err)
	}
	if _, err = a.c.FreezeAutomationCut(ctx, 1, nil); err == nil {
		t.Fatal("unsupported archived artifact schema accepted")
	}
}

// Legacy import advances the row's generation when raising a promise while
// retaining its authentic older acceptance signature. Export must preserve it.
func TestAutomationCutRetainsLegacyImportedSignature(t *testing.T) {
	ctx := context.Background()
	_, a, b, c := threeVoters(t)
	key := workloadKey()
	value := workloadValue("proof", "b", "old-owner")
	accepted, err := a.c.ClaimAccept(ctx, key, testBallot(2, "a"), value, 1, a.signer, unreachable)
	if err != nil || !accepted.Accepted {
		t.Fatal(accepted, err)
	}
	next := VoterConfigValue{Generation: 2, Members: membersOf(a, b, c), Change: VoterChangeGenesis, CreatedBy: "t", CreatedAt: "t"}
	if err = WriteVoterConfig(ctx, a.c, next, ClaimCertificate{}); err != nil {
		t.Fatal(err)
	}
	if _, err = a.c.ImportClaimsAndAdopt(ctx, 2, []string{"b", "c"}, []ClaimVoterState{{Key: key, Promised: testBallot(9, "b"), ConfigGeneration: 1}}); err != nil {
		t.Fatal(err)
	}
	before, found, err := a.c.ClaimState(ctx, key)
	if err != nil || !found || before.Accept == nil || before.Accept.ConfigGeneration != 1 || before.ConfigGeneration != 2 {
		t.Fatal("fixture lost legitimate older signature", before, err)
	}
	if err = a.c.SealVoterGeneration(ctx, 2, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err = a.c.FreezeAutomationCut(ctx, 2, nil); err != nil {
		t.Fatal("valid inherited acceptance refused", err)
	}
	after, _, err := a.c.ClaimState(ctx, key)
	if err != nil || after.Accept == nil || after.Accept.ConfigGeneration != 1 || after.ValueDigest != before.ValueDigest {
		t.Fatal("source changed inherited acceptance", err)
	}
}

func TestAutomationCutNewLiveExcludesPublicationEgress(t *testing.T) {
	producer, request := sourcePreparationFixture(t)
	ctx := context.Background()
	before, records := cutFixtureRead(t, producer.client, func() string {
		id, err := producer.client.FreezeAutomationCut(ctx, request.Generation, nil)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}())
	if before.SourceSchema != CurrentSchemaVersion || before.Codec != 1 {
		t.Fatal("new live descriptor differs", before)
	}
	if err := producer.InitializePublication(ctx); err != nil {
		t.Fatal(err)
	}
	p, err := producer.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Discard()
	if _, err := producer.Publish(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := producer.client.SealVoterGeneration(ctx, 2, "publication inventory test"); err != nil {
		t.Fatal(err)
	}
	nextID, err := producer.client.FreezeAutomationCut(ctx, 2, nil)
	if err != nil {
		t.Fatal("new live cut with prior egress rows refused", err)
	}
	next, _ := cutFixtureRead(t, producer.client, nextID)
	if nextID == before.ID || next.Generation != 2 || next.SourceSchema != CurrentSchemaVersion || next.Codec != 1 || len(next.Inventory) != 9 {
		t.Fatal("new live cut descriptor/inventory differs", next)
	}
	rows, err := producer.client.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_publications`)
	if err != nil || rows[0].Int("n") != 1 {
		t.Fatal("prior egress row did not survive new cut", err)
	}
	id, err := producer.client.FreezeAutomationCut(ctx, request.Generation, nil)
	if err != nil {
		t.Fatal(err)
	}
	after, later := cutFixtureRead(t, producer.client, id)
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(records, later) {
		t.Fatal("publication recursively changed content cut")
	}
}

func TestAutomationCutArchive70SurvivesReceiverSchema71(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	ctx := context.Background()
	if err := a.c.SealVoterGeneration(ctx, 1, "archive70"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.c.db.Exec(`UPDATE schema_state SET version=70 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	id, err := a.c.FreezeAutomationCut(ctx, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, records := cutFixtureRead(t, a.c, id)
	if before.SourceSchema != 70 {
		t.Fatal("archive descriptor wrong")
	}
	if _, err = a.c.db.Exec(`UPDATE schema_state SET version=71 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	again, err := a.c.FreezeAutomationCut(ctx, 1, nil)
	if err != nil || again != id {
		t.Fatal("receiver schema invalidated archive70", err)
	}
	after, later := cutFixtureRead(t, a.c, id)
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(records, later) {
		t.Fatal("receiver schema relabeled archive70 bytes/root")
	}
}
