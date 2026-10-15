package corrosion

import (
	"context"
	"reflect"
	"testing"
)

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
	after.SourceSchema++
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
