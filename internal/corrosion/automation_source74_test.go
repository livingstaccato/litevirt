package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

func source74LocalSnapshot(t *testing.T, c *Client) map[string][]Row {
	t.Helper()
	out := map[string][]Row{}
	for _, table := range []string{"local_automation_lifetimes", "local_automation_credential_issuance"} {
		rows, err := c.Query(context.Background(), "SELECT * FROM "+table+" ORDER BY rowid")
		if err != nil {
			t.Fatal(err)
		}
		out[table] = rows
	}
	return out
}

// Historical typed certificates use the existing fixture/reducer. This is real
// source publication/transport/audit, not a fresh business issuer or a proof that
// local lifecycle observations can be carried to another node as authority.
func TestAutomationSource74PublicationPrivacyAndReopen(t *testing.T) {
	ctx := context.Background()
	marker := "private-credential-digest-never-public-74"
	var localBefore map[string][]Row
	var typedBefore map[string][]Row
	var permanentBefore []Row
	p, r, q, peer, dir := receiverAuditFixture(t, 0, func(a *claimTestVoter, voters []*claimTestVoter) {
		// Exercise the current SQL namespace, independent of archived descriptors.
		if _, err := a.c.db.Exec(`UPDATE schema_state SET version=82 WHERE id=1`); err != nil {
			t.Fatal(err)
		}
		verifier, err := LoadClaimVerifier(a.pki)
		if err != nil {
			t.Fatal(err)
		}
		automationTypedHistoryFixture(t, a, voters[1], voters[2], verifier)
		key, _ := AutomationClaimKey(1)
		installAutomationEvidence(t, a.c, key, "", 1)
		if _, err := a.c.db.Exec(`UPDATE local_automation_authority SET bootstrap_request='initialize' WHERE id=1`); err != nil {
			t.Fatal(err)
		}
		if err := InsertUser(ctx, a.c, "local-observation", "operator", "fixture-hash"); err != nil {
			t.Fatal(err)
		}
		if err := InsertProject(ctx, a.c, ProjectRecord{Name: "local-project-observation"}); err != nil {
			t.Fatal(err)
		}
		lifetime, err := AutomationLifetime(ctx, a.c, "principal", "local-observation")
		if err != nil || lifetime.Witness == "" {
			t.Fatal("real local account observation missing", err)
		}
		// Invalid private sentinel deliberately grants no credential or principal.
		// A cut must exclude it regardless of its content or validity.
		if _, err = a.c.db.Exec(`INSERT INTO local_automation_credential_issuance(kind,credential_id,username,witness,principal_uid,cluster_uid,credential_digest,valid) VALUES('token','private-sentinel','local-observation',?,'unissued','unissued',?,0)`, lifetime.Witness, marker); err != nil {
			t.Fatal(err)
		}
		// Incoming retirement ordering and its secret remain outside every cut.
		if _, err = a.c.db.Exec(`INSERT INTO host_fence_credentials(host_name,ipmi_pass,updated_at,after_retirement) VALUES('private-retirement',?,'later','retired')`, marker); err != nil {
			t.Fatal(err)
		}
		localBefore = source74LocalSnapshot(t, a.c)
		typedBefore = automationTypedSnapshot(t, a.c)
		permanentBefore = sharedActiveRows(t, a.c)
	})
	if storedVersion(t, p.client) != CurrentSchemaVersion || storedVersion(t, r.client) != CurrentSchemaVersion {
		t.Fatal("fixture is not current SQL schema82")
	}
	if !reflect.DeepEqual(localBefore, source74LocalSnapshot(t, p.client)) || !reflect.DeepEqual(typedBefore, automationTypedSnapshot(t, p.client)) || !reflect.DeepEqual(permanentBefore, sharedActiveRows(t, p.client)) {
		t.Fatal("freeze/publication changed source evidence")
	}
	check := func(raw []byte) {
		t.Helper()
		if bytes.Contains(raw, []byte(marker)) {
			t.Fatal("private credential digest escaped public source")
		}
	}
	checkRows := func(c *Client, tables ...string) {
		t.Helper()
		for _, table := range tables {
			rows, err := c.Query(ctx, "SELECT * FROM "+table+" ORDER BY rowid")
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				for _, v := range row.Values {
					switch v := v.(type) {
					case string:
						check([]byte(v))
					case []byte:
						check(v)
					}
				}
			}
		}
	}
	checkRows(p.client, "local_automation_cuts", "local_automation_cut_records", "local_automation_publications")
	cutID, err := p.client.FreezeAutomationCut(ctx, q.Intent.Generation, contract.Reduce)
	if err != nil {
		t.Fatal(err)
	}
	meta, records := cutFixtureRead(t, p.client, cutID)
	if meta.SourceSchema != CurrentSchemaVersion || len(meta.Inventory) != 9 {
		t.Fatal("wrong source74 descriptor", meta)
	}
	for _, section := range records {
		for _, record := range section {
			check(record)
		}
	}
	sourceActive := receiverActive(t, p.client)
	receiverBefore := receiverActive(t, r.client)
	receiverLocal := source74LocalSnapshot(t, r.client)
	attempt, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	for component := uint32(0); component <= 11; component++ {
		request := q
		request.Component = component
		request.Cursor = ""
		for {
			page, err := p.ExportAutomationSource(peer, request)
			if err != nil {
				t.Fatal("actual source74 transport", err)
			}
			check(page.Metadata)
			check(page.Chunk)
			check([]byte(page.Cursor))
			for _, record := range page.Records {
				check(record)
			}
			progress, err := r.Stage(ctx, attempt, "a", request, page)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(progress)
			if err != nil {
				t.Fatal(err)
			}
			check(raw)
			if page.Terminal {
				break
			}
			request.Cursor = page.Cursor
		}
	}
	if err := r.AuditSource(ctx, attempt, "a"); err != nil {
		t.Fatal("typed source74 receiver audit", err)
	}
	if receiverActive(t, r.client) != receiverBefore || receiverActive(t, p.client) != sourceActive || !reflect.DeepEqual(receiverLocal, source74LocalSnapshot(t, r.client)) || !reflect.DeepEqual(localBefore, source74LocalSnapshot(t, p.client)) {
		t.Fatal("transport/audit promoted local observation or changed active source/receiver")
	}
	checkRows(r.client, "local_automation_receiver_sources", "local_automation_receiver_records", "local_automation_receiver_audits")
	rows, err := r.client.Query(ctx, `SELECT uid FROM local_automation_resources WHERE stage<>''`)
	if err != nil || len(rows) != 2 {
		t.Fatal("actual typed historical projection missing", rows, err)
	}
	stored, derived := receiverStored(t, r.client), receiverAudited(t, r.client)
	if err := r.client.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewLocalClient(dir, "b")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.SetVoterConfigGate(func() bool { return true })
	if storedVersion(t, reopened) != CurrentSchemaVersion || receiverActive(t, reopened) != receiverBefore || receiverStored(t, reopened) != stored || receiverAudited(t, reopened) != derived || !reflect.DeepEqual(receiverLocal, source74LocalSnapshot(t, reopened)) {
		t.Fatal("schema74 reopen changed inert evidence")
	}
	fresh := NewAutomationReceiver(reopened, r.dir)
	current, err := fresh.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.AuditSource(ctx, current, "a"); err != nil {
		t.Fatal("schema74 reauthorized audit", err)
	}
}

// An old supported descriptor keeps identical bytes/root even when live schema
// is newer or malformed. Archive reuse must precede the live typed-schema gate.
func TestAutomationSource82KeepsArchived69To81(t *testing.T) {
	for _, schema := range []int{69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			_, a, _, _ := threeVoters(t)
			ctx := context.Background()
			if err := a.c.SealVoterGeneration(ctx, 1, "archive before74"); err != nil {
				t.Fatal(err)
			}
			if _, err := a.c.db.Exec(`UPDATE schema_state SET version=? WHERE id=1`, schema); err != nil {
				t.Fatal(err)
			}
			id, err := a.c.FreezeAutomationCut(ctx, 1, nil)
			if err != nil {
				t.Fatal(err)
			}
			before, records := cutFixtureRead(t, a.c, id)
			if _, err := a.c.db.Exec(`UPDATE schema_state SET version=82 WHERE id=1`); err != nil {
				t.Fatal(err)
			}
			if _, err := a.c.db.Exec(`ALTER TABLE local_automation_resources ADD COLUMN unknown_private_column TEXT GENERATED ALWAYS AS (uid) VIRTUAL`); err != nil {
				t.Fatal(err)
			}
			again, err := a.c.FreezeAutomationCut(ctx, 1, nil)
			if err != nil || again != id {
				t.Fatal("live82 invalidated immutable archive", err)
			}
			after, later := cutFixtureRead(t, a.c, id)
			if before.SourceSchema != schema || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(records, later) {
				t.Fatal("archive descriptor/bytes/root changed")
			}
		})
	}
}

func TestAutomationSource74TypedRefusalInert(t *testing.T) {
	for _, mode := range []string{"missing-resource", "altered-resource"} {
		t.Run(mode, func(t *testing.T) {
			ca, a, b, c := threeVoters(t)
			verifier, err := LoadClaimVerifier(ca.pkiDir(t, "source74-refusal"))
			if err != nil {
				t.Fatal(err)
			}
			automationTypedHistoryFixture(t, a, b, c, verifier)
			ctx := context.Background()
			if err := InsertUser(ctx, a.c, "private-observation", "operator", "fixture-hash"); err != nil {
				t.Fatal(err)
			}
			if _, err := a.c.db.Exec(`INSERT INTO local_automation_credential_issuance(kind,credential_id,username,witness,principal_uid,cluster_uid,credential_digest,valid) VALUES('token','invalid-private','private-observation','local-only','unissued','unissued','private-refusal-marker',0)`); err != nil {
				t.Fatal(err)
			}
			if err := a.c.SealVoterGeneration(ctx, 1, "source74 projection refusal"); err != nil {
				t.Fatal(err)
			}
			mutation := `DELETE FROM local_automation_resources WHERE stage='' AND uid='resource-uid'`
			if mode == "altered-resource" {
				mutation = `UPDATE local_automation_resources SET revision='altered-source74' WHERE stage='' AND uid='resource-uid'`
			}
			result, err := a.c.db.Exec(mutation)
			if err != nil {
				t.Fatal(err)
			}
			count, err := result.RowsAffected()
			if err != nil || count != 1 {
				t.Fatal("fixture did not alter one active resource", count, err)
			}
			typed, local, active := automationTypedSnapshot(t, a.c), source74LocalSnapshot(t, a.c), receiverActive(t, a.c)
			id, err := a.c.FreezeAutomationCut(ctx, 1, contract.Reduce)
			if err == nil || id != "" {
				t.Fatal("corrupt typed source74 published", id, err)
			}
			if !reflect.DeepEqual(typed, automationTypedSnapshot(t, a.c)) || !reflect.DeepEqual(local, source74LocalSnapshot(t, a.c)) || receiverActive(t, a.c) != active {
				t.Fatal("source refusal repaired or changed source/local state")
			}
			rows, err := a.c.Query(ctx, `SELECT id FROM local_automation_cuts UNION ALL SELECT cut_id FROM local_automation_cut_records`)
			if err != nil || len(rows) != 0 {
				t.Fatal("source refusal wrote cut records", rows, err)
			}
		})
	}
}
