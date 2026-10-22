package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// Removing the complete-source whole-electorate gate must fail the exact
// observed/required assertion even if the later all-fixed gate also refuses.
func TestAutomationAggregateFixedWholeElectorate(t *testing.T) {
	for _, tc := range []struct{ old, fixed, complete int }{{3, 2, 2}, {5, 3, 3}, {5, 4, 4}, {5, 3, 2}, {5, 4, 3}} {
		t.Run(fmt.Sprintf("old%d_fixed%d_complete%d", tc.old, tc.fixed, tc.complete), func(t *testing.T) {
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: tc.old, Sources: tc.fixed})
			for i := 0; i < tc.complete; i++ {
				f.stage(t, i, 11, true)
			}
			if tc.complete < tc.fixed {
				f.stage(t, tc.complete, 2, false)
			}
			active, spool := receiverActive(t, f.receiver.client), receiverStored(t, f.receiver.client)
			typed, audits := automationTypedSnapshot(t, f.receiver.client), receiverAudited(t, f.receiver.client)
			id, err := f.receiver.auditAggregate(context.Background(), f.attempt)
			if tc.complete < MajorityOf(tc.old) {
				if err == nil || !strings.Contains(err.Error(), "complete old electorate observed 2 required 3") {
					t.Fatalf("whole-electorate count assertion: got id=%q error=%v", id, err)
				}
			} else if tc.complete < tc.fixed {
				if err == nil || !strings.Contains(err.Error(), "fixed source roster incomplete") {
					t.Fatalf("fixed roster silently reduced: id=%q error=%v", id, err)
				}
			} else {
				if err != nil || id == "" {
					t.Fatalf("independent complete old quorum not aggregated: %v", err)
				}
				rows, e := f.receiver.client.Query(context.Background(), `SELECT source,incarnation FROM local_automation_aggregate_sources WHERE bundle=? ORDER BY source`, id)
				if e != nil || len(rows) != tc.fixed {
					t.Fatalf("exact counted roster not pinned: %d %v", len(rows), e)
				}
				again, e := f.receiver.auditAggregate(context.Background(), f.attempt)
				if e != nil || again != id {
					t.Fatalf("immutable aggregate retry changed: %q -> %q: %v", id, again, e)
				}
			}
			if !reflect.DeepEqual(typed, automationTypedSnapshot(t, f.receiver.client)) || receiverAudited(t, f.receiver.client) != audits {
				t.Fatal("aggregate changed pre-existing typed stages or source audits")
			}
			if receiverActive(t, f.receiver.client) != active || receiverStored(t, f.receiver.client) != spool {
				t.Fatal("aggregate changed active state or original source spool")
			}
		})
	}
}

func TestAutomationAggregateMinorityMaximum(t *testing.T) {
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 5, Sources: 3, Heads: []int{3, 1, 1}})
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	active := receiverActive(t, f.receiver.client)
	id, err := f.receiver.auditAggregate(context.Background(), f.attempt)
	if err != nil {
		t.Fatalf("one complete minority maximum refused: %v", err)
	}
	rows, err := f.receiver.client.Query(context.Background(), `SELECT head FROM local_automation_aggregates WHERE id=?`, id)
	var head AutomationPrefix
	if err != nil || len(rows) != 1 || json.Unmarshal(rows[0].Bytes("head"), &head) != nil || head.Sequence != 3 {
		t.Fatalf("maximum complete baseline missing: %#v %v", head, err)
	}
	if receiverActive(t, f.receiver.client) != active {
		t.Fatal("aggregate applied minority history")
	}
}

func TestAutomationAggregateSchemaInventory(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	for _, table := range []string{"local_automation_local_audits", "local_automation_local_rows", "local_automation_aggregates", "local_automation_aggregate_sources", "local_automation_aggregate_copies", "local_automation_aggregate_maxima", "local_automation_aggregate_conflicts"} {
		rows, err := a.c.Query(context.Background(), `SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table)
		if err != nil || len(rows) != 1 {
			t.Fatalf("actual aggregate storage missing %s: %v", table, err)
		}
		if !IsNodeLocalClaimTable(table) || IsReplicatedTable(table) {
			t.Fatalf("aggregate evidence not exclusively inert local: %s", table)
		}
	}
	if !supportedAutomationCutDescriptor(75, 1) || !supportedAutomationCutDescriptor(76, 1) || !supportedAutomationCutDescriptor(77, 1) || !supportedAutomationCutDescriptor(78, 1) || !supportedAutomationCutDescriptor(79, 1) || !supportedAutomationCutDescriptor(80, 1) || !supportedAutomationCutDescriptor(81, 1) || !supportedAutomationCutDescriptor(82, 1) || !supportedAutomationCutDescriptor(83, 1) || !supportedAutomationCutDescriptor(84, 1) || !supportedAutomationCutDescriptor(85, 1) || !supportedAutomationCutDescriptor(86, 1) || supportedAutomationCutDescriptor(87, 1) {
		t.Fatal("archived75-81/current82 source inventory not classified")
	}
}

func TestAutomationAggregateLocalCertifiedHistory(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprintf("partial_%t", partial), func(t *testing.T) {
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{1, 1}, LocalHead: 3, Continuing: true})
			for i := range f.producers {
				f.stage(t, i, 11, true)
			}
			if partial {
				if err := f.local.c.ExecuteLocal(context.Background(), func(tx *LocalTx) error { return automationResetSemanticProjectionTx(context.Background(), tx, "") }); err != nil {
					t.Fatal(err)
				}
				if err := f.local.c.AutomationReplay(context.Background(), contract.Reduce, 1); err == nil {
					t.Fatal("partial replay fixture unexpectedly complete")
				}
			}
			active, typed := receiverActive(t, f.local.c), automationTypedSnapshot(t, f.local.c)
			id, err := f.receiver.auditAggregate(context.Background(), f.attempt)
			if err != nil {
				t.Fatalf("higher actual local certified history omitted: %v", err)
			}
			rows, err := f.local.c.Query(context.Background(), `SELECT head FROM local_automation_aggregates WHERE id=?`, id)
			var head AutomationPrefix
			if err != nil || len(rows) != 1 || json.Unmarshal(rows[0].Bytes("head"), &head) != nil || head.Sequence != 3 {
				t.Fatalf("local certified maximum lost: %#v %v", head, err)
			}
			if receiverActive(t, f.local.c) != active || !reflect.DeepEqual(typed, automationTypedSnapshot(t, f.local.c)) {
				t.Fatal("local aggregate repaired active partial state")
			}
		})
	}
}

func TestAutomationAggregateLocalAcceptanceOrigin(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprintf("missing_%t", missing), func(t *testing.T) {
			key := LeaseTermClaimKey("aggregate_lease", 7)
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Continuing: true, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
				value := ClaimValue{LeaseTerm: &LeaseTermValue{Key: key.TargetName, Term: key.OwnerEpoch, Holder: local.name}}
				reply, err := local.c.ClaimAccept(context.Background(), key, testBallot(2, local.name), value, 1, local.signer, unreachable)
				if err != nil || !reply.Accepted {
					t.Fatalf("real local lease acceptance failed: %+v %v", reply, err)
				}
			}})
			for i := range f.producers {
				f.stage(t, i, 11, true)
			}
			if missing {
				if _, err := f.local.c.db.Exec(`DELETE FROM local_automation_cut_records`); err != nil {
					t.Fatal(err)
				}
				if _, err := f.local.c.db.Exec(`DELETE FROM local_automation_cuts`); err != nil {
					t.Fatal(err)
				}
			}
			active, spool := receiverActive(t, f.local.c), receiverStored(t, f.local.c)
			id, err := f.receiver.auditAggregate(context.Background(), f.attempt)
			if missing {
				if err == nil || !strings.Contains(err.Error(), "local acceptance origin unavailable") {
					t.Fatalf("required genuine origin missing refusal absent: %q %v", id, err)
				}
			} else {
				if err != nil || id == "" {
					t.Fatalf("genuine owned cut origin refused: %v", err)
				}
				rows, e := f.local.c.Query(context.Background(), `SELECT origin_ref FROM local_automation_aggregate_copies WHERE bundle=? AND origin_kind='local'`, id)
				if e != nil || len(rows) != 1 || len(rows[0].Bytes("origin_ref")) == 0 {
					t.Fatalf("original local origin not retained: %d %v", len(rows), e)
				}
			}
			if receiverActive(t, f.local.c) != active || receiverStored(t, f.local.c) != spool {
				t.Fatal("origin outcome changed active/spool")
			}
		})
	}
}

func TestAutomationAggregateClaimsExactBallotCopies(t *testing.T) {
	permutations := [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for _, order := range permutations {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			key := LeaseTermClaimKey("aggregate_conflict", 7)
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 5, Sources: 3, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
				for i, copy := range order {
					round := uint64(2)
					if copy == 0 {
						round = 9
					}
					value := ClaimValue{LeaseTerm: &LeaseTermValue{Key: key.TargetName, Term: key.OwnerEpoch, Holder: fmt.Sprintf("copy%d", copy)}}
					reply, err := voters[i].c.ClaimAccept(context.Background(), key, testBallot(round, "common"), value, 1, voters[i].signer, unreachable)
					if err != nil || !reply.Accepted {
						t.Fatalf("real contradictory retained fixture: %+v %v", reply, err)
					}
				}
			}})
			for i := range f.producers {
				f.stage(t, i, 11, true)
			}
			active, spool, audits := receiverActive(t, f.receiver.client), receiverStored(t, f.receiver.client), receiverAudited(t, f.receiver.client)
			id, err := f.receiver.auditAggregate(context.Background(), f.attempt)
			if err == nil || !strings.Contains(err.Error(), "contradictory exact claim ballot") {
				t.Fatalf("lower exact-ballot contradiction escaped after any higher winner: %q %v", id, err)
			}
			if active != receiverActive(t, f.receiver.client) || spool != receiverStored(t, f.receiver.client) || audits != receiverAudited(t, f.receiver.client) {
				t.Fatal("conflict refusal changed original evidence")
			}
		})
	}
}

func TestAutomationAggregateIndependentMaximaAndLosers(t *testing.T) {
	key := LeaseTermClaimKey("aggregate_maxima", 7)
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 5, Sources: 3, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
		for _, i := range []int{0, 2} {
			value := ClaimValue{LeaseTerm: &LeaseTermValue{Key: key.TargetName, Term: key.OwnerEpoch, Holder: fmt.Sprintf("holder%d", i)}}
			reply, err := voters[i].c.ClaimAccept(context.Background(), key, testBallot(uint64(i+2), "common"), value, 1, voters[i].signer, unreachable)
			if err != nil || !reply.Accepted {
				t.Fatalf("real independent acceptance: %+v %v", reply, err)
			}
		}
		reply, err := voters[1].c.ClaimPrepare(context.Background(), key, testBallot(9, "common"), 1)
		if err != nil || !reply.Promised {
			t.Fatalf("real independent higher promise: %+v %v", reply, err)
		}
	}})
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	id, err := f.receiver.auditAggregate(context.Background(), f.attempt)
	if err != nil {
		t.Fatalf("legitimate lower copies refused: %v", err)
	}
	copies, e := f.receiver.client.Query(context.Background(), `SELECT origin_kind,origin_id FROM local_automation_aggregate_copies WHERE bundle=?`, id)
	if e != nil || len(copies) != 3 {
		t.Fatalf("original copies lost: %d %v", len(copies), e)
	}
	rows, e := f.receiver.client.Query(context.Background(), `SELECT promise_ref,accepted_ref FROM local_automation_aggregate_maxima WHERE bundle=?`, id)
	if e != nil || len(rows) != 1 {
		t.Fatalf("independent maxima missing: %d %v", len(rows), e)
	}
	for _, tc := range []struct {
		field    string
		producer int
	}{{"promise_ref", 1}, {"accepted_ref", 2}} {
		var ref struct {
			Kind, ID  string
			Component int
			Ordinal   int64
		}
		if json.Unmarshal(rows[0].Bytes(tc.field), &ref) != nil || ref.Kind != "source" {
			t.Fatalf("invalid %s original reference", tc.field)
		}
		sources, e := f.receiver.client.Query(context.Background(), `SELECT source FROM local_automation_aggregate_sources WHERE bundle=? AND audit=?`, id, ref.ID)
		if e != nil || len(sources) != 1 || sources[0].String("source") != f.producers[tc.producer].client.hostName {
			t.Fatalf("%s chose wrong independent copy: %+v %v", tc.field, ref, e)
		}
	}
}

func TestAutomationAggregateLocalCertifiedTypedHistory(t *testing.T) {
	for _, mode := range []string{"complete", "partial", "secret-coverage", "corrupt-resource"} {
		t.Run(mode, func(t *testing.T) {
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Continuing: true, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
				verifier, err := LoadClaimVerifier(local.pki)
				if err != nil {
					t.Fatal(err)
				}
				automationTypedHistoryFixtureWithDecision(t, local, voters[0], voters[1], verifier, func(d *contract.Decision) {
					if mode == "secret-coverage" || d.Command.Kind != "admit_create" {
						return
					}
					d.Command.Ciphertext = nil
					d.Command.SecretIntentTag = nil
					d.Command.SecretKeyEpoch = ""
					a, err := contract.DecodeAssignment(*d)
					if err != nil {
						t.Fatal(err)
					}
					a.Binding.PayloadID = ""
					d.Assignment, err = json.Marshal(a)
					if err != nil {
						t.Fatal(err)
					}
				})
				key, _ := AutomationClaimKey(1)
				installAutomationEvidence(t, local.c, key, "", 1)
				if _, err = local.c.db.Exec(`UPDATE local_automation_authority SET bootstrap_request='initialize' WHERE id=1`); err != nil {
					t.Fatal(err)
				}
			}})
			for i := range f.producers {
				f.stage(t, i, 11, true)
			}
			if mode == "partial" {
				if err := f.local.c.ExecuteLocal(context.Background(), func(tx *LocalTx) error { return automationResetSemanticProjectionTx(context.Background(), tx, "") }); err != nil {
					t.Fatal(err)
				}
				if err := f.local.c.AutomationReplay(context.Background(), contract.Reduce, 6); err == nil {
					t.Fatal("partial typed fixture completed")
				}
			}
			if mode == "corrupt-resource" {
				if _, err := f.local.c.db.Exec(`UPDATE local_automation_resources SET revision='corrupt' WHERE stage='' AND uid='resource-uid'`); err != nil {
					t.Fatal(err)
				}
			}
			active, typed := receiverActive(t, f.local.c), automationTypedSnapshot(t, f.local.c)
			id, err := f.receiver.auditAggregate(context.Background(), f.attempt)
			if mode == "secret-coverage" {
				if err == nil || !strings.Contains(err.Error(), "required secret/equality coverage unavailable") {
					t.Fatalf("nonempty coverage silently succeeded: %q %v", id, err)
				}
			} else if mode == "corrupt-resource" {
				if err == nil {
					t.Fatal("corrupt typed local predecessor aggregated")
				}
			} else {
				if err != nil {
					t.Fatalf("nonsecret certified typed local history unavailable: %v", err)
				}
				rows, e := f.local.c.Query(context.Background(), `SELECT head FROM local_automation_aggregates WHERE id=?`, id)
				var head AutomationPrefix
				if e != nil || len(rows) != 1 || json.Unmarshal(rows[0].Bytes("head"), &head) != nil || head.Sequence != 12 {
					t.Fatalf("typed local H lost: %+v %v", head, e)
				}
			}
			if active != receiverActive(t, f.local.c) || !reflect.DeepEqual(typed, automationTypedSnapshot(t, f.local.c)) {
				t.Fatal("typed aggregate changed active or prior stage state")
			}
		})
	}
}

func aggregateStored(t *testing.T, c *Client) string {
	t.Helper()
	var all []Row // Test snapshot only; production retains bounded readers.
	for _, table := range []string{"local_automation_local_audits", "local_automation_local_rows", "local_automation_aggregates", "local_automation_aggregate_sources", "local_automation_aggregate_copies", "local_automation_aggregate_maxima", "local_automation_aggregate_conflicts"} {
		rows, err := c.Query(context.Background(), "SELECT * FROM "+table+" ORDER BY rowid")
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, rows...)
	}
	raw, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	return sourceDigest(raw)
}

func TestAutomationAggregateRosterRevision(t *testing.T) {
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 5, Sources: 4})
	for i := 0; i < 3; i++ {
		f.stage(t, i, 11, true)
	}
	if _, err := f.receiver.auditAggregate(context.Background(), f.attempt); err == nil || !strings.Contains(err.Error(), "fixed source roster incomplete") {
		t.Fatalf("partial fixed roster silently reduced: %v", err)
	}
	intent := f.requests[0].Intent
	intent.Sources = append([]VoterMember(nil), intent.Sources[:3]...)
	if _, err := f.receiver.Begin(context.Background(), intent, f.attempt); err == nil {
		t.Fatal("same revision changed fixed roster")
	}
	intent.Revision++
	next, err := f.receiver.Begin(context.Background(), intent, f.attempt)
	if err != nil {
		t.Fatalf("authorized roster revision refused: %v", err)
	}
	f.attempt = next
	f.producers = f.producers[:3]
	f.requests = f.requests[:3]
	for i, p := range f.producers {
		candidate, e := p.Prepare(context.Background(), intent)
		if e != nil {
			t.Fatal(e)
		}
		publication, e := p.Publish(context.Background(), candidate)
		if e != nil {
			t.Fatal(e)
		}
		f.requests[i] = AutomationExportRequest{Intent: intent, Publication: publication, MaxRecords: 1}
		f.stage(t, i, 11, true)
	}
	id, err := f.receiver.auditAggregate(context.Background(), f.attempt)
	if err != nil || id == "" {
		t.Fatalf("exact new authorized fixed roster refused: %v", err)
	}
}

func TestAutomationAggregateRetryReopen(t *testing.T) {
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2})
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	id, err := f.receiver.auditAggregate(context.Background(), f.attempt)
	if err != nil {
		t.Fatal(err)
	}
	stored, active, spool := aggregateStored(t, f.receiver.client), receiverActive(t, f.receiver.client), receiverStored(t, f.receiver.client)
	again, err := f.receiver.auditAggregate(context.Background(), f.attempt)
	if err != nil || again != id || aggregateStored(t, f.receiver.client) != stored {
		t.Fatalf("exact retry rewrote immutable identity: %q %q %v", id, again, err)
	}
	host, dir := f.receiver.client.hostName, f.receiver.dir
	if err = f.receiver.client.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewLocalClient(f.dir, host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	reopened.SetVoterConfigGate(func() bool { return true })
	r := NewAutomationReceiver(reopened, dir)
	if _, err = r.auditAggregate(context.Background(), f.attempt); err == nil {
		t.Fatal("foreign process attempt revived by durable aggregate")
	}
	a, err := r.Begin(context.Background(), f.requests[0].Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	again, err = r.auditAggregate(context.Background(), a)
	if err != nil || again != id || aggregateStored(t, reopened) != stored || receiverActive(t, reopened) != active || receiverStored(t, reopened) != spool {
		t.Fatalf("reopened inert aggregate differs: %q %v", again, err)
	}
}
