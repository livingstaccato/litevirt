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

func TestAutomationAggregateSchemaShapeRefusal(t *testing.T) {
	for _, mode := range []string{"column", "index", "collation", "missing-lifetime-unique"} {
		t.Run(mode, func(t *testing.T) {
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2})
			var query string
			switch mode {
			case "column":
				query = `ALTER TABLE local_automation_aggregate_maxima ADD COLUMN surprise TEXT`
			case "index":
				query = `CREATE INDEX unexpected_aggregate_index ON local_automation_aggregate_maxima(bundle)`
			case "collation":
				query = `DROP TABLE local_automation_aggregate_maxima; CREATE TABLE local_automation_aggregate_maxima(bundle TEXT NOT NULL,claim_key BLOB COLLATE NOCASE NOT NULL,promise_ref BLOB NOT NULL,accepted_ref BLOB NOT NULL,PRIMARY KEY(bundle,claim_key))`
			case "missing-lifetime-unique":
				query = `DROP TABLE local_automation_aggregate_sources; CREATE TABLE local_automation_aggregate_sources(bundle TEXT NOT NULL,source TEXT NOT NULL,incarnation TEXT NOT NULL,audit TEXT NOT NULL,publication TEXT NOT NULL,root TEXT NOT NULL,cut_id TEXT NOT NULL,PRIMARY KEY(bundle,source))`
			}
			if _, err := f.local.c.db.Exec(query); err != nil {
				t.Fatal(err)
			}
			if _, err := f.receiver.auditAggregate(context.Background(), f.attempt); err == nil || !strings.Contains(err.Error(), "unsupported aggregate storage schema") {
				t.Fatalf("unexpected C storage shape not explicitly refused: %v", err)
			}
		})
	}
}

func TestAutomationAggregateFullClaimKeys(t *testing.T) {
	keys := []ClaimKey{workloadKey(), scopedKey("inc-one"), scopedKey("inc-two"), scopedKey("inc-two"), scopedKey("inc-two")}
	keys[3].OwnerEpoch++
	keys[4].Attempt++
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
		for i, key := range keys {
			value := workloadValue(fmt.Sprintf("full-key-%d", i), "destination", "ghost")
			value.Proof.OwnerEpoch = fmt.Sprint(key.OwnerEpoch)
			reply, err := voters[0].c.ClaimAccept(context.Background(), key, testBallot(2, "same"), value, 1, voters[0].signer, unreachable)
			if err != nil || !reply.Accepted {
				t.Fatalf("real fullkey acceptance: %+v %v", reply, err)
			}
			promise, e := voters[1].c.ClaimPrepare(context.Background(), key, testBallot(9, "same"), 1)
			if e != nil || !promise.Promised {
				t.Fatalf("real fullkey promise: %+v %v", promise, e)
			}
		}
	}})
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	id, err := f.receiver.auditAggregate(context.Background(), f.attempt)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := f.local.c.Query(context.Background(), `SELECT claim_key,promise_ref,accepted_ref FROM local_automation_aggregate_maxima WHERE bundle=?`, id)
	if err != nil || len(rows) != len(keys) {
		t.Fatalf("logical keys/incarnations collapsed: %d %v", len(rows), err)
	}
	seen := map[ClaimKey]bool{}
	for _, row := range rows {
		var encoded struct {
			Domain    string
			Component int
			Key       ClaimKey
		}
		if err = json.Unmarshal(row.Bytes("claim_key"), &encoded); err != nil {
			t.Fatal(err)
		}
		seen[encoded.Key] = true
		if (encoded.Key.Incarnation == "" && encoded.Component != 3) || (encoded.Key.Incarnation != "" && encoded.Component != 4) {
			t.Fatal("table provenance lost")
		}
		for _, field := range []string{"promise_ref", "accepted_ref"} {
			var ref aggregateCopyRef
			if err = json.Unmarshal(row.Bytes(field), &ref); err != nil {
				t.Fatal(err)
			}
			want := f.producers[0].client.hostName
			if field == "promise_ref" {
				want = f.producers[1].client.hostName
			}
			origin, e := f.local.c.Query(context.Background(), `SELECT source FROM local_automation_aggregate_sources WHERE bundle=? AND audit=?`, id, ref.ID)
			if e != nil || len(origin) != 1 || origin[0].String("source") != want {
				t.Fatalf("wrong independent %s for %+v: %v", field, encoded.Key, e)
			}
		}
	}
	for _, key := range keys {
		if !seen[key] {
			t.Fatalf("fullkey lost: %+v", key)
		}
	}
	copies, err := f.local.c.Query(context.Background(), `SELECT component FROM local_automation_aggregate_copies WHERE bundle=?`, id)
	if err != nil || len(copies) != 2*len(keys) {
		t.Fatalf("original promise/accepted copies lost: %d %v", len(copies), err)
	}
}

func TestAutomationAggregateBallotTieOrder(t *testing.T) {
	for _, mode := range []string{"coordinator", "nonce"} {
		t.Run(mode, func(t *testing.T) {
			key := LeaseTermClaimKey("aggregate_tie", 3)
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
				for i := 0; i < 2; i++ {
					ballot := testBallot(4, "z")
					if i == 1 {
						if mode == "coordinator" {
							ballot.Coordinator = "a"
						} else {
							ballot.Nonce = []byte{2}
						}
					}
					value := ClaimValue{LeaseTerm: &LeaseTermValue{Key: key.TargetName, Term: key.OwnerEpoch, Holder: voters[i].name}}
					reply, err := voters[i].c.ClaimAccept(context.Background(), key, ballot, value, 1, voters[i].signer, unreachable)
					if err != nil || !reply.Accepted {
						t.Fatalf("real tied round: %+v %v", reply, err)
					}
				}
			}})
			for i := range f.producers {
				f.stage(t, i, 11, true)
			}
			id, err := f.receiver.auditAggregate(context.Background(), f.attempt)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := f.local.c.Query(context.Background(), `SELECT promise_ref,accepted_ref FROM local_automation_aggregate_maxima WHERE bundle=?`, id)
			if err != nil || len(rows) != 1 {
				t.Fatal("tie maxima", err)
			}
			for _, field := range []string{"promise_ref", "accepted_ref"} {
				var ref aggregateCopyRef
				if err = json.Unmarshal(rows[0].Bytes(field), &ref); err != nil {
					t.Fatal(err)
				}
				source, e := f.local.c.Query(context.Background(), `SELECT source FROM local_automation_aggregate_sources WHERE bundle=? AND audit=?`, id, ref.ID)
				if e != nil || len(source) != 1 || source[0].String("source") != f.producers[1].client.hostName {
					t.Fatalf("%s order differs for %s: %v", mode, field, e)
				}
			}
		})
	}
}

func TestAutomationAggregateImmutableTamperRefusal(t *testing.T) {
	for _, mode := range []string{"copy-body", "copy-fractional-key", "copy-oversized-key", "maxima-reference", "extra-conflict", "manifest"} {
		t.Run(mode, func(t *testing.T) {
			key := LeaseTermClaimKey("aggregate_immutable", 8)
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
				value := ClaimValue{LeaseTerm: &LeaseTermValue{Key: key.TargetName, Term: key.OwnerEpoch, Holder: voters[0].name}}
				reply, err := voters[0].c.ClaimAccept(context.Background(), key, testBallot(2, "same"), value, 1, voters[0].signer, unreachable)
				if err != nil || !reply.Accepted {
					t.Fatalf("real immutable input: %+v %v", reply, err)
				}
			}})
			for i := range f.producers {
				f.stage(t, i, 11, true)
			}
			id, err := f.receiver.auditAggregate(context.Background(), f.attempt)
			if err != nil {
				t.Fatal(err)
			}
			var query string
			var args []any
			switch mode {
			case "copy-body":
				query = `UPDATE local_automation_aggregate_copies SET origin_ref=? WHERE bundle=?`
				args = []any{[]byte("bad"), id}
			case "copy-fractional-key":
				query = `UPDATE local_automation_aggregate_copies SET ordinal=0.5 WHERE bundle=?`
				args = []any{id}
			case "copy-oversized-key":
				query = `UPDATE local_automation_aggregate_copies SET origin_id=? WHERE bundle=?`
				args = []any{"x\x00" + strings.Repeat("z", 1024), id}
			case "maxima-reference":
				query = `UPDATE local_automation_aggregate_maxima SET promise_ref=? WHERE bundle=?`
				args = []any{[]byte("bogus"), id}
			case "extra-conflict":
				query = `INSERT INTO local_automation_aggregate_conflicts(bundle,claim_key,round,coord,nonce,first_ref) VALUES(?,?,?,?,?,?)`
				args = []any{id, []byte("extra"), 1, "x", []byte{1}, []byte("bad")}
			case "manifest":
				query = `UPDATE local_automation_aggregates SET head=? WHERE id=?`
				args = []any{[]byte("bad"), id}
			}
			if _, err = f.local.c.db.Exec(query, args...); err != nil {
				t.Fatal(err)
			}
			before, active, typed, audits := aggregateStored(t, f.local.c), receiverActive(t, f.local.c), automationTypedSnapshot(t, f.local.c), receiverAudited(t, f.local.c)
			if _, err = f.receiver.auditAggregate(context.Background(), f.attempt); err == nil {
				t.Fatal("tampered retained aggregate accepted or silently repaired")
			}
			if before != aggregateStored(t, f.local.c) || active != receiverActive(t, f.local.c) || audits != receiverAudited(t, f.local.c) || !reflect.DeepEqual(typed, automationTypedSnapshot(t, f.local.c)) {
				t.Fatal("refusal rewrote prior evidence or stages")
			}
		})
	}
}

func TestAutomationAggregateCertifiedLoserAndFrontier(t *testing.T) {
	for _, mode := range []string{"lower-loser", "frontier", "incompatible-history", "equal-conflict", "higher-conflict"} {
		t.Run(mode, func(t *testing.T) {
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
				first := sharedAutomationRecord(t, 1, "", "req", "op", voters...)
				for i, v := range voters {
					key, _ := AutomationClaimKey(1)
					installAutomationEvidence(t, v.c, key, "", 1)
					record := first
					if mode == "incompatible-history" && i == 1 {
						record = sharedAutomationRecord(t, 1, "", "different-request", "different-operation", voters...)
						if _, err := v.c.db.Exec(`UPDATE local_automation_authority SET bootstrap_request='different-request' WHERE id=1`); err != nil {
							t.Fatal(err)
						}
					}
					verifier, err := LoadClaimVerifier(v.pki)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = v.c.AutomationApply(context.Background(), record, verifier, contract.Reduce); err != nil {
						t.Fatalf("real first certified apply: %v", err)
					}
				}
				if mode == "incompatible-history" {
					return
				}
				loser := sharedAutomationRecord(t, 2, first.Value.MustDigest(), "loser-request", "loser-operation", voters...)
				key, _ := AutomationClaimKey(2)
				round := uint64(1)
				if mode == "equal-conflict" {
					round = 2
				}
				if mode == "higher-conflict" {
					round = 3
				}
				accepted, err := voters[0].c.ClaimAccept(context.Background(), key, testBallot(round, "a"), loser.Value, 1, voters[0].signer, nil)
				if err != nil || !accepted.Accepted {
					t.Fatalf("genuine pre-certified lower acceptance: %+v %v", accepted, err)
				}
				if mode == "lower-loser" || mode == "equal-conflict" || mode == "higher-conflict" {
					chosen := sharedAutomationRecord(t, 2, first.Value.MustDigest(), "chosen-request", "chosen-operation", voters...)
					for _, v := range voters {
						verifier, err := LoadClaimVerifier(v.pki)
						if err != nil {
							t.Fatal(err)
						}
						if _, err = v.c.AutomationApply(context.Background(), chosen, verifier, contract.Reduce); err != nil {
							t.Fatalf("real chosen certificate after lower acceptance: %v", err)
						}
					}
				}
			}})
			for i := range f.producers {
				f.stage(t, i, 11, true)
			}
			before := receiverActive(t, f.local.c)
			id, err := f.receiver.auditAggregate(context.Background(), f.attempt)
			if mode == "incompatible-history" {
				if err == nil || !strings.Contains(err.Error(), "incompatible aggregate certified history") {
					t.Fatalf("individually valid incompatible histories accepted: %q %v", id, err)
				}
			} else if mode == "equal-conflict" || mode == "higher-conflict" {
				if err == nil || !strings.Contains(err.Error(), "aggregate accepted maximum conflicts with certified baseline") {
					t.Fatalf("incompatible equal/higher accepted ballot escaped: %q %v", id, err)
				}
			} else {
				if err != nil {
					t.Fatalf("genuine %s not retained: %v", mode, err)
				}
				rows, e := f.local.c.Query(context.Background(), `SELECT accepted_round,origin_id FROM local_automation_aggregate_copies WHERE bundle=?`, id)
				if e != nil || len(rows) != 1 || rows[0].Int64("accepted_round") != 1 {
					t.Fatalf("original frontier/loser lost: %d %v", len(rows), e)
				}
			}
			if receiverActive(t, f.local.c) != before {
				t.Fatal("aggregate applied chosen or frontier value")
			}
		})
	}
}
