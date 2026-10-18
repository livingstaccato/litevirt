package corrosion

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// This counts SQLite executions and returned original bodies, independently of
// production instrumentation. Restoring per-acceptance reconstruction must fail
// both the single-cut metadata count and the linear original-body work bound.
func TestAggregateOwnedOriginSQLWorkLinearFullSeven(t *testing.T) {
	const history, claims = 130, 37
	reads := automationCapacity(t, history, claims, false)
	reads.mu.Lock()
	defer reads.mu.Unlock()
	var reconstructions, bodies int64
	for query, stats := range reads.queries {
		if query == "SELECT id,metadata,root FROM local_automation_cuts WHERE generation=? AND incarnation=? LIMIT 1" {
			reconstructions += stats.calls
		}
		if strings.HasPrefix(query, "SELECT record FROM local_automation_cut_records ") {
			bodies += stats.rows
		}
	}
	// Inventory, index, history/certificate verification and original matching
	// each retain their real passes; none may multiply them by the local claims.
	bound := int64(12*(3*history+claims+20) + 4*claims)
	t.Logf("actual owned-origin SQL reconstructions=%d returnedOriginalBodies=%d linearBodyBound=%d history=%d claims=%d", reconstructions, bodies, bound, history, claims)
	if reconstructions != 1 || bodies == 0 || bodies > bound {
		t.Fatalf("owned-origin SQL work repeats complete reconstruction: got reconstructions=%d bodies=%d; want one reconstruction and 1..%d bodies", reconstructions, bodies, bound)
	}
}

// Reusing a validated cut may never reuse a prior claim's identity or survive
// the transaction. These fixtures retain genuine native signed acceptances in
// both tables, including two incarnation-separated keys and a lower loser.
func TestAggregateOwnedOriginEveryAcceptanceAndRetry(t *testing.T) {
	for _, mode := range []string{"higher-promises", "late-mismatch", "unrelated-cut", "retry-corruption", "retry-extra-row"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			keys := []ClaimKey{LeaseTermClaimKey("first_origin", 1), scopedKey("inc-a"), scopedKey("inc-z")}
			var lower Row
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Continuing: true, BeforeFreeze: func(t *testing.T, _ []*claimTestVoter, local *claimTestVoter) {
				for i, key := range keys {
					value := workloadValue(fmt.Sprintf("origin-%d", i), "destination", "ghost")
					if i == 0 {
						value = ClaimValue{LeaseTerm: &LeaseTermValue{Key: key.TargetName, Term: 1, Holder: local.name}}
					}
					for round := uint64(2); round <= 3; round++ {
						reply, err := local.c.ClaimAccept(ctx, key, testBallot(round, local.name), value, 1, local.signer, unreachable)
						if err != nil || !reply.Accepted {
							t.Fatalf("genuine native acceptance %+v: %+v %v", key, reply, err)
						}
						if i == 2 && round == 2 {
							rows, err := local.c.Query(ctx, "SELECT "+automationCutSections[1].columns+" FROM local_incarnation_claims WHERE incarnation=?", key.Incarnation)
							if err != nil || len(rows) != 1 {
								t.Fatal("lower signed original", err)
							}
							lower = rows[0]
						}
					}
				}
			}})
			for i := range f.producers {
				f.stage(t, i, 11, true)
			}
			for _, table := range []string{"local_recovery_claims", "local_incarnation_claims"} {
				if _, err := f.local.c.db.Exec("UPDATE " + table + " SET promised_round=9 WHERE target_kind!='voter_config'"); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "late-mismatch" {
				_, err := f.local.c.db.Exec(`UPDATE local_incarnation_claims SET accepted_round=?,accepted_coord=?,accepted_nonce=?,value_json=?,value_digest=?,accept_json=? WHERE incarnation='inc-z'`, lower.Int64("accepted_round"), lower.String("accepted_coord"), lower.Bytes("accepted_nonce"), lower.String("value_json"), lower.String("value_digest"), lower.String("accept_json"))
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "unrelated-cut" {
				// The native UNIQUE key forbids two candidates for the selected lifetime.
				if _, err := f.local.c.db.Exec(`INSERT INTO local_automation_cuts SELECT 'duplicate',generation,incarnation,metadata,root FROM local_automation_cuts`); err == nil {
					t.Fatal("owned-cut lifetime uniqueness absent")
				}
				// An unused cut in another lifetime is copied by the FULL dependency reader,
				// but its malformed metadata is not a candidate for current native origin.
				if _, err := f.local.c.db.Exec(`INSERT INTO local_automation_cuts VALUES('unrelated',2,'other',x'01','bad')`); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasPrefix(mode, "retry-") {
				id, err := f.receiver.auditAggregate(ctx, f.attempt)
				if err != nil || id == "" {
					t.Fatalf("first real origin aggregate: %v", err)
				}
				if mode == "retry-corruption" {
					_, err = f.local.c.db.Exec(`UPDATE local_automation_cut_records SET record=x'01' WHERE section=1 AND ordinal=2`)
				} else {
					_, err = f.local.c.db.Exec(`INSERT INTO local_automation_cut_records SELECT id,99,1,x'01' FROM local_automation_cuts`)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			active, spool, stored, typed := receiverActive(t, f.local.c), receiverStored(t, f.local.c), aggregateStored(t, f.local.c), automationTypedSnapshot(t, f.local.c)
			id, err := f.receiver.auditAggregate(ctx, f.attempt)
			refuses := mode == "late-mismatch" || strings.HasPrefix(mode, "retry-")
			if refuses {
				if err == nil || !strings.Contains(err.Error(), "local acceptance origin unavailable") {
					t.Fatalf("late origin refusal missing: %s %v", id, err)
				}
				if mode == "late-mismatch" && !strings.Contains(err.Error(), "owned cut acceptance bytes differ") {
					t.Fatalf("wrong late mismatch refusal: %v", err)
				}
				if aggregateStored(t, f.local.c) != stored {
					t.Fatal("origin refusal changed prior aggregate/local evidence")
				}
			} else {
				if err != nil || id == "" {
					t.Fatalf("valid current origins refused: %v", err)
				}
				rows, err := f.local.c.Query(ctx, `SELECT component,origin_ref,promised_round,accepted_round FROM local_automation_aggregate_copies WHERE bundle=? AND origin_kind='local' ORDER BY component,ordinal`, id)
				if err != nil || len(rows) != 3 {
					t.Fatal("both domains/incarnations lost", rows, err)
				}
				for i, row := range rows {
					wantComponent := int64(4)
					if i == 0 {
						wantComponent = 3
					}
					if row.Int64("component") != wantComponent || row.Int64("promised_round") != 9 || row.Int64("accepted_round") != 3 || len(row.Bytes("origin_ref")) == 0 {
						t.Fatal("independent origin/promise lost", row)
					}
				}
				again, err := f.receiver.auditAggregate(ctx, f.attempt)
				if err != nil || again != id {
					t.Fatalf("origin identity retry drift: %s %s %v", id, again, err)
				}
			}
			if active != receiverActive(t, f.local.c) || spool != receiverStored(t, f.local.c) || !reflect.DeepEqual(typed, automationTypedSnapshot(t, f.local.c)) {
				t.Fatal("origin processing mutated active/spool/prior stages")
			}
			for _, table := range []string{"local_automation_receiver_refs", "local_automation_receiver_requests"} {
				rows, err := f.local.c.Query(ctx, "SELECT COUNT(*) AS n FROM "+table+" WHERE audit LIKE '%:owned-origin'")
				if err != nil || len(rows) != 1 || rows[0].Int64("n") != 0 {
					t.Fatal("owned origin scratch survived transaction", table, rows, err)
				}
			}
		})
	}
}
