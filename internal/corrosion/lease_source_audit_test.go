package corrosion

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

// These two legal contexts deliberately do not manufacture adopted automation
// authority. The old ordinary workload fixture remains separately selected.
func leaseSourceFixture(t *testing.T, legacy bool) (*AutomationSourcePreparer, *AutomationReceiver, AutomationExportRequest, context.Context, map[ClaimKey]ClaimVoterState, *claimTestVoter) {
	t.Helper()
	originals := map[ClaimKey]ClaimVoterState{}
	var signer *claimTestVoter
	options := receiverAuditOptions{legacy: legacy, legacyLease: legacy, legacyAccepted: func(st ClaimVoterState) { originals[st.Key] = st }, beforeApply: func(a *claimTestVoter, v []*claimTestVoter, r AutomationRecord) { receiverAuditClaimSeed(t, a, v, r) }}
	options.beforeFreeze = func(a *claimTestVoter, v []*claimTestVoter) {
		signer = a
		ctx := context.Background()
		if legacy {
			for key, old := range originals {
				st, found, err := a.c.ClaimState(ctx, key)
				if err != nil || !found || st.ConfigGeneration != 2 || st.Accept == nil || st.Accept.ConfigGeneration != 1 || !reflect.DeepEqual(old.Accept, st.Accept) || !reflect.DeepEqual(old.Value, st.Value) || old.ValueDigest != st.ValueDigest || st.Promised.Round != 9 {
					t.Fatal("ordinary adoption lost original lease/signature/higher promise", err)
				}
				originals[key] = st
			}
			return
		}
		for _, name := range []string{"failover", "future_lease"} {
			k := LeaseTermClaimKey(name, 7)
			value := ClaimValue{LeaseTerm: &LeaseTermValue{Key: name, Term: 7, Holder: "a"}}
			res, err := a.c.ClaimAccept(ctx, k, testBallot(2, "a"), value, 1, a.signer, nil)
			if err != nil || !res.Accepted {
				t.Fatal("real lease accept", res, err)
			}
			pr, err := a.c.ClaimPrepare(ctx, k, testBallot(9, "a"), 1)
			if err != nil || !pr.Promised {
				t.Fatal("real higher lease promise", err)
			}
			st, found, err := a.c.ClaimState(ctx, k)
			if err != nil || !found {
				t.Fatal(err)
			}
			originals[k] = st
		}
		k := LeaseTermClaimKey("future_promise", 11)
		pr, err := a.c.ClaimPrepare(ctx, k, testBallot(12, "a"), 1)
		if err != nil || !pr.Promised {
			t.Fatal("future promise-only", err)
		}
		st, _, err := a.c.ClaimState(ctx, k)
		if err != nil {
			t.Fatal(err)
		}
		originals[k] = st
		src, err := a.c.ClaimStatesForImport(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, st := range src.States {
			seen[st.Key.TargetKind] = true
		}
		if !seen[ClaimKindLeaseTerm] || !seen[ClaimKindAutomation] || !seen[ClaimKindVM] {
			t.Fatal("import union dropped source kinds", seen)
		}
	}
	n := 3
	if legacy {
		n = 0
	}
	p, r, q, peer, _ := receiverAuditFixtureOptions(t, n, options)
	return p, r, q, peer, originals, signer
}
func TestLeaseTermSourceCutAndDetachedAudit(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "native_G1"
		if legacy {
			name = "ordinary_G2_old_signature"
		}
		t.Run(name, func(t *testing.T) {
			p, r, q, peer, want, _ := leaseSourceFixture(t, legacy)
			ctx := context.Background()
			a, err := r.Begin(ctx, q.Intent, nil)
			if err != nil {
				t.Fatal(err)
			}
			receiverThrough(t, p, r, a, q, peer, 11)
			active, stored := receiverActive(t, r.client), receiverStored(t, r.client)
			if err = r.AuditSource(ctx, a, "a"); err != nil {
				t.Fatal("genuine lease source refused", err)
			}
			rows, err := r.client.Query(ctx, `SELECT ordinal,record FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=3 ORDER BY ordinal`, a.id)
			if err != nil {
				t.Fatal(err)
			}
			seen := map[ClaimKey]bool{}
			for _, row := range rows {
				fact, err := decodeSourceCutRow(0, row.Int64("ordinal"), row.Bytes("record"))
				if err != nil {
					t.Fatal(err)
				}
				if fact.String("target_kind") != ClaimKindLeaseTerm {
					continue
				}
				k := LeaseTermClaimKey(fact.String("target_name"), fact.Int64("owner_epoch"))
				st, err := scanClaimRow(k, fact)
				if err != nil || !reflect.DeepEqual(want[k], st) {
					t.Fatalf("lease cut lost exact state/signature/value/promise: %v want=%+v got=%+v", err, want[k], st)
				}
				seen[k] = true
			}
			if len(seen) != len(want) {
				t.Fatal("missing retained lease rows", len(seen), len(want))
			}
			if receiverActive(t, r.client) != active || receiverStored(t, r.client) != stored {
				t.Fatal("audit changed ACTIVE/spool")
			}
			audits, err := r.client.Query(ctx, `SELECT coverage,payloads FROM local_automation_receiver_audits WHERE attempt=?`, a.id)
			if err != nil || len(audits) != 1 || audits[0].String("coverage") == "" || audits[0].Int64("payloads") < 1 {
				t.Fatal("lease payload coverage missing", err)
			}
			if legacy {
				for _, table := range []string{"local_automation_authority", "local_automation_history", "local_automation_anchors", "local_automation_requests"} {
					rows, err := p.client.Query(ctx, `SELECT COUNT(*) AS n FROM `+table)
					if err != nil || rows[0].Int64("n") != 0 {
						t.Fatal("ordinary source manufactured automation authority/history", table, err)
					}
				}
			} else {
				for _, component := range []int{3, 4} {
					rows, err := r.client.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_receiver_refs WHERE component=?`, component)
					if err != nil || rows[0].Int64("n") < 81 {
						t.Fatal("both workload tables/loser lost", component, err)
					}
				}
			}
		})
	}
}
func TestLeaseTermSourceAuditRefusals(t *testing.T) {
	for _, mode := range []string{"key", "term", "holder", "digest", "signature", "generation", "member_lifetime", "promise"} {
		t.Run(mode, func(t *testing.T) {
			p, r, q, peer, _, signer := leaseSourceFixture(t, true)
			ctx := context.Background()
			prior, err := r.Begin(ctx, q.Intent, nil)
			if err != nil {
				t.Fatal(err)
			}
			receiverThrough(t, p, r, prior, q, peer, 11)
			if err = r.AuditSource(ctx, prior, "a"); err != nil {
				t.Fatal(err)
			}
			previousAudit := receiverAudited(t, r.client)
			receiverAuditChangeCut(t, p, &q, 0, func(rows []Row) []Row {
				for i := range rows {
					row := &rows[i]
					if row.String("target_kind") != ClaimKindLeaseTerm {
						continue
					}
					k := LeaseTermClaimKey(row.String("target_name"), row.Int64("owner_epoch"))
					st, err := scanClaimRow(k, *row)
					if err != nil {
						t.Fatal(err)
					}
					switch mode {
					case "key":
						receiverAuditSet(t, row, "target_name", "different")
					case "term":
						st.Value.LeaseTerm.Term++
						raw, _ := json.Marshal(st.Value)
						receiverAuditSet(t, row, "value_json", string(raw))
					case "holder":
						st.Value.LeaseTerm.Holder = "other"
						raw, _ := json.Marshal(st.Value)
						receiverAuditSet(t, row, "value_json", string(raw))
					case "digest":
						receiverAuditSet(t, row, "value_digest", "bad")
					case "signature":
						st.Accept.Signature[0] ^= 1
						raw, _ := json.Marshal(st.Accept)
						receiverAuditSet(t, row, "accept_json", string(raw))
					case "generation":
						st.Accept.ConfigGeneration = 3
						raw, _ := json.Marshal(st.Accept)
						receiverAuditSet(t, row, "accept_json", string(raw))
					case "member_lifetime":
						accept, err := signer.signer.Sign(k, 1, st.Accepted, st.ValueDigest, "foreign-lifetime")
						if err != nil {
							t.Fatal(err)
						}
						raw, _ := json.Marshal(accept)
						receiverAuditSet(t, row, "accept_json", string(raw))
					case "promise":
						receiverAuditSet(t, row, "promised_round", int64(1))
					}
					return rows
				}
				t.Fatal("lease row missing")
				return nil
			})
			a, err := r.Supersede(ctx, q.Intent)
			if err != nil {
				t.Fatal("real new revision", err)
			}
			receiverThrough(t, p, r, a, q, peer, 11)
			active, stored, derived := receiverActive(t, r.client), receiverStored(t, r.client), receiverAudited(t, r.client)
			if derived != previousAudit {
				t.Fatal("supersede erased prior audit")
			}
			if err = r.AuditSource(ctx, a, "a"); err == nil {
				t.Fatal("corrupt lease audited")
			}
			if receiverActive(t, r.client) != active || receiverStored(t, r.client) != stored || receiverAudited(t, r.client) != derived {
				t.Fatal("refusal changed active/spool/prior audit")
			}
		})
	}
}
