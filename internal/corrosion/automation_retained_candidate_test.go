package corrosion

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestRetainedExactLosingCandidateOriginal(t *testing.T) {
	ctx := context.Background()
	key := LeaseTermClaimKey("retained_losing", 7)
	var losing ClaimValue
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
		for i := 0; i < 2; i++ {
			v := ClaimValue{LeaseTerm: &LeaseTermValue{Key: key.TargetName, Term: 7, Holder: voters[i].name}}
			if i == 0 {
				losing = v
			}
			reply, err := voters[i].c.ClaimAccept(ctx, key, testBallot(uint64(i+2), "common"), v, 1, voters[i].signer, unreachable)
			if err != nil || !reply.Accepted {
				t.Fatal("genuine retained acceptance", err)
			}
		}
	}})
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	bundle, err := f.receiver.auditAggregate(ctx, f.attempt)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := f.receiver.client.Query(ctx, `SELECT accepted_ref FROM local_automation_aggregate_maxima WHERE bundle=?`, bundle)
	if err != nil || len(rows) != 1 {
		t.Fatal("real aggregate maximum unavailable", err)
	}
	var winner aggregateCopyRef
	if json.Unmarshal(rows[0].Bytes("accepted_ref"), &winner) != nil {
		t.Fatal("maximum reference malformed")
	}
	source := f.producers[0].client.hostName
	rows, err = f.receiver.client.Query(ctx, `SELECT id FROM local_automation_receiver_audits WHERE attempt=? AND source=?`, f.attempt.id, source)
	if err != nil || len(rows) != 1 {
		t.Fatal("real losing audit unavailable", err)
	}
	audit := rows[0].String("id")
	if winner.ID == audit {
		t.Fatal("fixture candidate must lose actual aggregate selection")
	}
	active := receiverActive(t, f.receiver.client)
	tx, err := f.receiver.client.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	s := receiverAuditStore{tx: &LocalTx{tx: tx}, attempt: f.attempt.id, source: source, id: audit, publication: f.attempt.publications[source]}
	keyRaw, _ := json.Marshal(key)
	refs, err := s.tx.Query(ctx, `SELECT component,ordinal FROM local_automation_receiver_refs WHERE audit=? AND claim_key=?`, audit, keyRaw)
	if err != nil || len(refs) != 1 {
		t.Fatal("exact losing claim index unavailable", err)
	}
	component, ordinal := refs[0].Int("component"), refs[0].Int64("ordinal")
	row, err := s.record(ctx, component, ordinal)
	if err != nil {
		t.Fatal(err)
	}
	original, err := encodeAutomationCutRecord(automationCutSections[component-3].name, ordinal, row)
	if err != nil {
		t.Fatal(err)
	}
	record := sourceDigest([]byte("litevirt/retained-acceptance-record/v1"), original)
	full, _ := json.Marshal(losing)
	ref, err := s.retainedCandidate(ctx, 3, key, testBallot(2, "common"), full, record)
	if err != nil {
		t.Fatalf("authentic nonmaximum original refused at inert inclusion layer: %v", err)
	}
	if ref.Object != 3 || ref.Component != component || ref.Ordinal != ordinal || ref.ValueDigest != sourceDigest([]byte("litevirt/aggregate-full-value/v1"), full) {
		t.Fatal("exact losing reference differs")
	}
	for _, mode := range []string{"full-bytes", "ballot", "nonce", "key", "original-record", "noncanonical-value"} {
		t.Run(mode, func(t *testing.T) {
			k, b, v, d := key, testBallot(2, "common"), append([]byte(nil), full...), record
			switch mode {
			case "full-bytes":
				other := losing
				copy := *other.LeaseTerm
				copy.Holder = "other"
				other.LeaseTerm = &copy
				v, _ = json.Marshal(other)
			case "ballot":
				b.Round++
			case "nonce":
				b.Nonce = append([]byte(nil), b.Nonce...)
				b.Nonce[0] ^= 1
			case "key":
				k.OwnerEpoch++
			case "original-record":
				d = strings.Repeat("b", 64)
			case "noncanonical-value":
				v = append([]byte(" "), v...)
			}
			if _, err := s.retainedCandidate(ctx, 3, k, b, v, d); err == nil {
				t.Fatal("spliced retained candidate accepted")
			}
		})
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if receiverActive(t, f.receiver.client) != active {
		t.Fatal("inert inclusion modified active state")
	}
}
