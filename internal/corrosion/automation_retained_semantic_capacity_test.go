package corrosion

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestRetainedNearBoundSemanticCandidate(t *testing.T) {
	ctx := context.Background()
	key := workloadKey()
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{2, 2}, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, _ *claimTestVoter) {
		for i := 0; i < 2; i++ {
			value := workloadValue(strings.Repeat(string(rune('x'+i)), maxAutomationCutRecordBytes-(64<<10)), "destination", "ghost")
			result, err := voters[i].c.ClaimAccept(ctx, key, testBallot(uint64(i+1), "same"), value, 1, voters[i].signer, unreachable)
			if err != nil || !result.Accepted {
				t.Fatalf("actual near-bound acceptance: %+v %v", result, err)
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
	before := receiverActive(t, f.local.c)
	reads := aggregateInstrument(t, f.receiver)
	tx0, err := f.local.c.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx0.Rollback()
	tx := &LocalTx{tx: tx0}
	h, directory := retainedCopyOriginalAggregate(t, ctx, tx, f, bundle)
	heap := &aggregateHeapEvidence{}
	observed := context.WithValue(ctx, aggregateHeapTestKey{}, heap)
	reads.enabled = true
	rebuilt, err := rebuildRetainedAggregate(observed, tx, h, f.attempt.binding, directory, f.attempt.view)
	if err != nil {
		t.Fatal("retained complete near-bound semantic C", err)
	}
	if rebuilt.id != bundle {
		t.Fatal("retained near-bound original C identity changed")
	}
	store := rebuilt.sources[0].store
	rawKey, _ := json.Marshal(key)
	rows, err := tx.Query(ctx, `SELECT component,ordinal FROM local_automation_receiver_refs WHERE audit=? AND claim_key=?`, store.id, rawKey)
	if err != nil || len(rows) != 1 {
		t.Fatal("near-bound candidate index", err)
	}
	component, ordinal := rows[0].Int("component"), rows[0].Int64("ordinal")
	row, err := store.record(ctx, component, ordinal)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := scanClaimRow(key, row)
	if err != nil || claim.Value == nil {
		t.Fatal("near-bound original value", err)
	}
	if claim.Accepted.Round != 1 {
		t.Fatal("selected candidate is not actual loser")
	}
	full, _ := json.Marshal(claim.Value)
	raw, err := encodeAutomationCutRecord(automationCutSections[component-3].name, ordinal, row)
	if err != nil {
		t.Fatal(err)
	}
	cut := store.publication.manifest.Cut
	identity := retainedHolderBody{OriginalSource: cut.Source, OriginalIncarnation: cut.Incarnation, OriginalCut: cut.ID, OriginalRoot: store.publication.manifest.Root, Key: key, Accepted: claim.Accepted, ValueDigest: sourceDigest([]byte("litevirt/aggregate-full-value/v1"), full), AcceptanceDigest: sourceDigest([]byte("litevirt/retained-acceptance-record/v1"), raw)}
	ref, err := rebuilt.candidate(ctx, tx, directory, identity, full)
	if err != nil {
		t.Fatal("actual near-bound retained loser inclusion", err)
	}
	if ref.ValueDigest != identity.ValueDigest || ref.Ordinal != ordinal {
		t.Fatal("near-bound exact candidate changed")
	}
	// The complete consumed graph is an equality fixture, never an actual receipt
	// or adopted-holder producer. Its C inputs and exact candidate are genuine.
	holder := retainedTestGraphMetadata(t, ctx, tx, h, directory, rebuilt)
	directory.objects += 2
	graph, err := verifyRetainedGraph(observed, tx, holder, directory, f.attempt.view)
	if err != nil || graph.id != bundle {
		t.Fatal("near-bound complete graph equality", err)
	}
	reads.enabled = false
	if reads.maxRows != 1 || reads.maxBytes < 2<<20 || reads.maxBytes > maxAggregateLocalRecordBytes || len(reads.bad) > 0 {
		t.Fatal("retained semantic query bounds", reads.maxRows, reads.maxBytes, reads.bad)
	}
	if heap.probes < 1 || heap.maxLiveBytes > 1<<20 {
		t.Fatal("prior decoded original survived advancing retained C", heap.probes, heap.maxLiveBytes, heap.stacks)
	}
	if err = tx0.Rollback(); err != nil {
		t.Fatal(err)
	}
	if receiverActive(t, f.local.c) != before {
		t.Fatal("near-bound retained semantics changed ACTIVE")
	}
	t.Logf("genuine retained near-bound original=%d full=%d queries=%d maxRows=%d maxField=%d prior-body probes=%d maxDecodedLive=%d", len(raw), len(full), reads.queries, reads.maxRows, reads.maxBytes, heap.probes, heap.maxLiveBytes)
}
