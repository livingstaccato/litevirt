package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"strings"
	"testing"
)

func TestRetainedExecution86Individual128ArtifactFrames(t *testing.T) {
	f := newExecutionStorageFixture(t)
	d, err := automationDecision(f.grant.Value)
	if err != nil {
		t.Fatal(err)
	}
	a, err := contract.DecodeAssignment(d)
	if err != nil {
		t.Fatal(err)
	}
	requirements := append([]contract.ArtifactRequirement(nil), f.want.Requirements...)
	for i := 0; i < 126; i++ {
		requirements = append(requirements, contract.ArtifactRequirement{Key: fmt.Sprintf("firmware-%03d", i), Kind: "firmware"})
	}
	a.Execution.Requirements = requirements
	d.Assignment = automationExecutionJSON(t, a)
	if err := contract.ValidateSupportedDecision(d); err != nil {
		t.Fatal(err)
	}
	f.grant = f.sign(d)
	f.want = automationExecutionFirstGrantWant(t, f.grant, f.admission, f.config)
	f.want.Requirements = requirements
	f.start(t)
	artifacts := f.artifacts()
	for i := 0; i < 126; i++ {
		v := artifacts[1]
		v.ID, v.Key, v.Kind = fmt.Sprintf("firmware-artifact-%03d", i), fmt.Sprintf("firmware-%03d", i), "firmware"
		v.Backend, v.ObjectID = "test-firmware", fmt.Sprintf("immutable-firmware-%03d", i)
		artifacts = append(artifacts, v)
	}
	f.apply(t, f.progress(t, "running", artifacts))
	f.apply(t, f.terminal(t, "succeeded", artifacts))
	ctx := context.Background()
	attempt := &AutomationReceiverAttempt{id: "retained-execution86-capacity-component", binding: []byte("retained-execution86-capacity-component")}
	counts := map[string]int64{}
	var grantBytes, terminalBytes int
	err = f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		layout, err := retainedLocalTablesForDigest(retainedLocalLayoutDigest())
		if err != nil {
			return err
		}
		var observation aggregateLocalObservation
		var out aggregateLocalAudit
		_, err = aggregateLocalSnapshot(ctx, tx, attempt, f.c, func(section int, n int64, row Row, raw []byte) error {
			if err := observation.observe(&out, section, n, row); err != nil {
				return err
			}
			d := layout[section]
			if !strings.HasPrefix(d.table, "local_automation_exec") {
				return nil
			}
			decoded, err := decodeAutomationFramedRow(d.descriptor(), n, raw, maxAggregateLocalRecordBytes)
			if err != nil {
				return err
			}
			counts[d.table]++
			if d.table == "local_automation_executors" {
				grantBytes = len(decoded.String("grant_json"))
			}
			if d.table == "local_automation_execution_terminals" {
				terminalBytes = len(decoded.String("terminal_json"))
				var wire map[string]json.RawMessage
				if err := json.Unmarshal([]byte(decoded.String("terminal_json")), &wire); err != nil {
					return err
				}
				if len(wire) != 3 {
					return fmt.Errorf("retained terminal expanded immutable artifact snapshot")
				}
			}
			return nil
		})
		return err
	})
	if err != nil {
		t.Fatal("actual128 bounded retained-frame snapshot", err)
	}
	if counts["local_automation_execution_artifacts"] != 128 || counts["local_automation_executors"] != 1 || counts["local_automation_execution_terminals"] != 1 {
		t.Fatal("retained execution inventory truncated", counts)
	}
	if grantBytes <= 4096 || terminalBytes <= 4096 {
		t.Fatal("capacity fixture did not cross ordinary string-field bound", grantBytes, terminalBytes)
	}
	f.reopen(t)
	if p := f.projection(t); p.Execution.Terminal == nil || len(p.Execution.Terminal.Artifacts) != 128 {
		t.Fatal("cold128 snapshot lost permanent artifacts")
	}
}

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
