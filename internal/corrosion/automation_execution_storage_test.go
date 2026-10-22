package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// UNCOMPILED/UNRUN external tests. Signers certify fixture history only; these
// tests confer no native issuance, exclusion, target release or resource retirement.
var executionStorageTables = []string{
	"local_automation_executors",
	"local_automation_execution_progress",
	"local_automation_execution_artifacts",
	"local_automation_execution_terminals",
}

type executionStorageFixture struct {
	c                *Client
	dir              string
	grant, admission AutomationRecord
	want             contract.ExecutorGrant
	config           contract.VMIntent
	sign             func(contract.Decision) AutomationRecord
}

func newExecutionStorageFixture(t *testing.T) *executionStorageFixture {
	t.Helper()
	dir := t.TempDir()
	c, grant, admission, config, sign := automationExecutionCertifiedFirstGrantSigningFixture(t, dir)
	return &executionStorageFixture{c: c, dir: dir, grant: grant, admission: admission,
		want: automationExecutionFirstGrantWant(t, grant, admission, config), config: config, sign: sign}
}

func (f *executionStorageFixture) apply(t *testing.T, record AutomationRecord) contract.Receipt {
	t.Helper()
	r, err := applySharedAutomation(t, f.c, record, contract.Reduce, automationFreshAnchor)
	if err != nil || r.Code != "" {
		t.Fatalf("certified FULL positive seq%s: %+v %v", record.Certificate.Key.TargetName, r, err)
	}
	return r
}

func (f *executionStorageFixture) start(t *testing.T) contract.Receipt {
	t.Helper()
	before := sharedActiveRows(t, f.c)
	r, err := applySharedAutomation(t, f.c, f.grant, contract.Reduce, automationFreshAnchor)
	if err != nil {
		if !reflect.DeepEqual(before, sharedActiveRows(t, f.c)) {
			t.Fatal("failed first grant changed certified history")
		}
		t.Fatalf("FULL first grant after valid admission10/gap11 must apply before execution SQL: code=%q err=%v", contract.Code(err), err)
	}
	if r.Code != "" || r.State != "accepted" || r.Sequence != 12 {
		t.Fatalf("first grant not accepted: %+v", r)
	}
	automationExecutionFirstGrantSnapshot(t, f.c, f.grant, r, f.want)
	return r
}

func (f *executionStorageFixture) body(t *testing.T) contract.ExecutionBody {
	t.Helper()
	d, err := automationDecision(f.grant.Value)
	if err != nil {
		t.Fatal(err)
	}
	b, err := contract.DecodeExecutionBody(d.Command)
	if err != nil {
		t.Fatal(err)
	}
	b.Grant = &contract.ExecutorReference{Generation: 1, Decision: f.want.Reference}
	return b
}

func (f *executionStorageFixture) next(t *testing.T, kind string, body contract.ExecutionBody) AutomationRecord {
	t.Helper()
	head, err := f.c.AutomationHead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	d, err := automationDecision(f.grant.Value)
	if err != nil {
		t.Fatal(err)
	}
	d.Sequence, d.ParentDigest = head.Sequence+1, head.Digest
	d.Command.Kind = kind
	d.Command.RequestID = fmt.Sprintf("storage-%s-request-%d", kind, d.Sequence)
	d.Command.Body = automationExecutionJSON(t, body)
	d.Assignment = automationExecutionJSON(t, contract.Assignment{Version: 1,
		ClusterUID: "established-cluster", OperationID: fmt.Sprintf("storage-%s-op-%d", kind, d.Sequence), RecordedAt: "2026-10-21T00:00:01Z"})
	if err := contract.ValidateSupportedDecision(d); err != nil {
		t.Fatal("continuation decision invalid", err)
	}
	return f.sign(d)
}

func (f *executionStorageFixture) artifacts() []contract.ArtifactRecord {
	origin := contract.ExecutorReference{Generation: 1, Decision: f.want.Reference}
	base := contract.ArtifactRecord{ResourceUID: "resource-uid", Incarnation: "runtime-incarnation", OperationID: "create-op",
		Origin: origin, HostUID: "host-uid", HostIncarnation: "positive-host-uid", State: "active"}
	disk, domain := base, base
	disk.ID, disk.Key, disk.Kind, disk.Backend, disk.ObjectID = "disk-artifact", "root", "disk", "test-storage", "immutable-disk-object"
	disk.PoolUID, disk.ImageDigest, disk.Locator = "pool-uid", strings.Repeat("a", 64), "/storage/root"
	domain.ID, domain.Key, domain.Kind, domain.Backend, domain.ObjectID = "domain-artifact", "domain", "domain", "test-libvirt", "domain-uuid"
	return []contract.ArtifactRecord{disk, domain}
}

func (f *executionStorageFixture) progress(t *testing.T, state string, artifacts []contract.ArtifactRecord) AutomationRecord {
	t.Helper()
	b := f.body(t)
	b.State, b.Artifacts = state, artifacts
	if state != "running" {
		b.Reason, b.NextAction = "backend-observation", "reconcile"
	}
	return f.next(t, "record_progress", b)
}

func (f *executionStorageFixture) terminal(t *testing.T, outcome string, artifacts []contract.ArtifactRecord) AutomationRecord {
	t.Helper()
	b := f.body(t)
	observed := "running"
	if outcome == "failed" {
		observed = "absent"
	}
	b.Result = &contract.ExecutionResult{Outcome: outcome, Code: "backend-result", ObservedState: observed}
	for _, a := range artifacts {
		b.Result.Artifacts = append(b.Result.Artifacts, contract.ArtifactDisposition{ID: a.ID, State: a.State})
	}
	return f.next(t, "complete_operation", b)
}

// One FULL read observes all execution rows together with original evidence,
// permanent receipts, desired-state projections and both cursor owners.
func executionStorageSnapshot(t *testing.T, c *Client) map[string][]Row {
	t.Helper()
	ctx := context.Background()
	out := map[string][]Row{}
	if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		for _, table := range append(append([]string{}, executionStorageTables...),
			"local_automation_history", "local_automation_anchors", "local_automation_requests", "local_automation_prefix",
			"local_automation_semantic_heads", "local_automation_resources", "local_automation_admissions",
			"local_automation_bindings", "local_automation_names", "local_automation_identities", "local_automation_owners") {
			rows, err := tx.Query(ctx, "SELECT * FROM "+table+" ORDER BY rowid")
			if err != nil {
				return err
			}
			out[table] = rows
		}
		return nil
	}); err != nil {
		t.Fatal("execution snapshot", err)
	}
	return out
}

func (f *executionStorageFixture) projection(t *testing.T) contract.Projection {
	t.Helper()
	probe := f.progress(t, "running", nil)
	d, err := automationDecision(probe.Value)
	if err != nil {
		t.Fatal(err)
	}
	var p contract.Projection
	if err := f.c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
		head, err := automationHeadTx(context.Background(), tx)
		if err != nil {
			return err
		}
		p, err = automationProjectionTx(context.Background(), tx, head, d, nil)
		return err
	}); err != nil {
		t.Fatal("execution projection", err)
	}
	return p
}

func (f *executionStorageFixture) reopen(t *testing.T) {
	t.Helper()
	if err := f.c.Close(); err != nil {
		t.Fatal(err)
	}
	c, err := NewLocalClient(f.dir, "a")
	if err != nil {
		t.Fatal(err)
	}
	c.SetVoterConfigGate(func() bool { return true })
	f.c = c
	t.Cleanup(func() { _ = c.Close() })
}

func TestAutomationExecutionFULLStorageLifecycle(t *testing.T) {
	for _, outcome := range []string{"succeeded", "failed"} {
		t.Run(outcome, func(t *testing.T) {
			f := newExecutionStorageFixture(t)
			grantReceipt := f.start(t)
			artifacts := f.artifacts()
			for _, state := range []string{"running", "recovering", "blocked"} {
				r := f.apply(t, f.progress(t, state, artifacts))
				p := f.projection(t)
				if r.State != state || p.Execution == nil || p.Execution.Progress == nil || p.Execution.Progress.State != state ||
					p.Execution.Progress.Sequence != r.Sequence || !reflect.DeepEqual(p.Execution.Artifacts, artifacts) ||
					p.Execution.Admission != f.want.Target.Admission || !reflect.DeepEqual(p.Execution.Grant, &f.want) {
					t.Fatalf("durable %s progress/grant/artifact projection differs: %+v", state, p.Execution)
				}
			}
			// Locator equality cannot authorize replacement of an immutable object.
			changed := append([]contract.ArtifactRecord(nil), artifacts...)
			changed[0].ObjectID = "different-object-same-locator"
			before := executionStorageSnapshot(t, f.c)
			if _, err := applySharedAutomation(t, f.c, f.progress(t, "running", changed), contract.Reduce, automationFreshAnchor); err == nil {
				t.Fatal("immutable artifact object replacement accepted")
			}
			if !reflect.DeepEqual(before, executionStorageSnapshot(t, f.c)) {
				t.Fatal("immutable artifact refusal changed state")
			}
			if outcome == "failed" {
				for i := range artifacts {
					artifacts[i].State = "deleted"
					b := f.body(t)
					b.Artifacts = []contract.ArtifactRecord{artifacts[i]}
					f.apply(t, f.next(t, "retire_artifact", b))
				}
			}
			terminal := f.terminal(t, outcome, artifacts)
			terminalReceipt := f.apply(t, terminal)
			p := f.projection(t)
			if terminalReceipt.State != outcome || p.Execution.Terminal == nil || p.Execution.Terminal.Sequence != terminalReceipt.Sequence ||
				p.Execution.Terminal.Target != f.want.Target || p.Execution.Terminal.Grant.Decision != f.want.Reference ||
				p.Execution.Terminal.Result.Outcome != outcome || !reflect.DeepEqual(p.Execution.Terminal.Artifacts, artifacts) {
				t.Fatalf("permanent terminal projection incomplete: %+v", p.Execution)
			}
			// Terminal wire row omits the expanded permanent artifact snapshot.
			stored := executionStorageSnapshot(t, f.c)
			rows := stored["local_automation_execution_terminals"]
			if len(rows) != 1 {
				t.Fatal("terminal count", len(rows))
			}
			var wire map[string]json.RawMessage
			if err := json.Unmarshal([]byte(rows[0].String("terminal_json")), &wire); err != nil {
				t.Fatal(err)
			}
			if len(wire) != 3 {
				t.Fatal("terminal wire row must contain Target/Grant/Result only", wire)
			}
			for key := range wire {
				switch strings.ToLower(key) {
				case "target", "grant", "result":
				default:
					t.Fatal("terminal row contains expanded snapshot or unsupported field", key)
				}
			}
			// A fresh identical semantic request may advance history but cannot
			// rewrite the permanent terminal/artifact snapshot or its original sequence.
			f.apply(t, f.terminal(t, outcome, artifacts))
			after := executionStorageSnapshot(t, f.c)
			for _, table := range []string{"local_automation_execution_terminals", "local_automation_execution_artifacts"} {
				if !reflect.DeepEqual(stored[table], after[table]) {
					t.Fatal("identical terminal rewrote permanent rows", table)
				}
			}
			before = after
			conflict := f.terminal(t, outcome, artifacts)
			d, _ := automationDecision(conflict.Value)
			b, _ := contract.DecodeExecutionBody(d.Command)
			b.Result.Code = "conflicting-result"
			d.Command.Body = automationExecutionJSON(t, b)
			if _, err := applySharedAutomation(t, f.c, f.sign(d), contract.Reduce, automationFreshAnchor); err == nil {
				t.Fatal("conflicting terminal accepted")
			}
			if !reflect.DeepEqual(before, executionStorageSnapshot(t, f.c)) {
				t.Fatal("terminal conflict changed state")
			}
			// Even approved artifact retirement cannot mutate a permanent terminal.
			b = f.body(t)
			retired := artifacts[0]
			retired.State = "deleted"
			b.Artifacts = []contract.ArtifactRecord{retired}
			if _, err := applySharedAutomation(t, f.c, f.next(t, "retire_artifact", b), contract.Reduce, automationFreshAnchor); err == nil {
				t.Fatal("post-terminal artifact mutation accepted")
			}
			if !reflect.DeepEqual(before, executionStorageSnapshot(t, f.c)) {
				t.Fatal("post-terminal artifact mutation changed state")
			}
			f.reopen(t)
			if !reflect.DeepEqual(before, executionStorageSnapshot(t, f.c)) {
				t.Fatal("cold reopen changed terminal/evidence/cursors")
			}
			for _, retry := range []struct {
				record  AutomationRecord
				receipt contract.Receipt
			}{{f.grant, grantReceipt}, {terminal, terminalReceipt}} {
				if got := f.apply(t, retry.record); got != retry.receipt {
					t.Fatal("exact original retry changed receipt", got, retry.receipt)
				}
			}
			// The original admitted request survives execution and artifact retirement.
			if got := f.apply(t, f.admission); got.Sequence != 10 || got.OperationID != "create-op" || got.State != "accepted" {
				t.Fatal("original admission retry changed", got)
			}
			if !reflect.DeepEqual(before, executionStorageSnapshot(t, f.c)) {
				t.Fatal("cold exact retries changed rows")
			}
			if p := f.projection(t); p.Execution.Terminal == nil || !reflect.DeepEqual(p.Execution.Terminal.Artifacts, artifacts) {
				t.Fatal("cold terminal snapshot lost artifacts")
			}
		})
	}
}

func TestAutomationExecutionFULLAtomicFailures(t *testing.T) {
	for _, boundary := range []string{"artifact-write", "terminal-write", "semantic-head", "commit", "sync"} {
		t.Run(boundary, func(t *testing.T) {
			f := newExecutionStorageFixture(t)
			f.start(t)
			artifacts := f.artifacts()
			record := f.progress(t, "running", artifacts)
			if boundary != "artifact-write" {
				f.apply(t, record)
				record = f.terminal(t, "succeeded", artifacts)
			}
			before := executionStorageSnapshot(t, f.c)
			injected := errors.New("actual completed execution insert failure")
			var fault *targetInsertFault
			var err error
			switch boundary {
			case "artifact-write", "terminal-write", "semantic-head":
				table := "local_automation_execution_artifacts"
				if boundary == "terminal-write" {
					table = "local_automation_execution_terminals"
				}
				if boundary == "semantic-head" {
					table = "local_automation_semantic_heads"
				}
				fault = &targetInsertFault{table: table, ordinal: 1, failure: injected}
				targetInjectInsert(t, f.c, fault)
				_, err = applySharedAutomation(t, f.c, record, contract.Reduce, automationFreshAnchor)
				if !fault.fired || !errors.Is(err, injected) {
					t.Fatal("actual completed write boundary not reached", boundary, fault, err)
				}
			case "commit":
				reached := false
				err = executionStorageApplyWithSeams(t, f.c, record, &localCommitSeams{beforeCommit: func(tx *sql.Tx) error {
					reached = true
					// Existing negative LocalTx owner: real COMMIT on a transaction
					// already rolled back must fail and disclose no accepted receipt.
					return tx.Rollback()
				}})
				if !reached || err == nil || !strings.Contains(err.Error(), "commit local tx") {
					t.Fatal("real LocalTx commit failure not reached", reached, err)
				}
			case "sync":
				f.c.db.SetMaxOpenConns(1)
				if _, err := f.c.db.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
					t.Fatal(err)
				}
				_, err = applySharedAutomation(t, f.c, record, contract.Reduce, automationFreshAnchor)
				if err == nil || !strings.Contains(err.Error(), "automation requires synchronous FULL on its transaction") {
					t.Fatal("real non-FULL connection refusal missing", err)
				}
				if _, err := f.c.db.Exec(`PRAGMA synchronous=FULL`); err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(before, executionStorageSnapshot(t, f.c)) {
				t.Fatal("failure changed execution/history/anchors/request/heads/prefix", boundary)
			}
			f.reopen(t)
			if !reflect.DeepEqual(before, executionStorageSnapshot(t, f.c)) {
				t.Fatal("failed decision survived cold reopen", boundary)
			}
			f.apply(t, record)
		})
	}
}

func executionStorageApplyWithSeams(t *testing.T, c *Client, record AutomationRecord, seams *localCommitSeams) error {
	t.Helper()
	ctx := context.Background()
	d, err := automationDecision(record.Value)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := AdoptedVoterConfig(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	// Same FULL transaction/application owner as applySharedAutomation, with the
	// existing negative commit seam; no callback manufactures receipt or success.
	return c.executeLocal(ctx, func(tx *LocalTx) error {
		_, err := automationApplyTx(ctx, tx, record, d, record.Value.MustDigest(), contract.Reduce,
			automationApplicationProvenance{kind: automationFreshAnchor, sequence: d.Sequence, generation: 1, membersHash: cfg.MembersHash}, nil)
		return err
	}, seams)
}

func TestAutomationExecutionFULLArtifactInventory128And129(t *testing.T) {
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
		t.Fatal("bounded128 claim invalid", err)
	}
	// This is still a genuine signed first grant with original admission10 and
	// distinct head11. Its decision digest changes with the declared obligations.
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
	if p := f.projection(t); p.Execution == nil || len(p.Execution.Artifacts) != 128 || len(p.Execution.Grant.Requirements) != 128 {
		t.Fatal("128 inventory did not survive real FULL load")
	}
	before := executionStorageSnapshot(t, f.c)
	extra := artifacts[len(artifacts)-1]
	extra.ID, extra.Key, extra.ObjectID = "firmware-artifact-126", "firmware-126", "immutable-firmware-126"
	oversized := append(append([]contract.ArtifactRecord(nil), artifacts...), extra)
	// Keep positive construction strict. Start from a valid next decision and
	// change only its artifact array for this explicitly negative signed input.
	negative, err := automationDecision(f.progress(t, "running", artifacts).Value)
	if err != nil {
		t.Fatal(err)
	}
	b := f.body(t)
	b.State, b.Artifacts = "running", oversized
	negative.Command.Body = automationExecutionJSON(t, b)
	if err := contract.ValidateSupportedDecision(negative); contract.Code(err) != contract.CodeValidation {
		t.Fatal("129 artifact command validation refusal missing", err)
	}
	// The existing envelope codec/signer accepts this negative candidate, but
	// FULL apply rejects its typed body before reducer effects or SQL writes.
	r, err := applySharedAutomation(t, f.c, f.sign(negative), contract.Reduce, automationFreshAnchor)
	if contract.Code(err) != contract.CodeValidation || r != (contract.Receipt{}) {
		t.Fatal("129 artifact command must refuse without a receipt", r, err)
	}
	if !reflect.DeepEqual(before, executionStorageSnapshot(t, f.c)) {
		t.Fatal("129 artifact refusal changed state")
	}
	// The 129th declared obligation is independently rejected by the existing
	// command validator; no malformed claim is presented as accepted history.
	a.Execution.Requirements = append(append([]contract.ArtifactRequirement(nil), requirements...), contract.ArtifactRequirement{Key: "firmware-126", Kind: "firmware"})
	d.Assignment = automationExecutionJSON(t, a)
	if err := contract.ValidateSupportedDecision(d); err == nil {
		t.Fatal("129 declared requirements accepted")
	}
	f.apply(t, f.terminal(t, "succeeded", artifacts))
	before = executionStorageSnapshot(t, f.c)
	f.reopen(t)
	if !reflect.DeepEqual(before, executionStorageSnapshot(t, f.c)) {
		t.Fatal("cold128 permanent inventory changed")
	}
	if p := f.projection(t); p.Execution.Terminal == nil || len(p.Execution.Terminal.Artifacts) != 128 {
		t.Fatal("cold128 terminal snapshot truncated")
	}
}
