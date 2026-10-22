package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// Reconstruct originals through the existing real source-audit owner, rather
// than copying execution rows into a purported authenticated stage.
func executionReplayCompletedFixture(t *testing.T) (*executionStorageFixture, AutomationRecord) {
	t.Helper()
	f := newExecutionStorageFixture(t)
	f.start(t)
	f.apply(t, f.progress(t, "running", f.artifacts()))
	f.apply(t, f.terminal(t, "succeeded", f.artifacts()))
	head, err := f.c.AutomationHead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, value := automationFixture(t, head.Sequence+1, head.Digest)
	d, err := automationDecision(value)
	if err != nil {
		t.Fatal(err)
	}
	d.Command.RequestID = "after-terminal-barrier"
	d.Assignment = automationExecutionJSON(t, contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: "after-terminal-barrier-op", RecordedAt: "2026-10-21T00:00:02Z"})
	barrier := f.sign(d)
	f.apply(t, barrier)
	return f, barrier
}

func TestAutomationExecutionFULLStageResetAndAuthenticatedReplay(t *testing.T) {
	f, barrier := executionReplayCompletedFixture(t)
	ctx := context.Background()
	before := executionStorageSnapshot(t, f.c)
	terminalBefore := f.projection(t).Execution.Terminal
	visited := 0
	if err := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		_, err := auditAutomationCutTx(ctx, tx, func(p AutomationProjection, d contract.Decision) (AutomationReduction, error) {
			r, err := contract.Reduce(p, d)
			if err != nil || d.Command.RequestID != "after-terminal-barrier" {
				return r, err
			}
			visited++
			const stage = "source-cut-audit"
			// The genuine audit has now rebuilt admission10, gap11, grant12,
			// progress13 and terminal14 from their actual original envelopes.
			probe := d
			probe.Command = executionReplayProbe(t, f, d).Command
			q := contract.Projection{Head: p.Head}
			if err := automationSemanticProjectionSourceTx(ctx, tx, stage, &q, probe, nil); err != nil {
				return r, err
			}
			if q.Execution == nil || q.Execution.Terminal == nil || !reflect.DeepEqual(q.Execution.Terminal, terminalBefore) || !reflect.DeepEqual(q.Execution.Grant, &f.want) {
				return r, errors.New("isolated original-history replay lost grant/terminal/artifacts")
			}
			// A missing receiver source cannot borrow the active local originals.
			missing := receiverAutomationKeySource{receiverAuditStore{tx: tx, id: "missing-execution-receiver"}}
			q = contract.Projection{Head: p.Head}
			if err := automationSemanticProjectionSourceTx(ctx, tx, stage, &q, probe, missing); err == nil {
				return r, errors.New("receiver execution projection fell back to active originals")
			}
			return r, nil
		})
		return err
	}); err != nil || visited != 1 {
		t.Fatal("actual source-stage replay", visited, err)
	}
	if !reflect.DeepEqual(before, executionStorageSnapshot(t, f.c)) {
		t.Fatal("source audit changed active rows or evidence")
	}

	// Reach the same genuine reconstructed stage again and reset that exact
	// stage only. Roll back the deliberate audit interruption after observation.
	stop := errors.New("observed exact reconstructed-stage reset")
	resetReached := false
	err := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		_, err := auditAutomationCutTx(ctx, tx, func(p AutomationProjection, d contract.Decision) (AutomationReduction, error) {
			r, err := contract.Reduce(p, d)
			if err != nil || d.Command.RequestID != "after-terminal-barrier" {
				return r, err
			}
			for _, table := range executionStorageTables {
				rows, err := tx.Query(ctx, "SELECT * FROM "+table+" WHERE stage=?", "source-cut-audit")
				if err != nil || len(rows) == 0 {
					return r, fmt.Errorf("genuine stage missing %s before reset: %v", table, err)
				}
			}
			// Negative future-row poison is confined to the genuine scratch stage;
			// reset must remove it rather than treating its sequence as protected.
			if _, err := tx.Exec(ctx, `UPDATE local_automation_executors SET grant_sequence=999 WHERE stage=?`, "source-cut-audit"); err != nil {
				return r, err
			}
			if _, err := tx.Exec(ctx, `UPDATE local_automation_execution_terminals SET applied_sequence=999 WHERE stage=?`, "source-cut-audit"); err != nil {
				return r, err
			}
			if err := automationResetSemanticProjectionTx(ctx, tx, "source-cut-audit"); err != nil {
				return r, err
			}
			for _, table := range executionStorageTables {
				rows, err := tx.Query(ctx, "SELECT * FROM "+table+" WHERE stage=?", "source-cut-audit")
				if err != nil || len(rows) != 0 {
					return r, fmt.Errorf("reset retained %s: %v", table, err)
				}
				active, err := tx.Query(ctx, "SELECT * FROM "+table+" ORDER BY rowid")
				if err != nil || !reflect.DeepEqual(active, before[table]) {
					return r, fmt.Errorf("stage reset changed active %s: %v", table, err)
				}
			}
			resetReached = true
			return r, stop
		})
		return err
	})
	if !resetReached || !errors.Is(err, stop) {
		t.Fatal("exact stage reset witness missing", resetReached, err)
	}
	if !reflect.DeepEqual(before, executionStorageSnapshot(t, f.c)) {
		t.Fatal("stage reset escaped transaction isolation")
	}

	// Active reset preserves immutable originals and requests; bounded existing
	// replay must reconstruct exactly the same current execution and cursors.
	if err := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationResetSemanticProjectionTx(ctx, tx, "") }); err != nil {
		t.Fatal(err)
	}
	for _, table := range executionStorageTables {
		rows, err := f.c.Query(ctx, "SELECT * FROM "+table+" WHERE stage='' LIMIT 1")
		if err != nil || len(rows) != 0 {
			t.Fatal("active reset retained execution", table, err)
		}
	}
	if err := f.c.AutomationReplay(ctx, contract.Reduce, 64); err != nil {
		t.Fatal("authenticated active replay", err)
	}
	if !reflect.DeepEqual(before, executionStorageSnapshot(t, f.c)) {
		t.Fatal("active reset/replay differs from original FULL state")
	}
	f.reopen(t)
	if !reflect.DeepEqual(before, executionStorageSnapshot(t, f.c)) {
		t.Fatal("cold replayed state differs")
	}
	if got := f.apply(t, barrier); got.State != "succeeded" {
		t.Fatal("replayed permanent request changed", got)
	}
}

func executionReplayProbe(t *testing.T, f *executionStorageFixture, d contract.Decision) contract.Decision {
	t.Helper()
	base, err := automationDecision(f.grant.Value)
	if err != nil {
		t.Fatal(err)
	}
	base.Sequence, base.ParentDigest = d.Sequence, d.ParentDigest
	base.Command.Kind, base.Command.RequestID = "record_progress", "unapplied-replay-probe"
	b := f.body(t)
	b.State = "running"
	base.Command.Body = automationExecutionJSON(t, b)
	base.Assignment = automationExecutionJSON(t, contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: "unapplied-replay-probe-op", RecordedAt: "2026-10-21T00:00:03Z"})
	return base
}

func TestAutomationExecutionFULLOriginalClosureRejectsCorruption(t *testing.T) {
	// Every mutation is negative evidence after an actual accepted FULL grant
	// and terminal. No changed row is ever used to establish positive authority.
	for _, mode := range []string{"future-grant", "missing-grant", "foreign-grant", "mixed-digest", "future-terminal", "missing-terminal", "foreign-terminal", "missing-artifact", "foreign-artifact", "backend-object", "extra-artifact", "missing-original-admission", "erase-all-effects"} {
		t.Run(mode, func(t *testing.T) {
			f, _ := executionReplayCompletedFixture(t)
			ctx := context.Background()
			probe := f.progress(t, "running", nil)
			d, _ := automationDecision(probe.Value)
			if err := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				var query string
				var args []any
				switch mode {
				case "future-grant":
					query = `UPDATE local_automation_executors SET grant_sequence=999 WHERE stage=''`
				case "missing-grant":
					query = `DELETE FROM local_automation_executors WHERE stage=''`
				case "foreign-grant":
					query = `UPDATE local_automation_executors SET cluster_uid='foreign-cluster' WHERE stage=''`
				case "mixed-digest":
					query, args = `UPDATE local_automation_executors SET grant_digest=? WHERE stage=''`, []any{f.grant.Value.MustDigest()}
				case "future-terminal":
					query = `UPDATE local_automation_execution_terminals SET applied_sequence=999 WHERE stage=''`
				case "missing-terminal":
					query = `DELETE FROM local_automation_execution_terminals WHERE stage=''`
				case "foreign-terminal":
					query = `UPDATE local_automation_execution_terminals SET cluster_uid='foreign-cluster' WHERE stage=''`
				case "missing-artifact":
					query = `DELETE FROM local_automation_execution_artifacts WHERE stage='' AND artifact_id='disk-artifact'`
				case "foreign-artifact":
					query = `UPDATE local_automation_execution_artifacts SET operation_id='foreign-operation' WHERE stage='' AND artifact_id='disk-artifact'`
				case "backend-object":
					query = `UPDATE local_automation_execution_artifacts SET object_id='different-immutable-object' WHERE stage='' AND artifact_id='disk-artifact'`
				case "extra-artifact":
					rows, err := tx.Query(ctx, `SELECT * FROM local_automation_execution_artifacts WHERE stage='' AND artifact_id='disk-artifact'`)
					if err != nil {
						return err
					}
					if len(rows) != 1 {
						return fmt.Errorf("extra-artifact source count %d", len(rows))
					}
					row := rows[0]
					var orphan contract.ArtifactRecord
					if err := json.Unmarshal([]byte(row.String("artifact_json")), &orphan); err != nil {
						return err
					}
					orphan.ID, orphan.Key, orphan.ObjectID = "orphan-artifact", "orphan-key", "orphan-object"
					body, err := json.Marshal(orphan)
					if err != nil {
						return err
					}
					// Keep columns and JSON consistent: only original-history
					// membership is absent. This row is negative evidence only.
					query = `INSERT INTO local_automation_execution_artifacts(stage,cluster_uid,operation_id,artifact_id,resource_uid,artifact_key,artifact_kind,backend,object_id,applied_sequence,artifact_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)`
					args = []any{row.String("stage"), row.String("cluster_uid"), row.String("operation_id"), orphan.ID, orphan.ResourceUID, orphan.Key, orphan.Kind, orphan.Backend, orphan.ObjectID, row.Int64("applied_sequence"), string(body)}
				case "missing-original-admission":
					query = `DELETE FROM local_automation_history WHERE sequence=10`
				case "erase-all-effects":
					for _, table := range executionStorageTables {
						if _, err := tx.Exec(ctx, "DELETE FROM "+table+" WHERE stage=''"); err != nil {
							return err
						}
					}
					return nil
				}
				result, err := tx.Exec(ctx, query, args...)
				if err != nil {
					return err
				}
				n, err := result.RowsAffected()
				if err != nil || n != 1 {
					return fmt.Errorf("corruption witness changed %d rows: %v", n, err)
				}
				return nil
			}); err != nil {
				t.Fatal("negative corruption setup", err)
			}
			corrupt := executionStorageSnapshot(t, f.c)
			// The existing source-aware projection entrypoint must detect inverse
			// absence, including complete derived erasure with intact history.
			err := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				head, err := automationHeadTx(ctx, tx)
				if err != nil {
					return err
				}
				_, err = automationProjectionTx(ctx, tx, head, d, nil)
				return err
			})
			if err == nil {
				t.Fatal("corrupt current execution projection accepted", mode)
			}
			if !reflect.DeepEqual(corrupt, executionStorageSnapshot(t, f.c)) {
				t.Fatal("corruption refusal changed rows", mode)
			}
			// Source audit also compares both directions, including active extras
			// and the all-derived-rows-deleted inverse closure.
			if err := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error { _, err := auditAutomationCutTx(ctx, tx, contract.Reduce); return err }); err == nil {
				t.Fatal("source audit accepted corrupt current execution", mode)
			}
			if !reflect.DeepEqual(corrupt, executionStorageSnapshot(t, f.c)) {
				t.Fatal("failed source audit changed rows", mode)
			}
			f.reopen(t)
			if !reflect.DeepEqual(corrupt, executionStorageSnapshot(t, f.c)) {
				t.Fatal("reopen silently blessed or repaired corrupt rows", mode)
			}
		})
	}
}

func TestAutomationExecutionFULLCallbackCannotEraseEffects(t *testing.T) {
	for _, effect := range []string{"grant", "progress", "artifact", "terminal"} {
		t.Run(effect, func(t *testing.T) {
			f := newExecutionStorageFixture(t)
			record := f.grant
			if effect != "grant" {
				f.start(t)
				record = f.progress(t, "running", f.artifacts())
			}
			if effect == "terminal" {
				f.apply(t, record)
				record = f.terminal(t, "succeeded", f.artifacts())
			}
			// Execution SQL is available only after a genuine grant, so the grant
			// erasure control compares the existing predecessor snapshot instead.
			beforeHistory, beforeTyped := sharedActiveRows(t, f.c), automationTypedSnapshot(t, f.c)
			var before map[string][]Row
			if effect != "grant" {
				before = executionStorageSnapshot(t, f.c)
			}
			visited := 0
			_, err := applySharedAutomation(t, f.c, record, func(p AutomationProjection, d contract.Decision) (AutomationReduction, error) {
				r, err := contract.Reduce(p, d)
				if err != nil {
					return r, err
				}
				visited++
				switch effect {
				case "grant":
					if r.ExecutorEffect == nil {
						return r, errors.New("callback never received real grant effect")
					}
					r.ExecutorEffect = nil
				case "progress":
					if r.ProgressEffect == nil {
						return r, errors.New("callback never received real progress effect")
					}
					r.ProgressEffect = nil
				case "artifact":
					if len(r.ArtifactEffects) == 0 {
						return r, errors.New("callback never received real artifact effect")
					}
					r.ArtifactEffects = nil
				case "terminal":
					if r.TerminalEffect == nil {
						return r, errors.New("callback never received real terminal effect")
					}
					r.TerminalEffect = nil
				}
				return r, nil
			}, automationFreshAnchor)
			if visited != 1 || err == nil || !strings.Contains(err.Error(), "automation reducer result drift") {
				t.Fatal("FULL callback effect equality not enforced", effect, visited, err)
			}
			if !reflect.DeepEqual(beforeHistory, sharedActiveRows(t, f.c)) || !reflect.DeepEqual(beforeTyped, automationTypedSnapshot(t, f.c)) {
				t.Fatal("callback erasure changed predecessor")
			}
			if before != nil && !reflect.DeepEqual(before, executionStorageSnapshot(t, f.c)) {
				t.Fatal("callback erasure changed execution")
			}
		})
	}
}

func TestAutomationExecutionFULLCallbackNestedProjectionIsolation(t *testing.T) {
	f, _ := executionReplayCompletedFixture(t)
	before := executionStorageSnapshot(t, f.c)
	original := f.projection(t).Execution
	// Use an identical terminal at a new certified slot: authoritative evaluation
	// must remain equal after the compatibility callback mutates its own copy.
	record := f.terminal(t, "succeeded", f.artifacts())
	visited := 0
	r, err := applySharedAutomation(t, f.c, record, func(p AutomationProjection, d contract.Decision) (AutomationReduction, error) {
		result, err := contract.Reduce(p, d)
		if err != nil {
			return result, err
		}
		if p.Execution == nil || p.Execution.Grant == nil || p.Execution.Progress == nil || p.Execution.Terminal == nil || len(p.Execution.Artifacts) == 0 || len(p.Execution.Terminal.Result.Artifacts) == 0 {
			return result, errors.New("callback missing genuine nested predecessor")
		}
		visited++
		p.Execution.Admission.Digest = strings.Repeat("f", 64)
		p.Execution.Grant.Target.HostUID = "mutated-callback-host"
		p.Execution.Grant.Requirements[0].Key = "mutated-callback-requirement"
		p.Execution.Progress.State = "mutated-callback-progress"
		p.Execution.Artifacts[0].ObjectID = "mutated-callback-object"
		p.Execution.Terminal.Target.HostUID = "mutated-callback-terminal-host"
		p.Execution.Terminal.Result.Artifacts[0].State = "deleted"
		p.Execution.Terminal.Artifacts[0].ObjectID = "mutated-callback-terminal-object"
		return result, nil
	}, automationFreshAnchor)
	if visited != 1 || err != nil || r.Code != "" || r.State != "succeeded" {
		t.Fatal("callback alias changed authoritative evaluation", visited, r, err)
	}
	if after := f.projection(t).Execution; !reflect.DeepEqual(original, after) {
		t.Fatal("nested callback mutation changed actual immutable predecessor")
	}
	after := executionStorageSnapshot(t, f.c)
	for _, table := range executionStorageTables {
		if !reflect.DeepEqual(before[table], after[table]) {
			t.Fatal("nested callback mutation changed stored execution", table)
		}
	}
	// Exclusions have no certified producer and stay empty. Check deep cloning of
	// their nested predecessor requirements separately, with an explicitly local
	// alias-only value; it is never submitted as execution authority.
	p := contract.Projection{Execution: &contract.ExecutionProjection{Exclusions: []contract.ExecutorExclusion{{Predecessor: f.want}}}}
	originalRequirement := p.Execution.Exclusions[0].Predecessor.Requirements[0].Key
	cloned := cloneAutomationProjection(p)
	cloned.Execution.Exclusions[0].Predecessor.Requirements[0].Key = "alias-only-mutation"
	if p.Execution.Exclusions[0].Predecessor.Requirements[0].Key != originalRequirement {
		t.Fatal("exclusion predecessor requirements share callback storage")
	}
}

func TestAutomationExecutionLoadedProjectionCloneIsolation(t *testing.T) {
	f, _ := executionReplayCompletedFixture(t)
	for _, tc := range []struct {
		name   string
		mutate func(*contract.ExecutionProjection)
	}{
		{"admission-reference", func(p *contract.ExecutionProjection) { p.Admission.Digest = strings.Repeat("f", 64) }},
		{"grant-target", func(p *contract.ExecutionProjection) { p.Grant.Target.HostUID = "clone-only-host" }},
		{"grant-requirements", func(p *contract.ExecutionProjection) { p.Grant.Requirements[0].Key = "clone-only-requirement" }},
		{"progress", func(p *contract.ExecutionProjection) { p.Progress.State = "clone-only-progress" }},
		{"current-artifacts", func(p *contract.ExecutionProjection) { p.Artifacts[0].ObjectID = "clone-only-current-object" }},
		{"terminal-target", func(p *contract.ExecutionProjection) { p.Terminal.Target.HostUID = "clone-only-terminal-host" }},
		{"terminal-result-dispositions", func(p *contract.ExecutionProjection) { p.Terminal.Result.Artifacts[0].State = "deleted" }},
		{"terminal-artifact-snapshot", func(p *contract.ExecutionProjection) { p.Terminal.Artifacts[0].ObjectID = "clone-only-terminal-object" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Each control reloads a genuinely applied predecessor independently.
			// Capture owned JSON bytes BEFORE invoking the clone under test; a
			// second shallow clone or a later SQLite reload cannot mask an alias.
			loaded := f.projection(t)
			p := loaded.Execution
			if p == nil || p.Grant == nil || len(p.Grant.Requirements) == 0 || p.Progress == nil || len(p.Artifacts) == 0 ||
				p.Terminal == nil || len(p.Terminal.Result.Artifacts) == 0 || len(p.Terminal.Artifacts) == 0 {
				t.Fatal("genuine loaded predecessor missing nested clone control")
			}
			before := automationExecutionJSON(t, p)
			cloned := cloneAutomationProjection(loaded)
			if cloned.Execution == nil {
				t.Fatal("clone omitted execution projection")
			}
			tc.mutate(cloned.Execution)
			if string(automationExecutionJSON(t, cloned.Execution)) == string(before) {
				t.Fatal("selected clone mutation was ineffective")
			}
			if string(automationExecutionJSON(t, loaded.Execution)) != string(before) {
				t.Fatal("clone mutation changed original loaded predecessor", tc.name)
			}
		})
	}
}
