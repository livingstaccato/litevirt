package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// A held line of spec edits (spec_conflict_ae.go): a node keeps its row,
// whose operation's barrier is still standing, against a longer line of
// out-of-band edits under the same owner. Nothing ends an operation that
// never reaches a terminal step — no reaper exists, only an admin abort — so
// for as long as it stands the replicas hold different desired specs: this
// node and those that saw the claim first show the operation, those that saw
// the line first show the line and no operation. The hold is made visible,
// once per (VM, operation) on each node that holds:
//
//   - a warning;
//   - litevirt_spec_edit_held_total;
//   - a health condition vm.spec_edit_held (evaluator spec_conflict, subject
//     vm/<name>@<this host>, warning) naming the operation, the owner host it
//     shows on and the remedy.
//
// The condition resolves when the operation turns terminal here or the held
// line applies — when the row no longer holds that operation's barrier.

const (
	specHoldEvaluator = "spec_conflict"
	// SpecEditHeldCode is the health condition code of a held line of edits.
	SpecEditHeldCode = "vm.spec_edit_held"
)

type specHold struct {
	vm, op, owner string
}

type specHoldEvidence struct {
	VM        string `json:"vm"`
	Operation string `json:"operation"`
	Owner     string `json:"owner"`
	Remedy    string `json:"remedy"`
}

func (c *Client) specHoldSubject(vm string) string { return vm + "@" + c.hostName }

// specHoldTimeout bounds one write of the condition.
const specHoldTimeout = 30 * time.Second

// noteSpecEditHeld records h once tx commits, once per (VM, operation).
func (c *Client) noteSpecEditHeld(tx *sql.Tx, h specHold) {
	c.deferAfterCommit(tx, func() {
		key := h.vm + "\x00" + h.op
		c.specDropsMu.Lock()
		if c.specHolds == nil {
			c.specHolds = make(map[string]struct{})
		}
		_, seen := c.specHolds[key]
		c.specHolds[key] = struct{}{}
		c.specDropsMu.Unlock()
		if seen {
			return
		}
		slog.Warn("replication: a longer line of spec edits is held off a VM by a running operation",
			"vm", h.vm, "operation", h.op, "owner", h.owner,
			"remedy", "finish the operation, or run `lv operation abort "+h.vm+" --force` on "+h.owner)
		if m, ok := c.syncMetrics.(interface{ ObserveSpecEditHeld() }); ok {
			m.ObserveSpecEditHeld()
		}
		// Not here: the deferred effects run under the client's lock, which
		// the condition's own replicated write takes.
		go c.raiseSpecEditHeld(h)
	})
}

// noteSpecHoldMaybeOver asks, once tx commits, whether vm's held line here
// has ended.
func (c *Client) noteSpecHoldMaybeOver(tx *sql.Tx, vm string) {
	c.deferAfterCommit(tx, func() { go c.resolveSpecEditHeld(vm) })
}

// stillHeld reports whether vm's row here still holds operation op's
// unfinished barrier. Read fresh: the goroutine runs after other commits.
func (c *Client) stillHeld(ctx context.Context, vm, op string) (bool, error) {
	rows, err := c.Query(ctx, `SELECT active_operation_id FROM vms WHERE name = ? AND deleted_at IS NULL`, vm)
	if err != nil {
		return false, err
	}
	if len(rows) == 0 || rows[0].String("active_operation_id") != op {
		return false, nil
	}
	done, err := c.Query(ctx, `SELECT 1 AS one FROM operation_steps
		WHERE operation_id = ? AND step_name IN (?, ?, ?, ?) LIMIT 1`,
		op, OpStepCompleted, OpStepFailed, OpStepCancelled, OpStepSuperseded)
	if err != nil {
		return false, err
	}
	return len(done) == 0, nil
}

func (c *Client) raiseSpecEditHeld(h specHold) {
	ctx, cancel := context.WithTimeout(context.Background(), specHoldTimeout)
	defer cancel()
	if held, err := c.stillHeld(ctx, h.vm, h.op); err != nil || !held {
		c.forgetSpecHold(h.vm, h.op)
		return
	}
	ev, err := json.Marshal(specHoldEvidence{
		VM: h.vm, Operation: h.op, Owner: h.owner,
		Remedy: fmt.Sprintf("finish operation %s on %s, or run `lv operation abort %s --force` there", h.op, h.owner, h.vm),
	})
	if err != nil {
		return
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	row := HealthCondition{
		Evaluator: specHoldEvaluator, Code: SpecEditHeldCode, SubjectKind: "vm", SubjectID: c.specHoldSubject(h.vm),
		Lifecycle: ConditionConfirmed, Severity: SeverityWarning, Hosts: []string{h.owner},
		Evidence: string(ev), ObserveCount: 1, FirstSeen: ts, LastSeen: ts, ConfirmedAt: ts, Reporter: c.hostName,
	}
	if err := UpsertHealthCondition(ctx, c, row); err != nil {
		slog.Warn("replication: could not raise the held-spec-edit condition", "vm", h.vm, "error", err)
		c.forgetSpecHold(h.vm, h.op) // raised again on the next pass that holds
	}
}

func (c *Client) forgetSpecHold(vm, op string) {
	c.specDropsMu.Lock()
	delete(c.specHolds, vm+"\x00"+op)
	c.specDropsMu.Unlock()
}

// resolveSpecEditHeld resolves vm's open held-line condition on this host
// once the row no longer holds that operation's unfinished barrier.
func (c *Client) resolveSpecEditHeld(vm string) {
	ctx, cancel := context.WithTimeout(context.Background(), specHoldTimeout)
	defer cancel()
	row, found, err := GetHealthCondition(ctx, c, specHoldEvaluator, SpecEditHeldCode, "vm", c.specHoldSubject(vm))
	if err != nil || !found || row.Lifecycle == ConditionResolved {
		return
	}
	var ev specHoldEvidence
	_ = json.Unmarshal([]byte(row.Evidence), &ev)
	if held, err := c.stillHeld(ctx, vm, ev.Operation); err != nil || held {
		return
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = ConditionResolved, ts, ts, c.hostName
	row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
	if err := UpsertHealthCondition(ctx, c, row); err != nil {
		slog.Warn("replication: could not resolve the held-spec-edit condition", "vm", vm, "error", err)
		return
	}
	c.forgetSpecHold(vm, ev.Operation)
}
