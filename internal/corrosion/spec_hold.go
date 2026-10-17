package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// A held line of spec edits (spec_conflict_ae.go): a node keeps its row,
// whose operation's barrier is still standing, against a longer line of
// out-of-band edits under the same owner. Nothing ends an operation that
// never reaches a terminal step — no reaper exists, only an admin abort — so
// for as long as it stands the replicas hold different desired specs: this
// node and those that saw the claim first show the operation, those that saw
// the line first show the line and no operation. The hold is made visible on
// each node that holds, as a health condition vm.spec_edit_held (evaluator
// spec_conflict, subject vm/<name>@<this host>, warning) naming the
// operation, the owner host it shows on and the remedy:
//
//   - raised OBSERVED at the end of the first anti-entropy pass that holds,
//     and CONFIRMED only at the end of a second consecutive one for the same
//     operation, each time only if the row still holds the operation's
//     unfinished barrier once the whole pass has merged. A node that merely
//     has not yet heard an operation finish — the paged pull merges its
//     terminal step after the vms row, in the same pass — is not left
//     holding at the end of that pass, so it never confirms;
//   - on confirmation, once per (VM, operation): a warning and
//     litevirt_spec_edit_held_total. Not repeated while the condition's own
//     write fails; the write alone is retried, on the next pass that holds;
//   - on every pass that holds, the owner named is the row's host as it is
//     now, so a transfer that keeps the barrier does not leave it stale.
//
// The condition resolves when the row no longer holds that operation's
// unfinished barrier — the operation turned terminal here, the held line
// applied, or the VM was deleted — and, for a removed host, through
// ResolveSpecEditHeldOfHost. Every read-then-write of the condition on this
// node runs under one lock, so a raise cannot land after the resolve that
// followed the clear it missed.

const (
	specHoldEvaluator = "spec_conflict"
	// SpecEditHeldCode is the health condition code of a held line of edits.
	SpecEditHeldCode = "vm.spec_edit_held"
)

// SpecEditHeldObserver is the optional sync-metrics method that counts a
// confirmed hold (litevirt_spec_edit_held_total).
type SpecEditHeldObserver interface {
	ObserveSpecEditHeld()
}

type specHoldEvidence struct {
	VM        string `json:"vm"`
	Operation string `json:"operation"`
	Owner     string `json:"owner"`
	Remedy    string `json:"remedy"`
}

// specHoldRemedy is what an operator does about a hold: check the operation
// on its owner, and abort that operation alone if it is wedged. The abort is
// scoped by --operation, so an operation that finished, or one that began
// since, is never the one cleared.
func specHoldRemedy(vm, op, owner string) string {
	return fmt.Sprintf("on %s, check `lv operation show %s`; if operation %s is wedged there, run `lv operation abort %s --operation %s --force`",
		owner, vm, op, vm, op)
}

// specHoldState is one VM's hold on this node.
type specHoldState struct {
	op           string
	passes       int    // consecutive anti-entropy passes that held for op
	noted        bool   // warned and counted (on confirmation)
	written      string // lifecycle last written for op; "" none
	writtenOwner string
	firstSeen    string
	confirmedAt  string
}

// specHoldTracker is the client's in-memory view of its holds. mu guards the
// maps and flags and is never held across a database call; writeMu
// serialises every read-then-write of a condition and is never taken under
// the client's lock (the deferred effects run under it), only in the
// goroutines below.
type specHoldTracker struct {
	mu           sync.Mutex
	holds        map[string]*specHoldState // vm → hold
	heldThisPass map[string]string         // vm → operation, held in the pass under way
	seeded       bool                      // holds loaded from this host's open conditions
	pending      map[string]struct{}       // VMs whose hold may be over
	sweeping     bool

	writeMu sync.Mutex
	wg      sync.WaitGroup // in-flight raises and sweeps (tests drain it)

	// Test seams; nil in production.
	beforeWrite func(vm string) // a raise has read the row held, before it writes
	listed      func()          // a batched read of the open conditions
	swept       func()          // a sweep round has finished
}

func (c *Client) specHoldSubject(vm string) string { return vm + "@" + c.hostName }

// specHoldTimeout bounds one write of the condition.
const specHoldTimeout = 30 * time.Second

// noteSpecEditHeld records, once tx commits, that this anti-entropy pass held
// vm's line off operation op. It is counted, and the condition written, when
// the pass ends (endSpecHoldPass): the paged pull merges the operation's
// terminal step after the vms row, so a check made before the pass ends can
// take an operation that finished for one still running.
func (c *Client) noteSpecEditHeld(tx *sql.Tx, vm, op string) {
	c.deferAfterCommit(tx, func() {
		t := &c.specHold
		t.mu.Lock()
		if t.heldThisPass == nil {
			t.heldThisPass = make(map[string]string)
		}
		t.heldThisPass[vm] = op
		t.mu.Unlock()
	})
}

// endSpecHoldPass ends an anti-entropy pass for the holds: each VM held in it
// counts one more consecutive pass for its operation, and its condition is
// written as it now stands — after every table of the pass has merged.
func (c *Client) endSpecHoldPass() {
	t := &c.specHold
	t.mu.Lock()
	held := t.heldThisPass
	t.heldThisPass = nil
	if len(held) > 0 && t.holds == nil {
		t.holds = make(map[string]*specHoldState)
	}
	for vm, op := range held {
		st := t.holds[vm]
		if st == nil || st.op != op {
			st = &specHoldState{op: op}
			t.holds[vm] = st
		}
		st.passes++
	}
	t.mu.Unlock()
	for vm := range held {
		// Not inline: the condition's own replicated write takes the
		// client's lock, which a caller may hold.
		t.wg.Add(1)
		go func(vm string) {
			defer t.wg.Done()
			c.raiseSpecEditHeld(vm)
		}(vm)
	}
}

// noteSpecHoldMaybeOver asks, once tx commits, whether vm's held line here
// has ended. Cheap when nothing is held here: no goroutine and no read. Every
// VM it names while a sweep is pending is checked by that one sweep.
func (c *Client) noteSpecHoldMaybeOver(tx *sql.Tx, vm string) {
	if vm == "" {
		return
	}
	c.deferAfterCommit(tx, func() {
		t := &c.specHold
		t.mu.Lock()
		if t.seeded && t.holds[vm] == nil {
			t.mu.Unlock()
			return
		}
		if t.pending == nil {
			t.pending = make(map[string]struct{})
		}
		t.pending[vm] = struct{}{}
		start := !t.sweeping
		t.sweeping = true
		t.mu.Unlock()
		if start {
			t.wg.Add(1)
			go func() {
				defer t.wg.Done()
				c.sweepSpecHolds()
			}()
		}
	})
}

// heldRow reads whether vm's row here still holds operation op's unfinished
// barrier, and the row's host. Read fresh: the goroutine runs after other
// commits.
func (c *Client) heldRow(ctx context.Context, vm, op string) (held bool, owner string, err error) {
	rows, err := c.Query(ctx, `SELECT active_operation_id, COALESCE(host_name, '') AS host_name
		FROM vms WHERE name = ? AND deleted_at IS NULL`, vm)
	if err != nil {
		return false, "", err
	}
	if len(rows) == 0 || op == "" || rows[0].String("active_operation_id") != op {
		return false, "", nil
	}
	done, err := c.Query(ctx, `SELECT 1 AS one FROM operation_steps
		WHERE operation_id = ? AND step_name IN (?, ?, ?, ?) LIMIT 1`,
		op, OpStepCompleted, OpStepFailed, OpStepCancelled, OpStepSuperseded)
	if err != nil {
		return false, "", err
	}
	return len(done) == 0, rows[0].String("host_name"), nil
}

// seedSpecHoldsLocked loads this host's open conditions into the tracker,
// once per process, so a restart neither re-raises a confirmed hold as
// observed nor misses one to resolve. Under writeMu. open is this host's open
// rows, already read.
func (c *Client) seedSpecHoldsLocked(open []HealthCondition) {
	t := &c.specHold
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.seeded {
		return
	}
	t.seeded = true
	if t.holds == nil {
		t.holds = make(map[string]*specHoldState)
	}
	for _, row := range open {
		var ev specHoldEvidence
		_ = json.Unmarshal([]byte(row.Evidence), &ev)
		vm := strings.TrimSuffix(row.SubjectID, "@"+c.hostName)
		st := t.holds[vm]
		if st == nil {
			st = &specHoldState{op: ev.Operation}
			t.holds[vm] = st
		}
		if st.op != ev.Operation {
			continue // a later operation is held now: its write replaces the row
		}
		if row.Lifecycle == ConditionConfirmed && st.passes < 2 {
			st.passes, st.noted = 2, true
		}
		st.written, st.writtenOwner, st.firstSeen, st.confirmedAt = row.Lifecycle, ev.Owner, row.FirstSeen, row.ConfirmedAt
	}
}

// openSpecHoldsHere is the one batched read: this host's open held-line
// conditions.
func (c *Client) openSpecHoldsHere(ctx context.Context) ([]HealthCondition, error) {
	if f := c.specHold.listed; f != nil {
		f()
	}
	rows, err := ListOpenHealthConditionsByCode(ctx, c, specHoldEvaluator, SpecEditHeldCode)
	if err != nil {
		return nil, err
	}
	out := rows[:0]
	for _, row := range rows {
		if row.SubjectKind == "vm" && strings.HasSuffix(row.SubjectID, "@"+c.hostName) {
			out = append(out, row)
		}
	}
	return out, nil
}

func (c *Client) ensureSpecHoldsSeeded(ctx context.Context) error {
	t := &c.specHold
	t.mu.Lock()
	seeded := t.seeded
	t.mu.Unlock()
	if seeded {
		return nil
	}
	open, err := c.openSpecHoldsHere(ctx)
	if err != nil {
		return err
	}
	c.seedSpecHoldsLocked(open)
	return nil
}

// raiseSpecEditHeld writes vm's hold as it now stands: observed after one
// pass, confirmed after two, naming the row's current host.
func (c *Client) raiseSpecEditHeld(vm string) {
	t := &c.specHold
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), specHoldTimeout)
	defer cancel()
	if err := c.ensureSpecHoldsSeeded(ctx); err != nil {
		return // the next pass that holds retries
	}
	t.mu.Lock()
	st := t.holds[vm]
	if st == nil {
		t.mu.Unlock()
		return
	}
	op := st.op
	t.mu.Unlock()

	held, owner, err := c.heldRow(ctx, vm, op)
	if err != nil {
		return
	}
	if !held {
		c.resolveSpecHoldLocked(ctx, vm, op, nil)
		return
	}

	ts := time.Now().UTC().Format(time.RFC3339)
	t.mu.Lock()
	if t.holds[vm] != st {
		t.mu.Unlock()
		return // resolved, or replaced by a later operation's hold
	}
	lifecycle := ConditionObserved
	if st.passes >= 2 {
		lifecycle = ConditionConfirmed
	}
	note := lifecycle == ConditionConfirmed && !st.noted
	if note {
		st.noted = true
	}
	same := st.written == lifecycle && st.writtenOwner == owner
	if st.firstSeen == "" {
		st.firstSeen = ts
	}
	if lifecycle == ConditionConfirmed && st.confirmedAt == "" {
		st.confirmedAt = ts
	}
	firstSeen, confirmedAt, passes := st.firstSeen, st.confirmedAt, st.passes
	t.mu.Unlock()

	if note {
		slog.Warn("replication: a longer line of spec edits is held off a VM by a running operation",
			"vm", vm, "operation", op, "owner", owner, "remedy", specHoldRemedy(vm, op, owner))
		if m, ok := c.syncMetrics.(SpecEditHeldObserver); ok {
			m.ObserveSpecEditHeld()
		}
	}
	if same {
		return
	}
	ev, err := json.Marshal(specHoldEvidence{VM: vm, Operation: op, Owner: owner, Remedy: specHoldRemedy(vm, op, owner)})
	if err != nil {
		return
	}
	row := HealthCondition{
		Evaluator: specHoldEvaluator, Code: SpecEditHeldCode, SubjectKind: "vm", SubjectID: c.specHoldSubject(vm),
		Lifecycle: lifecycle, Severity: SeverityWarning, Hosts: []string{owner},
		Evidence: string(ev), ObserveCount: passes, FirstSeen: firstSeen, LastSeen: ts, Reporter: c.hostName,
	}
	if lifecycle == ConditionConfirmed {
		row.ConfirmedAt = confirmedAt
	}
	if f := t.beforeWrite; f != nil {
		f(vm)
	}
	if err := UpsertHealthCondition(ctx, c, row); err != nil {
		slog.Warn("replication: could not write the held-spec-edit condition", "vm", vm, "error", err)
		return // the next pass that holds writes it; not warned or counted again
	}
	t.mu.Lock()
	if t.holds[vm] == st {
		st.written, st.writtenOwner = lifecycle, owner
	}
	t.mu.Unlock()
}

// sweepSpecHolds resolves this host's holds that are over, for every VM
// queued until the queue is empty: one batched read of the open conditions
// per round, then a check of each open one — a VM deleted since is over
// whatever queued it.
func (c *Client) sweepSpecHolds() {
	t := &c.specHold
	for {
		t.mu.Lock()
		batch := t.pending
		t.pending = nil
		if len(batch) == 0 {
			t.sweeping = false
			t.mu.Unlock()
			return
		}
		t.mu.Unlock()
		c.sweepSpecHoldsOnce(batch)
	}
}

func (c *Client) sweepSpecHoldsOnce(batch map[string]struct{}) {
	t := &c.specHold
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if f := t.swept; f != nil {
		defer f()
	}
	ctx, cancel := context.WithTimeout(context.Background(), specHoldTimeout)
	defer cancel()
	open, err := c.openSpecHoldsHere(ctx)
	if err != nil {
		return
	}
	c.seedSpecHoldsLocked(open)
	rows := make(map[string]HealthCondition, len(open))
	for _, row := range open {
		rows[strings.TrimSuffix(row.SubjectID, "@"+c.hostName)] = row
	}
	check := map[string]struct{}{}
	for vm := range rows {
		check[vm] = struct{}{}
	}
	t.mu.Lock()
	for vm := range batch {
		if t.holds[vm] != nil {
			check[vm] = struct{}{} // held in memory, its condition not yet written
		}
	}
	t.mu.Unlock()
	for vm := range check {
		op := ""
		t.mu.Lock()
		if st := t.holds[vm]; st != nil {
			op = st.op
		}
		t.mu.Unlock()
		var row *HealthCondition
		if r, ok := rows[vm]; ok {
			row = &r
			var ev specHoldEvidence
			_ = json.Unmarshal([]byte(r.Evidence), &ev)
			if op == "" {
				op = ev.Operation
			}
		}
		held, _, err := c.heldRow(ctx, vm, op)
		if err != nil || held {
			continue
		}
		c.resolveSpecHoldLocked(ctx, vm, op, row)
	}
}

// resolveSpecHoldLocked ends vm's hold of op here: the in-memory hold is
// dropped and an open condition resolved. Under writeMu. row is the open
// condition when the caller has read it; nil reads it.
func (c *Client) resolveSpecHoldLocked(ctx context.Context, vm, op string, row *HealthCondition) {
	t := &c.specHold
	t.mu.Lock()
	if st := t.holds[vm]; st != nil && st.op == op {
		delete(t.holds, vm)
	}
	t.mu.Unlock()
	if row == nil {
		r, found, err := GetHealthCondition(ctx, c, specHoldEvaluator, SpecEditHeldCode, "vm", c.specHoldSubject(vm))
		if err != nil || !found || r.Lifecycle == ConditionResolved {
			return
		}
		row = &r
	}
	if err := resolveSpecHoldRow(ctx, c, *row, c.hostName); err != nil {
		slog.Warn("replication: could not resolve the held-spec-edit condition", "vm", vm, "error", err)
		// Kept open; the next check of the VM resolves it.
		t.mu.Lock()
		if t.holds[vm] == nil {
			t.holds[vm] = &specHoldState{op: op, written: row.Lifecycle, noted: true, passes: 2}
		}
		t.mu.Unlock()
	}
}

func resolveSpecHoldRow(ctx context.Context, c *Client, row HealthCondition, reporter string) error {
	ts := time.Now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = ConditionResolved, ts, ts, reporter
	row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
	return UpsertHealthCondition(ctx, c, row)
}

// ResolveSpecEditHeldOfHost resolves every open held-line condition a removed
// host raised. Only the raising host resolves its own otherwise, and a
// removed one never will.
func ResolveSpecEditHeldOfHost(ctx context.Context, c *Client, host string) error {
	open, err := ListOpenHealthConditionsByCode(ctx, c, specHoldEvaluator, SpecEditHeldCode)
	if err != nil {
		return err
	}
	for _, row := range open {
		if row.SubjectKind != "vm" || !strings.HasSuffix(row.SubjectID, "@"+host) {
			continue
		}
		if err := resolveSpecHoldRow(ctx, c, row, c.hostName); err != nil {
			return err
		}
	}
	return nil
}
