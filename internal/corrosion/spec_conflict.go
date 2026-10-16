package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// Two edits of one VM's desired spec made from the same spec_generation.
//
// Every out-of-band edit (MutateDesiredSpec) and every operation's claim
// (BeginVMOperation) is a compare-and-swap: WHERE spec_generation = E, SET
// spec_generation = E+1. Two hosts that each make one from E — one on each
// side of a partition, or an operation on the owner racing a metadata edit
// elsewhere — produce two versions of the spec at E+1. Before spec_conflict_v1
// each replica kept whichever reached it first: the other's CAS missed and
// applied as a silent zero-row no-op. Anti-entropy then took the newer row by
// timestamp, which dropped one edit without a trace and could overwrite an
// operation's barrier with an out-of-band edit while the operation ran.
//
// Once spec_conflict_v1 has latched, an out-of-band edit carries the owner
// epoch it was made at (vmSpecMutateAtEpochSQL). Gated by the latch because a
// previous-release peer has no ledger entry for that shape.

// The out-of-band spec edit. vmSpecMutateSQL is the previous release's shape,
// emitted until spec_conflict_v1 latches; vmSpecMutateAtEpochSQL carries the
// owner epoch the edit was made at, so a receiver can tell an edit made under
// a superseded owner from a concurrent one.
const (
	vmSpecMutateSQL = `UPDATE vms SET spec = ?, spec_generation = spec_generation + 1, updated_at = ?
			 WHERE name = ? AND spec_generation = ? AND active_operation_id = '' AND deleted_at IS NULL`
	vmSpecMutateAtEpochSQL = `UPDATE vms SET spec = ?, spec_generation = spec_generation + 1, updated_at = ?
			 WHERE name = ? AND vm_owner_epoch = ? AND spec_generation = ? AND active_operation_id = '' AND deleted_at IS NULL`
)

// SetSpecConflictGate injects the predicate that says spec_conflict_v1 has
// durably latched, wired at daemon start. Nil-safe: an unset gate reads
// false, so spec edits keep the previous release's shape and resolution.
func (c *Client) SetSpecConflictGate(fn func() bool) {
	if fn == nil {
		c.specConflictGate.Store(nil)
		return
	}
	c.specConflictGate.Store(&fn)
}

// SpecConflictOn reports whether spec_conflict_v1 has durably latched here.
func (c *Client) SpecConflictOn() bool {
	fn := c.specConflictGate.Load()
	return fn != nil && (*fn)()
}

// specEditDrop is one desired-spec edit a conflict resolution dropped.
type specEditDrop struct {
	vm, host   string
	epoch, gen int64 // the kept version's owner epoch and generation
	reason     string
	path       resolveTiePath
	keptAt     string // updated_at of the version kept
	droppedAt  string // updated_at of the edit dropped
	// droppedSpec is the dropped edit's whole spec, so it can be made again.
	droppedSpec string
}

// SpecEditDroppedEvent is the vm_events type that records a dropped spec edit.
const SpecEditDroppedEvent = "vm.spec_edit_dropped"

// specDropReasonText says what each reason means, for the event's detail.
var specDropReasonText = map[string]string{
	specDropStaleEpoch: "it was made under an owner the VM has since moved from",
	specDropOperation:  "an operation on the VM held its barrier at that generation",
	specDropLaterEdit:  "a later edit was made from the same generation",
	specDropTie:        "another edit was made from the same generation at the same instant; the one on each host stands until one is made again",
}

// specDropDetailMax bounds the dropped spec quoted in an event's detail.
const specDropDetailMax = 4096

// noteSpecEditDropped records d once tx commits — a rolled-back resolution
// dropped nothing: a warning, litevirt_merge_apply_rejected_total{table="vms",
// reason="spec_edit_dropped"}, and a vm.spec_edit_dropped event on the VM
// carrying the dropped spec so the edit can be made again.
func (c *Client) noteSpecEditDropped(tx *sql.Tx, d specEditDrop) {
	c.deferAfterCommit(tx, func() {
		slog.Warn("replication: a concurrent edit of a VM's spec was dropped",
			"vm", d.vm, "generation", d.gen, "owner_epoch", d.epoch, "reason", d.reason, "path", string(d.path),
			"kept_updated_at", d.keptAt, "dropped_updated_at", d.droppedAt)
		c.observeMergeRejected("vms", string(d.path), "spec_edit_dropped")
		// Not here: the deferred effects run under the client's lock, which
		// the event's own replicated write takes.
		go c.recordSpecEditDropped(d)
	})
}

// specEditDroppedRecord is d's event. Every host that drops the same edit —
// on either lane — derives the same record, so the replicated rows collapse
// into one (vm_events is INSERT OR IGNORE on its id).
func specEditDroppedRecord(d specEditDrop) VMEventRecord {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		SpecEditDroppedEvent, d.vm, strconv.FormatInt(d.gen, 10), d.droppedAt, d.droppedSpec,
	}, "\x00")))
	ts := ""
	if t, ok := parseInstant(d.keptAt); ok {
		if dt, dok := parseInstant(d.droppedAt); dok && dt.After(t) {
			t = dt
		}
		ts = t.UTC().Format(nowTSLayout)
	}
	spec := d.droppedSpec
	if len(spec) > specDropDetailMax {
		spec = spec[:specDropDetailMax] + "…"
	}
	why := specDropReasonText[d.reason]
	if why == "" {
		why = d.reason
	}
	return VMEventRecord{
		ID:       hex.EncodeToString(sum[:16]),
		VMName:   d.vm,
		HostName: d.host,
		Type:     SpecEditDroppedEvent,
		Result:   "error",
		Severity: "warn",
		Detail: fmt.Sprintf("an edit of the spec made at %s was dropped at generation %d: %s; the version made at %s was kept. "+
			"Make the edit again if it is still wanted. Dropped spec: %s", d.droppedAt, d.gen, why, d.keptAt, spec),
		TS: ts,
	}
}

func (c *Client) recordSpecEditDropped(d specEditDrop) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := InsertVMEvent(ctx, c, specEditDroppedRecord(d)); err != nil {
		slog.Warn("replication: could not record a dropped spec edit", "vm", d.vm, "generation", d.gen, "error", err)
	}
}
